"""
ATP v1.8 — QUIC Transport Module (aioquic)
ECDSA P-256 invece di RSA 2048 per performance (~100x più veloce).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import tempfile
import time
import ssl as ssl_module
from typing import Optional
from pathlib import Path

from aioquic.asyncio import connect, serve
from aioquic.quic.configuration import QuicConfiguration

from config import SERVER_HOST, SERVER_PORT
from agent import ATPAgent, AgentIdentity
from agent_tls import get_quic_cert
from monitor import Monitor

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
#  Cert persistence — ECDSA P-256 (aioquic 1.3 compat)
#  CA + node certs persist to ~/.atp/quic/ instead of tempfiles.
# ═══════════════════════════════════════════════════════════════════════════════

_QUIC_CERT_DIR = os.path.join(os.path.expanduser("~"), ".atp", "quic")


def _ensure_quic_cert_dir() -> str:
    os.makedirs(_QUIC_CERT_DIR, exist_ok=True)
    return _QUIC_CERT_DIR


def _get_quic_cert_paths(cn: str) -> tuple[str, str, str]:
    """Return (cert_path, key_path, ca_path) for a given CN.
    Certificates are generated once and cached on disk.
    """
    import hashlib
    cn_hash = hashlib.sha256(cn.encode()).hexdigest()[:16]
    cert_dir = _ensure_quic_cert_dir()
    ca_cert_path = os.path.join(cert_dir, "ca_cert.pem")
    ca_key_path = os.path.join(cert_dir, "ca_key.pem")
    cert_path = os.path.join(cert_dir, f"cert-{cn_hash}.pem")
    key_path = os.path.join(cert_dir, f"key-{cn_hash}.pem")

    if os.path.isfile(cert_path) and os.path.isfile(key_path) and os.path.isfile(ca_cert_path):
        return cert_path, key_path, ca_cert_path

    # Generate new ECDSA P-256 cert using agent_tls.get_quic_cert
    import atexit
    cert_pem, key_pem, ca_cert_pem = get_quic_cert(cn=cn)
    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(key_pem)
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert_pem)
    logger.info("QUIC cert generated (ECDSA P-256) for CN=%s", cn)
    return cert_path, key_path, ca_cert_path


def _make_quic_config(server_side: bool = False, cn: str = "atp-quic") -> QuicConfiguration:
    """Build aioquic config with ECDSA P-256 certs.
    Server: CERT_REQUIRED (verifica client). Client: CERT_NONE (verifica via MCC).
    """
    config = QuicConfiguration(
        alpn_protocols=["atp-v1.8"],
        is_client=not server_side,
        verify_mode=ssl_module.CERT_REQUIRED if server_side else ssl_module.CERT_NONE,
    )
    cert_path, key_path, ca_path = _get_quic_cert_paths(cn)
    config.ca_certs = ca_path
    config.load_cert_chain(cert_path, key_path)
    return config


# ═══════════════════════════════════════════════════════════════════════════════
#  QUICServer
# ═══════════════════════════════════════════════════════════════════════════════

class QUICServer:
    """ATP server over QUIC (RFC 9000) using aioquic."""

    def __init__(self, monitor: Optional[Monitor] = None,
                 trust_bootstrap_mode: Optional[str] = None):
        self.monitor = monitor
        self.trust_bootstrap_mode = trust_bootstrap_mode
        self._server = None
        self._running = False
        self._server_task: Optional[asyncio.Task] = None
        self.identity = AgentIdentity(agent_name="atp-quic-server")
        self._push_root_store = False

    async def start(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        config = _make_quic_config(server_side=True, cn=f"quic-server-{host}-{port}")
        self._server = await serve(
            host=host, port=port,
            configuration=config,
            stream_handler=self._on_quic_stream,
        )
        self._running = True
        logger.info("ATP QUIC Server listening on %s:%s (ECDSA P-256)", host, port)

    async def stop(self):
        """Graceful stop with drain."""
        self._running = False
        if self._server:
            self._server.close()
            # Give active connections time to drain
            await asyncio.sleep(1)

    def _on_quic_stream(self, reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter):
        """Handle one QUIC stream. aioquic calls this synchronously."""
        asyncio.create_task(self._handle_quic_stream(reader, writer))

    async def _handle_quic_stream(self, reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter):
        from config import RateLimiter, AntiReplay, HandshakeRateLimiter
        peer = writer.get_extra_info("peername", ("0.0.0.0", 0))
        peer_ip = str(peer[0]) if peer else "0.0.0.0"
        if not hasattr(QUICServer, "_hs_limiter"):
            QUICServer._hs_limiter = HandshakeRateLimiter()
        if not await QUICServer._hs_limiter.allow(peer_ip):
            writer.close(); return
        agent = ATPAgent(
            identity=self.identity, is_server=True, monitor=self.monitor,
            task_handler=self._default_task_handler,
            rate_limiter=RateLimiter(), anti_replay=AntiReplay(),
            trust_bootstrap_mode=self.trust_bootstrap_mode,
        )
        try:
            ok = await agent.perform_handshake(reader, writer)
            if ok:
                if hasattr(QUICServer, "_hs_limiter"):
                    QUICServer._hs_limiter.reset(peer_ip)
                await agent.handle_task_loop()
        except Exception as exc:
            logger.exception("QUIC error: %s", exc)
        finally:
            await agent.close_async()
            try: writer.close()
            except Exception: pass

    async def _default_task_handler(self, frame: dict) -> dict:
        task_payload = frame.get("task_payload", b"")
        task_type = frame.get("task_type", "unknown")
        if task_type == "deepseek_chat":
            prompt = task_payload.decode("utf-8", errors="replace")
            result = await ATPAgent.call_deepseek(prompt, self.monitor)
            if result: return {"result": result}
            return {"error": "DeepSeek returned no result"}
        return {"echo": task_payload.decode("utf-8", errors="replace")}


# ═══════════════════════════════════════════════════════════════════════════════
#  QUICClient
# ═══════════════════════════════════════════════════════════════════════════════

class QUICClient:
    """ATP client over QUIC (RFC 9000) using aioquic."""

    def __init__(self, monitor: Optional[Monitor] = None,
                 trust_bootstrap_mode: Optional[str] = None):
        self.monitor = monitor
        self.trust_bootstrap_mode = trust_bootstrap_mode
        self.agent: Optional[ATPAgent] = None
        self._connected = False
        self._protocol = None
        self._cm = None
        self.identity = AgentIdentity(agent_name="atp-quic-client")

    async def connect(self, host: str = SERVER_HOST, port: int = SERVER_PORT) -> bool:
        config = _make_quic_config(server_side=False, cn=f"quic-client-{host}-{port}")
        t0 = time.time()
        try:
            self._cm = connect(
                host=host, port=port, configuration=config,
                stream_handler=self._on_stream, wait_connected=True,
            )
            self._protocol = await asyncio.wait_for(
                self._cm.__aenter__(), timeout=8.0
            )
            log_prefix = f"QUIC[{host}:{port}]"
            logger.info("%s connected in %.1fs (ECDSA P-256)", log_prefix, time.time() - t0)
            reader, writer = await asyncio.wait_for(
                self._protocol.create_stream(), timeout=5.0
            )
            logger.info("%s stream created", log_prefix)
        except asyncio.TimeoutError:
            logger.error("QUIC connect: timeout establishing QUIC connection")
            return False
        except Exception as exc:
            logger.error("QUIC connect failed: %s", exc)
            return False

        self.agent = ATPAgent(
            identity=self.identity, is_server=False, monitor=self.monitor,
            trust_bootstrap_mode=self.trust_bootstrap_mode,
        )
        try:
            t1 = time.time()
            ok = await asyncio.wait_for(
                self.agent.perform_handshake(reader, writer), timeout=10.0
            )
            logger.info("%s ATP handshake done in %.1fs (ok=%s)", log_prefix, time.time() - t1, ok)
        except asyncio.TimeoutError:
            logger.error("QUIC connect: ATP handshake timeout")
            return False
        except Exception as exc:
            logger.error("QUIC connect: ATP handshake failed: %s", exc)
            return False

        self._connected = ok
        if ok:
            logger.info("QUIC Client bound to %s:%s", host, port)
        else:
            await self.disconnect()
        return ok

    async def _on_stream(self, reader, writer):
        """Handle a server-initiated QUIC stream (back-channel)."""
        if not self.agent:
            logger.warning("QUIC back-channel: no agent bound")
            try: writer.close()
            except Exception: pass
            return
        try:
            from atp_core import decode_frame, build_header, send_frame
            while self._connected and self.agent:
                frame = await asyncio.wait_for(
                    decode_frame(reader), timeout=60.0
                )
                if frame is None:
                    break
                ft = frame.get("header", {}).get("frame_type")
                if ft == 0x21:  # ROOT_STORE_UPDATE
                    await self.agent._handle_root_store_update(frame)
                elif ft == 0x15:  # CONTROL_PING
                    try:
                        pong = {"header": build_header(0x16),
                                "timestamp": int(time.time() * 1000)}
                        await send_frame(writer, pong)
                    except Exception:
                        pass
                elif ft == 0x20:  # ERROR
                    logger.warning("QUIC back-channel ERROR: %s",
                                   frame.get("error_message", ""))
                    break
                else:
                    logger.debug("QUIC back-channel: ignored frame 0x%02x", ft)
        except asyncio.TimeoutError:
            logger.debug("QUIC back-channel: idle timeout")
        except (ConnectionError, OSError):
            logger.debug("QUIC back-channel: connection lost")
        except Exception as exc:
            logger.debug("QUIC back-channel error: %s", exc)
        finally:
            try: writer.close()
            except Exception: pass

    async def send_task(self, task_type: str, payload: str,
                         deadline_ms: int = 30_000) -> dict:
        if not self._connected or not self.agent:
            return {"status": "disconnected", "data": None}
        return await self.agent.send_task(
            task_type=task_type, payload=payload.encode("utf-8"), deadline_ms=deadline_ms)

    async def disconnect(self):
        if self.agent: await self.agent.close_async()
        self._connected = False
        if self._protocol and self._cm:
            try:
                await self._cm.__aexit__(None, None, None)
            except Exception:
                pass
            self._protocol = None
            self._cm = None
