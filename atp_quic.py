"""
ATP v1.8 — QUIC Transport Module (aioquic)

Implementa QUIC server e client usando aioquic con certificati RSA 2048
(compatibili con aioquic 1.3.0). stream_handler riceve (StreamReader,
StreamWriter) identico a asyncio.start_server.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import logging
import os
import tempfile
import time
import ssl as ssl_module
from typing import Optional

from aioquic.asyncio import connect, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.tls import CipherSuite

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from config import SERVER_HOST, SERVER_PORT
from agent import ATPAgent, AgentIdentity
from monitor import Monitor

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
#  Cert persistence — RSA 2048 (aioquid 1.3 compat)
# ═══════════════════════════════════════════════════════════════════════════════

_quic_ca_path: Optional[str] = None
_quic_ca_key: Optional[rsa.RSAPrivateKey] = None
_quic_ca_cert_pem: Optional[bytes] = None


def _ensure_quic_ca() -> tuple[str, bytes, rsa.RSAPrivateKey]:
    global _quic_ca_path, _quic_ca_key, _quic_ca_cert_pem
    if _quic_ca_path is None:
        import datetime as _dt
        ca_key = rsa.generate_private_key(65537, 2048, default_backend())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ATP QUIC CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name).issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(days=1))
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=365 * 10))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        _quic_ca_cert_pem = ca_cert.public_bytes(Encoding.PEM)
        _quic_ca_key = ca_key
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
            f.write(_quic_ca_cert_pem)
            _quic_ca_path = f.name
    return _quic_ca_path, _quic_ca_cert_pem, _quic_ca_key


def _write_quic_cert(cn: str) -> tuple[str, str]:
    import datetime as _dt
    ca_path, ca_cert_pem, ca_key = _ensure_quic_ca()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    node_key = rsa.generate_private_key(65537, 2048, default_backend())
    node_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(node_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(days=1))
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=365 * 10))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    cert_pem = node_cert.public_bytes(Encoding.PEM)
    key_pem = node_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
        cf.write(cert_pem); cert_path = cf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(key_pem); key_path = kf.name
    return cert_path, key_path


def _make_quic_config(server_side: bool = False, cn: str = "atp-quic") -> QuicConfiguration:
    """Build aioquic config with RSA 2048 certs.
    Server: CERT_REQUIRED (verifica client). Client: CERT_NONE (verifica via MCC)."""
    config = QuicConfiguration(
        alpn_protocols=["atp-v1.8"],
        is_client=not server_side,
        verify_mode=ssl_module.CERT_REQUIRED if server_side else ssl_module.CERT_NONE,
    )
    ca_path, _, _ = _ensure_quic_ca()
    config.ca_certs = ca_path
    cert_path, key_path = _write_quic_cert(cn)
    config.load_cert_chain(cert_path, key_path)
    return config


# ═══════════════════════════════════════════════════════════════════════════════
#  QUICServer
# ═══════════════════════════════════════════════════════════════════════════════

class QUICServer:
    """ATP server over QUIC (RFC 9000) using aioquic."""

    def __init__(self, monitor: Optional[Monitor] = None):
        self.monitor = monitor
        self._server = None
        self._running = False
        self.identity = AgentIdentity(agent_name="atp-quic-server")

    async def start(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        config = _make_quic_config(server_side=True, cn=f"quic-server-{host}-{port}")
        self._server = await serve(
            host=host, port=port,
            configuration=config,
            stream_handler=self._on_quic_stream,
        )
        self._running = True
        logger.info("ATP QUIC Server listening on %s:%s (RSA 2048)", host, port)

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()

    def _on_quic_stream(self, reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter):
        """Handle one QUIC stream. aioquic calls this synchronously
        (non-async), so we launch the handler as a background task."""
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

    def __init__(self, monitor: Optional[Monitor] = None):
        self.monitor = monitor
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
            logger.info("%s connected in %.1fs", log_prefix, time.time() - t0)
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

        self.agent = ATPAgent(identity=self.identity, is_server=False, monitor=self.monitor)
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
        pass

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
