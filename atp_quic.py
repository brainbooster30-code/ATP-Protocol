"""
ATP v1.8 — QUIC Transport Module (aioquic)

Reimplementa ATPServer e ATPClient usando aioquic (QUIC RFC 9000)
invece di TCP+TLS. stream_handler riceve (StreamReader, StreamWriter)
identico a asyncio.start_server — compatibile con ATPAgent esistente.
"""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from typing import Optional

from aioquic.asyncio import connect, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.tls import CipherSuite

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

from config import SERVER_HOST, SERVER_PORT
from agent import ATPAgent, AgentIdentity
from monitor import Monitor

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
#  Cert persistence (aioquic needs file paths, not PEM bytes)
# ═══════════════════════════════════════════════════════════════════════════════

_quic_ca_path: Optional[str] = None
_quic_ca_key: Optional[ec.EllipticCurvePrivateKey] = None
_quic_ca_cert_pem: Optional[bytes] = None


def _ensure_quic_ca() -> tuple[str, bytes, ec.EllipticCurvePrivateKey]:
    """Generate or retrieve the ECDSA P-256 CA for QUIC.
    Returns (ca_path, ca_cert_pem, ca_private_key)."""
    global _quic_ca_path, _quic_ca_key, _quic_ca_cert_pem
    if _quic_ca_path is None:
        import datetime as _dt
        ca_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ATP QUIC CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name).issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(days=1))
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=365 * 10))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("atp-ca")]), critical=False)
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        _quic_ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        _quic_ca_key = ca_key
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
            f.write(_quic_ca_cert_pem)
            _quic_ca_path = f.name
    return _quic_ca_path, _quic_ca_cert_pem, _quic_ca_key


def _write_quic_cert(cn: str) -> tuple[str, str]:
    """Write a CA-signed ECDSA P-256 cert+key for *cn* to temp files.
    Uses the shared QUIC CA from _ensure_quic_ca().
    Returns (cert_path, key_path)."""
    import datetime as _dt
    ca_path, ca_cert_pem, ca_key = _ensure_quic_ca()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    
    node_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    node_pub = node_key.public_key()
    node_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    san = x509.DNSName(cn.replace(":", "-").replace(".", "-"))
    node_cert = (
        x509.CertificateBuilder()
        .subject_name(node_name).issuer_name(ca_cert.subject)
        .public_key(node_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(days=1))
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=365 * 10))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    cert_pem = node_cert.public_bytes(serialization.Encoding.PEM)
    key_pem = node_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
        cf.write(cert_pem); cert_path = cf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(key_pem); key_path = kf.name
    return cert_path, key_path


def _make_quic_config(server_side: bool = False, cn: str = "atp-quic") -> QuicConfiguration:
    """Build a QuicConfiguration for ATP over QUIC.

    Uses the same CA-signed Ed25519 cert as the TCP transport.
    Supports mutual TLS (CERT_REQUIRED) like the TCP layer.
    """
    config = QuicConfiguration(
        alpn_protocols=["atp-v1.8"],
        is_client=not server_side,
        verify_mode=ssl_module.CERT_REQUIRED,
    )
    # Load CA cert for peer verification
    ca_path, _, _ = _ensure_quic_ca()
    config.ca_certs = ca_path
    # Load node cert+key (ECDSA P-256 per QUIC compatibilità)
    cert_path, key_path = _write_quic_cert(cn)
    config.certificate = cert_path
    config.private_key = key_path
    return config


# ═══════════════════════════════════════════════════════════════════════════════
#  Import ssl for constants (not for connections)
# ═══════════════════════════════════════════════════════════════════════════════
import ssl as ssl_module


# ═══════════════════════════════════════════════════════════════════════════════
#  QUICServer
# ═══════════════════════════════════════════════════════════════════════════════

class QUICServer:
    """
    ATP server over QUIC (RFC 9000) using aioquic.

    Accepts QUIC connections and runs an ATPAgent per stream.
    Parallels ATPServer but with native stream multiplexing.
    """

    def __init__(self, monitor: Optional[Monitor] = None):
        self.monitor = monitor
        self._server = None
        self._running = False
        self.identity = AgentIdentity(agent_name="atp-quic-server")

    async def start(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        """Start the QUIC server."""
        config = _make_quic_config(
            server_side=True,
            cn=f"atp-quic-server-{host}:{port}",
        )

        self._server = await serve(
            host=host,
            port=port,
            configuration=config,
            stream_handler=self._on_quic_stream,
        )
        self._running = True
        logger.info("ATP QUIC Server listening on %s:%s", host, port)

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _on_quic_stream(self, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter):
        """Handle one QUIC stream — same interface as TCP _on_connect."""
        from config import RateLimiter, AntiReplay, HandshakeRateLimiter

        peer = writer.get_extra_info("peername", ("0.0.0.0", 0))
        peer_ip = str(peer[0]) if peer else "0.0.0.0"

        if not hasattr(QUICServer, "_hs_limiter"):
            QUICServer._hs_limiter = HandshakeRateLimiter()
        if not await QUICServer._hs_limiter.allow(peer_ip):
            logger.warning("QUIC handshake rate limit exceeded for %s", peer_ip)
            writer.close()
            return

        agent = ATPAgent(
            identity=self.identity,
            is_server=True,
            monitor=self.monitor,
            task_handler=self._default_task_handler,
            rate_limiter=RateLimiter(),
            anti_replay=AntiReplay(),
        )
        try:
            ok = await agent.perform_handshake(reader, writer)
            if ok:
                if hasattr(QUICServer, "_hs_limiter"):
                    QUICServer._hs_limiter.reset(peer_ip)
                await agent.handle_task_loop()
        except Exception as exc:
            logger.exception("QUIC connection error: %s", exc)
        finally:
            await agent.close_async()
            try:
                writer.close()
            except Exception:
                pass

    async def _default_task_handler(self, frame: dict) -> dict:
        task_payload = frame.get("task_payload", b"")
        task_type = frame.get("task_type", "unknown")
        if task_type == "deepseek_chat":
            prompt = task_payload.decode("utf-8", errors="replace")
            result = await ATPAgent.call_deepseek(prompt, self.monitor)
            if result:
                return {"result": result}
            return {"error": "DeepSeek returned no result"}
        return {"echo": task_payload.decode("utf-8", errors="replace")}


# ═══════════════════════════════════════════════════════════════════════════════
#  QUICClient
# ═══════════════════════════════════════════════════════════════════════════════

class QUICClient:
    """
    ATP client over QUIC (RFC 9000) using aioquic.
    Parallels ATPClient but with native QUIC transport.
    """

    def __init__(self, monitor: Optional[Monitor] = None):
        self.monitor = monitor
        self.agent: Optional[ATPAgent] = None
        self._connected = False
        self._protocol = None
        self.identity = AgentIdentity(agent_name="atp-quic-client")

    async def connect(self, host: str = SERVER_HOST, port: int = SERVER_PORT) -> bool:
        """Connect to a QUIC server and perform ATP handshake."""
        config = _make_quic_config(
            server_side=False,
            cn=f"atp-quic-client-{host}:{port}",
        )

        try:
            # Enter the connect context manager manually so we
            # can keep the protocol alive past the __aenter__
            cm = connect(
                host=host,
                port=port,
                configuration=config,
                stream_handler=self._on_stream,
                wait_connected=True,
            )
            self._protocol = await cm.__aenter__()
            reader, writer = await self._protocol.create_stream()
        except Exception as exc:
            logger.error("QUIC connect failed: %s", exc)
            return False

        self.agent = ATPAgent(
            identity=self.identity,
            is_server=False,
            monitor=self.monitor,
        )
        ok = await self.agent.perform_handshake(reader, writer)
        self._connected = ok
        if ok:
            logger.info("QUIC Client connected and bound to %s:%s", host, port)
        else:
            await self.disconnect()
        return ok

    async def _on_stream(self, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter):
        pass  # Client-side incoming streams unused

    async def send_task(self, task_type: str, payload: str,
                         deadline_ms: int = 30_000) -> dict:
        if not self._connected or not self.agent:
            return {"status": "disconnected", "data": None}
        return await self.agent.send_task(
            task_type=task_type,
            payload=payload.encode("utf-8"),
            deadline_ms=deadline_ms,
        )

    async def disconnect(self):
        if self.agent:
            await self.agent.close_async()
        self._connected = False
        # Close QUIC protocol
        if self._protocol:
            try:
                self._protocol.close()
                await self._protocol.wait_closed()
            except Exception:
                pass
            self._protocol = None
