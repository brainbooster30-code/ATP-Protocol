"""
ATP v1.6.1 — Agent: identity, handshake (5 phases), task lifecycle, DeepSeek.
"""

from __future__ import annotations

import os
import time
import json
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.backends import default_backend

import aiohttp
import cbor2

from config import (
    ATP_VERSION,
    SERVER_HOST,
    SERVER_PORT,
    CLOCK_SKEW_MS,
    ANTI_REPLAY_TTL_MS,
    RATE_LIMIT_RPS,
    MAX_BATCH_BYTES,
    get_deepseek_api_key,
    DEEPSEEK_MODEL,
    DEEPSEEK_API_URL,
)
from atp_core import (
    generate_x25519_keypair,
    generate_ed25519_keypair,
    ed25519_sign,
    ed25519_verify,
    blake3_hash,
    MCCLeaf,
    MCC,
    FRAME_TYPES,
    ERROR_CODES,
    build_header,
    encode_frame,
    send_frame,
    decode_frame,
)
from authority import get_default_authority
from monitor import (
    Monitor,
    CONNECTION_OPEN,
    CONNECTION_CLOSE,
    HANDSHAKE_START,
    HANDSHAKE_COMPLETE,
    HANDSHAKE_FAILED,
    FRAME_SENT,
    FRAME_RECEIVED,
    TASK_START,
    TASK_COMPLETE,
    TASK_ERROR,
    MCC_VERIFICATION_SUCCESS,
    MCC_VERIFICATION_FAILED,
    BINDING_SUCCESS,
    BINDING_FAILED,
    DEEPSEEK_CALL_START,
    DEEPSEEK_CALL_END,
    RATE_LIMIT_HIT,
    ERROR_OCCURRED,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
#  Agent identity
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AgentIdentity:
    """Cryptographic material for one agent."""

    # Identity claims (stored in MCC leaves)
    agent_name: str = "agent"

    # X25519 keypair — for ECDH / TLS key agreement (agent_pk)
    x25519_sk: bytes = field(default=b"")
    x25519_pk: bytes = field(default=b"")

    # Ed25519 keypair — for signatures (agent_sign_pk)
    ed25519_sk: bytes = field(default=b"")
    ed25519_pk: bytes = field(default=b"")

    def __post_init__(self):
        # Generate fresh, correctly-matched keypairs
        self.x25519_sk, self.x25519_pk = generate_x25519_keypair()
        self.ed25519_sk, self.ed25519_pk = generate_ed25519_keypair()


def create_mcc_for_identity(
    identity: AgentIdentity,
) -> MCC:
    """Build an MCC that contains the agent's public keys as claims."""
    authority = get_default_authority()

    leaves = [
        MCCLeaf(key="agent_pk", value=identity.x25519_pk, salt=os.urandom(16)),
        MCCLeaf(key="agent_sign_pk", value=identity.ed25519_pk, salt=os.urandom(16)),
        MCCLeaf(key="agent_name", value=identity.agent_name.encode(), salt=os.urandom(16)),
        MCCLeaf(key="expiry_date", value=str(int(time.time()) + 86400 * 365).encode(), salt=os.urandom(16)),
        MCCLeaf(key="authority_id", value=authority.authority_id.encode(), salt=os.urandom(16)),
        MCCLeaf(key="mcc_version", value=b"1", salt=os.urandom(16)),
        MCCLeaf(key="serial_number", value=os.urandom(16), salt=os.urandom(16)),
    ]

    critical_mask = [
        "agent_pk",
        "agent_sign_pk",
        "expiry_date",
        "authority_id",
        "mcc_version",
        "serial_number",
    ]

    return authority.sign_mcc(
        leaves=leaves,
        critical_mask=critical_mask,
        serial_number=os.urandom(16),
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  Self-signed TLS certificate helper
# ═══════════════════════════════════════════════════════════════════════════════

def _generate_self_signed_ed25519_cert() -> tuple[bytes, bytes]:
    """Generate a self-signed Ed25519 TLS cert + key.
    Returns (cert_pem_bytes, private_key_pem_bytes)."""
    import datetime
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ATP Demo Agent"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365 * 10))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, None, default_backend())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


# ── cache cert/key per process ────────────────────────────────────────────────
_cert_pem: Optional[bytes] = None
_key_pem: Optional[bytes] = None


def get_self_signed_cert() -> tuple[bytes, bytes]:
    global _cert_pem, _key_pem
    if _cert_pem is None:
        _cert_pem, _key_pem = _generate_self_signed_ed25519_cert()
    return _cert_pem, _key_pem


def make_ssl_context(
    server_side: bool = False,
) -> tuple:
    """Build an SSLContext and return (ssl_context, cert_pem, key_pem)."""
    import ssl
    cert_pem, key_pem = get_self_signed_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE if not server_side else ssl.CERT_REQUIRED
    ctx.load_cert_chain(certfile=None, keyfile=None)
    # Workaround: write cert to temp files for SSLContext
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
        cf.write(cert_pem)
        cert_path = cf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(key_pem)
        key_path = kf.name
    ctx.load_cert_chain(cert_path, key_path)
    if server_side:
        ctx.load_verify_locations(cert_path)
    return ctx, cert_pem, key_pem


# ═══════════════════════════════════════════════════════════════════════════════
#  ATP Agent  (core protocol handler)
# ═══════════════════════════════════════════════════════════════════════════════

class ATPAgent:
    """
    Implements the ATP protocol logic for one connection.
    Can act as initiator (client) or responder (server).

    Handles:
      - 5-phase handshake
      - Frame read/write with length prefix
      - Task dispatch
      - DeepSeek integration
    """

    def __init__(
        self,
        identity: AgentIdentity,
        is_server: bool = False,
        monitor: Optional[Monitor] = None,
        task_handler: Optional[Callable[[dict], Awaitable[dict]]] = None,
        demo_mode: bool = False,
    ):
        self.identity = identity
        self.is_server = is_server
        self.monitor = monitor
        self.task_handler = task_handler  # async callable(task_payload) -> result
        self.demo_mode = demo_mode  # skip root store verification for demo/deploy

        self.mcc: Optional[MCC] = create_mcc_for_identity(identity)
        self.peer_mcc: Optional[MCC] = None
        self.bound = False
        self._peer_nonce: Optional[bytes] = None
        self._my_nonce: Optional[bytes] = None
        self._conn_id: str = ""
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._task_lock = asyncio.Lock()  # serialize concurrent send_task calls

        # Register agent identity in monitor
        if self.monitor:
            role = "server" if is_server else "client"
            self.monitor.register_agent(
                agent_name=identity.agent_name,
                role=role,
                x25519_pk=identity.x25519_pk.hex()[:16],
                ed25519_pk=identity.ed25519_pk.hex()[:16],
                mcc_hash=self.mcc.root_hash.hex()[:16] if self.mcc else "",
                status="initialized",
            )

    # ── public API ───────────────────────────────────────────────────────

    async def perform_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> bool:
        """
        Execute the full 5-phase ATP handshake.
        Returns True on success.
        """
        self._reader = reader
        self._writer = writer
        self._conn_id = f"{id(self):x}"

        if self.monitor:
            self.monitor.add_event(CONNECTION_OPEN, {
                "conn_id": self._conn_id,
                "agent": self.identity.agent_name,
                "mcc_hash": self.mcc.root_hash.hex()[:16] if self.mcc else "",
                "state": "HANDSHAKE",
            })
            self.monitor.add_event(HANDSHAKE_START, {
                "conn_id": self._conn_id,
                "role": "server" if self.is_server else "client",
            })

        try:
            if self.is_server:
                await self._server_handshake(reader, writer)
            else:
                await self._client_handshake(reader, writer)

            self.bound = True
            if self.monitor:
                self.monitor.add_event(HANDSHAKE_COMPLETE, {
                    "conn_id": self._conn_id,
                    "role": "server" if self.is_server else "client",
                })
                self.monitor.add_event(BINDING_SUCCESS, {
                    "conn_id": self._conn_id,
                    "mcc_hash": self.peer_mcc.root_hash.hex()[:16] if self.peer_mcc else "",
                })
                # Update agent status in monitor
                self.monitor.register_agent(
                    agent_name=self.identity.agent_name,
                    role="server" if self.is_server else "client",
                    x25519_pk=self.identity.x25519_pk.hex()[:16],
                    ed25519_pk=self.identity.ed25519_pk.hex()[:16],
                    mcc_hash=self.mcc.root_hash.hex()[:16] if self.mcc else "",
                    status="bound",
                )
            return True

        except Exception as exc:
            logger.exception("Handshake failed")
            # Try to send an ERROR frame to notify the peer
            try:
                err_header = build_header(0x20)
                err_frame = {
                    "header": err_header,
                    "error_code": 0x02,
                    "error_message": str(exc)[:200],
                }
                await send_frame(writer, err_frame)
            except Exception:
                pass
            if self.monitor:
                self.monitor.add_event(HANDSHAKE_FAILED, {
                    "conn_id": self._conn_id,
                    "reason": str(exc),
                })
            return False

    async def send_task(
        self,
        task_type: str,
        payload: bytes,
        deadline_ms: int = 30_000,
        priority: int = 4,
    ) -> Optional[dict]:
        """Send a TASK_REQUEST and wait for the TASK_RESPONSE."""
        if not self.bound or not self._writer:
            logger.error("send_task: not bound")
            return None

        async with self._task_lock:
            if self.monitor:
                self.monitor.add_event(TASK_START, {
                    "conn_id": self._conn_id,
                    "task_type": task_type,
                })

            task_id = os.urandom(16)
            header = build_header(0x01, task_id)
            req_frame = {
                "header": header,
                "task_type": task_type,
                "task_payload": payload,
                "deadline_ms": deadline_ms,
                "metadata": {"priority": priority},
                "priority_hint": priority,
            }

            # Send TASK_REQUEST
            await self._send_frame(req_frame)

            # Expect TASK_ACK
            ack = await self._read_frame()
            if ack is None or ack.get("header", {}).get("frame_type") != 0x03:
                logger.warning("send_task: expected TASK_ACK, got %s",
                               FRAME_TYPES.get(ack.get("header", {}).get("frame_type"), "?"))
                return None

            # Expect TASK_RESPONSE
            resp = await self._read_frame()
            if resp is None:
                return None

            ft = resp.get("header", {}).get("frame_type")
            if ft == 0x04:
                if self.monitor:
                    self.monitor.add_event(TASK_ERROR, {
                        "conn_id": self._conn_id,
                        "error_code": resp.get("error_code"),
                        "error_message": resp.get("error_message"),
                    })
                    self.monitor.add_task({
                        "task_id": task_id.hex()[:8],
                        "task_type": task_type,
                        "request": payload.decode("utf-8", errors="replace")[:80],
                        "response": resp.get("error_message", "")[:200],
                        "status": "error",
                        "error_code": resp.get("error_code"),
                        "latency_ms": 0,
                        "agent": self.identity.agent_name,
                        "direction": "sent",
                        "timestamp": time.time(),
                    })
                return resp

            if ft == 0x02:
                sent_time = header["timestamp"]
                latency = int(time.time() * 1000) - sent_time
                result_bytes = resp.get("result_payload", b"")
                result_text = result_bytes.decode("utf-8", errors="replace")[:200]
                if self.monitor:
                    self.monitor.add_event(TASK_COMPLETE, {
                        "conn_id": self._conn_id,
                        "task_type": task_type,
                        "latency_ms": latency,
                    })
                    self.monitor.add_task({
                        "task_id": task_id.hex()[:8],
                        "task_type": task_type,
                        "request": payload.decode("utf-8", errors="replace")[:80],
                        "response": result_text,
                        "status": "completed",
                        "error_code": None,
                        "latency_ms": latency,
                        "agent": self.identity.agent_name,
                        "direction": "sent",
                        "timestamp": time.time(),
                    })
                return resp

            logger.warning("send_task: unexpected frame 0x%02x", ft)
            return None

    async def handle_task_loop(self):
        """Server loop: read incoming frames and dispatch tasks."""
        if not self.is_server:
            return
        while self.bound and self._reader:
            try:
                frame = await self._read_frame()
                if frame is None:
                    break

                ft = frame.get("header", {}).get("frame_type")
                if ft == 0x01:
                    await self._handle_task_request(frame)
                elif ft == 0x10:
                    logger.info("Received CONTROL_SHUTDOWN")
                    break
                elif ft == 0x20:
                    logger.warning("Received ERROR frame: %s", frame.get("error_message"))
                else:
                    logger.debug("Ignoring frame 0x%02x", ft)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("handle_task_loop error")
                break

    async def close_async(self):
        """Close the connection gracefully with SSL shutdown handshake."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        if self.monitor:
            self.monitor.add_event(CONNECTION_CLOSE, {
                "conn_id": self._conn_id,
                "agent": self.identity.agent_name,
            })

    def close(self):
        """Close the connection (synchronous, best-effort)."""
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass
        if self.monitor:
            self.monitor.add_event(CONNECTION_CLOSE, {
                "conn_id": self._conn_id,
                "agent": self.identity.agent_name,
            })

    # ── DeepSeek API ─────────────────────────────────────────────────────

    @staticmethod
    async def call_deepseek(prompt: str, monitor: Optional[Monitor] = None,
                            conn_id: str = "") -> Optional[str]:
        """Call the DeepSeek chat API with *prompt*."""
        # Check for placeholder / missing API key early
        api_key = get_deepseek_api_key()
        if not api_key:
            logger.warning("DeepSeek API key missing — returning mock response")
            if monitor:
                monitor.add_event(DEEPSEEK_CALL_START, {
                    "conn_id": conn_id,
                    "prompt_preview": prompt[:80],
                })
                monitor.add_event(DEEPSEEK_CALL_END, {
                    "conn_id": conn_id,
                    "success": True,
                })
            return (
                f"[ATP v1.6.1 Mock Response] Richiesta ricevuta: \"{prompt[:100]}{'...' if len(prompt) > 100 else ''}\". "
                f"Configura DEEPSEEK_API_KEY per risposte reali da DeepSeek."
            )

        if monitor:
            monitor.add_event(DEEPSEEK_CALL_START, {
                "conn_id": conn_id,
                "prompt_preview": prompt[:80],
            })
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    DEEPSEEK_API_URL,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": DEEPSEEK_MODEL,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 1024,
                        "temperature": 0.7,
                    },
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        logger.warning("DeepSeek API error %d: %s", resp.status, text)
                        if monitor:
                            monitor.add_event(DEEPSEEK_CALL_END, {
                                "conn_id": conn_id,
                                "error": text[:200],
                            })
                        return None
                    data = await resp.json()
                    result = data["choices"][0]["message"]["content"]
                    if monitor:
                        monitor.add_event(DEEPSEEK_CALL_END, {
                            "conn_id": conn_id,
                            "success": True,
                            "tokens": data.get("usage", {}).get("total_tokens", 0),
                        })
                    return result
        except Exception as exc:
            logger.exception("DeepSeek call failed")
            if monitor:
                monitor.add_event(DEEPSEEK_CALL_END, {
                    "conn_id": conn_id,
                    "error": str(exc),
                })
            return None

    # ══════════════════════════════════════════════════════════════════════
    #  Internal: handshake phases
    # ══════════════════════════════════════════════════════════════════════

    async def _server_handshake(self, reader, writer):
        """Responder-side handshake."""
        # Phase 1 — TLS already done by caller

        # Phase 2 — Version negotiation: receive VERSION_PROPOSE, send VERSION_ACK
        propose = await self._read_frame()
        if propose is None or propose.get("header", {}).get("frame_type") != 0x30:
            raise ConnectionError("Expected VERSION_PROPOSE (0x30)")

        ack_header = build_header(0x31)
        ack = {
            "header": ack_header,
            "atp_version": ATP_VERSION,
            "max_batch_bytes": MAX_BATCH_BYTES,
            "clock_skew_ms": CLOCK_SKEW_MS,
            "anti_replay_ttl_ms": ANTI_REPLAY_TTL_MS,
            "rate_limit_rps": RATE_LIMIT_RPS,
        }
        await self._send_frame(ack)

        # Phase 3 — MCC Exchange & Identity Binding
        # Receive MCC_BIND_REQUEST
        bind_req = await self._read_frame()
        if bind_req is None or bind_req.get("header", {}).get("frame_type") != 0x40:
            raise ConnectionError("Expected MCC_BIND_REQUEST (0x40)")

        # Verify peer's MCC with full ATP-Full checks
        peer_mcc_raw = bind_req.get("mcc_cbor")
        if peer_mcc_raw is None:
            raise ConnectionError("MCC_BIND_REQUEST missing mcc_cbor")
        self.peer_mcc = MCC.from_cbor(peer_mcc_raw)

        # Verify peer's MCC
        if not self.demo_mode:
            # Full ATP-Full: lookup authority in RootStore, verify signature, check revocation
            from revocation import get_root_store, get_degradation
            rs = get_root_store()
            dp = get_degradation()
            auth_pk = rs.get_authority(self.peer_mcc.authority_id)

            if auth_pk is None:
                deg_state = dp.evaluate(self.peer_mcc.authority_id, rs)
                if self.monitor:
                    self.monitor.add_event("DEGRADATION_STATE", {
                        "conn_id": self._conn_id, "state": deg_state,
                    })
                if deg_state == "UNCERTAIN":
                    raise ConnectionError("Authority UNCERTAIN — connection refused")
                authority = get_default_authority()
                auth_pk = authority.public_key

            if not self.peer_mcc.verify(auth_pk, check_revoked=True):
                if self.monitor:
                    self.monitor.add_event(MCC_VERIFICATION_FAILED, {
                        "conn_id": self._conn_id,
                    })
                raise ConnectionError("Peer MCC verification failed")
            if self.monitor:
                self.monitor.add_event(MCC_VERIFICATION_SUCCESS, {
                    "conn_id": self._conn_id,
                })
        else:
            # Demo mode: trust-on-first-use, skip authority signature verification
            if self.monitor:
                self.monitor.add_event(MCC_VERIFICATION_SUCCESS, {
                    "conn_id": self._conn_id,
                    "demo_mode": True,
                })

        # Check if peer wants key separation (dual_use check)
        peer_leaves = {l.key: l.value for l in self.peer_mcc.leaves}

        # Generate my nonce
        self._my_nonce = os.urandom(16)
        peer_nonce = bind_req.get("nonce", b"")

        # Send MCC_BIND_RESPONSE with our MCC, nonce_r, and signature
        resp_header = build_header(0x41)
        resp_payload = {
            "header": resp_header,
            "mcc_cbor": self.mcc.to_cbor(),
            "nonce": self._my_nonce,
            "signature": ed25519_sign(
                self.identity.ed25519_sk,
                peer_nonce + b"atp-bind-response",
            ),
        }
        await self._send_frame(resp_payload)

        # Receive MCC_BIND_CONFIRM
        confirm = await self._read_frame()
        if confirm is None or confirm.get("header", {}).get("frame_type") != 0x42:
            raise ConnectionError("Expected MCC_BIND_CONFIRM (0x42)")

        peer_sig = confirm.get("signature", b"")
        peer_sign_pk = peer_leaves.get("agent_sign_pk", b"")
        if not ed25519_verify(peer_sign_pk, peer_sig, self._my_nonce + b"atp-bind-confirm"):
            raise ConnectionError("Bad bind-confirm signature")
        if self.monitor:
            self.monitor.add_event(BINDING_SUCCESS, {
                "conn_id": self._conn_id,
                "mcc_hash": self.peer_mcc.root_hash.hex()[:16],
            })

        # Phase 4 — Capability Exchange (receive)
        cap_req = await self._read_frame()
        if cap_req and cap_req.get("header", {}).get("frame_type") == 0x50:
            cap_header = build_header(0x50)
            cap_resp = {
                "header": cap_header,
                "capabilities": {
                    "max_tasks": 10,
                    "supports_deepseek": True,
                    "atp_version": ATP_VERSION,
                },
            }
            await self._send_frame(cap_resp)

        # Phase 5 — ready for task streams
        self.bound = True

    async def _client_handshake(self, reader, writer):
        """Initiator-side handshake."""
        # Phase 1 — TLS done by caller

        # Phase 2 — Send VERSION_PROPOSE, receive VERSION_ACK
        prop_header = build_header(0x30)
        propose = {
            "header": prop_header,
            "atp_versions": [ATP_VERSION],
            "max_batch_bytes": MAX_BATCH_BYTES,
            "clock_skew_ms": CLOCK_SKEW_MS,
            "anti_replay_ttl_ms": ANTI_REPLAY_TTL_MS,
            "rate_limit_rps": RATE_LIMIT_RPS,
        }
        await self._send_frame(propose)

        ack = await self._read_frame()
        if ack is None or ack.get("header", {}).get("frame_type") != 0x31:
            raise ConnectionError("Expected VERSION_ACK (0x31)")

        # Phase 3 — Send MCC_BIND_REQUEST
        self._my_nonce = os.urandom(16)
        req_header = build_header(0x40)
        bind_req = {
            "header": req_header,
            "mcc_cbor": self.mcc.to_cbor(),
            "nonce": self._my_nonce,
        }
        await self._send_frame(bind_req)

        # Receive MCC_BIND_RESPONSE
        bind_resp = await self._read_frame()
        if bind_resp is None or bind_resp.get("header", {}).get("frame_type") != 0x41:
            raise ConnectionError("Expected MCC_BIND_RESPONSE (0x41)")

        self.peer_mcc = MCC.from_cbor(bind_resp["mcc_cbor"])

        # Verify peer's MCC
        if not self.demo_mode:
            # Full ATP-Full: lookup authority in RootStore, verify signature, check revocation
            from revocation import get_root_store, get_degradation
            rs = get_root_store()
            dp = get_degradation()
            auth_pk = rs.get_authority(self.peer_mcc.authority_id)
            if auth_pk is None:
                deg_state = dp.evaluate(self.peer_mcc.authority_id, rs)
                if deg_state == "UNCERTAIN":
                    raise ConnectionError("Authority UNCERTAIN — connection refused")
                authority = get_default_authority()
                auth_pk = authority.public_key

            if not self.peer_mcc.verify(auth_pk, check_revoked=True):
                if self.monitor:
                    self.monitor.add_event(MCC_VERIFICATION_FAILED, {
                        "conn_id": self._conn_id,
                    })
                raise ConnectionError("Peer MCC verification failed")
            if self.monitor:
                self.monitor.add_event(MCC_VERIFICATION_SUCCESS, {
                    "conn_id": self._conn_id,
                })
        else:
            # Demo mode: trust-on-first-use, skip authority signature verification
            if self.monitor:
                self.monitor.add_event(MCC_VERIFICATION_SUCCESS, {
                    "conn_id": self._conn_id,
                    "demo_mode": True,
                })

        peer_leaves = {l.key: l.value for l in self.peer_mcc.leaves}
        peer_nonce = bind_resp.get("nonce", b"")

        # Verify peer's signature on (my_nonce || "atp-bind-response")
        peer_sign_pk = peer_leaves.get("agent_sign_pk", b"")
        peer_sig = bind_resp.get("signature", b"")
        if not ed25519_verify(peer_sign_pk, peer_sig, self._my_nonce + b"atp-bind-response"):
            raise ConnectionError("Bad bind-response signature")

        # Send MCC_BIND_CONFIRM
        confirm_header = build_header(0x42)
        confirm = {
            "header": confirm_header,
            "signature": ed25519_sign(
                self.identity.ed25519_sk,
                peer_nonce + b"atp-bind-confirm",
            ),
        }
        await self._send_frame(confirm)
        if self.monitor:
            self.monitor.add_event(BINDING_SUCCESS, {
                "conn_id": self._conn_id,
                "mcc_hash": self.peer_mcc.root_hash.hex()[:16],
            })

        # Phase 4 — Capability Exchange
        cap_header = build_header(0x50)
        cap_req = {
            "header": cap_header,
            "capabilities": {
                "max_tasks": 10,
                "supports_deepseek": True,
                "atp_version": ATP_VERSION,
            },
        }
        await self._send_frame(cap_req)
        cap_resp = await self._read_frame()
        if cap_resp and cap_resp.get("header", {}).get("frame_type") == 0x50:
            logger.info("Capability exchange complete: %s", cap_resp.get("capabilities"))

        self.bound = True

    # ══════════════════════════════════════════════════════════════════════
    #  Internal: task handling
    # ══════════════════════════════════════════════════════════════════════

    async def _handle_task_request(self, frame: dict):
        """Process an incoming task request and send response."""
        header = frame.get("header", {})
        task_type = frame.get("task_type", "unknown")
        task_payload = frame.get("task_payload", b"")

        if self.monitor:
            self.monitor.add_event(TASK_START, {
                "conn_id": self._conn_id,
                "task_type": task_type,
                "direction": "incoming",
            })

        # Send TASK_ACK immediately
        ack_header = build_header(0x03, header.get("frame_id"))
        ack = {"header": ack_header}
        await self._send_frame(ack)

        # Process the task
        try:
            result_bytes = task_payload  # default echo
            if self.task_handler:
                result = await self.task_handler(frame)
                if isinstance(result, dict):
                    result_bytes = json.dumps(result).encode("utf-8")
                elif isinstance(result, bytes):
                    result_bytes = result
                else:
                    result_bytes = str(result).encode("utf-8")
            elif task_type == "deepseek_chat":
                prompt = task_payload.decode("utf-8", errors="replace")
                result_text = await self.call_deepseek(prompt, self.monitor, self._conn_id)
                result = {"result": result_text or "no response"} if result_text else {"error": "DeepSeek returned no result"}
                result_bytes = json.dumps(result).encode("utf-8")

            resp_header = build_header(0x02, header.get("frame_id"))
            response = {
                "header": resp_header,
                "status": 0,
                "result_payload": result_bytes,
            }
            await self._send_frame(response)

            if self.monitor:
                self.monitor.add_event(TASK_COMPLETE, {
                    "conn_id": self._conn_id,
                    "task_type": task_type,
                })
                self.monitor.add_task({
                    "task_id": (header.get("frame_id") or b"\x00"*16).hex()[:8],
                    "task_type": task_type,
                    "request": task_payload.decode("utf-8", errors="replace")[:80],
                    "response": result_bytes.decode("utf-8", errors="replace")[:200],
                    "status": "completed",
                    "error_code": None,
                    "latency_ms": 0,
                    "agent": self.identity.agent_name,
                    "direction": "received",
                    "timestamp": time.time(),
                })

        except Exception as exc:
            logger.exception("Task processing error")
            err_header = build_header(0x04, header.get("frame_id"))
            error_frame = {
                "header": err_header,
                "error_code": 0x0B,
                "error_message": str(exc),
            }
            await self._send_frame(error_frame)
            if self.monitor:
                self.monitor.add_event(TASK_ERROR, {
                    "conn_id": self._conn_id,
                    "error_code": 0x0B,
                    "error_message": str(exc),
                })
                self.monitor.add_task({
                    "task_id": (header.get("frame_id") or b"\x00"*16).hex()[:8],
                    "task_type": task_type,
                    "request": task_payload.decode("utf-8", errors="replace")[:80],
                    "response": str(exc)[:200],
                    "status": "error",
                    "error_code": 0x0B,
                    "latency_ms": 0,
                    "agent": self.identity.agent_name,
                    "direction": "received",
                    "timestamp": time.time(),
                })

    # ══════════════════════════════════════════════════════════════════════
    #  I/O helpers
    # ══════════════════════════════════════════════════════════════════════

    async def _send_frame(self, payload: dict):
        """Send a frame and log the event."""
        ft = payload.get("header", {}).get("frame_type")
        if self.monitor:
            self.monitor.add_event(FRAME_SENT, {
                "conn_id": self._conn_id,
                "frame_type": ft,
                "frame_name": FRAME_TYPES.get(ft, f"0x{ft:02x}"),
            })
        await send_frame(self._writer, payload)

    async def _read_frame(self) -> Optional[dict]:
        """Read a frame and log the event."""
        frame = await decode_frame(self._reader)
        if frame is None:
            return None
        ft = frame.get("header", {}).get("frame_type")
        if self.monitor:
            self.monitor.add_event(FRAME_RECEIVED, {
                "conn_id": self._conn_id,
                "frame_type": ft,
                "frame_name": FRAME_TYPES.get(ft, f"0x{ft:02x}"),
            })
        return frame
