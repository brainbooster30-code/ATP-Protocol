"""
ATP v1.8 — Agent: identity, handshake (5 phases), task lifecycle, DeepSeek.
"""

from __future__ import annotations

import os
import time
import json
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable

import uuid

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
import datetime
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
    TRUST_BOOTSTRAP_MODE,
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
from agent_tls import (
    get_self_signed_cert, get_ca_cert_pem, get_cert_expiry_days,
    rotate_cert, make_ssl_context, get_quic_cert,
)
from agent_io import get_tls_peer_pk, send_frame_to, read_frame_from
from agent_task import handle_task_request, forward_task_to_peer
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
#  TLS Certificate helpers — imported from agent_tls.py
#  (self-signed CA, signed certs, make_ssl_context, cert rotation, QUIC certs)
# ═══════════════════════════════════════════════════════════════════════════════
#  All TLS helper functions (get_self_signed_cert, make_ssl_context, etc.)
#  now live in agent_tls.py and are imported above.
#  Kept here for backward compatibility.
# ═══════════════════════════════════════════════════════════════════════════════


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
        rate_limiter=None,
        anti_replay=None,
        trust_bootstrap_mode: Optional[str] = None,
    ):
        self.identity = identity
        self.is_server = is_server
        self.monitor = monitor
        self.task_handler = task_handler  # async callable(task_payload) -> result
        self.rate_limiter = rate_limiter
        self.anti_replay = anti_replay
        self.trust_bootstrap_mode = (trust_bootstrap_mode or TRUST_BOOTSTRAP_MODE).lower()

        self.mcc: Optional[MCC] = create_mcc_for_identity(identity)
        self.peer_mcc: Optional[MCC] = None
        self.bound = False
        self._peer_nonce: Optional[bytes] = None
        self._my_nonce: Optional[bytes] = None
        self._conn_id: str = ""
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._pending_responses: dict[bytes, asyncio.Future] = {}
        self._pending_lock = asyncio.Lock()
        self._frame_reader_task: Optional[asyncio.Task] = None
        self._keepalive_task: Optional[asyncio.Task] = None
        self._keepalive_interval: float = 30.0
        self._current_task: Optional[asyncio.Task] = None
        self._e2e_key: Optional[bytes] = None
        self._peer_ed25519_pk: Optional[bytes] = None
        self._root_store_pushed: bool = False
        self._root_store_nonces: set[bytes] = set()

        # Ephemeral X25519 keypair for forward secrecy (ECDHE)
        self._eph_sk: bytes = b""
        self._eph_pk: bytes = b""
        self._peer_eph_pk: Optional[bytes] = None

        # Buffered frame reader (higher throughput, fewer syscalls)
        self._buffered_reader: Optional[BufferedFrameReader] = None


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

    def _local_authority_pk(self) -> bytes:
        """Return the authority public key for this agent's MCC."""
        if not self.mcc:
            return b""
        from revocation import get_root_store
        rs = get_root_store()
        auth_pk = rs.get_authority(self.mcc.authority_id)
        if auth_pk:
            return auth_pk
        authority = get_default_authority()
        if authority.authority_id == self.mcc.authority_id:
            return authority.public_key
        return b""

    def _verify_peer_mcc(self, peer_mcc: MCC, source_frame: dict) -> bool:
        """Verify a peer MCC using strict trust or explicit TOFU bootstrap."""
        from revocation import get_root_store, get_degradation

        rs = get_root_store()
        auth_pk = rs.get_authority(peer_mcc.authority_id)
        if auth_pk is not None:
            return peer_mcc.verify(auth_pk, check_revoked=True)

        if self.trust_bootstrap_mode == "tofu":
            candidate = source_frame.get("authority_pk", b"")
            if not isinstance(candidate, bytes) or len(candidate) != 32:
                logger.warning("MCC verify: TOFU requested but authority_pk is missing/invalid")
                return False
            if not peer_mcc.verify(candidate, check_revoked=True):
                return False
            rs.add_authority(peer_mcc.authority_id, candidate)
            logger.warning("Trust bootstrap TOFU: pinned authority %s", peer_mcc.authority_id)
            return True

        deg_state = get_degradation().evaluate(peer_mcc.authority_id, rs)
        if self.monitor:
            self.monitor.add_event("DEGRADATION_STATE", {
                "conn_id": self._conn_id,
                "state": deg_state,
                "authority_id": peer_mcc.authority_id,
            })
        logger.warning(
            "MCC verify: authority %s not trusted (mode=%s)",
            peer_mcc.authority_id, self.trust_bootstrap_mode,
        )
        return False

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
        self._conn_id = uuid.uuid4().hex[:12]

        # Generate ephemeral X25519 keypair for ECDHE forward secrecy
        self._eph_sk, self._eph_pk = generate_x25519_keypair()

        from config import HANDSHAKE_TIMEOUT_S, USE_BUFFERED_READER

        # Wrap reader in buffered reader for higher throughput
        if USE_BUFFERED_READER and not self._buffered_reader:
            from atp_core import BufferedFrameReader
            self._buffered_reader = BufferedFrameReader(reader)

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
                await asyncio.wait_for(
                    self._server_handshake(reader, writer),
                    timeout=HANDSHAKE_TIMEOUT_S,
                )
            else:
                await asyncio.wait_for(
                    self._client_handshake(reader, writer),
                    timeout=HANDSHAKE_TIMEOUT_S,
                )

            self.bound = True
            self._setup_e2e()
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
                pass  # nosec — cleanup, connection already dying
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
    ) -> dict:
        """Send a TASK_REQUEST and wait for the TASK_RESPONSE.

        Returns dict with keys:
          - status: "ok" | "timeout" | "error" | "disconnected"
          - data: response dict (for ok/error)
          - error_code: int (for error)
          - error_message: str (for error)

        Supports multiple concurrent in-flight tasks (multiplexing per task_id).
        Starts a background frame reader if not already running.
        """
        result: dict = {"status": "disconnected", "data": None}

        if not self.bound or not self._writer:
            logger.error("send_task: not bound")
            return result

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
            "task_payload": self._e2e_encrypt_signed(payload, self._e2e_key, self.identity.ed25519_sk)
                          if self._e2e_key and self._peer_ed25519_pk else
                          self._e2e_encrypt(payload, self._e2e_key) if self._e2e_key else payload,
            "deadline_ms": deadline_ms,
            "metadata": {"priority": priority},
            "priority_hint": priority,
        }

        # Register pending response
        future: asyncio.Future[Optional[dict]] = asyncio.get_running_loop().create_future()
        async with self._pending_lock:
            self._pending_responses[task_id] = future

        # Start background frame reader if not running
        if self._frame_reader_task is None or self._frame_reader_task.done():
            self._frame_reader_task = asyncio.create_task(self._frame_reader_loop())

        # Send TASK_REQUEST
        await self._send_frame(req_frame)

        try:
            # Wait for response with timeout
            resp = await asyncio.wait_for(future, timeout=deadline_ms / 1000 + 5)
        except asyncio.TimeoutError:
            logger.warning("send_task: timeout waiting for response (task %s)", task_id.hex()[:8])
            async with self._pending_lock:
                self._pending_responses.pop(task_id, None)
            result = {"status": "timeout", "data": None, "error_code": 0x0B, "error_message": "Task timeout"}
            if self.monitor:
                self.monitor.add_event(TASK_ERROR, {
                    "conn_id": self._conn_id,
                    "error_code": 0x0B,
                    "error_message": "Task timeout",
                })
            return result
        finally:
            async with self._pending_lock:
                self._pending_responses.pop(task_id, None)

        if resp is None:
            return {"status": "disconnected", "data": None, "error_code": None, "error_message": "Peer closed connection"}

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
            return {"status": "error", "data": resp, "error_code": resp.get("error_code"), "error_message": resp.get("error_message")}

        if ft == 0x02:
            # Handle streaming: accumulate chunks until partial=false
            sent_time = header["timestamp"]
            is_partial = resp.get("partial", False)
            chunk = resp.get("result_payload", b"")
            if self._e2e_key and self._peer_ed25519_pk:
                decrypted = self._e2e_decrypt_verify(chunk, self._e2e_key, self._peer_ed25519_pk)
                if decrypted is not None:
                    chunk = decrypted
                else:
                    logger.warning("E2E auth failed for task %s chunk", task_id.hex()[:8])
            elif self._e2e_key:
                decrypted = self._e2e_decrypt(chunk, self._e2e_key)
                if decrypted is not None:
                    chunk = decrypted

            if is_partial:
                # Not the final chunk — accumulate and wait for more
                chunks = [chunk]
                seq = resp.get("sequence", 1)
                logger.debug("Streaming: received chunk %d for task %s", seq, task_id.hex()[:8])
                while True:
                    next_resp = await self._read_frame()
                    if next_resp is None:
                        break
                    nft = next_resp.get("header", {}).get("frame_type")
                    if nft == 0x04:
                        chunks.append(b"")
                        break
                    if nft != 0x02:
                        break
                    n_partial = next_resp.get("partial", False)
                    n_chunk = next_resp.get("result_payload", b"")
                    if self._e2e_key and self._peer_ed25519_pk:
                        nd = self._e2e_decrypt_verify(n_chunk, self._e2e_key, self._peer_ed25519_pk)
                        if nd is not None:
                            n_chunk = nd
                    elif self._e2e_key:
                        nd = self._e2e_decrypt(n_chunk, self._e2e_key)
                        if nd is not None:
                            n_chunk = nd
                    chunks.append(n_chunk)
                    if not n_partial:
                        break
                result_bytes = b"".join(chunks)
            else:
                result_bytes = chunk

            latency = int(time.time() * 1000) - sent_time
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
            return {"status": "ok", "data": resp, "error_code": None, "error_message": None, "result_bytes": result_bytes}

        logger.warning("send_task: unexpected frame 0x%02x", ft)
        return {"status": "error", "data": None, "error_code": None, "error_message": f"Unexpected frame type 0x{ft:02x}"}

    async def handle_task_loop(self):
        """Server loop: read incoming frames and dispatch tasks."""
        if not self.is_server:
            return
        # Push RootStore ora che il reader loop e' attivo
        await self._maybe_push_root_store()
        while self.bound and self._reader:
            try:
                frame = await self._read_frame()
                if frame is None:
                    break
                await self._dispatch_frame(frame)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("handle_task_loop error")
                break

    async def _frame_reader_loop(self):
        """Background reader: reads and dispatches frames (client + server)."""
        # Push RootStore prima di leggere (reader loop attivo)
        await self._maybe_push_root_store()
        while self.bound and self._reader:
            try:
                frame = await asyncio.wait_for(
                    self._read_frame(), timeout=30.0
                )
                if frame is None:
                    logger.debug("FRAME READER: frame is None, exiting")
                    break
                await self._dispatch_frame(frame)
            except asyncio.TimeoutError:
                logger.debug("FRAME READER: idle timeout (30s)")
                continue
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("_frame_reader_loop error")
                break

    async def _dispatch_frame(self, frame: dict):
        """Dispatch an incoming frame to the right handler."""
        ft = frame.get("header", {}).get("frame_type")
        task_id = frame.get("header", {}).get("task_id", b"")
        logger.debug("DISPATCH frame 0x%02x task %s", ft, task_id.hex()[:8] if task_id else "nil")

        # Route TASK_RESPONSE / TASK_ERROR to pending futures
        if ft in (0x02, 0x04) and task_id != b"\x00" * 16:
            async with self._pending_lock:
                future = self._pending_responses.get(task_id)
                if future and not future.done():
                    future.set_result(frame)
                    logger.debug("Routed frame 0x%02x to pending future for task %s",
                                 ft, task_id.hex()[:8])
                    return
                # No pending future — might be a server receiving a task response
                # (not expected for server, but log and continue)
                logger.debug("No pending future for task %s (frame 0x%02x)",
                             task_id.hex()[:8], ft)

        if self.is_server:
            # Server-side dispatch
            if ft == 0x01:
                await self._handle_task_request(frame)
            elif ft == 0x10:
                logger.info("Received CONTROL_SHUTDOWN")
                try:
                    ack = {"header": build_header(0x12)}
                    await self._send_frame(ack)
                except Exception:
                    pass
            elif ft == 0x05:
                logger.info("Received TASK_CANCEL — cancelling current task")
                if self._current_task and not self._current_task.done():
                    self._current_task.cancel()
                if self.monitor:
                    self.monitor.add_event(TASK_ERROR, {
                        "conn_id": self._conn_id,
                        "error_code": 0x0F,
                        "error_message": "Task cancelled by peer",
                    })
            elif ft == 0x13:
                try:
                    health_resp = {
                        "header": build_header(0x14),
                        "status": "ok",
                        "timestamp": int(time.time() * 1000),
                        "bound": self.bound,
                    }
                    await self._send_frame(health_resp)
                except Exception:
                    pass
            elif ft == 0x11:
                """CONTROL_REVOKE_NOTIFY — receive revocation serials from a connected ATP peer."""
                serials = frame.get("serial_numbers", [])
                from revocation import revoke_serial
                count = 0
                for s in serials:
                    revoke_serial(bytes(s))
                    count += 1
                logger.info("Revoke notify: %d serials received via ATP", count)
                if self.monitor:
                    self.monitor.add_event("REVOKE_NOTIFY", {
                        "conn_id": self._conn_id,
                        "serials_count": count,
                    })
            elif ft == 0x21:
                await self._handle_root_store_update(frame)
            # Federation handlers (v2.0)
            elif ft == 0x60:
                """PEER_DISCOVERY — receive peer list from federated peer.
                Verifies the Ed25519 signature before updating routing table.
                """
                peers = frame.get("peers", [])
                peer_node_id = frame.get("node_id", "")
                peer_sig = frame.get("signature", b"")
                if not peers:
                    return
                # Verify signature using peer's Ed25519 key from their MCC
                peer_sign_pk = None
                if self.peer_mcc:
                    for leaf in self.peer_mcc.leaves:
                        if leaf.key == "agent_sign_pk":
                            peer_sign_pk = leaf.value
                            break
                if not peer_sign_pk:
                    logger.warning("PEER_DISCOVERY: no peer Ed25519 key — ignoring")
                    return
                if not peer_sig:
                    logger.warning("PEER_DISCOVERY: missing signature from %s — ignoring",
                                   peer_node_id[:16])
                    return
                import cbor2 as _cbor2
                from atp_core import ed25519_verify
                expected_payload = _cbor2.dumps(
                    {"node_id": peer_node_id, "peers": peers},
                    canonical=True,
                )
                if not ed25519_verify(peer_sign_pk, peer_sig, expected_payload):
                    logger.warning("PEER_DISCOVERY: bad signature from %s — ignoring",
                                   peer_node_id[:16])
                    return
                from federation import FederationRouter, PeerRecord
                if not hasattr(self, "_fed_router"):
                    self._fed_router = None  # set by ATPServer
                if self._fed_router:
                        for p in peers[:10]:
                            if p.get("peer_id") == self._fed_router.node_id:
                                continue
                            rec = PeerRecord(
                                peer_id=p["peer_id"],
                                host=p.get("host", ""),
                                port=p.get("port", 0),
                                ed25519_pk=p.get("ed25519_pk", b""),
                                x25519_pk=b"",
                                capabilities=p.get("capabilities", []),
                            )
                            asyncio.create_task(
                                self._fed_router.add_or_update_peer(rec, peer_node_id)
                            )
                        # Send ACK
                        ack = {"header": build_header(0x63), "node_id": self.identity.agent_name}
                        try: await self._send_frame(ack)
                        except Exception: pass
            elif ft == 0x61:
                """PEER_HEARTBEAT — keepalive from federated peer."""
                peer_id = frame.get("node_id", "")
                if hasattr(self, "_fed_router") and self._fed_router:
                    async with self._fed_router._peers_lock:
                        if peer_id in self._fed_router._peers:
                            self._fed_router._peers[peer_id].last_seen = time.time()
            elif ft == 0x62:
                """TASK_FORWARD — forward a task through the federation.
                Verifies the Ed25519 signature before accepting.
                """
                inner_task = frame.get("task_frame", {})
                target = frame.get("target_peer_id", "")
                ttl = frame.get("ttl", 5)
                fwd_sig = frame.get("signature", b"")
                fwd_id = frame.get("forwarder_id", "")
                if ttl <= 0:
                    return  # TTL exhausted
                # Verify signature using connected peer's Ed25519 key from MCC
                peer_sign_pk = None
                if self.peer_mcc:
                    for leaf in self.peer_mcc.leaves:
                        if leaf.key == "agent_sign_pk":
                            peer_sign_pk = leaf.value
                            break
                if not peer_sign_pk:
                    logger.warning("TASK_FORWARD: no peer Ed25519 key — dropping")
                    return
                if not fwd_sig:
                    logger.warning("TASK_FORWARD: missing signature from %s — dropping",
                                   fwd_id[:16])
                    return
                import cbor2 as _cbor2
                from atp_core import ed25519_verify
                expected = _cbor2.dumps({
                    "target_peer_id": target,
                    "ttl": ttl,
                    "task_frame": inner_task,
                    "forwarder_id": fwd_id,
                }, canonical=True)
                if not ed25519_verify(peer_sign_pk, fwd_sig, expected):
                    logger.warning("TASK_FORWARD: bad signature from %s — dropping",
                                   fwd_id[:16])
                    return
                # Re-forward if we're not the target
                if hasattr(self, "_fed_router") and self._fed_router:
                    if target and target != self._fed_router.node_id:
                        # Forward to next hop
                        asyncio.create_task(self._forward_task_to_peer(inner_task, target, ttl - 1))
                    else:
                        # We're the target: process locally
                        asyncio.create_task(self._dispatch_frame(inner_task))
            elif ft == 0x63:
                """PEER_DISCOVERY_ACK — peer acknowledged our discovery."""
                pass  # No action needed, just keepalive
            elif ft == 0x12:
                logger.info("Received SHUTDOWN_ACK — closing cleanly")
            elif ft == 0x15:
                try:
                    pong = {"header": build_header(0x16), "timestamp": int(time.time() * 1000)}
                    await self._send_frame(pong)
                except Exception:
                    pass
                self._last_peer_activity = time.time()
            elif ft == 0x16:
                self._last_peer_activity = time.time()
            elif ft == 0x20:
                logger.warning("Received ERROR frame: %s", frame.get("error_message"))
            else:
                logger.debug("Ignoring frame 0x%02x", ft)
        else:
            # Client-side dispatch
            if ft == 0x15:
                try:
                    pong = {"header": build_header(0x16), "timestamp": int(time.time() * 1000)}
                    await self._send_frame(pong)
                except Exception:
                    pass
            elif ft == 0x16:
                self._last_peer_activity = time.time()
            elif ft == 0x21:
                await self._handle_root_store_update(frame)
            elif ft == 0x20:
                logger.warning("Received ERROR frame: %s", frame.get("error_message"))



    # ── Keepalive ──────────────────────────────────────────────────────────

    async def _keepalive_loop(self):
        """Send periodic PING frames to detect dead connections."""
        while self.bound and self._writer:
            try:
                await asyncio.wait_for(
                    asyncio.sleep(self._keepalive_interval), timeout=self._keepalive_interval
                )
                if not self.bound:
                    break
                # Send PING frame
                hdr = build_header(0x15)
                payload = {"header": hdr, "timestamp": int(time.time() * 1000)}
                await self._send_frame(payload)
                self._last_ping_ts = time.time()
            except asyncio.TimeoutError:
                continue
            except (ConnectionError, OSError):
                logger.warning("Keepalive: connection lost for %s", self._conn_id)
                self.bound = False
                break
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Keepalive error for %s", self._conn_id)
                break

    async def close_async(self):
        """Close the connection gracefully with SSL shutdown handshake."""
        if self._keepalive_task:
            self._keepalive_task.cancel()
            self._keepalive_task = None
        if self._frame_reader_task:
            self._frame_reader_task.cancel()
            self._frame_reader_task = None
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass  # nosec — cleanup on close, connection may already be gone
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
                pass  # nosec — sync cleanup, best-effort
        if self.monitor:
            self.monitor.add_event(CONNECTION_CLOSE, {
                "conn_id": self._conn_id,
                "agent": self.identity.agent_name,
            })

    # ── E2E ECDH + AES-GCM ─────────────────────────────────────────

    def _derive_session_key(self, peer_x25519_pk: bytes) -> Optional[bytes]:
        """Derive AES-256-GCM session key from X25519 ECDH shared secret.

        Uses X25519 ECDH + BLAKE3 KDF with domain separation.
        Both sides sort public keys deterministically so the
        derived key is identical.

        When ephemeral keys are available (ECDHE), derives from:
          ECDH(eph_sk, peer_eph_pk)  —  forward secret

        Falls back to static ECDH for backward compatibility with
        peers that don't support ECDHE.

        Returns 32-byte AES key, or None if peer key is invalid.
        """
        # Prefer ECDHE (forward secrecy) when both sides have ephemeral keys
        if self._eph_sk and self._peer_eph_pk:
            if len(self._peer_eph_pk) != 32 or len(self._eph_sk) != 32:
                return None
            try:
                eph_sk = x25519.X25519PrivateKey.from_private_bytes(self._eph_sk)
                peer_eph_pk = x25519.X25519PublicKey.from_public_bytes(
                    self._peer_eph_pk
                )
                shared_secret = eph_sk.exchange(peer_eph_pk)
                pk1, pk2 = sorted([self._peer_eph_pk, self._eph_pk])
                kdf_input = b"atp-v1.8-ecdhe" + shared_secret + pk1 + pk2
                return blake3_hash(kdf_input)
            except Exception:
                logger.exception("ECDHE key derivation failed")
                return None

        # Fallback: static ECDH (backward compat, no forward secrecy)
        if len(peer_x25519_pk) != 32 or len(self.identity.x25519_sk) != 32:
            return None
        try:
            our_sk = x25519.X25519PrivateKey.from_private_bytes(
                self.identity.x25519_sk
            )
            peer_pk = x25519.X25519PublicKey.from_public_bytes(peer_x25519_pk)
            shared_secret = our_sk.exchange(peer_pk)
            pk1, pk2 = sorted([peer_x25519_pk, self.identity.x25519_pk])
            kdf_input = b"atp-v1.8-ecdh" + shared_secret + pk1 + pk2
            return blake3_hash(kdf_input)
        except Exception:
            logger.exception("ECDH key derivation failed (static fallback)")
            return None

    def _setup_e2e(self):
        """Derive E2E session key from ECDHE ephemeral keys (preferred)
        or static ECDH (fallback).

        Stores session key in self._e2e_key, peer Ed25519 pk for auth.
        """
        self._e2e_key: Optional[bytes] = None
        self._peer_ed25519_pk: Optional[bytes] = None
        if self.peer_mcc is None:
            return

        # Read peer's static X25519 pk from MCC (used for ECDH fallback)
        peer_static_pk = None
        for leaf in self.peer_mcc.leaves:
            if leaf.key == "agent_pk":
                peer_static_pk = leaf.value
            elif leaf.key == "agent_sign_pk":
                self._peer_ed25519_pk = leaf.value

        if peer_static_pk is None:
            logger.warning("E2E setup: no agent_pk in peer MCC")
            return

        # Try ECDHE first, fall back to static ECDH
        if self._eph_sk and self._peer_eph_pk:
            pk = self._derive_session_key(peer_static_pk)
            # _derive_session_key uses ECDHE when eph fields are set
        else:
            pk = self._derive_session_key(peer_static_pk)

        if pk:
            self._e2e_key = pk
            method = "ECDHE" if (self._eph_sk and self._peer_eph_pk) else "ECDH"
            logger.info(
                "E2E session key derived (%s: %s...)",
                method, pk.hex()[:8],
            )

    @staticmethod
    def _e2e_encrypt(plaintext: bytes, session_key: bytes) -> bytes:
        """Encrypt *plaintext* with AES-256-GCM using *session_key*.

        Returns: 12-byte nonce || ciphertext || 16-byte tag
        """
        nonce = os.urandom(12)
        aesgcm = AESGCM(session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    @staticmethod
    def _e2e_decrypt(encrypted: bytes, session_key: bytes) -> Optional[bytes]:
        """Decrypt AES-256-GCM payload. Returns plaintext or None."""
        if len(encrypted) < 12 + 16:
            return None
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        try:
            aesgcm = AESGCM(session_key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            logger.warning("E2E decryption failed (bad key/tampered data)")
            return None

    def _e2e_encrypt_signed(self, plaintext: bytes, session_key: bytes,
                             ed25519_sk: bytes) -> bytes:
        """Encrypt-then-sign: AES-GCM + Ed25519 signature.

        Returns: nonce(12) || ciphertext+tag(28) || signature(64)
        Total: 104 bytes overhead.
        Verify with _e2e_decrypt_verify().
        """
        encrypted = self._e2e_encrypt(plaintext, session_key)
        sig = ed25519_sign(ed25519_sk, encrypted)
        return encrypted + sig

    def _e2e_decrypt_verify(self, encrypted_signed: bytes, session_key: bytes,
                             ed25519_pk: bytes) -> Optional[bytes]:
        """Verify-then-decrypt: check Ed25519 sig, then AES-GCM decrypt.

        Returns plaintext or None (tampered/invalid).
        """
        if len(encrypted_signed) < 12 + 16 + 64:
            return None
        encrypted = encrypted_signed[:-64]
        sig = encrypted_signed[-64:]
        if not ed25519_verify(ed25519_pk, sig, encrypted):
            logger.warning("E2E auth failed: Ed25519 signature mismatch")
            return None
        return self._e2e_decrypt(encrypted, session_key)

    async def _handle_root_store_update(self, frame: dict):
        """Handle ROOT_STORE_UPDATE without granting trust to agent-signed ads."""
        signed_manifest = frame.get("signed_manifest", b"")
        if not signed_manifest:
            return

        from revocation import get_root_store
        rs = get_root_store()

        try:
            manifest = cbor2.loads(signed_manifest)
        except Exception as exc:
            logger.warning("RootStore update rejected (bad CBOR): %s", exc)
            return

        manifest_type = manifest.get("manifest_type", "")
        if manifest_type == "authority-chain":
            if rs.chain_add(signed_manifest):
                logger.info("RootStore updated via authority-chain manifest")
            else:
                logger.warning("RootStore authority-chain manifest rejected")
            return

        if manifest_type != "rootstore-advertisement":
            logger.warning("RootStore update rejected (unknown manifest_type=%r)", manifest_type)
            return

        if not self._peer_ed25519_pk:
            logger.warning("RootStore advertisement rejected (no peer Ed25519 key)")
            return

        sig = manifest.pop("signature", b"")
        if len(sig) != 64:
            logger.warning("RootStore advertisement rejected (bad signature length)")
            return

        payload = cbor2.dumps(manifest, canonical=True)
        if not ed25519_verify(self._peer_ed25519_pk, sig, payload):
            logger.warning("RootStore advertisement rejected (bad agent signature)")
            return

        nonce = manifest.get("manifest_nonce", b"")
        manifest_ts = manifest.get("manifest_ts", 0)
        now = int(time.time())
        if not isinstance(nonce, bytes) or len(nonce) != 16:
            logger.warning("RootStore advertisement rejected (missing nonce)")
            return
        if nonce in self._root_store_nonces:
            logger.warning("RootStore advertisement rejected (duplicate nonce)")
            return
        if not isinstance(manifest_ts, int) or abs(now - manifest_ts) > 300:
            logger.warning("RootStore advertisement rejected (stale timestamp)")
            return
        self._root_store_nonces.add(nonce)

        matched = skipped_unknown = skipped_conflict = 0
        for entry in manifest.get("authorities", []):
            authority_id = entry.get("authority_id", "")
            pk = entry.get("pk", b"")
            current = rs.get_authority(authority_id)
            if current is None:
                skipped_unknown += 1
            elif current != pk:
                skipped_conflict += 1
            else:
                matched += 1

        logger.info(
            "RootStore advertisement from %s: matched=%d skipped_unknown=%d skipped_conflict=%d",
            manifest.get("sender_name", "?"), matched, skipped_unknown, skipped_conflict,
        )

    async def _maybe_push_root_store(self):
        """Push RootStore to peer once after handshake.
        Chiamato dal reader loop, non da perform_handshake, per evitare
        deadlock su QUIC (entrambi i lati scrivono prima di leggere)."""
        if self._root_store_pushed or not self._writer:
            return
        self._root_store_pushed = True
        try:
            await asyncio.wait_for(self._do_push_root_store(), timeout=3.0)
        except asyncio.TimeoutError:
            logger.debug("RootStore push timeout")
        except Exception as exc:
            logger.debug("RootStore push skipped: %s", exc)

    async def _do_push_root_store(self):
        from revocation import get_root_store
        rs = get_root_store()
        import cbor2 as _cbor2
        manifest = rs.manifest
        if not manifest.get("authorities"):
            return
        # Build a manifest listing our known authorities.
        # The manifest is signed with OUR Ed25519 key (the agent's identity key),
        # NOT the shared authority key.  The receiver verifies using our
        # Ed25519 public key from the MCC exchanged during handshake.
        manifest_data = {
            "manifest_type": "rootstore-advertisement",
            "manifest_version": 1,
            "manifest_id": os.urandom(16),
            "manifest_nonce": os.urandom(16),     # anti-replay
            "manifest_ts": int(time.time()),       # freshness window
            "rootstore_version": getattr(rs, "_version", manifest.get("version", 1)),
            "timestamp": int(time.time()),
            "sender_name": self.identity.agent_name,
            "authorities": [
                {"authority_id": aid, "pk": info["pk"]}
                for aid, info in manifest["authorities"].items()
            ],
        }
        payload = _cbor2.dumps(manifest_data, canonical=True)
        sig = ed25519_sign(self.identity.ed25519_sk, payload)
        logger.debug("ROOTSTORE_PUSH: sender=%s payload=%dB sig=%dB",
                     self.identity.agent_name, len(payload), len(sig))
        manifest_data["signature"] = sig
        signed = _cbor2.dumps(manifest_data, canonical=True)
        frame = {
            "header": build_header(0x21),
            "signed_manifest": signed,
        }
        await self._send_frame(frame)

    @staticmethod
    async def call_deepseek(prompt: str, monitor: Optional[Monitor] = None,
                            conn_id: str = "") -> Optional[str]:
        """Call the DeepSeek chat API with *prompt*.
        
        Returns None if the API key is not configured or the call fails.
        Circuit breaker is managed by the caller.
        """
        from production import deepseek_circuit

        api_key = get_deepseek_api_key()
        if not api_key:
            logger.error("DeepSeek API key missing — cannot call API")
            deepseek_circuit.record_failure()
            return None

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
            deepseek_circuit.record_failure()
            return None

    # ══════════════════════════════════════════════════════════════════════
    #  Internal: handshake phases
    # ══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _get_tls_peer_pk(writer) -> Optional[bytes]:
        """Extract TLS peer cert public key (delegates to agent_io)."""
        return get_tls_peer_pk(writer)

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
            "selected_version": ATP_VERSION,
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

        # Verify peer's MCC. Unknown authorities are refused in strict mode;
        # TOFU mode requires authority_pk in the bind frame and pins it.
        if not self._verify_peer_mcc(self.peer_mcc, bind_req):
            if self.monitor:
                self.monitor.add_event(MCC_VERIFICATION_FAILED, {
                    "conn_id": self._conn_id,
                })
            raise ConnectionError("Peer MCC verification failed")
        if self.monitor:
            self.monitor.add_event(MCC_VERIFICATION_SUCCESS, {
                "conn_id": self._conn_id,
            })

        # TLS-ATP binding: verify TLS certificate's Ed25519 key matches MCC agent_sign_pk
        tls_pk = self._get_tls_peer_pk(writer)
        if tls_pk is not None and len(tls_pk) == 32:
            peer_sign_pk = None
            for leaf in self.peer_mcc.leaves:
                if leaf.key == "agent_sign_pk":
                    peer_sign_pk = leaf.value
                    break
            if peer_sign_pk is not None and tls_pk != peer_sign_pk:
                raise ConnectionError(
                    "TLS-ATP binding failed: TLS cert public key does not match MCC agent_sign_pk"
                )
            logger.info("TLS-ATP binding verified: TLS key matches MCC agent_sign_pk")

        # Check if peer wants key separation (dual_use check)
        peer_leaves = {l.key: l.value for l in self.peer_mcc.leaves}

        # Generate my nonce
        self._my_nonce = os.urandom(16)
        peer_nonce = bind_req.get("nonce", b"")

        # Extract peer's ephemeral X25519 key for ECDHE forward secrecy
        self._peer_eph_pk = bind_req.get("eph_pk", b"")
        if not isinstance(self._peer_eph_pk, bytes) or len(self._peer_eph_pk) != 32:
            self._peer_eph_pk = None
            logger.warning("ECDHE: peer did not provide valid eph_pk — falling back to static ECDH")

        # Send MCC_BIND_RESPONSE with our MCC, nonce_r, ephemeral key, and signature
        resp_header = build_header(0x41)
        resp_payload = {
            "header": resp_header,
            "mcc_cbor": self.mcc.to_cbor(),
            "authority_pk": self._local_authority_pk(),
            "nonce": self._my_nonce,
            "eph_pk": self._eph_pk,
            "signature": ed25519_sign(
                self.identity.ed25519_sk,
                peer_nonce + self._eph_pk + b"atp-bind-response",
            ),
        }
        await self._send_frame(resp_payload)

        # Receive MCC_BIND_CONFIRM
        confirm = await self._read_frame()
        if confirm is None or confirm.get("header", {}).get("frame_type") != 0x42:
            raise ConnectionError("Expected MCC_BIND_CONFIRM (0x42)")

        peer_sig = confirm.get("signature", b"")
        peer_sign_pk = peer_leaves.get("agent_sign_pk", b"")
        eph_confirm_msg = self._my_nonce + (self._eph_pk or b"") + b"atp-bind-confirm"
        if not ed25519_verify(peer_sign_pk, peer_sig, eph_confirm_msg):
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
        # Start keepalive task
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())

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
            "authority_pk": self._local_authority_pk(),
            "nonce": self._my_nonce,
            "eph_pk": self._eph_pk,
        }
        await self._send_frame(bind_req)

        # Receive MCC_BIND_RESPONSE
        bind_resp = await self._read_frame()
        if bind_resp is None or bind_resp.get("header", {}).get("frame_type") != 0x41:
            raise ConnectionError("Expected MCC_BIND_RESPONSE (0x41)")

        self.peer_mcc = MCC.from_cbor(bind_resp["mcc_cbor"])

        # Verify peer's MCC. Unknown authorities are refused in strict mode;
        # TOFU mode requires authority_pk in the bind frame and pins it.
        if not self._verify_peer_mcc(self.peer_mcc, bind_resp):
            if self.monitor:
                self.monitor.add_event(MCC_VERIFICATION_FAILED, {
                    "conn_id": self._conn_id,
                })
            raise ConnectionError("Peer MCC verification failed")
        if self.monitor:
            self.monitor.add_event(MCC_VERIFICATION_SUCCESS, {
                "conn_id": self._conn_id,
            })

        # TLS-ATP binding: verify TLS certificate's Ed25519 key matches MCC agent_sign_pk
        tls_pk = self._get_tls_peer_pk(writer)
        if tls_pk is not None and len(tls_pk) == 32:
            peer_sign_pk = None
            for leaf in self.peer_mcc.leaves:
                if leaf.key == "agent_sign_pk":
                    peer_sign_pk = leaf.value
                    break
            if peer_sign_pk is not None and tls_pk != peer_sign_pk:
                raise ConnectionError(
                    "TLS-ATP binding failed: TLS cert public key does not match MCC agent_sign_pk"
                )
            logger.info("TLS-ATP binding verified: TLS key matches MCC agent_sign_pk")

        peer_leaves = {l.key: l.value for l in self.peer_mcc.leaves}
        peer_nonce = bind_resp.get("nonce", b"")

        # Extract peer's ephemeral X25519 key for ECDHE forward secrecy
        self._peer_eph_pk = bind_resp.get("eph_pk", b"")
        if not isinstance(self._peer_eph_pk, bytes) or len(self._peer_eph_pk) != 32:
            self._peer_eph_pk = None
            logger.warning("ECDHE: peer did not provide valid eph_pk — falling back to static ECDH")

        # Verify peer's signature on (my_nonce || peer_eph_pk || "atp-bind-response")
        peer_sign_pk = peer_leaves.get("agent_sign_pk", b"")
        peer_sig = bind_resp.get("signature", b"")
        peer_sig_msg = self._my_nonce + (self._peer_eph_pk or b"") + b"atp-bind-response"
        if not ed25519_verify(peer_sign_pk, peer_sig, peer_sig_msg):
            raise ConnectionError("Bad bind-response signature")

        # Send MCC_BIND_CONFIRM
        confirm_header = build_header(0x42)
        confirm = {
            "header": confirm_header,
            "signature": ed25519_sign(
                self.identity.ed25519_sk,
                peer_nonce + (self._eph_pk or b"") + b"atp-bind-confirm",
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
        """Process an incoming task request (delegates to agent_task)."""
        await handle_task_request(self, frame)

    # ══════════════════════════════════════════════════════════════════════
    #  Federation helpers
    # ══════════════════════════════════════════════════════════════════════

    async def _forward_task_to_peer(self, task_frame: dict, target: str, ttl: int):
        """Forward a task to the next hop (delegates to agent_task)."""
        await forward_task_to_peer(self, task_frame, target, ttl)

    # ══════════════════════════════════════════════════════════════════════
    #  I/O helpers
    # ══════════════════════════════════════════════════════════════════════

    async def _send_frame(self, payload: dict):
        """Send a frame (delegates to agent_io)."""
        await send_frame_to(self, payload)

    async def _read_frame(self) -> Optional[dict]:
        """Read a frame with anti-replay and clock skew (delegates to agent_io)."""
        return await read_frame_from(self)
