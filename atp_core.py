"""
ATP v1.7 — Core module.
Cryptographic primitives, MCC (Merkle-Claim Card), and wire-format frames.
"""

from __future__ import annotations

import os
import uuid
import struct
import time
import logging
from typing import Optional
from dataclasses import dataclass, field

import cbor2
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
#  BLAKE3 wrapper  (pure-python fallback if C extension absent)
# ═══════════════════════════════════════════════════════════════════════════════
try:
    import blake3

    def blake3_hash(data: bytes) -> bytes:
        return blake3.blake3(data).digest()
except ImportError:
    raise ImportError(
        "BLAKE3 is REQUIRED for ATP v1.7. Install: pip install blake3\n"
        "No fallback is allowed — BLAKE2b is NOT interoperable with BLAKE3."
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  Key generation
# ═══════════════════════════════════════════════════════════════════════════════

def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """Return (private_key_bytes, public_key_bytes) for X25519."""
    private = x25519.X25519PrivateKey.generate()
    return (
        private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Return (private_key_bytes, public_key_bytes) for Ed25519."""
    private = ed25519.Ed25519PrivateKey.generate()
    return (
        private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )


def ed25519_sign(private_bytes: bytes, data: bytes) -> bytes:
    """Sign *data* with an Ed25519 private key (raw 32 bytes)."""
    private = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    return private.sign(data)


def ed25519_verify(public_bytes: bytes, signature: bytes, data: bytes) -> bool:
    """Return True if *signature* on *data* is valid."""
    try:
        public = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        public.verify(signature, data)
        return True
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
#  MCC — Merkle-Claim Card
# ═══════════════════════════════════════════════════════════════════════════════
#
#  Leaf hash formula:
#    L_i = BLAKE3(0x00 || salt_16 || uint16_BE(len(key)) || key_utf8
#                 || uint32_BE(len(value)) || value)
#
#  Internal node:
#    Node = BLAKE3(0x01 || Left || Right)
#
#  Padding: if N is not a power of 2, the last real leaf is duplicated.
#

@dataclass
class MCCLeaf:
    key: str            # 1..128 chars
    value: bytes        # arbitrary
    salt: bytes         # 16 bytes

    def compute_leaf_hash(self) -> bytes:
        k = self.key.encode("utf-8")
        data = (
            b"\x00"
            + self.salt
            + struct.pack("!H", len(k))
            + k
            + struct.pack("!I", len(self.value))
            + self.value
        )
        return blake3_hash(data)

    def to_dict(self) -> dict:
        return {"key": self.key, "value": self.value, "salt": self.salt}

    @staticmethod
    def from_dict(d: dict) -> MCCLeaf:
        return MCCLeaf(key=d["key"], value=d["value"], salt=d["salt"])


@dataclass
class MCC:
    mcc_version: int                     # must be 1
    serial_number: bytes                 # 16 bytes
    root_hash: bytes                     # 32 bytes
    authority_id: str                    # 1..256 chars
    authority_sig: bytes                 # 64 bytes (Ed25519)
    expiry_date: int                     # unix epoch seconds
    leaves: list[MCCLeaf]
    critical_mask: list[str]             # e.g. ["agent_pk", "agent_sign_pk", …]

    # ── builder ──────────────────────────────────────────────────────────

    @staticmethod
    def create(
        leaves: list[MCCLeaf],
        critical_mask: list[str],
        serial_number: bytes,
        authority_id: str,
        expiry_date: int,
        authority_sign_fn,               # callable: bytes → signature
    ) -> MCC:
        """Build an MCC: compute the Merkle root, then sign the commitment."""
        root_hash = _build_merkle_tree(leaves)
        commitment = _commitment_cbor(root_hash, expiry_date, 1, authority_id, serial_number)
        authority_sig = authority_sign_fn(commitment)
        return MCC(
            mcc_version=1,
            serial_number=serial_number,
            root_hash=root_hash,
            authority_id=authority_id,
            authority_sig=authority_sig,
            expiry_date=expiry_date,
            leaves=leaves,
            critical_mask=critical_mask,
        )

    # ── serialisation ────────────────────────────────────────────────────

    def to_cbor(self) -> bytes:
        """Encode to canonical CBOR — leaf_hash is NEVER transmitted."""
        return cbor2.dumps(
            {
                "mcc_version": self.mcc_version,
                "serial_number": self.serial_number,
                "root_hash": self.root_hash,
                "authority_id": self.authority_id,
                "authority_sig": self.authority_sig,
                "expiry_date": self.expiry_date,
                "leaves": [l.to_dict() for l in self.leaves],
                "critical_mask": self.critical_mask,
                # NOTE: leaf_hash is deliberately absent from the wire format
            },
            canonical=True,
        )

    @staticmethod
    def from_cbor(data: bytes) -> MCC:
        d: dict = cbor2.loads(data)
        return MCC(
            mcc_version=d["mcc_version"],
            serial_number=d["serial_number"],
            root_hash=d["root_hash"],
            authority_id=d["authority_id"],
            authority_sig=d["authority_sig"],
            expiry_date=d["expiry_date"],
            leaves=[MCCLeaf.from_dict(l) for l in d["leaves"]],
            critical_mask=list(d["critical_mask"]),
        )

    # ── verification (8 steps) ───────────────────────────────────────────

    def verify(
        self,
        authority_pk: bytes,
        expected_agent_pk: Optional[bytes] = None,
        check_revoked: bool = False,
    ) -> bool:
        """
        Full MCC verification per ATP v1.7 §Identity.
        Returns True if all checks pass, False otherwise.

        Steps:
          1. mcc_version == 1
          2. expiry_date > now
          3. all critical_mask fields present among leaves
          4. recompute leaf_hash → root_hash (ignore any transmitted hash)
          5. fetch authority_pk from store
          6. verify Ed25519 signature on commitment CBOR
          7. (optional) agent_pk matches TLS identity
          8. (ATP-Full) serial_number not revoked
        """
        # Step 1 — version
        if self.mcc_version != 1:
            logger.warning("MCC verify: unsupported version %d", self.mcc_version)
            return False

        # Step 2 — expiry
        if self.expiry_date <= int(time.time()):
            logger.warning("MCC verify: expired")
            return False

        # Step 3 — critical_mask presence
        leaf_keys = {l.key for l in self.leaves}
        for required in self.critical_mask:
            if required not in leaf_keys:
                logger.warning("MCC verify: missing critical key %r", required)
                return False

        # Step 4 — recompute root
        computed_root = _build_merkle_tree(self.leaves)
        if computed_root != self.root_hash:
            logger.warning("MCC verify: root hash mismatch")
            return False

        # Step 5 — authority_pk (caller provides)
        # Step 6 — signature
        commitment = _commitment_cbor(
            self.root_hash,
            self.expiry_date,
            self.mcc_version,
            self.authority_id,
            self.serial_number,
        )
        if not ed25519_verify(authority_pk, self.authority_sig, commitment):
            logger.warning("MCC verify: bad authority signature")
            return False

        # Step 7 — agent_pk match (optional)
        if expected_agent_pk is not None:
            for leaf in self.leaves:
                if leaf.key == "agent_pk" and leaf.value != expected_agent_pk:
                    logger.warning("MCC verify: agent_pk mismatch")
                    return False

        # Step 7.5 — Key separation check (ATP-Full §6)
        pk_val = sign_pk_val = None
        for leaf in self.leaves:
            if leaf.key == "agent_pk":
                pk_val = leaf.value
            elif leaf.key == "agent_sign_pk":
                sign_pk_val = leaf.value
        if pk_val is not None and sign_pk_val is not None and pk_val == sign_pk_val:
            logger.warning("MCC verify: agent_pk == agent_sign_pk — key separation violated")
            return False

        # Step 8 — revocation check (ATP-Full)
        if check_revoked:
            from revocation import check_revoked as _check_revoked
            if _check_revoked(self.serial_number):
                logger.warning("MCC verify: serial %s is REVOKED",
                               self.serial_number.hex()[:8])
                return False

        return True


# ── internal helpers ──────────────────────────────────────────────────────────

def _build_merkle_tree(leaves: list[MCCLeaf]) -> bytes:
    """Build full Merkle tree. If N is not a power of 2, pad with last leaf.
    
    Leaves are sorted by key first to ensure deterministic root hash
    regardless of insertion order (ATP v1.7 §2.2).
    """
    if not leaves:
        return b"\x00" * 32
    
    # Sort by key for deterministic tree
    sorted_leaves = sorted(leaves, key=lambda l: l.key)
    hashes = [l.compute_leaf_hash() for l in sorted_leaves]
    n = len(hashes)

    # pad to power-of-2
    size = 1
    while size < n:
        size <<= 1
    while len(hashes) < size:
        hashes.append(hashes[-1])

    # build tree bottom-up
    while len(hashes) > 1:
        next_level = []
        for i in range(0, len(hashes), 2):
            left = hashes[i]
            right = hashes[i + 1]
            next_level.append(blake3_hash(b"\x01" + left + right))
        hashes = next_level

    return hashes[0]


def _commitment_cbor(
    root_hash: bytes,
    expiry_date: int,
    mcc_version: int,
    authority_id: str,
    serial_number: bytes,
) -> bytes:
    """Canonical CBOR of the 5-field commitment that gets signed."""
    return cbor2.dumps(
        {
            "root_hash": root_hash,
            "expiry_date": expiry_date,
            "mcc_version": mcc_version,
            "authority_id": authority_id,
            "serial_number": serial_number,
        },
        canonical=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  Frame types & error codes
# ═══════════════════════════════════════════════════════════════════════════════

FRAME_TYPES: dict[int, str] = {
    0x01: "TASK_REQUEST",
    0x02: "TASK_RESPONSE",
    0x03: "TASK_ACK",
    0x04: "TASK_ERROR",
    0x05: "TASK_CANCEL",
    0x10: "CONTROL_SHUTDOWN",
    0x11: "CONTROL_REVOKE_NOTIFY",
    0x12: "CONTROL_SHUTDOWN_ACK",
    0x13: "CONTROL_HEALTH",
    0x14: "CONTROL_HEALTH_RESP",
    0x15: "CONTROL_PING",
    0x16: "CONTROL_PONG",
    0x20: "ERROR",
    0x21: "ROOT_STORE_UPDATE",
    # Federation (v2.0)
    0x60: "PEER_DISCOVERY",
    0x61: "PEER_HEARTBEAT",
    0x62: "TASK_FORWARD",
    0x63: "PEER_DISCOVERY_ACK",
    # Handshake
    0x30: "VERSION_PROPOSE",
    0x31: "VERSION_ACK",
    0x40: "MCC_BIND_REQUEST",
    0x41: "MCC_BIND_RESPONSE",
    0x42: "MCC_BIND_CONFIRM",
    0x50: "CAPABILITY_EXCHANGE",
}

ERROR_CODES: dict[int, tuple[str, str]] = {
    0x01: ("ERR_ATP_VERSION_UNSUPPORTED", "close"),
    0x02: ("ERR_INVALID_ROOT", "close"),
    0x03: ("ERR_MISSING_CRITICAL_CLAIM", "close"),
    0x04: ("ERR_IDENTITY_MISMATCH", "close"),
    0x05: ("ERR_BAD_SIGNATURE", "close"),
    0x06: ("ERR_REVOKED", "close"),
    0x07: ("ERR_IDENTITY_NOT_BOUND", "close"),
    0x08: ("ERR_STREAM_PROTOCOL_VIOLATION", "close"),
    0x09: ("ERR_TASK_TOO_LARGE", "close_stream"),
    0x0A: ("ERR_UNSUPPORTED_TASK_TYPE", "close_stream"),
    0x0B: ("ERR_TASK_TIMEOUT", "close_stream"),
    0x0C: ("ERR_CLOCK_SKEW", "close_stream"),
    0x0D: ("ERR_RATE_LIMITED", "recoverable"),
    0x0E: ("ERR_STREAM_VIOLATION_MINOR", "close_stream"),
    0x0F: ("ERR_TASK_CANCELLED", "close_stream"),
}


# ═══════════════════════════════════════════════════════════════════════════════
#  Frame encoding / decoding
# ═══════════════════════════════════════════════════════════════════════════════

def build_header(frame_type: int, task_id: Optional[bytes] = None) -> dict:
    """Standard frame header (frame_type, frame_id, task_id, timestamp, atp_version)."""
    from config import ATP_VERSION
    return {
        "frame_type": frame_type,
        "frame_id": uuid.uuid4().bytes,                      # 16 bytes
        "task_id": task_id if task_id is not None else b"\x00" * 16,  # nil UUID
        "timestamp": int(time.time() * 1000),                  # epoch ms
        "atp_version": ATP_VERSION,
    }


def encode_frame(payload: dict) -> bytes:
    """
    Encode a frame dict to CBOR, prepended with a 4-byte big-endian length.
    """
    body = cbor2.dumps(payload, canonical=True)
    return struct.pack("!I", len(body)) + body


async def decode_frame(reader) -> Optional[dict]:
    """
    Read a length-prefixed CBOR frame from an asyncio StreamReader.
    Returns None on connection close or decoding error.
    """
    import asyncio
    try:
        raw_len = await asyncio.wait_for(reader.readexactly(4), timeout=30)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        return None
    length = struct.unpack("!I", raw_len)[0]
    if length == 0 or length > 2 * 1024 * 1024:  # sanity cap at 2 MiB
        logger.warning("decode_frame: invalid length %d", length)
        return None
    try:
        body = await asyncio.wait_for(reader.readexactly(length), timeout=30)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        return None
    try:
        return cbor2.loads(body)
    except Exception as exc:
        logger.warning("decode_frame: CBOR error — %s", exc)
        return None


async def send_frame(writer, payload: dict) -> None:
    """Encode and send a frame."""
    data = encode_frame(payload)
    writer.write(data)
    await writer.drain()
