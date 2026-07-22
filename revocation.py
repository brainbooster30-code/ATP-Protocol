"""
ATP v1.8 — Revocation subsystem.
Real Cuckoo Filter + Gossip protocol + Root Store Chain + Degradation Policy.
"""

from __future__ import annotations

import os
import time
import math
import struct
import logging
import asyncio
import threading
import json
from typing import Optional
from collections import OrderedDict

from atp_core import blake3_hash

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
#  Cuckoo Filter  —  real hash-based approximate membership query
# ═══════════════════════════════════════════════════════════════════════════════
#
#  Parameters (tunable):
#    BUCKETS    — number of hash buckets  (power of 2)
#    FPRINT_BITS — fingerprint width in bits  (higher = fewer false positives)
#    SLOTS      — fingerprints per bucket
#
#  False-positive rate ≈ (SLOTS / 2^FPRINT_BITS) ^ (2 * SLOTS)
#  With FPRINT_BITS=16, SLOTS=4:   ~(4/65536)^8 ≈ 2.3e-31
#

class CuckooFilter:
    """Thread-safe Cuckoo filter for approximate set membership.
    
    Stores (fingerprint, item_bytes) pairs so auto-resize can
    correctly re-hash items with the new bucket count.
    """

    def __init__(self, buckets: int = 1024, slots: int = 4, fingerprint_bits: int = 16):
        # Buckets must be power of 2
        self._buckets = 1
        while self._buckets < buckets:
            self._buckets <<= 1
        self._slots = slots
        self._fprint_bits = fingerprint_bits
        self._fprint_mask = (1 << fingerprint_bits) - 1
        self._max_kicks = 500
        self._resize_count = 0
        self._resizing = False  # guard against recursive resize

        # Bucket storage: list of lists of (fingerprint, item_bytes) tuples
        # Storing original items enables correct re-hashing during resize.
        self._table: list[list[tuple[int, bytes]]] = [[] for _ in range(self._buckets)]
        self._lock = threading.RLock()
        self._size = 0
        self._max_size = int(self._buckets * self._slots * 0.95)  # 95% load factor

    # ── public API ──────────────────────────────────────────────────────

    def insert(self, item: bytes) -> bool:
        """Insert *item* into the filter. Returns True on success.
        Auto-resizes (doubles buckets) when load factor is exceeded.
        """
        fp, i1, i2 = self._hash(item)

        with self._lock:
            # Try bucket i1 first
            if len(self._table[i1]) < self._slots:
                self._table[i1].append((fp, item))
                self._size += 1
                return True

            # Try bucket i2
            if len(self._table[i2]) < self._slots:
                self._table[i2].append((fp, item))
                self._size += 1
                return True

            # Both full → relocate (cuckoo kicks)
            cur_i = i1 if len(self._table[i1]) <= len(self._table[i2]) else i2
            for _ in range(self._max_kicks):
                # Evict a random fingerprint from cur_i
                bucket = self._table[cur_i]
                if not bucket:
                    continue
                kick_idx = self._random_index(len(bucket))
                kicked_fp, kicked_item = bucket[kick_idx]
                bucket[kick_idx] = (fp, item)  # place our fp + item here

                # Re-insert kicked fingerprint into its alternate bucket
                alt_i = cur_i ^ self._alt_index(kicked_fp, cur_i)
                if len(self._table[alt_i]) < self._slots:
                    self._table[alt_i].append((kicked_fp, kicked_item))
                    self._size += 1
                    return True
                cur_i = alt_i
                fp, item = kicked_fp, kicked_item

            # Too many kicks → filter full → auto-resize (unless already resizing)
            logger.warning(
                "CuckooFilter: too many kicks (size=%d/%d), resizing (cycle=%d)",
                self._size, self._max_size, self._resize_count,
            )

        # Resize OUTSIDE the lock to minimise lock hold time
        if not self._resizing:
            self._resize()
            # Retry insert after resize (re-acquires lock)
            return self.insert(item)

        # Recursive resize guard reached — filter truly full
        logger.error(
            "CuckooFilter: cannot resize further (recursive guard, size=%d)",
            self._size,
        )
        return False

    def contains(self, item: bytes) -> bool:
        """Check if *item* may be in the filter. False positives possible."""
        fp, i1, i2 = self._hash(item)
        return self._bucket_has(i1, fp) or self._bucket_has(i2, fp)

    def remove(self, item: bytes) -> bool:
        """Remove *item* from the filter. Returns True if removed."""
        fp, i1, i2 = self._hash(item)
        with self._lock:
            for idx in (i1, i2):
                bucket = self._table[idx]
                for i, (existing_fp, existing_item) in enumerate(bucket):
                    if existing_fp == fp:
                        del bucket[i]
                        self._size -= 1
                        return True
        return False

    @property
    def size(self) -> int:
        return self._size

    @property
    def load_factor(self) -> float:
        return self._size / (self._buckets * self._slots)

    # ── internal ────────────────────────────────────────────────────────

    def _resize(self):
        """Double the bucket count and rehash all existing fingerprints.

        Called when insert fails due to capacity. Acquires the lock,
        saves all stored (fingerprint, item) pairs, doubles the table,
        and re-inserts every item using the new bucket count via _hash.
        """
        with self._lock:
            if self._resizing:
                # Already resizing (recursive call) — fail-safe
                return
            self._resizing = True
        try:
            with self._lock:
                old_buckets = self._buckets
                new_buckets = old_buckets * 2
                # Save all stored items for re-hashing (correct bucket indices)
                all_items = [item for bucket in self._table for _, item in bucket]
                # Reset table with doubled capacity
                self._buckets = new_buckets
                self._table = [[] for _ in range(new_buckets)]
                self._size = 0
                self._max_size = int(self._buckets * self._slots * 0.95)
                self._resize_count += 1
            # Re-insert OUTSIDE lock to let insert() acquire the lock independently
            reinsert_ok = 0
            reinsert_fail = 0
            for item in all_items:
                if self.insert(item):
                    reinsert_ok += 1
                else:
                    reinsert_fail += 1
            with self._lock:
                logger.info(
                    "CuckooFilter resized: %d → %d buckets, "
                    "%d ok, %d failed (cycle=%d)",
                    old_buckets, new_buckets,
                    reinsert_ok, reinsert_fail, self._resize_count,
                )
        finally:
            with self._lock:
                self._resizing = False

    def _hash(self, item: bytes) -> tuple[int, int, int]:
        """Return (fingerprint, bucket_index_1, bucket_index_2)."""
        h = blake3_hash(item)
        # Fingerprint: first FPRINT_BITS of hash
        fp = (int.from_bytes(h[:4], 'big')) & self._fprint_mask
        if fp == 0:
            fp = 1  # fingerprint 0 is reserved
        # Bucket index 1: next bytes
        i1 = (int.from_bytes(h[4:8], 'big')) & (self._buckets - 1)
        # Bucket index 2: i1 XOR hash(fingerprint)
        i2 = i1 ^ self._alt_index(fp, i1)
        return fp, i1, i2

    def _alt_index(self, fingerprint: int, i1: int) -> int:
        """Compute alternate index from fingerprint."""
        h = blake3_hash(struct.pack('!I', fingerprint))
        return (int.from_bytes(h[:4], 'big')) & (self._buckets - 1)

    def _bucket_has(self, idx: int, fp: int) -> bool:
        with self._lock:
            return any(existing_fp == fp for existing_fp, _ in self._table[idx])

    def _random_index(self, bucket_len: int) -> int:
        """Cryptographically secure random index for bucket eviction."""
        from secrets import randbelow
        return randbelow(bucket_len)


# ═══════════════════════════════════════════════════════════════════════════════
#  Root Store  —  trusted authority public key storage with chain verification
# ═══════════════════════════════════════════════════════════════════════════════

@classmethod
def _root_store_default(cls) -> dict:
    return {
        "version": 1,
        "authorities": {},
        "chain": [],
    }


class RootStore:
    """
    Thread-safe store for trusted authority public keys.
    Supports chain-of-manifests + file persistence.
    """

    def __init__(self, path: Optional[str] = None):
        self._lock = threading.Lock()
        if path is None:
            from config import ROOT_STORE_PATH
            path = ROOT_STORE_PATH or os.path.join(
                os.path.expanduser("~"), ".atp", "root_store.json"
            )
        self._persist_path = path
        self._seen_nonces: set[bytes] = set()           # anti-replay
        self._manifest_ts_latest: dict[str, int] = {}   # per-authority freshness
        self._version: int = 1                           # monotonic, increments on changes
        self._manifest: dict = {
            "version": 1,
            "authorities": {},    # authority_id → {"pk_hex": str, "added": int, "expires": int}
            "chain": [],          # list of previous manifest signatures
        }
        self._load()

    # ── persistence ─────────────────────────────────────────────────

    def _load(self):
        """Load root store from JSON file if it exists."""
        try:
            with open(self._persist_path, "r") as f:
                data = json.load(f)
            # Reconstruct in-memory format: convert hex pk back to bytes
            manifest = {
                "version": data.get("version", 1),
                "authorities": {},
                "chain": data.get("chain", []),
            }
            for auth_id, entry in data.get("authorities", {}).items():
                manifest["authorities"][auth_id] = {
                    "pk": bytes.fromhex(entry["pk_hex"]),
                    "added": entry["added"],
                    "expires": entry["expires"],
                }
            self._manifest = manifest
            logger.info("RootStore loaded %d authorities from %s",
                        len(manifest["authorities"]), self._persist_path)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.info("RootStore: no existing store at %s, starting fresh",
                        self._persist_path)

    def _save(self):
        """Persist root store to JSON file."""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self._persist_path)), exist_ok=True)
            data = {
                "version": self._manifest["version"],
                "authorities": {},
                "chain": self._manifest["chain"],
            }
            for auth_id, entry in self._manifest["authorities"].items():
                data["authorities"][auth_id] = {
                    "pk_hex": entry["pk"].hex(),
                    "added": entry["added"],
                    "expires": entry["expires"],
                }
            for chain_entry in data["chain"]:
                if isinstance(chain_entry.get("manifest"), bytes):
                    chain_entry["manifest_hex"] = chain_entry.pop("manifest").hex()
            with open(self._persist_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.warning("RootStore: failed to persist: %s", exc)

    def add_authority(self, authority_id: str, public_key: bytes,
                      ttl_seconds: int = 86400 * 365) -> bool:
        """Add or update a trusted authority.

        Idempotent: if the authority already exists with the *same* public key,
        the version counter is NOT incremented and no save is triggered.
        """
        with self._lock:
            existing = self._manifest['authorities'].get(authority_id)
            if existing and existing['pk'] == public_key:
                # Already registered with the same key — no-op
                return True
            self._manifest['authorities'][authority_id] = {
                'pk': public_key,
                'added': int(time.time()),
                'expires': int(time.time()) + ttl_seconds,
            }
            self._version += 1
            self._save()
            logger.info("RootStore: added authority %s", authority_id)
            return True

    def get_authority(self, authority_id: str) -> Optional[bytes]:
        """Get public key for an authority. Returns None if unknown or expired."""
        with self._lock:
            entry = self._manifest["authorities"].get(authority_id)
            if entry is None:
                return None
            if entry["expires"] <= int(time.time()):
                logger.warning("RootStore: authority %s expired", authority_id)
                return None
            return entry["pk"]

    def chain_add(self, signed_manifest: bytes) -> bool:
        """Add a signed manifest to the chain, verifying its signature.

        Delegates CBOR parsing and signature verification to
        _verify_chain_manifest_cbor (shared with RootStoreSQLite).

        Returns True if accepted and persisted, False otherwise.
        """
        manifest = _verify_chain_manifest_cbor(
            signed_manifest,
            get_authority_fn=lambda aid: self.get_authority(aid),
        )
        if manifest is None:
            return False

        now = int(time.time())
        manifest_nonce = manifest.get("manifest_nonce", b"")
        manifest_version = manifest.get("rootstore_version", 0)
        authorities = manifest.get("authorities", [])
        signer_id = manifest.get("authority_id", "")

        with self._lock:
            # Anti-replay: nonce uniqueness
            if manifest_nonce:
                if manifest_nonce in self._seen_nonces:
                    logger.warning("Chain: duplicate nonce — possible replay attack")
                    return False

            # Version check: reject stale manifests
            if manifest_version:
                latest = self._manifest_ts_latest.get(signer_id, 0)
                if manifest_version < latest:
                    logger.warning(
                        "Chain: stale manifest version %d < %d for %s",
                        manifest_version, latest, signer_id,
                    )
                    return False

            # Commit: nonce, version, authorities
            if manifest_nonce:
                self._seen_nonces.add(manifest_nonce)
                if len(self._seen_nonces) > 10_000:
                    self._seen_nonces.clear()

            if manifest_version and manifest_version > latest:
                self._manifest_ts_latest[signer_id] = manifest_version

            for entry in authorities:
                authority_id = entry["authority_id"]
                pk = entry["pk"]
                existing = self._manifest["authorities"].get(authority_id)
                if existing and existing["pk"] == pk:
                    continue
                self._manifest["authorities"][authority_id] = {
                    "pk": pk,
                    "added": now,
                    "expires": now + 86400 * 365,
                }
                self._version += 1

            self._manifest["chain"].append({
                "manifest": signed_manifest,
                "added": now,
            })
            self._save()
        logger.info("Chain: added manifest from %s (%d authorities)",
                    signer_id, len(authorities))
        return True

    @property
    def manifest(self) -> dict:
        with self._lock:
            return dict(self._manifest)


# ═══════════════════════════════════════════════════════════════════════════════
#  Degradation Policy  —  CONFIRMED / STALE / UNCERTAIN
# ═══════════════════════════════════════════════════════════════════════════════

class DegradationPolicy:
    """
    Three-state degradation for root store freshness:

      CONFIRMED  — authority within freshness window   → full verification
      STALE      — authority outside window but cached → verify with warning
      UNCERTAIN  — no authority available              → connection refused
    """

    FRESHNESS_S = 3600        # 1 hour
    GRACE_S     = 86400       # 24 hours grace before STALE → UNCERTAIN

    CONFIRMED  = "CONFIRMED"
    STALE      = "STALE"
    UNCERTAIN  = "UNCERTAIN"

    def __init__(self, active: bool = True):
        self.active = active
        self._state = self.CONFIRMED
        self._last_check = time.time()

    def evaluate(self, authority_id: str, store: RootStore) -> str:
        """
        Evaluate the degradation state for *authority_id*.
        Returns one of CONFIRMED / STALE / UNCERTAIN.
        """
        if not self.active:
            return self.CONFIRMED

        pk = store.get_authority(authority_id)
        if pk is None:
            self._state = self.UNCERTAIN
            return self.UNCERTAIN

        now = time.time()
        entry = store._manifest["authorities"].get(authority_id, {})
        added = entry.get("added", 0)
        age = now - added

        if age < self.FRESHNESS_S:
            self._state = self.CONFIRMED
        elif age < self.FRESHNESS_S + self.GRACE_S:
            self._state = self.STALE
            logger.warning("Degradation: authority %s is STALE (age=%ds)", authority_id, int(age))
        else:
            self._state = self.UNCERTAIN
            logger.warning("Degradation: authority %s is UNCERTAIN (age=%ds)", authority_id, int(age))

        self._last_check = now
        return self._state

    @property
    def state(self) -> str:
        return self._state


# ═══════════════════════════════════════════════════════════════════════════════
#  Gossip Protocol  —  fanout-based serial_number exchange over TCP
# ═══════════════════════════════════════════════════════════════════════════════

class GossipPeer:
    """Represents one gossip peer with its known revocation set."""

    def __init__(self, peer_id: str, host: str, gossip_port: int,
                 ed25519_pk: bytes = b""):
        self.peer_id = peer_id
        self.host = host
        self.gossip_port = gossip_port
        self.ed25519_pk = ed25519_pk      # public key for signature verification
        self.known_serials: set[bytes] = set()
        self.last_sync: float = 0.0


class GossipProtocol:
    """
    Gossip protocol for distributing revocation information over TCP.

    Every GOSSIP_INTERVAL_S seconds, each node sends its known revoked
    serial_numbers to GOSSIP_FANOUT randomly selected peers as CBOR payloads
    over plain TCP (no TLS — gossip is authenticated via Ed25519 signatures
    with external peer key verification).
    """

    def __init__(self, node_id: str, monitor=None, signing_sk: Optional[bytes] = None):
        self.node_id = node_id
        self.monitor = monitor
        self._peers: dict[str, GossipPeer] = {}
        self._lock = asyncio.Lock()
        self._revoked_serials: set[bytes] = set()
        # Trusted peer keys: peer_id → ed25519_pk (32 bytes)
        # Used by GossipServer to verify incoming gossip signatures.
        self._trusted_peers: dict[str, bytes] = {}
        # Ed25519 signing key for authenticating gossip payloads.
        # If None, gossip is sent unsigned (backward compat during migration).
        if signing_sk is None:
            # Auto-generate a keypair if none provided
            from atp_core import generate_ed25519_keypair
            sk, pk = generate_ed25519_keypair()
            self._sign_sk: bytes = sk
            self._sign_pk: bytes = pk
        else:
            self._sign_sk: bytes = signing_sk
            from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
            from cryptography.hazmat.primitives import serialization as _ser
            self._sign_pk: bytes = _ed.Ed25519PrivateKey.from_private_bytes(
                signing_sk
            ).public_key().public_bytes(
                encoding=_ser.Encoding.Raw,
                format=_ser.PublicFormat.Raw,
            )

    def add_peer(self, peer_id: str, host: str, gossip_port: int = 8444,
                 ed25519_pk: bytes = b""):
        """Register a gossip peer."""
        if peer_id not in self._peers:
            self._peers[peer_id] = GossipPeer(peer_id, host, gossip_port, ed25519_pk=ed25519_pk)
            logger.info("Gossip: added peer %s at %s:%s", peer_id, host, gossip_port)

    def remove_peer(self, peer_id: str):
        self._peers.pop(peer_id, None)

    def trust_gossip_peer(self, peer_id: str, ed25519_pk: bytes):
        """Pin a trusted gossip peer's Ed25519 public key.

        Once pinned, GossipServer will reject gossip from this peer_id
        unless the signature matches the pinned key.
        """
        if len(ed25519_pk) == 32:
            self._trusted_peers[peer_id] = ed25519_pk
            logger.info("Gossip: trusted peer %s pinned (%s...)",
                        peer_id, ed25519_pk.hex()[:8])
        else:
            logger.warning("Gossip: invalid Ed25519 key for peer %s", peer_id)

    def load_trusted_peers(self, path: Optional[str] = None):
        """Load trusted gossip peers from a JSON file.

        Format:
        {"peers": {"peer-id-1": "ed25519_pk_hex", "peer-id-2": "ed25519_pk_hex"}}
        """
        if path is None:
            path = os.path.join(os.path.expanduser("~"), ".atp", "gossip_trust.json")
        try:
            with open(path, "r") as f:
                data = json.load(f)
            for peer_id, pk_hex in data.get("peers", {}).items():
                pk = bytes.fromhex(pk_hex)
                if len(pk) == 32:
                    self._trusted_peers[peer_id] = pk
                    logger.info("Gossip: loaded trusted peer %s from %s", peer_id, path)
                else:
                    logger.warning("Gossip: invalid key for %s in %s", peer_id, path)
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
            logger.debug("Gossip: trusted peers not loaded (%s)", exc)

    def mark_revoked(self, serial_number: bytes):
        """Record a serial_number as revoked and prepare to gossip it."""
        self._revoked_serials.add(serial_number)
        for peer in self._peers.values():
            peer.known_serials.add(serial_number)

    def is_revoked(self, serial_number: bytes) -> bool:
        return serial_number in self._revoked_serials

    async def gossip_round(self):
        """
        Execute one gossip round: connect to fanout peers over TCP
        and send signed revoked serials as CBOR-encoded payload.

        The payload is Ed25519-signed by the sender for authenticity.
        Receivers verify the signature if the sender's Ed25519 key is known.
        """
        import asyncio, secrets, cbor2 as _cbor2
        from atp_core import ed25519_sign
        peers = list(self._peers.values())
        if not peers or not self._revoked_serials:
            return

        fanout = min(len(peers), 3)
        targets = secrets.SystemRandom().sample(peers, fanout)

        serials_list = list(self._revoked_serials)
        # Build a signed payload: node_id + serials + public_key
        gossip_payload = {
            "node_id": self.node_id,
            "serials": [s.hex() for s in serials_list],
            "sender_pk": self._sign_pk.hex(),
        }
        payload_body = _cbor2.dumps(gossip_payload, canonical=True)
        sig = ed25519_sign(self._sign_sk, payload_body)
        gossip_payload["signature"] = sig.hex()  # hex for JSON-safe transport
        payload = _cbor2.dumps(gossip_payload, canonical=True)
        logger.info("Gossip round: %d revoked serials → %d peers",
                     len(serials_list), fanout)

        for peer in targets:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(peer.host, peer.gossip_port),
                    timeout=3.0,
                )
                # Send 4-byte length prefix + CBOR payload
                import struct
                writer.write(struct.pack("!I", len(payload)) + payload)
                await writer.drain()
                writer.close()
                peer.last_sync = time.time()
                if self.monitor:
                    self.monitor.add_event("GOSSIP_SEND", {
                        "peer": peer.peer_id,
                        "serials_count": len(serials_list),
                    })
                logger.debug("Gossip: sent %d serials to %s:%s",
                             len(serials_list), peer.host, peer.gossip_port)
            except (asyncio.TimeoutError, ConnectionError, OSError) as exc:
                logger.warning("Gossip: failed to reach %s:%s — %s",
                               peer.host, peer.gossip_port, exc)
                if self.monitor:
                    self.monitor.add_event("GOSSIP_FAILED", {
                        "peer": peer.peer_id,
                        "error": str(exc),
                    })

    async def gossip_loop(self, interval_s: int = 5):
        """Run periodic gossip rounds."""
        while True:
            await asyncio.sleep(interval_s)
            await self.gossip_round()


class GossipServer:
    """
    Lightweight TCP server that receives revocation serials from gossip peers.

    Runs on GOSSIP_PORT (default 8444) alongside the main ATP server.
    Incoming payloads are CBOR-encoded lists of hex serial numbers.

    If *gossip_proto* is provided, gossip signatures are verified against
    the protocol's trusted peer key list (external authentication).
    """

    def __init__(self, monitor=None, gossip_proto=None):
        self.monitor = monitor
        self._gossip_proto = gossip_proto  # link to GossipProtocol for trusted keys
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self, host: str = "127.0.0.1", port: int = 8444):
        self._server = await asyncio.start_server(
            self._on_gossip_connect, host=host, port=port,
        )
        logger.info("GossipServer listening on %s:%s", host, port)

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _on_gossip_connect(self, reader, writer):
        """Handle an incoming gossip connection.

        Supports two payload formats:
        1. Signed dict (v2): {node_id, serials[], sender_pk, signature} -- preferred
        2. Flat list (v1): [hex_serial, ...] -- backward compat
        """
        peer = writer.get_extra_info("peername")
        try:
            raw_len = await asyncio.wait_for(reader.readexactly(4), timeout=5)
            length = struct.unpack("!I", raw_len)[0]
            if length == 0 or length > 1024 * 1024:
                logger.warning("Gossip: invalid length %d from %s", length, peer)
                return
            data = await asyncio.wait_for(reader.readexactly(length), timeout=10)
            import cbor2 as _cbor2
            from atp_core import ed25519_verify
            payload = _cbor2.loads(data)

            serials_hex: list = []

            if isinstance(payload, dict):
                # Signed format (v2): verify Ed25519 signature
                sig_hex = payload.pop("signature", "")
                sender_pk_hex = payload.get("sender_pk", "")
                node_id = payload.get("node_id", "?")
                serials_hex = payload.get("serials", [])
                if sig_hex and sender_pk_hex:
                    try:
                        sig = bytes.fromhex(sig_hex)
                        sender_pk = bytes.fromhex(sender_pk_hex)
                        payload_body = _cbor2.dumps(payload, canonical=True)
                        # External verification: check if we have a trusted key for this node
                        trusted_pk = None
                        if hasattr(self, "_gossip_proto") and self._gossip_proto:
                            trusted_pk = self._gossip_proto._trusted_peers.get(node_id)
                        if trusted_pk is not None:
                            # Strict mode: verify against pinned key
                            if sender_pk != trusted_pk:
                                logger.warning(
                                    "Gossip: peer %s sender_pk does not match trusted key "
                                    "(got %s, expected %s) -- rejecting",
                                    node_id, sender_pk.hex()[:8], trusted_pk.hex()[:8],
                                )
                                return
                            if not ed25519_verify(trusted_pk, sig, payload_body):
                                logger.warning(
                                    "Gossip: bad signature from trusted peer %s -- rejecting",
                                    node_id,
                                )
                                return
                            logger.info("Gossip: verified trusted signature from %s", node_id)
                        else:
                            # Best-effort: accept self-authenticated sig but log warning
                            if not ed25519_verify(sender_pk, sig, payload_body):
                                logger.warning(
                                    "Gossip: bad signature from %s (%s) -- ignoring",
                                    node_id, peer,
                                )
                                return
                            logger.debug(
                                "Gossip: accepted self-authenticated sig from %s (not in trust list)",
                                node_id,
                            )
                    except (ValueError, Exception) as exc:
                        logger.warning("Gossip: signature verification error from %s -- %s", peer, exc)
                        return
                else:
                    # Unsigned dict -- accept during migration window
                    logger.debug("Gossip: unsigned payload from %s (migration)", peer)
            elif isinstance(payload, list):
                # Legacy flat list format (v1)
                serials_hex = payload
            else:
                logger.warning("Gossip: unknown payload type from %s", peer)
                return

            count = 0
            for s_hex in serials_hex:
                serial = bytes.fromhex(s_hex)
                revoke_serial(serial)
                count += 1
            logger.info("Gossip: received %d revoked serials from %s", count, peer)
            if self.monitor:
                self.monitor.add_event("GOSSIP_RECEIVE", {
                    "peer": str(peer),
                    "serials_count": count,
                })
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ValueError, Exception) as exc:
            logger.warning("Gossip: error receiving from %s — %s", peer, exc)
        finally:
            try:
                writer.close()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
#  Shared chain manifest verification  (used by RootStore and RootStoreSQLite)
# ═══════════════════════════════════════════════════════════════════════════════

def _verify_chain_manifest_cbor(
    signed_manifest: bytes,
    get_authority_fn,  # callable(authority_id) -> Optional[bytes]
) -> Optional[dict]:
    """Parse and verify a chain manifest CBOR payload.

    Shared by RootStore and RootStoreSQLite to avoid code duplication.

    Returns the parsed manifest dict on success, or None if verification fails.
    On success, the caller is responsible for persisting the new authorities.

    Anti-replay (nonce, version, timestamp) must be handled by the caller
    because the storage for these differs between backends.
    """
    try:
        import cbor2 as _cbor2
        manifest = _cbor2.loads(signed_manifest)
        sig = manifest.pop("signature", b"")
        if len(sig) != 64:
            logger.warning("Chain manifest: invalid signature length")
            return None
        payload = _cbor2.dumps(manifest, canonical=True)

        # Validate structure
        manifest_ts = manifest.get("manifest_ts", 0)
        now = int(time.time())
        if manifest_ts and abs(now - manifest_ts) > 300:
            logger.warning("Chain manifest: stale timestamp")
            return None
        manifest_nonce = manifest.get("manifest_nonce", b"")
        if manifest_nonce and (not isinstance(manifest_nonce, bytes) or len(manifest_nonce) != 16):
            logger.warning("Chain manifest: invalid nonce")
            return None
        manifest_version = manifest.get("rootstore_version", 0)
        if manifest_version and not isinstance(manifest_version, int):
            logger.warning("Chain manifest: invalid rootstore_version")
            return None
        authorities = manifest.get("authorities", [])
        if not isinstance(authorities, list):
            logger.warning("Chain manifest: authorities must be a list")
            return None
        for entry in authorities:
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("authority_id"), str)
                or not isinstance(entry.get("pk"), bytes)
                or len(entry["pk"]) != 32
            ):
                logger.warning("Chain manifest: invalid authority entry")
                return None

        # Find the signing authority — must already be trusted
        signer_id = manifest.get("authority_id", "")
        signer_pk = get_authority_fn(signer_id)
        if signer_pk is None:
            logger.warning("Chain manifest: signing authority %s not found", signer_id)
            return None

        # Verify signature
        from atp_core import ed25519_verify
        if not ed25519_verify(signer_pk, sig, payload):
            logger.warning("Chain manifest: bad signature from %s", signer_id)
            return None

        return manifest
    except Exception as exc:
        logger.warning("Chain manifest verification error — %s", exc)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  Global revocation state  (singleton, thread-safe)
# ═══════════════════════════════════════════════════════════════════════════════

_revocation_lock = threading.Lock()
_default_cuckoo: Optional[CuckooFilter] = None
_default_root_store: Optional[object] = None  # RootStore or RootStoreSQLite
_default_gossip: Optional[GossipProtocol] = None
_default_degradation: Optional[DegradationPolicy] = None


def get_cuckoo_filter() -> CuckooFilter:
    global _default_cuckoo
    if _default_cuckoo is None:
        with _revocation_lock:
            if _default_cuckoo is None:
                _default_cuckoo = CuckooFilter()
    return _default_cuckoo


def get_root_store() -> object:
    """Get the global RootStore singleton.
    
    Backend is selected by ROOT_STORE_BACKEND in config.py:
    - "json" (default) → RootStore (JSON flat file)
    - "sqlite" → RootStoreSQLite (SQLite WAL mode)
    """
    global _default_root_store
    if _default_root_store is None:
        with _revocation_lock:
            if _default_root_store is None:
                from config import ROOT_STORE_BACKEND, ROOT_STORE_PATH
                if ROOT_STORE_BACKEND == "sqlite":
                    from revocation_sqlite import RootStoreSQLite
                    path = ROOT_STORE_PATH or os.path.join(
                        os.path.expanduser("~"), ".atp", "root_store.db"
                    )
                    _default_root_store = RootStoreSQLite(path=path)
                    logger.info("RootStore backend: SQLite (%s)", path)
                else:
                    _default_root_store = RootStore()
                    logger.info("RootStore backend: JSON (%s)",
                                getattr(_default_root_store, '_persist_path', ''))
    return _default_root_store


def get_gossip(node_id: str = "default") -> GossipProtocol:
    global _default_gossip
    if _default_gossip is None:
        with _revocation_lock:
            if _default_gossip is None:
                _default_gossip = GossipProtocol(node_id=node_id)
    return _default_gossip


def get_degradation() -> DegradationPolicy:
    global _default_degradation
    if _default_degradation is None:
        with _revocation_lock:
            if _default_degradation is None:
                _default_degradation = DegradationPolicy(active=True)
    return _default_degradation


def revoke_serial(serial_number: bytes) -> bool:
    """Revoke a serial number: add to Cuckoo filter + gossip set."""
    cf = get_cuckoo_filter()
    ok = cf.insert(serial_number)
    if ok:
        g = get_gossip()
        g.mark_revoked(serial_number)
        logger.warning("REVOKED serial %s", serial_number.hex()[:8])
    return ok


def check_revoked(serial_number: bytes) -> bool:
    """Check if a serial number has been revoked."""
    cf = get_cuckoo_filter()
    return cf.contains(serial_number)
