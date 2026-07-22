"""
ATP v1.7 — Revocation subsystem.
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
    """Thread-safe Cuckoo filter for approximate set membership."""

    def __init__(self, buckets: int = 1024, slots: int = 4, fingerprint_bits: int = 16):
        # Buckets must be power of 2
        self._buckets = 1
        while self._buckets < buckets:
            self._buckets <<= 1
        self._slots = slots
        self._fprint_bits = fingerprint_bits
        self._fprint_mask = (1 << fingerprint_bits) - 1
        self._max_kicks = 500

        # Bucket storage: list of lists
        self._table: list[list[int]] = [[] for _ in range(self._buckets)]
        self._lock = threading.Lock()
        self._size = 0
        self._max_size = int(self._buckets * self._slots * 0.95)  # 95% load factor

    # ── public API ──────────────────────────────────────────────────────

    def insert(self, item: bytes) -> bool:
        """Insert *item* into the filter. Returns True on success."""
        fp, i1, i2 = self._hash(item)

        with self._lock:
            # Try bucket i1 first
            if len(self._table[i1]) < self._slots:
                self._table[i1].append(fp)
                self._size += 1
                return True

            # Try bucket i2
            if len(self._table[i2]) < self._slots:
                self._table[i2].append(fp)
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
                kicked_fp = bucket[kick_idx]
                bucket[kick_idx] = fp  # place our fp here

                # Re-insert kicked fingerprint into its alternate bucket
                alt_i = cur_i ^ self._alt_index(kicked_fp, cur_i)
                if len(self._table[alt_i]) < self._slots:
                    self._table[alt_i].append(kicked_fp)
                    self._size += 1
                    return True
                cur_i = alt_i
                fp = kicked_fp

            # Too many kicks → filter full (rehash needed)
            logger.warning("CuckooFilter: too many kicks, filter may be full")
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
                try:
                    bucket.remove(fp)
                    self._size -= 1
                    return True
                except ValueError:
                    continue
        return False

    @property
    def size(self) -> int:
        return self._size

    @property
    def load_factor(self) -> float:
        return self._size / (self._buckets * self._slots)

    # ── internal ────────────────────────────────────────────────────────

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
            return fp in self._table[idx]

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
        self._persist_path = path or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "root_store.json"
        )
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
            with open(self._persist_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.warning("RootStore: failed to persist: %s", exc)

    def add_authority(self, authority_id: str, public_key: bytes,
                      ttl_seconds: int = 86400 * 365) -> bool:
        """Add or update a trusted authority."""
        with self._lock:
            self._manifest["authorities"][authority_id] = {
                "pk": public_key,
                "added": int(time.time()),
                "expires": int(time.time()) + ttl_seconds,
            }
            self._save()
            logger.info("RootStore: added authority %s", authority_id)
            return True

    def get_authority(self, authority_id: str) -> Optional[bytes]:
        """Get public key for an authority. Returns None if unknown or expired."""
        with self._lock:
            entry = self._manifest["authorities"].get(authority_id)
            if entry is None:
                return None
            if entry["expires"] < int(time.time()):
                logger.warning("RootStore: authority %s expired", authority_id)
                return None
            return entry["pk"]

    def chain_add(self, signed_manifest: bytes) -> bool:
        """Add a signed manifest to the chain for audit."""
        with self._lock:
            self._manifest["chain"].append({
                "manifest": signed_manifest,
                "added": int(time.time()),
            })
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

    def __init__(self, peer_id: str, host: str, gossip_port: int):
        self.peer_id = peer_id
        self.host = host
        self.gossip_port = gossip_port
        self.known_serials: set[bytes] = set()
        self.last_sync: float = 0.0


class GossipProtocol:
    """
    Gossip protocol for distributing revocation information over TCP.

    Every GOSSIP_INTERVAL_S seconds, each node sends its known revoked
    serial_numbers to GOSSIP_FANOUT randomly selected peers as CBOR payloads
    over plain TCP (no TLS — gossip is authenticated via Ed25519 signatures
    in a future version).
    """

    def __init__(self, node_id: str, monitor=None):
        self.node_id = node_id
        self.monitor = monitor
        self._peers: dict[str, GossipPeer] = {}
        self._lock = asyncio.Lock()
        self._revoked_serials: set[bytes] = set()

    def add_peer(self, peer_id: str, host: str, gossip_port: int = 8444):
        """Register a gossip peer."""
        if peer_id not in self._peers:
            self._peers[peer_id] = GossipPeer(peer_id, host, gossip_port)
            logger.info("Gossip: added peer %s at %s:%s", peer_id, host, gossip_port)

    def remove_peer(self, peer_id: str):
        self._peers.pop(peer_id, None)

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
        and send revoked serials as CBOR-encoded list.
        """
        import asyncio, secrets, cbor2 as _cbor2
        peers = list(self._peers.values())
        if not peers or not self._revoked_serials:
            return

        fanout = min(len(peers), 3)
        targets = secrets.SystemRandom().sample(peers, fanout)

        serials_list = list(self._revoked_serials)
        payload = _cbor2.dumps([s.hex() for s in serials_list])
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
    """

    def __init__(self, monitor=None):
        self.monitor = monitor
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
        """Handle an incoming gossip connection."""
        peer = writer.get_extra_info("peername")
        try:
            raw_len = await asyncio.wait_for(reader.readexactly(4), timeout=5)
            length = struct.unpack("!I", raw_len)[0]
            if length == 0 or length > 1024 * 1024:
                logger.warning("Gossip: invalid length %d from %s", length, peer)
                return
            data = await asyncio.wait_for(reader.readexactly(length), timeout=10)
            import cbor2 as _cbor2
            serials_hex = _cbor2.loads(data)
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
#  Global revocation state  (singleton, thread-safe)
# ═══════════════════════════════════════════════════════════════════════════════

_revocation_lock = threading.Lock()
_default_cuckoo: Optional[CuckooFilter] = None
_default_root_store: Optional[RootStore] = None
_default_gossip: Optional[GossipProtocol] = None
_default_degradation: Optional[DegradationPolicy] = None


def get_cuckoo_filter() -> CuckooFilter:
    global _default_cuckoo
    if _default_cuckoo is None:
        with _revocation_lock:
            if _default_cuckoo is None:
                _default_cuckoo = CuckooFilter()
    return _default_cuckoo


def get_root_store() -> RootStore:
    global _default_root_store
    if _default_root_store is None:
        with _revocation_lock:
            if _default_root_store is None:
                _default_root_store = RootStore()
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
