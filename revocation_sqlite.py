"""
ATP v1.8 — RootStore SQLite backend.
Drop-in replacement for the JSON-based RootStore with WAL-mode SQLite
for concurrent multi-process access.

Usage:
    from revocation_sqlite import RootStoreSQLite
    rs = RootStoreSQLite(path="~/.atp/root_store.db")
    rs.add_authority("ca-1", b"\\x00" * 32)
    pk = rs.get_authority("ca-1")

Thread-safe via sqlite3's internal locking + WAL mode.
"""

from __future__ import annotations

import os
import time
import json
import logging
import sqlite3
import threading
from typing import Optional

from atp_core import blake3_hash, ed25519_verify

logger = logging.getLogger(__name__)


class RootStoreSQLite:
    """Thread-safe SQLite-backed RootStore with chain-of-manifests.

    Schema
    ------
    authorities:
        authority_id TEXT PRIMARY KEY,
        pk_hex TEXT NOT NULL,
        added INTEGER NOT NULL,
        expires INTEGER NOT NULL

    chain:
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        manifest_hex TEXT NOT NULL,
        added INTEGER NOT NULL

    seen_nonces:
        nonce_hex TEXT PRIMARY KEY,
        seen_at INTEGER NOT NULL

    version_tracking:
        authority_id TEXT PRIMARY KEY,
        rootstore_version INTEGER NOT NULL DEFAULT 0
    """

    def __init__(self, path: Optional[str] = None):
        if path is None:
            path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "root_store.db"
            )
        self._path = os.path.expanduser(path)
        self._lock = threading.Lock()
        self._local = threading.local()  # per-thread connection
        self._init_db()

    # ── connection management ───────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local SQLite connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._path, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _init_db(self):
        """Create tables if they don't exist.
        
        Thread-safe: CREATE TABLE IF NOT EXISTS is idempotent.
        """
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS authorities (
                authority_id TEXT PRIMARY KEY,
                pk_hex TEXT NOT NULL,
                added INTEGER NOT NULL,
                expires INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                manifest_hex TEXT NOT NULL,
                added INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS seen_nonces (
                nonce_hex TEXT PRIMARY KEY,
                seen_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS version_tracking (
                authority_id TEXT PRIMARY KEY,
                rootstore_version INTEGER NOT NULL DEFAULT 0
            );
        """)
        conn.commit()
        logger.info("RootStoreSQLite: initialised at %s", self._path)

    # ── authority CRUD ──────────────────────────────────────────────────

    def add_authority(self, authority_id: str, public_key: bytes,
                      ttl_seconds: int = 86400 * 365) -> bool:
        """Add or update a trusted authority. Idempotent for same key."""
        pk_hex = public_key.hex()
        now = int(time.time())
        expires = now + ttl_seconds
        conn = self._get_conn()
        with self._lock:
            row = conn.execute(
                "SELECT pk_hex FROM authorities WHERE authority_id = ?",
                (authority_id,),
            ).fetchone()
            if row and row["pk_hex"] == pk_hex:
                return True  # idempotent
            conn.execute(
                """INSERT OR REPLACE INTO authorities
                   (authority_id, pk_hex, added, expires)
                   VALUES (?, ?, ?, ?)""",
                (authority_id, pk_hex, now, expires),
            )
            conn.commit()
            logger.info("RootStoreSQLite: added authority %s", authority_id)
            return True

    def get_authority(self, authority_id: str) -> Optional[bytes]:
        """Get public key for an authority. Returns None if unknown/expired."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT pk_hex, expires FROM authorities WHERE authority_id = ?",
            (authority_id,),
        ).fetchone()
        if row is None:
            return None
        if row["expires"] <= int(time.time()):
            logger.warning("RootStoreSQLite: authority %s expired", authority_id)
            return None
        return bytes.fromhex(row["pk_hex"])

    def list_authorities(self) -> dict[str, dict]:
        """Return all non-expired authorities as {id: {pk, added, expires}}."""
        conn = self._get_conn()
        now = int(time.time())
        result = {}
        for row in conn.execute(
            "SELECT authority_id, pk_hex, added, expires FROM authorities"
        ):
            if row["expires"] >= now:
                result[row["authority_id"]] = {
                    "pk": bytes.fromhex(row["pk_hex"]),
                    "added": row["added"],
                    "expires": row["expires"],
                }
        return result

    # ── chain-of-manifests ──────────────────────────────────────────────

    def chain_add(self, signed_manifest: bytes) -> bool:
        """Verify and append a signed manifest. Returns True if accepted."""
        try:
            import cbor2 as _cbor2
            manifest = _cbor2.loads(signed_manifest)
            sig = manifest.pop("signature", b"")
            if len(sig) != 64:
                logger.warning("RootStoreSQLite: invalid signature length")
                return False
            payload = _cbor2.dumps(manifest, canonical=True)

            # Anti-replay: nonce + timestamp
            manifest_nonce = manifest.get("manifest_nonce", b"")
            manifest_ts = manifest.get("manifest_ts", 0)
            now = int(time.time())
            if manifest_ts and abs(now - manifest_ts) > 300:
                logger.warning("RootStoreSQLite: stale manifest")
                return False
            if manifest_nonce:
                nonce_hex = manifest_nonce.hex()
                conn = self._get_conn()
                with self._lock:
                    existing = conn.execute(
                        "SELECT 1 FROM seen_nonces WHERE nonce_hex = ?",
                        (nonce_hex,),
                    ).fetchone()
                    if existing:
                        logger.warning("RootStoreSQLite: duplicate nonce — replay?")
                        return False
                    conn.execute(
                        "INSERT OR REPLACE INTO seen_nonces (nonce_hex, seen_at) VALUES (?, ?)",
                        (nonce_hex, now),
                    )
                    # Prune old nonces
                    conn.execute(
                        "DELETE FROM seen_nonces WHERE seen_at < ?",
                        (now - 3600,),
                    )

            # Find signing authority
            signer_id = manifest.get("authority_id", "")
            signer_pk = self.get_authority(signer_id)
            if signer_pk is None:
                # Bootstrap: look in manifest's authorities list
                for entry in manifest.get("authorities", []):
                    if entry.get("authority_id") == signer_id:
                        signer_pk = entry["pk"]
                        break
            if signer_pk is None:
                logger.warning("RootStoreSQLite: signing authority %s not found", signer_id)
                return False

            # Verify signature
            if not ed25519_verify(signer_pk, sig, payload):
                logger.warning("RootStoreSQLite: bad signature from %s", signer_id)
                return False

            # Version tracking (allow equal — anti-replay via nonce above)
            manifest_version = manifest.get("rootstore_version", 0)
            if manifest_version:
                conn = self._get_conn()
                with self._lock:
                    row = conn.execute(
                        "SELECT rootstore_version FROM version_tracking WHERE authority_id = ?",
                        (signer_id,),
                    ).fetchone()
                    latest = row["rootstore_version"] if row else 0
                    if manifest_version < latest:
                        logger.warning(
                            "RootStoreSQLite: stale version %d < %d for %s",
                            manifest_version, latest, signer_id,
                        )
                        return False
                    if manifest_version > latest:
                        conn.execute(
                            """INSERT OR REPLACE INTO version_tracking
                               (authority_id, rootstore_version) VALUES (?, ?)""",
                            (signer_id, manifest_version),
                        )

            # Add new authorities from manifest
            for entry in manifest.get("authorities", []):
                self.add_authority(
                    entry["authority_id"], entry["pk"],
                )

            # Append to chain
            conn = self._get_conn()
            with self._lock:
                conn.execute(
                    "INSERT INTO chain (manifest_hex, added) VALUES (?, ?)",
                    (signed_manifest.hex(), now),
                )
                conn.commit()
            logger.info(
                "RootStoreSQLite: chain manifest from %s (%d authorities)",
                signer_id, len(manifest.get("authorities", [])),
            )
            return True

        except Exception as exc:
            logger.warning("RootStoreSQLite: chain_add error — %s", exc)
            return False

    # ── manifest export ─────────────────────────────────────────────────

    @property
    def manifest(self) -> dict:
        """Return in-memory-style manifest dict (compat with JSON RootStore)."""
        auths = self.list_authorities()
        chain = []
        conn = self._get_conn()
        for row in conn.execute(
            "SELECT manifest_hex, added FROM chain ORDER BY id"
        ):
            chain.append({
                "manifest": bytes.fromhex(row["manifest_hex"]),
                "added": row["added"],
            })
        return {
            "version": 1,
            "authorities": {
                aid: {
                    "pk": info["pk"],
                    "added": info["added"],
                    "expires": info["expires"],
                }
                for aid, info in auths.items()
            },
            "chain": chain,
        }

    @property
    def version(self) -> int:
        """Number of authority entries (monotonic-ish)."""
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) AS cnt FROM authorities").fetchone()
        return row["cnt"] if row else 0

    # ── cleanup ─────────────────────────────────────────────────────────

    def close(self):
        """Close thread-local connections."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
