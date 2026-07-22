"""
ATP v1.8 — Local Certificate Authority.
Generates a persistent Ed25519 authority key and signs MCCs.
"""

from __future__ import annotations

import os
import time
import logging
import threading
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from atp_core import (
    generate_ed25519_keypair,
    ed25519_sign,
    MCCLeaf,
    MCC,
    blake3_hash,
)

logger = logging.getLogger(__name__)


class Authority:
    """Local CA that signs Merkle-Claim Cards for this installation."""

    def __init__(self, authority_id: Optional[str] = None):
        key_name = authority_id or "default"
        self._sign_sk, self._sign_pk = self._load_or_create_keypair(key_name)
        self.authority_id = authority_id or self._derive_authority_id(self._sign_pk)
        # Register in root store
        from revocation import get_root_store
        rs = get_root_store()
        rs.add_authority(self.authority_id, self._sign_pk)
        logger.info(
            "Authority %s initialized — pubkey %s",
            self.authority_id,
            self._sign_pk.hex()[:16],
        )

    @property
    def public_key(self) -> bytes:
        return self._sign_pk

    @staticmethod
    def _derive_authority_id(public_key: bytes) -> str:
        return f"atp-local-{blake3_hash(public_key)[:8].hex()}"

    @staticmethod
    def _load_or_create_keypair(key_name: str) -> tuple[bytes, bytes]:
        """Persist the local authority key so process restarts keep identity."""
        key_dir = os.getenv("ATP_AUTHORITY_DIR") or os.path.join(
            os.path.expanduser("~"), ".atp", "authorities"
        )
        key_path = os.path.join(key_dir, f"{key_name}.ed25519.key")
        try:
            if os.path.isfile(key_path):
                with open(key_path, "rb") as f:
                    sk = f.read()
                if len(sk) == 32:
                    private = ed25519.Ed25519PrivateKey.from_private_bytes(sk)
                    pk = private.public_key().public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                    return sk, pk
                logger.warning("Authority key at %s has invalid length; regenerating", key_path)
        except Exception as exc:
            logger.warning("Authority key load failed: %s", exc)

        sk, pk = generate_ed25519_keypair()
        try:
            os.makedirs(key_dir, exist_ok=True)
            with open(key_path, "wb") as f:
                f.write(sk)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
        except Exception as exc:
            logger.warning("Authority key persist failed: %s (in-memory only)", exc)
        return sk, pk

    def sign_mcc(
        self,
        leaves: list[MCCLeaf],
        critical_mask: Optional[list[str]] = None,
        serial_number: Optional[bytes] = None,
        expiry_date: Optional[int] = None,
    ) -> MCC:
        """Create and sign an MCC."""
        if serial_number is None:
            serial_number = os.urandom(16)
        if expiry_date is None:
            expiry_date = int(time.time()) + 86400 * 365  # 1 year
        if critical_mask is None:
            critical_mask = [
                "agent_pk",
                "agent_sign_pk",
                "expiry_date",
                "authority_id",
                "mcc_version",
                "serial_number",
            ]

        metadata_defaults = {
            "expiry_date": str(expiry_date).encode(),
            "authority_id": self.authority_id.encode(),
            "mcc_version": b"1",
            "serial_number": serial_number,
        }
        key_defaults = {
            "agent_pk": generate_ed25519_keypair()[1],
            "agent_sign_pk": generate_ed25519_keypair()[1],
        }

        leaves = [leaf for leaf in leaves if leaf.key not in metadata_defaults]
        existing_keys = {leaf.key for leaf in leaves}
        added_metadata = set()
        for key in critical_mask:
            if key in metadata_defaults and key not in added_metadata:
                leaves.append(MCCLeaf(
                    key=key,
                    value=metadata_defaults[key],
                    salt=os.urandom(16),
                ))
                added_metadata.add(key)
            elif key in key_defaults and key not in existing_keys:
                leaves.append(MCCLeaf(
                    key=key,
                    value=key_defaults[key],
                    salt=os.urandom(16),
                ))
                existing_keys.add(key)

        mcc = MCC.create(
            leaves=leaves,
            critical_mask=critical_mask,
            serial_number=serial_number,
            authority_id=self.authority_id,
            expiry_date=expiry_date,
            authority_sign_fn=lambda data: ed25519_sign(self._sign_sk, data),
        )
        logger.info("Signed MCC — serial %s", serial_number.hex()[:8])
        return mcc


# ── singleton (thread-safe) ────────────────────────────────────────────────────

_default_authority: Optional[Authority] = None
_authority_lock = threading.Lock()


def get_default_authority() -> Authority:
    global _default_authority
    if _default_authority is None:
        with _authority_lock:
            if _default_authority is None:
                _default_authority = Authority()
    return _default_authority
