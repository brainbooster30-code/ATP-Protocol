"""
ATP v1.6.1 — Mock Certificate Authority.
Generates a persistent Ed25519 authority key and signs MCCs.
"""

from __future__ import annotations

import os
import time
import logging
import threading
from typing import Optional

from atp_core import (
    generate_ed25519_keypair,
    ed25519_sign,
    MCCLeaf,
    MCC,
    blake3_hash,
)

logger = logging.getLogger(__name__)


class Authority:
    """A mock CA that signs Merkle-Claim Cards for demo/testing."""

    def __init__(self, authority_id: str = "atp-mock-ca"):
        self.authority_id = authority_id
        self._sign_sk, self._sign_pk = generate_ed25519_keypair()
        # Register in root store
        from revocation import get_root_store
        rs = get_root_store()
        rs.add_authority(authority_id, self._sign_pk)
        logger.info(
            "Authority %s initialized — pubkey %s",
            self.authority_id,
            self._sign_pk.hex()[:16],
        )

    @property
    def public_key(self) -> bytes:
        return self._sign_pk

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

        # Auto-populate missing critical leaves from defaults
        existing_keys = {l.key for l in leaves}
        defaults = {
            "agent_pk": generate_ed25519_keypair()[1],
            "agent_sign_pk": generate_ed25519_keypair()[1],
            "expiry_date": str(expiry_date).encode(),
            "authority_id": self.authority_id.encode(),
            "mcc_version": b"1",
            "serial_number": serial_number,
        }
        for key in critical_mask:
            if key not in existing_keys and key in defaults:
                leaves.append(MCCLeaf(key=key, value=defaults[key], salt=os.urandom(16)))

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
