"""
ATP v1.8 — E2E cryptographic helpers.
Extracted from ATPAgent class in agent.py.
Pure functions: no ATPAgent state dependency.
"""
from __future__ import annotations

import os
import logging
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from atp_core import blake3_hash, ed25519_sign, ed25519_verify

logger = logging.getLogger(__name__)


def derive_session_key(
    our_x25519_sk: bytes,
    peer_x25519_pk: bytes,
    our_x25519_pk: bytes,
) -> Optional[bytes]:
    """Derive AES-256-GCM session key from X25519 ECDH shared secret.

    Uses BLAKE3 KDF with domain separation (b"atp-v1.8-ecdh").
    Both sides sort public keys deterministically so the derived key is identical.

    Returns 32-byte AES key, or None if peer key is invalid.
    """
    if len(peer_x25519_pk) != 32 or len(our_x25519_sk) != 32:
        return None
    try:
        our_sk = x25519.X25519PrivateKey.from_private_bytes(our_x25519_sk)
        peer_pk = x25519.X25519PublicKey.from_public_bytes(peer_x25519_pk)
        shared_secret = our_sk.exchange(peer_pk)
        pk1, pk2 = sorted([peer_x25519_pk, our_x25519_pk])
        kdf_input = b"atp-v1.8-ecdh" + shared_secret + pk1 + pk2
        return blake3_hash(kdf_input)
    except Exception:
        logger.exception("ECDH key derivation failed")
        return None


def derive_ecdhe_session_key(
    eph_sk: bytes,
    peer_eph_pk: bytes,
    eph_pk: bytes,
) -> Optional[bytes]:
    """Derive AES-256-GCM session key from ECDHE ephemeral shared secret.

    Uses X25519 ephemeral ECDH + BLAKE3 KDF with domain separation
    (b"atp-v1.8-ecdhe") for forward secrecy.

    The ephemeral keys are exchanged during handshake Phase 3 and
    discarded after the session ends. Compromise of static keys does
    NOT compromise past session keys.

    Returns 32-byte AES key, or None if peer key is invalid.
    """
    if len(peer_eph_pk) != 32 or len(eph_sk) != 32:
        return None
    try:
        our_sk = x25519.X25519PrivateKey.from_private_bytes(eph_sk)
        peer_pk = x25519.X25519PublicKey.from_public_bytes(peer_eph_pk)
        shared_secret = our_sk.exchange(peer_pk)
        pk1, pk2 = sorted([peer_eph_pk, eph_pk])
        kdf_input = b"atp-v1.8-ecdhe" + shared_secret + pk1 + pk2
        return blake3_hash(kdf_input)
    except Exception:
        logger.exception("ECDHE key derivation failed")
        return None


def e2e_encrypt(plaintext: bytes, session_key: bytes) -> bytes:
    """Encrypt *plaintext* with AES-256-GCM using *session_key*.

    Returns: 12-byte nonce || ciphertext || 16-byte tag
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def e2e_decrypt(encrypted: bytes, session_key: bytes) -> Optional[bytes]:
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


def e2e_encrypt_signed(
    plaintext: bytes, session_key: bytes, ed25519_sk: bytes
) -> bytes:
    """Encrypt-then-sign: AES-GCM + Ed25519 signature.

    Returns: nonce(12) || ciphertext+tag(28) || signature(64)
    Total: 104 bytes overhead.
    """
    encrypted = e2e_encrypt(plaintext, session_key)
    sig = ed25519_sign(ed25519_sk, encrypted)
    return encrypted + sig


def e2e_decrypt_verify(
    encrypted_signed: bytes, session_key: bytes, ed25519_pk: bytes
) -> Optional[bytes]:
    """Verify-then-decrypt: check Ed25519 sig, then AES-GCM decrypt."""
    if len(encrypted_signed) < 12 + 16 + 64:
        return None
    encrypted = encrypted_signed[:-64]
    sig = encrypted_signed[-64:]
    if not ed25519_verify(ed25519_pk, sig, encrypted):
        logger.warning("E2E auth failed: Ed25519 signature mismatch")
        return None
    return e2e_decrypt(encrypted, session_key)
