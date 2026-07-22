"""
ATP v1.7 — TLS Certificate helpers.
Extracted from agent.py for separation of concerns.
CA + signed certs for mutual TLS.
"""
from __future__ import annotations

import os
import datetime
import logging
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


# ── CA persistence path ─────────────────────────────────────────
_CA_DIR = os.path.join(os.path.expanduser("~"), ".atp")
_CA_CERT_PATH = os.path.join(_CA_DIR, "ca_cert.pem")
_CA_KEY_PATH = os.path.join(_CA_DIR, "ca_key.pem")

# ── cache per process ────────────────────────────────────────────────
_ca_cert_pem: Optional[bytes] = None
_ca_key_pem: Optional[bytes] = None
_cert_pem: Optional[bytes] = None
_key_pem: Optional[bytes] = None
_cert_cn: str = ""


def _generate_ca_cert() -> tuple[bytes, bytes]:
    """Generate a self-signed CA cert + key (Ed25519)."""
    ca_key = ed25519.Ed25519PrivateKey.generate()
    ca_pub = ca_key.public_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ATP Test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365 * 10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, None, default_backend())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _sign_cert(ca_cert_pem: bytes, ca_key_pem: bytes, cn: str) -> tuple[bytes, bytes]:
    """Sign a new Ed25519 cert with the CA. Returns (cert_pem, key_pem)."""
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None, backend=default_backend())
    node_key = ed25519.Ed25519PrivateKey.generate()
    node_pub = node_key.public_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(node_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365 * 10))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, None, default_backend())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = node_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _ensure_ca() -> tuple[bytes, bytes]:
    """Get or create the shared CA cert+key. Persists to ~/.atp/."""
    global _ca_cert_pem, _ca_key_pem
    if _ca_cert_pem is not None:
        return _ca_cert_pem, _ca_key_pem
    loaded = False
    if os.path.isfile(_CA_CERT_PATH) and os.path.isfile(_CA_KEY_PATH):
        try:
            with open(_CA_CERT_PATH, "rb") as f:
                _ca_cert_pem = f.read()
            with open(_CA_KEY_PATH, "rb") as f:
                _ca_key_pem = f.read()
            loaded = True
            logger.info("CA loaded from %s", _CA_DIR)
        except Exception as exc:
            logger.warning("CA load failed: %s — regenerating", exc)
    if not loaded:
        _ca_cert_pem, _ca_key_pem = _generate_ca_cert()
        try:
            os.makedirs(_CA_DIR, exist_ok=True)
            with open(_CA_CERT_PATH, "wb") as f:
                f.write(_ca_cert_pem)
            with open(_CA_KEY_PATH, "wb") as f:
                f.write(_ca_key_pem)
            logger.info("CA generated and persisted to %s", _CA_DIR)
        except Exception as exc:
            logger.warning("CA persist failed: %s (in-memory only)", exc)
    return _ca_cert_pem, _ca_key_pem


def get_self_signed_cert(cn: str = "atp-agent") -> tuple[bytes, bytes]:
    """Get a CA-signed cert for *cn*. Cached per distinct CN."""
    global _cert_pem, _key_pem, _cert_cn
    if _cert_pem is None or _cert_cn != cn:
        ca_cert, ca_key = _ensure_ca()
        _cert_pem, _key_pem = _sign_cert(ca_cert, ca_key, cn)
        _cert_cn = cn
    return _cert_pem, _key_pem


def get_cert_expiry_days(cert_pem: bytes) -> int:
    """Return days until certificate expiry. Negative if expired."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    delta = cert.not_valid_after_utc - datetime.datetime.now(datetime.UTC)
    return delta.days


def rotate_cert(cn: str = "atp-agent") -> tuple[bytes, bytes, bool]:
    """Regenerate cert if within rotation window. Returns (cert, key, rotated)."""
    global _cert_pem, _key_pem, _cert_cn
    from config import CERT_ROTATION_WINDOW_DAYS
    if _cert_pem and get_cert_expiry_days(_cert_pem) > CERT_ROTATION_WINDOW_DAYS:
        return _cert_pem, _key_pem, False
    ca_cert, ca_key = _ensure_ca()
    _cert_pem, _key_pem = _sign_cert(ca_cert, ca_key, cn)
    _cert_cn = cn
    logger.info("mTLS cert rotated for CN=%s (window=%dd)", cn, CERT_ROTATION_WINDOW_DAYS)
    return _cert_pem, _key_pem, True


def get_ca_cert_pem() -> bytes:
    """Return the CA cert PEM (for client trust store)."""
    ca_cert, _ = _ensure_ca()
    return ca_cert


def get_quic_cert(cn: str = "atp-quic") -> tuple[bytes, bytes, bytes]:
    """Get ECDSA P-256 cert+key for QUIC/TLS 1.3 compatibility.

    QUIC (via aioquic) has limited Ed25519 support in TLS handshake.
    ECDSA P-256 is universally supported by all TLS 1.3 stacks.

    Returns (cert_pem, key_pem, ca_cert_pem).
    """
    # Generate ECDSA P-256 CA
    ca_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ca_pub = ca_key.public_key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ATP QUIC CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365 * 10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("atp-ca")]), critical=False)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    # Generate ECDSA P-256 node keypair, signed by the ECDSA CA
    node_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    node_pub = node_key.public_key()
    node_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    san = x509.DNSName(cn) if not cn.startswith("atp-") else x509.DNSName("atp-node")
    node_cert = (
        x509.CertificateBuilder()
        .subject_name(node_name)
        .issuer_name(ca_cert.subject)
        .public_key(node_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365 * 10))
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
    return cert_pem, key_pem, ca_cert_pem


def make_ssl_context(
    server_side: bool = False,
    cn: str = "atp-agent",
):
    """Build an SSLContext for server or client with mutual TLS.

    Both sides share the same CA. Server uses CERT_REQUIRED,
    client uses CERT_REQUIRED + presents its own cert.

    SECURITY NOTE: hostname verification (check_hostname) is DISABLED
    by default because self-signed certs use only CN, not SAN.
    Set env ATP_ENFORCE_HOSTNAME=true (with proper SAN certs) to enable.
    """
    import ssl, tempfile, atexit, shutil

    # One temp dir per process for all cert PEM files
    if not hasattr(make_ssl_context, "_cert_dir"):
        make_ssl_context._cert_dir = tempfile.mkdtemp(prefix="atp-certs-")
        atexit.register(shutil.rmtree, make_ssl_context._cert_dir, ignore_errors=True)

    cert_pem, key_pem = get_self_signed_cert(cn=cn)
    ca_cert_pem = get_ca_cert_pem()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)
    enforce_hs = os.environ.get("ATP_ENFORCE_HOSTNAME", "").lower() in ("1", "true", "yes")
    ctx.check_hostname = enforce_hs
    ctx.verify_mode = ssl.CERT_REQUIRED

    cert_path = os.path.join(make_ssl_context._cert_dir, f"cert-{cn}.pem")
    key_path = os.path.join(make_ssl_context._cert_dir, f"key-{cn}.pem")
    ca_path = os.path.join(make_ssl_context._cert_dir, "ca.pem")
    with open(cert_path, "wb") as cf:
        cf.write(cert_pem)
    with open(key_path, "wb") as kf:
        kf.write(key_pem)
    with open(ca_path, "wb") as caf:
        caf.write(ca_cert_pem)
    ctx.load_cert_chain(cert_path, key_path)
    ctx.load_verify_locations(ca_path)
    return ctx
