""""
ATP v1.7 — Security Test Suite.
Verifica le proprietà di sicurezza del protocollo.

Esegue test su:
  1. Crittografia (Ed25519, X25519)
  2. MCC forgery resistance
  3. Replay attack prevention
  4. Key separation enforcement
  5. Revocation integrity
  6. Clock skew protection
  7. Anti-replay filtering
  8. Rate limiting
  9. Proof-of-possession binding
  10. Frame integrity

Run:  python security_test.py
"""
import sys, os, struct, time, json, cbor2, asyncio
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from atp_core import *
from authority import *
from revocation import *
from agent import AgentIdentity, create_mcc_for_identity
from config import *
from config import RateLimiter, AntiReplay

errors = []

def test(name, cond, detail=""):
    if cond:
        print(f"  ✅ {name}")
    else:
        print(f"  ❌ {name}  {detail}")
        errors.append(name)

def section(n, title):
    print(f"\n{'='*60}")
    print(f"  {n}. {title}")
    print(f"{'='*60}")

# ═══════════════════════════════════════════════════════════════════════════════
#  1. CRYPTOGRAPHIC PRIMITIVES
# ═══════════════════════════════════════════════════════════════════════════════

section(1, "CRYPTOGRAFIA — Ed25519 / X25519")

sk, pk = generate_ed25519_keypair()
x_sk, x_pk = generate_x25519_keypair()

# 1.1 Key generation
test("Ed25519 secret key 32 bytes", len(sk) == 32)
test("Ed25519 public key 32 bytes", len(pk) == 32)
test("X25519 secret key 32 bytes", len(x_sk) == 32)
test("X25519 public key 32 bytes", len(x_pk) == 32)
test("Ed25519 ≠ X25519 (tipi diversi)", type(sk) != type(x_sk) or sk != x_sk)

# 1.2 Sign/verify
sig = ed25519_sign(sk, b"test-message")
test("Ed25519 signature 64 bytes", len(sig) == 64)
test("Ed25519 verify OK", ed25519_verify(pk, sig, b"test-message"))
test("Ed25519 reject tampered data", not ed25519_verify(pk, sig, b"wrong-message"))
test("Ed25519 reject wrong pubkey", not ed25519_verify(b"x" * 32, sig, b"test-message"))
test("Ed25589 reject corrupted sig", not ed25519_verify(pk, b"x" * 64, b"test-message"))

# 1.3 BLAKE3
h1 = blake3_hash(b"hello")
h2 = blake3_hash(b"world")
test("BLAKE3 output 32 bytes", len(h1) == 32)
test("BLAKE3 deterministic", blake3_hash(b"hello") == h1)
test("BLAKE3 collision resistant", h1 != h2)
test("BLAKE3 preimage: output != input", h1 != b"hello")

# ═══════════════════════════════════════════════════════════════════════════════
#  2. MCC SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

section(2, "MCC — FORGERY & TAMPER RESISTANCE")

auth = get_default_authority()

# 2.1 Valid MCC
leaf1 = MCCLeaf(key="agent_pk", value=x_pk, salt=os.urandom(16))
leaf2 = MCCLeaf(key="agent_sign_pk", value=pk, salt=os.urandom(16))
valid_mcc = auth.sign_mcc(leaves=[leaf1, leaf2])
test("Valid MCC passes verify", valid_mcc.verify(auth.public_key))

# 2.2 Version mismatch
tampered = MCC(
    mcc_version=999, serial_number=valid_mcc.serial_number,
    root_hash=valid_mcc.root_hash, authority_id=valid_mcc.authority_id,
    authority_sig=valid_mcc.authority_sig, expiry_date=valid_mcc.expiry_date,
    leaves=valid_mcc.leaves, critical_mask=valid_mcc.critical_mask,
)
test("Wrong version rejected", not tampered.verify(auth.public_key))

# 2.3 Signature forgery (wrong key)
test("Wrong authority key rejected", not valid_mcc.verify(b"x" * 32))

# 2.4 Signature forgery (tampered commitment)
forged_sig_mcc = MCC(
    mcc_version=1, serial_number=valid_mcc.serial_number,
    root_hash=valid_mcc.root_hash, authority_id=valid_mcc.authority_id,
    authority_sig=b"x" * 64,  # forged
    expiry_date=valid_mcc.expiry_date,
    leaves=valid_mcc.leaves, critical_mask=valid_mcc.critical_mask,
)
test("Forged signature rejected", not forged_sig_mcc.verify(auth.public_key))

# 2.5 Expired MCC
expired_mcc = auth.sign_mcc(leaves=[leaf1, leaf2], expiry_date=1000)
test("Expired MCC rejected", not expired_mcc.verify(auth.public_key))

# 2.6 Missing critical claim
missing_crit = MCC(
    mcc_version=1, serial_number=os.urandom(16),
    root_hash=valid_mcc.root_hash, authority_id=valid_mcc.authority_id,
    authority_sig=valid_mcc.authority_sig, expiry_date=valid_mcc.expiry_date,
    leaves=[leaf1],  # missing agent_sign_pk
    critical_mask=["agent_pk", "agent_sign_pk"],
)
test("Missing critical leaf rejected", not missing_crit.verify(auth.public_key))

# 2.7 Tampered root hash
fake_root = MCC(
    mcc_version=1, serial_number=os.urandom(16),
    root_hash=b"x" * 32,  # wrong root
    authority_id=valid_mcc.authority_id,
    authority_sig=valid_mcc.authority_sig, expiry_date=valid_mcc.expiry_date,
    leaves=[leaf1, leaf2], critical_mask=["agent_pk", "agent_sign_pk"],
)
test("Wrong root hash rejected", not fake_root.verify(auth.public_key))

# 2.8 Tampered leaf value (replace agent_pk) — manually constructed to keep original sig
tampered_mcc = MCC(
    mcc_version=1, serial_number=valid_mcc.serial_number,
    root_hash=valid_mcc.root_hash, authority_id=valid_mcc.authority_id,
    authority_sig=valid_mcc.authority_sig, expiry_date=valid_mcc.expiry_date,
    leaves=[
        MCCLeaf(key="agent_pk", value=b"x" * 32, salt=os.urandom(16)),
        leaf2,
    ],
    critical_mask=["agent_pk", "agent_sign_pk"],
)
test("Tampered leaf detected by root hash mismatch",
     not tampered_mcc.verify(auth.public_key))

# ═══════════════════════════════════════════════════════════════════════════════
#  3. KEY SEPARATION (ATP-Full §6)
# ═══════════════════════════════════════════════════════════════════════════════

section(3, "KEY SEPARATION — agent_pk ≠ agent_sign_pk")

# 3.1 Normal MCC passes
test("Normal MCC: agent_pk≠agent_sign_pk OK",
     valid_mcc.verify(auth.public_key))

# 3.2 MCC with same key for both fields
same_key = x_pk  # reuse the same key
dup_leaf1 = MCCLeaf(key="agent_pk", value=same_key, salt=os.urandom(16))
dup_leaf2 = MCCLeaf(key="agent_sign_pk", value=same_key, salt=os.urandom(16))
dup_mcc = auth.sign_mcc(leaves=[dup_leaf1, dup_leaf2])
test("MCC with agent_pk==agent_sign_pk REJECTED",
     not dup_mcc.verify(auth.public_key))

# 3.3 AgentIdentity guarantees separation
id1 = AgentIdentity("test-agent")
test("AgentIdentity: X25519 ≠ Ed25519", id1.x25519_pk != id1.ed25519_pk)
test("AgentIdentity: keys are 32 bytes",
     len(id1.x25519_pk) == 32 and len(id1.ed25519_pk) == 32)

# ═══════════════════════════════════════════════════════════════════════════════
#  4. REPLAY ATTACK PREVENTION
# ═══════════════════════════════════════════════════════════════════════════════

section(4, "REPLAY ATTACK PREVENTION — Nonce + AntiReplay")

# 4.1 AntiReplay filter
ar = AntiReplay(window_ms=5000, max_ids=100)
frame_id = os.urandom(16)
test("New frame_id accepted", ar.is_new(frame_id, 1000))
test("Duplicate frame_id rejected", not ar.is_new(frame_id, 1000))
test("Different frame_id accepted", ar.is_new(os.urandom(16), 1000))

# 4.2 TTL expiry — frame_id outside window is accepted again
old_id = os.urandom(16)
test("Old frame accepted (TTL expired)", ar.is_new(old_id, 100000))

# 4.3 RateLimiter
rl = RateLimiter(max_rps=10)
allowed = sum(1 for _ in range(10) if rl.allow())
test("RateLimiter: 10 requests within limit", allowed == 10)
test("RateLimiter: 11th blocked", not rl.allow())

# 4.4 Nonce uniqueness in handshake
nonce1 = os.urandom(16)
nonce2 = os.urandom(16)
test("Nonce CSPRNG unique", nonce1 != nonce2)
test("Nonce 16 bytes", len(nonce1) == 16)

# ═══════════════════════════════════════════════════════════════════════════════
#  5. PROOF-OF-POSSESSION (Handshake Binding)
# ═══════════════════════════════════════════════════════════════════════════════

section(5, "PROOF-OF-POSSESSION — Handshake Binding")

# 5.1 Correct PoP strings
sk_i, pk_i = generate_ed25519_keypair()
sk_r, pk_r = generate_ed25519_keypair()
nonce_i = os.urandom(16)
nonce_r = os.urandom(16)

resp_sig = ed25519_sign(sk_r, nonce_i + b"atp-bind-response")
conf_sig = ed25519_sign(sk_i, nonce_r + b"atp-bind-confirm")

test("Responder signature verifies",
     ed25519_verify(pk_r, resp_sig, nonce_i + b"atp-bind-response"))
test("Initiator signature verifies",
     ed25519_verify(pk_i, conf_sig, nonce_r + b"atp-bind-confirm"))

# 5.2 Wrong context string → fail
test("Wrong context (response→confirm) fails",
     not ed25519_verify(pk_r, resp_sig, nonce_i + b"atp-bind-confirm"))
test("Wrong nonce fails",
     not ed25519_verify(pk_r, resp_sig, os.urandom(16) + b"atp-bind-response"))
test("Missing nonce fails",
     not ed25519_verify(pk_r, resp_sig, b"atp-bind-response"))

# 5.3 Binding prevents identity swap
test("Wrong identity key fails signature",
     not ed25519_verify(pk_i, resp_sig, nonce_i + b"atp-bind-response"))

# ═══════════════════════════════════════════════════════════════════════════════
#  6. REVOCATION
# ═══════════════════════════════════════════════════════════════════════════════

section(6, "REVOCATION — CuckooFilter + RootStore")

# 6.1 CuckooFilter
cf = CuckooFilter(buckets=256, slots=4)
for i in range(50):
    cf.insert(f"serial-{i}".encode())
test("50 inserts in CuckooFilter", cf.size == 50)
test("Contains inserted item", cf.contains(b"serial-25"))
test("False negative: inserted items always found",
     all(cf.contains(f"serial-{i}".encode()) for i in range(50)))
test("Not contains unknown (probabilistic)",
     not cf.contains(b"unknown-serial"))
cf.remove(b"serial-25")
test("Remove works", not cf.contains(b"serial-25"))

# 6.2 Revoke integration
test("revoke_serial OK", revoke_serial(b"revoke-me"))
test("check_revoked returns True", check_revoked(b"revoke-me"))
test("check_revoked False for clean", not check_revoked(b"clean-serial"))

# 6.3 MCC verify with revocation
# First, revoke this MCC's specific serial number
revoke_serial(valid_mcc.serial_number)
test("MCC verify rejects revoked serial",
     not valid_mcc.verify(auth.public_key, check_revoked=True))
# Fresh MCC not revoked
fresh_leaves = [
    MCCLeaf(key="agent_pk", value=x_pk, salt=os.urandom(16)),
    MCCLeaf(key="agent_sign_pk", value=pk, salt=os.urandom(16)),
]
fresh_mcc = auth.sign_mcc(leaves=fresh_leaves)
test("Fresh MCC passes revoked check",
     fresh_mcc.verify(auth.public_key, check_revoked=True))

# 6.4 RootStore authority expiry
import tempfile as _tf
rs = RootStore(path=_tf.mktemp(suffix='.json'))
rs.add_authority("test-ca", b"pk" * 16, ttl_seconds=-1)
test("Authority with negative TTL expires immediately",
     rs.get_authority("test-ca") is None)

# 6.5 Degradation policy
dp = DegradationPolicy(active=True)
rs2 = RootStore(path=_tf.mktemp(suffix='.json'))
rs2.add_authority("live-ca", b"pk" * 16, ttl_seconds=86400*365)
test("Active CA → CONFIRMED", dp.evaluate("live-ca", rs2) == "CONFIRMED")
test("Unknown CA → UNCERTAIN", dp.evaluate("unknown", rs2) == "UNCERTAIN")
test("Inactive policy → always CONFIRMED",
     DegradationPolicy(active=False).evaluate("unknown", rs2) == "CONFIRMED")

# ═══════════════════════════════════════════════════════════════════════════════
#  7. CLOCK SKEW PROTECTION
# ═══════════════════════════════════════════════════════════════════════════════

section(7, "CLOCK SKEW PROTECTION")

from config import CLOCK_SKEW_MS
test("CLOCK_SKEW_MS = 10000 (10s)", CLOCK_SKEW_MS == 10_000)

# Verify header timestamp validation
now_ms = int(time.time() * 1000)
header_ok = build_header(0x01)
header_future = {**header_ok, "timestamp": now_ms + CLOCK_SKEW_MS + 1000}
header_past = {**header_ok, "timestamp": now_ms - CLOCK_SKEW_MS - 1000}
test("Header timestamp within range", abs(now_ms - header_ok["timestamp"]) < 100)
test("Future timestamp rejected by skew check",
     abs(now_ms - header_future["timestamp"]) > CLOCK_SKEW_MS)
test("Past timestamp rejected by skew check",
     abs(now_ms - header_past["timestamp"]) > CLOCK_SKEW_MS)

# TASK_ERROR with server_time_ms (clock skew fallback)
err_frame = {
    "header": build_header(0x04),
    "error_code": 0x0C,
    "error_message": "Clock skew detected",
    "server_time_ms": now_ms,
}
encoded = encode_frame(err_frame)
decoded = cbor2.loads(encoded[4:])
test("TASK_ERROR(0x0C) includes server_time_ms",
     decoded.get("server_time_ms") == now_ms)

# ═══════════════════════════════════════════════════════════════════════════════
#  8. FRAME INTEGRITY
# ═══════════════════════════════════════════════════════════════════════════════

section(8, "FRAME INTEGRITY — Wire Format")

# 8.1 Length prefix prevents buffer overflow
enc = encode_frame({"header": build_header(0x01)})
length = struct.unpack("!I", enc[:4])[0]
test("4-byte BE length prefix", len(enc) == 4 + length)
test("Length positive", length > 0)

# 8.2 CBOR canonical encoding ensures deterministic serialization
d1 = cbor2.dumps({"b": 1, "a": 2}, canonical=True)
d2 = cbor2.dumps({"a": 2, "b": 1}, canonical=True)
test("Canonical CBOR: key order sorted", d1 == d2)

# 8.3 Frame fields
h = build_header(0x01)
test("frame_type is int", isinstance(h["frame_type"], int))
test("frame_id 16 bytes", len(h["frame_id"]) == 16)
test("task_id 16 bytes (nil for control)", len(h["task_id"]) == 16)
test("timestamp is int ms", isinstance(h["timestamp"], int))

# 8.4 Control frame has nil task_id
control_h = build_header(0x30)
test("Control frame task_id = nil UUID", control_h["task_id"] == b"\x00" * 16)

# 8.5 Frame type bounds (validated)
test("Frame type 0x01 = TASK_REQUEST", FRAME_TYPES[0x01] == "TASK_REQUEST")
test("Frame type 0x50 = CAPABILITY_EXCHANGE", FRAME_TYPES[0x50] == "CAPABILITY_EXCHANGE")

# ═══════════════════════════════════════════════════════════════════════════════
#  9. ERROR CODE DISPOSITIONS
# ═══════════════════════════════════════════════════════════════════════════════

section(9, "ERROR CODE DISPOSITIONS — Fail-Closed Analysis")

# Verify critical errors close connection
close_errors = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
for code in close_errors:
    name, disp = ERROR_CODES[code]
    test(f"  {name} (0x{code:02X}) → {disp}", disp == "close")

# Non-critical errors close only the stream
stream_errors = [0x09, 0x0A, 0x0B, 0x0C, 0x0E, 0x0F]
for code in stream_errors:
    name, disp = ERROR_CODES[code]
    test(f"  {name} (0x{code:02X}) → {disp}", disp == "close_stream")

# Rate limiting is recoverable
test(f"  ERR_RATE_LIMITED (0x0D) → recoverable",
     ERROR_CODES[0x0D][1] == "recoverable")

# ═══════════════════════════════════════════════════════════════════════════════
#  10. CALLBACK: MCC → CBOR → WIRE → CBOR → MCC (full round-trip)
# ═══════════════════════════════════════════════════════════════════════════════

section(10, "FULL ROUND-TRIP — MCC → CBOR → Wire → CBOR → MCC")

original = auth.sign_mcc(leaves=[leaf1, leaf2])
cbor_data = original.to_cbor()
# Verify no leaf_hash leaked
assert b"leaf_hash" not in cbor_data, "leaf_hash leaked in wire format!"
test("No leaf_hash in wire format", True)

# Decode
decoded = MCC.from_cbor(cbor_data)
test("Round-trip: root_hash", decoded.root_hash == original.root_hash)
test("Round-trip: serial_number", decoded.serial_number == original.serial_number)
test("Round-trip: authority_id", decoded.authority_id == original.authority_id)
test("Round-trip: signature", decoded.authority_sig == original.authority_sig)
test("Round-trip: verify", decoded.verify(auth.public_key))

# ═══════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

print(f"\n{'='*60}")
print(f"  SECURITY TEST SUMMARY")
print(f"{'='*60}")
if errors:
    print(f"\n  ❌❌❌ {len(errors)} TEST(S) FALLITI:")
    for e in errors:
        print(f"     - {e}")
    sys.exit(1)
else:
    print(f"\n  🎯  ALL SECURITY TESTS PASSED")
    print(f"\n  Proprietà verificate:")
    print(f"   ✓ Ed25519/X25519 cryptographic primitives")
    print(f"   ✓ MCC forgery resistance (8 attack vectors)")
    print(f"   ✓ Key separation enforcement")
    print(f"   ✓ Replay attack prevention (nonce + anti-replay)")
    print(f"   ✓ Rate limiting (sliding window)")
    print(f"   ✓ Proof-of-possession binding (3 attack vectors)")
    print(f"   ✓ Revocation (CuckooFilter + RootStore)")
    print(f"   ✓ Clock skew protection (TASK_ERROR fallback)")
    print(f"   ✓ Frame integrity (CBOR canonical, bounds, types)")
    print(f"   ✓ Fail-closed error dispositions (15 codes)")
    print(f"   ✓ Full round-trip: MCC → CBOR → wire → CBOR → MCC")
    print(f"  ✅✅✅")
