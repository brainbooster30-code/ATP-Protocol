# ATP v1.8 — Cross-Language SDK Specification

**Agent Transport Protocol — Wire Format Reference for Independent Implementations**

*Version: 1.8*
*Status: Stable*
*Languages: Any (CBOR-based wire format)*

---

## 1. Overview

This document specifies the exact byte-level wire format of ATP so that anyone can implement a compliant client or server in any language (Go, Rust, Node.js, C#, Java, etc.) without reading the Python source.

**Minimal dependencies required for an implementation:**
- CBOR (RFC 8949) encoder/decoder with **canonical encoding** (sorted maps)
- BLAKE3-256 hash function
- Ed25519 signing and verification
- X25519 ECDH key exchange
- AES-256-GCM encryption/decryption
- TLS 1.3 with mutual authentication

---

## 2. Wire Format

### 2.1 Frame Encoding

Every ATP frame on the wire is:

```
┌──────────────────────────────┐
│ 4 bytes: uint32_BE(length)  │  ← CBOR payload length (big-endian)
├──────────────────────────────┤
│ N bytes: CBOR canonical map  │  ← the actual frame
└──────────────────────────────┘
```

**Example (hex):**
```
00 00 00 7B          ← length = 123 bytes
A5 66 68 65 61 64... ← CBOR-encoded frame starts here
```

### 2.2 Frame Header (in every frame)

```
header = {
    "frame_type":  uint,       # see §3
    "frame_id":    bstr .size 16,  # UUID v4 (random bytes)
    "task_id":     bstr .size 16,  # nil UUID for control frames
    "timestamp":   uint,       # Unix epoch milliseconds
    "atp_version": tstr,       # "1.7"
}
```

CDDL:
```
header = {
    "frame_type": uint,
    "frame_id": bytes .size 16,
    "task_id": bytes .size 16,
    "timestamp": uint,
    "atp_version": tstr,
}
```

### 2.3 Wire Examples (byte-level)

#### TASK_REQUEST (0x01)

When serialized with canonical CBOR, the map keys are alphabetically sorted:

```
{
    "header": {
        "atp_version": "1.7",
        "frame_id": h'01234567012345670123456701234567',
        "frame_type": 1,
        "task_id": h'00000000000000000000000000000000',
        "timestamp": 1700000000000,
    },
    "deadline_ms": 30000,
    "metadata": {"p": 4},
    "priority_hint": 4,
    "task_payload": h'68656c6c6f',      # "hello" in UTF-8
    "task_type": "echo",
}
```

CBOR diagnostic (canonical, sorted keys):
```
A6                                      # map(6)
   6A 64 65 61 64 6C 69 6E 65 5F 6D 73 # key "deadline_ms"
      19 75 30                          # 30000
   68 68 65 61 64 65 72                 # key "header"
      A5                               # map(5)
         6B 61 74 70 5F 76 65 72 73 69 6F 6E # "atp_version"
            63 31 2E 37                 # "1.7"
         68 66 72 61 6D 65 5F 69 64    # "frame_id"
            50 01 23 45 67 01 23 45 67 01 23 45 67 01 23 45 67  # 16 bytes
         6A 66 72 61 6D 65 5F 74 79 70 65 # "frame_type"
            01                          # 1
         67 74 61 73 6B 5F 69 64       # "task_id"
            50 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  # nil UUID
         69 74 69 6D 65 73 74 61 6D 70 # "timestamp"
            1B 00 01 8B BA 3F 5E 7A 00 # 1700000000000
   68 6D 65 74 61 64 61 74 61          # key "metadata"
      A1                               # map(1)
         61 70                         # "p"
            04                          # 4
   6D 70 72 69 6F 72 69 74 79 5F 68 69 6E 74 # "priority_hint"
      04                                # 4
   6D 74 61 73 6B 5F 70 61 79 6C 6F 61 64 # "task_payload"
      45 68 65 6C 6C 6F                # 5 bytes
   69 74 61 73 6B 5F 74 79 70 65       # "task_type"
      64 65 63 68 6F                   # "echo"
```

---

## 3. Frame Types

| Code | Name | Direction | Description |
|------|------|-----------|-------------|
| 0x01 | TASK_REQUEST | C→S | Request a task execution |
| 0x02 | TASK_RESPONSE | S→C | Task result (may be partial) |
| 0x03 | TASK_ACK | S→C | Acknowledge task receipt |
| 0x04 | TASK_ERROR | S→C | Task error |
| 0x05 | TASK_CANCEL | C→S | Cancel running task |
| 0x10 | CONTROL_SHUTDOWN | either | Graceful shutdown request |
| 0x11 | CONTROL_REVOKE_NOTIFY | either | Revocation serials |
| 0x12 | CONTROL_SHUTDOWN_ACK | either | Shutdown acknowledged |
| 0x13 | CONTROL_HEALTH | either | Health check request |
| 0x14 | CONTROL_HEALTH_RESP | either | Health check response |
| 0x15 | CONTROL_PING | either | Keepalive ping |
| 0x16 | CONTROL_PONG | either | Keepalive pong |
| 0x20 | ERROR | either | Protocol error |
| 0x21 | ROOT_STORE_UPDATE | either | RootStore manifest sync |
| 0x30 | VERSION_PROPOSE | C→S | Propose protocol version |
| 0x31 | VERSION_ACK | S→C | Accept protocol version |
| 0x40 | MCC_BIND_REQUEST | C→S | Send MCC for identity binding |
| 0x41 | MCC_BIND_RESPONSE | S→C | Respond with MCC + signature |
| 0x42 | MCC_BIND_CONFIRM | C→S | Confirm binding with signature |
| 0x50 | CAPABILITY_EXCHANGE | either | Exchange capabilities |
| 0x60 | PEER_DISCOVERY | P↔P | Federation peer list (signed) |
| 0x61 | PEER_HEARTBEAT | P↔P | Federation keepalive |
| 0x62 | TASK_FORWARD | P→P | Forward task (signed) |
| 0x63 | PEER_DISCOVERY_ACK | P→P | Discovery acknowledged |

---

## 4. Handshake Protocol

### 4.1 Phase 1 — TLS

Establish TCP connection, then TLS 1.3 with **mutual authentication**:
- Both sides present X.509 certificates
- Both sides set `verify_mode = CERT_REQUIRED`
- Certificates are Ed25519 or ECDSA P-256
- ALPN: `"atp-v1.8"`

### 4.2 Phase 2 — Version Negotiation

**Client sends** (frame type 0x30):
```
{
    "header": Header,
    "atp_versions": ["1.7"],
    "max_batch_bytes": 1048576,
    "clock_skew_ms": 10000,
    "anti_replay_ttl_ms": 20000,
    "rate_limit_rps": 100,
}
```

**Server responds** (frame type 0x31):
```
{
    "header": Header,
    "selected_version": "1.7",
    "max_batch_bytes": 1048576,
    "clock_skew_ms": 10000,
    "anti_replay_ttl_ms": 20000,
    "rate_limit_rps": 100,
}
```

### 4.3 Phase 3 — MCC Exchange & Identity Binding

**Step 3a — Client sends MCC_BIND_REQUEST** (0x40):
```
{
    "header": Header,
    "mcc_cbor": bstr,              # MCC serialized via MCC.to_cbor()
    "nonce": bstr .size 16,        # random nonce
}
```

**Step 3b — Server verifies MCC, then responds** (0x41):
```
{
    "header": Header,
    "mcc_cbor": bstr,              # server's MCC
    "nonce": bstr .size 16,        # server's random nonce
    "signature": bstr .size 64,    # Ed25519_sign(sk, client_nonce || "atp-bind-response")
}
```

**Step 3c — Client verifies server's MCC + signature, then confirms** (0x42):
```
{
    "header": Header,
    "signature": bstr .size 64,    # Ed25519_sign(sk, server_nonce || "atp-bind-confirm")
}
```

**Signature verification details:**
- Server verifies: `Ed25519_verify(client_sign_pk, client_sig, server_nonce || "atp-bind-confirm")`
- Client verifies: `Ed25519_verify(server_sign_pk, server_sig, client_nonce || "atp-bind-response")`

### 4.4 Phase 4 — Capability Exchange (0x50)

Bidirectional, same frame type:
```
{
    "header": Header,
    "capabilities": {
        "max_tasks": 10,
        "supports_deepseek": true,
        "atp_version": "1.7",
    },
}
```

### 4.5 Phase 5 — Task Streams

After capability exchange, either side may send TASK_REQUEST (0x01) frames.
The server runs `handle_task_loop()` which reads frames and dispatches.

---

## 5. MCC — Merkle-Claim Card

### 5.1 Structure

```
MCC = {
    "mcc_version": 1,
    "serial_number": bstr .size 16,
    "root_hash": bstr .size 32,
    "authority_id": tstr,
    "authority_sig": bstr .size 64,
    "expiry_date": uint,
    "leaves": [MCCLeaf],
    "critical_mask": [tstr],
}
```

### 5.2 MCCLeaf

```
MCCLeaf = {
    "key": tstr,
    "value": bstr,
    "salt": bstr .size 16,
}
```

### 5.3 Leaf Hash Formula

```
leaf_hash = BLAKE3(
    0x00                              # leaf prefix
    || salt                           # 16 bytes
    || uint16_BE(len(key_utf8))      # 2 bytes, big-endian
    || key_utf8                       # UTF-8 encoded key string
    || uint32_BE(len(value))          # 4 bytes, big-endian
    || value                          # raw bytes
)
```

### 5.4 Merkle Tree Construction

1. Sort leaves by `key` (lexicographic UTF-8)
2. Compute `leaf_hash` for each sorted leaf
3. If N is not a power of 2, pad by duplicating the last leaf
4. Build bottom-up: each internal node = `BLAKE3(0x01 || left_hash || right_hash)`
5. Single leaf: `root_hash = leaf_0`
6. Zero leaves: `root_hash = 0x00 * 32`

### 5.5 Commitment & Signature

```
commitment = CBOR_canonical({
    "root_hash": root_hash,
    "expiry_date": expiry_date,
    "mcc_version": mcc_version,
    "authority_id": authority_id,
    "serial_number": serial_number,
})
authority_sig = Ed25519_sign(authority_sk, commitment)
```

### 5.6 Verification (8 Steps)

1. `mcc_version == 1`
2. `expiry_date > current_time()`
3. All `critical_mask` keys present in leaves
4. Recompute `root_hash` from leaves (ignore any transmitted hash)
5. Lookup `authority_pk` in RootStore by `authority_id`
6. `Ed25519_verify(authority_pk, authority_sig, commitment_cbor)`
7. (Optional): verify `agent_pk` matches TLS certificate
8. Check `serial_number` is not revoked (Cuckoo filter)

---

## 6. E2E Encryption

### 6.1 Key Derivation

```
shared_secret = X25519_ECDH(my_sk, peer_pk)
pk1, pk2 = sorted([my_x25519_pk, peer_x25519_pk])
kdf_input = "atp-v1.7-ecdh" || shared_secret || pk1 || pk2
session_key = BLAKE3(kdf_input)     # 32 bytes → AES-256-GCM key
```

### 6.2 Encryption (AES-GCM only)

```
nonce = random(12 bytes)
ciphertext = AES_256_GCM_encrypt(session_key, nonce, plaintext, aad=None)
result = nonce || ciphertext       # nonce(12) + ciphertext(plaintext_len + 16)
```

### 6.3 Encrypt-then-Sign (authenticated)

```
encrypted = AES_256_GCM_encrypt(session_key, nonce, plaintext)
signature = Ed25519_sign(my_ed25519_sk, encrypted)
result = encrypted || signature     # nonce(12) + ciphertext(N) + tag(16) + sig(64)
```

### 6.4 Verify-then-Decrypt

```
encrypted = payload[:-64]
signature = payload[-64:]
if not Ed25519_verify(peer_ed25519_pk, signature, encrypted): reject
nonce = encrypted[:12]
ciphertext = encrypted[12:]
plaintext = AES_256_GCM_decrypt(session_key, nonce, ciphertext)
```

---

## 7. Revocation

### 7.1 Cuckoo Filter

Parameters: 1024 buckets, 4 slots/bucket, 16-bit fingerprint.

For item `x`:
```
h = BLAKE3(x)
fingerprint = (h[0:4] as uint32) & 0xFFFF
if fingerprint == 0: fingerprint = 1
i1 = (h[4:8] as uint32) & 0x3FF       # 1024-1
h2 = BLAKE3(uint32_BE(fingerprint))
i2 = i1 ^ ((h2[0:4] as uint32) & 0x3FF)
```

### 7.2 RootStore Manifest Format

```
manifest = {
    "manifest_version": 1,
    "manifest_id": bstr .size 16,
    "manifest_nonce": bstr .size 16,     # anti-replay
    "manifest_ts": uint,                  # timestamp
    "rootstore_version": uint,           # monotonic counter
    "timestamp": uint,
    "authority_id": tstr,                 # signing authority
    "authorities": [                      # authority entries
        {"authority_id": tstr, "pk": bstr .size 32},
    ],
    "signature": bstr .size 64,           # Ed25519 over all other fields
}
```

---

## 8. Error Codes

| Code | Name | Disposition |
|------|------|-------------|
| 0x01 | ERR_ATP_VERSION_UNSUPPORTED | close |
| 0x02 | ERR_INVALID_ROOT | close |
| 0x03 | ERR_MISSING_CRITICAL_CLAIM | close |
| 0x04 | ERR_IDENTITY_MISMATCH | close |
| 0x05 | ERR_BAD_SIGNATURE | close |
| 0x06 | ERR_REVOKED | close |
| 0x07 | ERR_IDENTITY_NOT_BOUND | close |
| 0x08 | ERR_STREAM_PROTOCOL_VIOLATION | close |
| 0x09 | ERR_TASK_TOO_LARGE | close_stream |
| 0x0A | ERR_UNSUPPORTED_TASK_TYPE | close_stream |
| 0x0B | ERR_TASK_TIMEOUT | close_stream |
| 0x0C | ERR_CLOCK_SKEW | close_stream |
| 0x0D | ERR_RATE_LIMITED | recoverable |
| 0x0E | ERR_STREAM_VIOLATION_MINOR | close_stream |
| 0x0F | ERR_TASK_CANCELLED | close_stream |

---

## 9. Implementation Checklist

- [ ] CBOR canonical encoding (sorted map keys, definite-length strings)
- [ ] BLAKE3-256 hash
- [ ] Ed25519 key generation, signing, verification
- [ ] X25519 key generation, ECDH
- [ ] AES-256-GCM encrypt/decrypt
- [ ] TLS 1.3 mutual auth (client + server certs)
- [ ] Frame encode/decode (4-byte BE length prefix + CBOR)
- [ ] MCC create: leaf hash → Merkle tree → commitment → sign
- [ ] MCC verify: 8-step verification
- [ ] 5-phase handshake (TLS → Version → MCC → Cap → Streams)
- [ ] Proof-of-possession (context strings)
- [ ] E2E key derivation (X25519 ECDH + BLAKE3 KDF)
- [ ] E2E encrypt-then-sign / verify-then-decrypt
- [ ] Keepalive (PING/PONG every 30s)
- [ ] Clock skew check (configurable, default 10s)
- [ ] Anti-replay (frame_id sliding window, 20s)
- [ ] Cuckoo filter for revocation
- [ ] RootStore chain-of-manifests
- [ ] Federation: PEER_DISCOVERY (signed), HEARTBEAT, TASK_FORWARD (signed)
