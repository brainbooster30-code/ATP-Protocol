# ATP v1.6.1 — RFC: Agent Transport Protocol

**Category:** Experimental
**RFC No:** ATP-RFC-001  
**Date:** July 2026  
**Status:** Draft  
**Obsoletes:** None  
**Updates:** None  

---

## 1. Introduction

This document specifies the Agent Transport Protocol (ATP) version 1.6.1,
a peer-to-peer cryptographic protocol for secure communication between
autonomous software agents. ATP provides identity, authentication, proof
of origin, and task dispatch without a central server.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174].

### 1.2 Notation

- `||` denotes concatenation of byte strings.
- `0x` prefix denotes hexadecimal notation.
- CBOR values are described using CDDL [RFC8610].
- `uint16_BE(x)`: 16-bit unsigned integer in big-endian byte order.
- `uint32_BE(x)`: 32-bit unsigned integer in big-endian byte order.

---

## 2. Protocol Overview

ATP operates over TLS 1.3 [RFC8446] and uses a 5-phase handshake to
establish a bound channel between two agents. After binding, agents
exchange tasks as CBOR-encoded frames with a 4-byte length prefix.

```
Agent A                      Agent B
   │                            │
   ├── TLS 1.3 ────────────────►│
   ├── VERSION_PROPOSE ────────►│
   │◄── VERSION_ACK ───────────┤
   ├── MCC_BIND_REQUEST ──────►│
   │◄── MCC_BIND_RESPONSE ─────┤
   ├── MCC_BIND_CONFIRM ──────►│
   ├── CAPABILITY_EXCHANGE ───►│
   │◄── CAPABILITY_EXCHANGE ───┤
   ├── TASK_REQUEST(ACK,RESP)─►│
   │◄── TASK_REQUEST(ACK,RESP)─┤
```

---

## 3. Identifiers

### 3.1 Agent Identity

Each agent is identified by a name that is embedded in its MCC.

```
agent-identity = tstr               ; 1..256 UTF-8 characters
```

### 3.2 Frame Identifier

Each frame carries a unique 16-byte UUID v4 [RFC4122].

```
frame-id = bstr .size 16            ; UUID v4
```

### 3.3 Task Identifier

Task frames carry a task-id (16-byte UUID v4). Control frames use the
nil UUID (all zeros).

```
task-id = bstr .size 16             ; UUID v4 or nil for control
```

### 3.4 Connection Identifier

Generated at connection setup, logged for debugging.

```
conn-id = tstr                      ; hex string of random 8 bytes
```

---

## 4. Merkle-Claim Card

### 4.1 CDDL Specification

```
mcc = {
    "mcc_version":    uint .size 1,             ; MUST be 1
    "root_hash":      bstr .size 32,            ; BLAKE3-256 Merkle root
    "expiry_date":    uint,                     ; Unix timestamp
    "critical_mask":  [* tstr],                 ; required leaf keys
    "authority_id":   tstr,                     ; 1..256 chars
    "serial_number":  bstr .size 16,            ; unique ID
    "leaves":         [* mcc-leaf],             ; claims
    "authority_sig":  bstr .size 64,            ; Ed25519 signature
}

mcc-leaf = {
    "key":    tstr,                              ; claim name
    "value":  bstr,                              ; claim value
    "salt":   bstr .size 16,                     ; CSPRNG nonce
}
```

### 4.2 Leaf Hash Computation

```
leaf_hash = BLAKE3(0x00 || salt || uint16_BE(len(key)) ||
                   key_utf8 || uint32_BE(len(value)) || value)
```

The implementation MUST:
1. Prefix with literal 0x00
2. Append the 16-byte salt
3. Append uint16_BE of UTF-8 key length
4. Append UTF-8 encoded key bytes
5. Append uint32_BE of value length
6. Append value bytes

### 4.3 Internal Node Computation

```
internal_hash = BLAKE3(0x01 || left_hash || right_hash)
```

### 4.4 Merkle Tree Construction

The tree is built as follows:

1. Sort leaves by key in ascending lexicographic order (UTF-8 byte order)
2. Compute leaf_hash for each leaf
3. If N is not a power of 2, repeatedly duplicate the last leaf until N
   is a power of 2
4. Build internal nodes pairwise (left || right):
   `hash = BLAKE3(0x01 || left || right)`
5. Repeat until a single root_hash remains

Special cases:
- N=0: root_hash = 0x0000000000000000000000000000000000000000000000000000000000000000
- N=1: root_hash = leaf_hash[0]

### 4.5 Commitment CBOR

The commitment CBOR is a canonical CBOR map containing exactly 5 fields:

```
commitment = {
    "root_hash":     bstr .size 32,
    "expiry_date":   uint,
    "mcc_version":   uint,
    "authority_id":  tstr,
    "serial_number": bstr .size 16,
}
```

This MUST be encoded with canonical CBOR (RFC 8949 §4.2.1: sorted map
keys, definite-length strings, shortest integer encoding).

The authority signature is:

```
authority_sig = Ed25519_sign(authority_sk, commitment_bytes)
```

### 4.6 Verification Algorithm

Given an MCC `m` and the peer's authority public key `pk`:

1. **Version check**: If `m.mcc_version != 1`, return FAIL
2. **Expiry check**: If `m.expiry_date <= current_time()`, return FAIL
3. **Critical mask check**: For each key `k` in `m.critical_mask`,
   if no leaf with key `k` exists in `m.leaves`, return FAIL
4. **Root recompute**: Recompute `leaf_hash` for every leaf and rebuild
   the Merkle tree per §4.4. If `root_hash != m.root_hash`, return FAIL
5. **Authority key**: Retrieve authority public key from trusted store
   using `m.authority_id`
6. **Signature verify**:
   `if NOT Ed25519_verify(pk, m.authority_sig, commitment_cbor)`,
   return FAIL
7. **Agent PK match (OPTIONAL)**: If `m.leaves` contain `agent_pk`
   and the TLS peer certificate provides a public key, they MUST match
8. **Revocation check (ATP-Full)**: If `check_revoked(m.serial_number)`,
   return FAIL

---

## 5. Frame Encoding

### 5.1 Wire Format

Every frame is transmitted as:

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload Length                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                    CBOR Encoded Frame                         ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Payload Length: uint32_BE of the following CBOR bytes.
CBOR Encoded Frame: canonical CBOR (RFC 8949 §4.2).

### 5.2 Frame Types

| Code | Name | Section |
|------|------|---------|
| 0x01 | TASK_REQUEST | §5.3 |
| 0x02 | TASK_RESPONSE | §5.4 |
| 0x03 | TASK_ACK | §5.5 |
| 0x04 | TASK_ERROR | §5.6 |
| 0x10 | CONTROL_SHUTDOWN | §5.7 |
| 0x11 | CONTROL_REVOKE_NOTIFY | §5.8 |
| 0x20 | ERROR | §5.9 |
| 0x21 | ROOT_STORE_UPDATE | §5.10 |
| 0x30 | VERSION_PROPOSE | §5.11 |
| 0x31 | VERSION_ACK | §5.12 |
| 0x40 | MCC_BIND_REQUEST | §5.13 |
| 0x41 | MCC_BIND_RESPONSE | §5.14 |
| 0x42 | MCC_BIND_CONFIRM | §5.15 |
| 0x50 | CAPABILITY_EXCHANGE | §5.16 |

### 5.3 TASK_REQUEST (0x01)

```
task-request = {
    "header": header,
    "task_type": tstr,
    "task_payload": bstr,
    "deadline_ms": uint,
    ? "metadata": {* tstr => any},
    ? "priority_hint": uint,
}
```

The `task_payload` is opaque to the protocol. The server dispatches based
on `task_type`.

### 5.4 TASK_RESPONSE (0x02)

```
task-response = {
    "header": header,
    "status": uint,
    "result_payload": bstr,
    ? "partial": bool,
    ? "sequence": uint,
}
```

### 5.5 TASK_ACK (0x03)

```
task-ack = {
    "header": header,
}
```

### 5.6 TASK_ERROR (0x04)

```
task-error = {
    "header": header,
    "error_code": uint .size 1,
    "error_message": tstr,
    ? "retry_after_ms": uint,
    ? "server_time_ms": uint,
}
```

`server_time_ms` allows the client to correct clock skew (see §11.2).

### 5.7 CONTROL_SHUTDOWN (0x10)

```
control-shutdown = {
    "header": header,
    ? "reason": tstr,
}
```

### 5.8 CONTROL_REVOKE_NOTIFY (0x11)

```
control-revoke-notify = {
    "header": header,
    "serial_numbers": [* bstr .size 16],
}
```

### 5.9 ERROR (0x20)

```
error-frame = {
    "header": header,
    "error_code": uint .size 1,
    "error_message": tstr,
}
```

### 5.10 ROOT_STORE_UPDATE (0x21)

```
root-store-update = {
    "header": header,
    "signed_manifest": bstr,
}
```

### 5.11 VERSION_PROPOSE (0x30)

```
version-propose = {
    "header": header,
    "atp_versions": [2* tstr],
    "max_batch_bytes": uint,
    "clock_skew_ms": uint,
    "anti_replay_ttl_ms": uint,
    "rate_limit_rps": uint,
}
```

### 5.12 VERSION_ACK (0x31)

```
version-ack = {
    "header": header,
    "selected_version": tstr,
    "max_batch_bytes": uint,
    "clock_skew_ms": uint,
    "anti_replay_ttl_ms": uint,
    "rate_limit_rps": uint,
}
```

### 5.13 MCC_BIND_REQUEST (0x40)

```
mcc-bind-request = {
    "header": header,
    "mcc_cbor": bstr,
    "nonce": bstr .size 16,
}
```

The `nonce` MUST be generated from a CSPRNG and used only once.

### 5.14 MCC_BIND_RESPONSE (0x41)

```
mcc-bind-response = {
    "header": header,
    "mcc_cbor": bstr,
    "nonce": bstr .size 16,
    "signature": bstr .size 64,
}
```

The `signature` MUST be:
```
Ed25519_sign(responder_sk, peer_nonce || "atp-bind-response")
```

### 5.15 MCC_BIND_CONFIRM (0x42)

```
mcc-bind-confirm = {
    "header": header,
    "signature": bstr .size 64,
}
```

The `signature` MUST be:
```
Ed25519_sign(initiator_sk, peer_nonce || "atp-bind-confirm")
```

### 5.16 CAPABILITY_EXCHANGE (0x50)

```
capability-exchange = {
    "header": header,
    "max_tasks": uint,
    "supports_deepseek": bool,
    "atp_version": tstr,
}
```

---

## 6. Error Codes

| Code | Name | Disposition | Description |
|------|------|-------------|-------------|
| 0x01 | ERR_ATP_VERSION_UNSUPPORTED | CONNECTION_CLOSE | No common ATP version |
| 0x02 | ERR_INVALID_ROOT | CONNECTION_CLOSE | MCC root hash mismatch |
| 0x03 | ERR_MISSING_CRITICAL_CLAIM | CONNECTION_CLOSE | Required leaf missing |
| 0x04 | ERR_IDENTITY_MISMATCH | CONNECTION_CLOSE | Agent identity conflict |
| 0x05 | ERR_BAD_SIGNATURE | CONNECTION_CLOSE | Invalid Ed25519 signature |
| 0x06 | ERR_REVOKED | CONNECTION_CLOSE | Agent/serial revoked |
| 0x07 | ERR_IDENTITY_NOT_BOUND | CONNECTION_CLOSE | Not yet bound |
| 0x08 | ERR_STREAM_PROTOCOL_VIOLATION | CONNECTION_CLOSE | Fatal stream error |
| 0x09 | ERR_TASK_TOO_LARGE | TASK_STREAM_CLOSE | Payload exceeds limit |
| 0x0A | ERR_UNSUPPORTED_TASK_TYPE | TASK_STREAM_CLOSE | Unknown task_type |
| 0x0B | ERR_TASK_TIMEOUT | TASK_STREAM_CLOSE | Task deadline exceeded |
| 0x0C | ERR_CLOCK_SKEW | TASK_STREAM_CLOSE | Clock difference > limit |
| 0x0D | ERR_RATE_LIMITED | RECOVERABLE | Rate limit exceeded |
| 0x0E | ERR_STREAM_VIOLATION_MINOR | TASK_STREAM_CLOSE | Minor protocol error |

Disposition meanings:
- CONNECTION_CLOSE: The entire connection MUST be torn down.
- TASK_STREAM_CLOSE: Only the current task stream is terminated.
- RECOVERABLE: The sender MAY retry after `retry_after_ms`.

---

## 7. Handshake Protocol (5 Phases)

### 7.1 Phase 1 — TLS

Both peers MUST establish a TLS 1.3 [RFC8446] connection over TCP.
Implementation MAY accept self-signed certificates for testing; production
deployments SHOULD use certificates signed by a trusted CA.

### 7.2 Phase 2 — Version Negotiation

1. Initiator sends VERSION_PROPOSE with supported versions and parameters
2. Responder selects a version from the intersection of supported sets
3. Responder replies with VERSION_ACK containing the selected version
4. If no common version exists, Responder sends ERROR(0x01) and closes

Negotiated parameters (clock_skew_ms, anti_replay_ttl_ms, rate_limit_rps)
apply for the duration of the connection.

### 7.3 Phase 3 — MCC Exchange & Identity Binding

1. Initiator generates `nonce_i` (16 bytes CSPRNG)
2. Initiator sends MCC_BIND_REQUEST containing its MCC and `nonce_i`
3. Responder verifies Initiator's MCC (8-step verification, §4.6)
4. If verification fails, Responder sends ERROR(0x05) and closes
5. Responder generates `nonce_r` (16 bytes CSPRNG)
6. Responder sends MCC_BIND_RESPONSE with its MCC, `nonce_r`, and
   `signature = Ed25519_sign(sk_r, nonce_i || "atp-bind-response")`
7. Initiator verifies Responder's MCC (§4.6)
8. Initiator verifies the proof-of-possession signature
9. If any verification fails, Initiator sends ERROR(0x05) and closes
10. Initiator sends MCC_BIND_CONFIRM with
    `signature = Ed25519_sign(sk_i, nonce_r || "atp-bind-confirm")`
11. Responder verifies the proof-of-possession signature
12. Both peers set `bound = True`

### 7.4 Phase 4 — Capability Exchange

Each peer announces its capabilities in a CAPABILITY_EXCHANGE frame.
Both peers MUST send this frame before Phase 5 begins.

### 7.5 Phase 5 — Task Streams

After Phase 4, either peer MAY send TASK_REQUEST frames. The receiving
peer MUST respond with TASK_ACK, process the task, and send either
TASK_RESPONSE or TASK_ERROR.

---

## 8. Revocation

### 8.1 Cuckoo Filter

The Cuckoo Filter is a probabilistic data structure for approximate
member checking:

- Table size: 1024 buckets
- Slots per bucket: 4
- Fingerprint size: 16 bits
- False positive rate: ~2.3 × 10⁻³¹
- Supports insert, lookup, and delete operations

### 8.2 Root Store

The Root Store maintains a list of trusted authority public keys:

```python
root-store-manifest = {
    "version": uint,
    "authorities": { tstr => {
        "pk": bstr,
        "added": uint,
        "expires": uint
    }},
    "chain": [* { "manifest": bstr, "added": uint }]
}
```

### 8.3 Gossip Protocol

The Gossip Protocol distributes revocation information:

1. Each peer maintains a set of known serials
2. Every GOSSIP_INTERVAL_S (default 5s), the peer selects
   GOSSIP_FANOUT (default 3) peers and sends CONTROL_REVOKE_NOTIFY
3. Receiving peers merge new serials into their local Cuckoo Filter
4. Peers track known serials to avoid broadcast loops

---

## 9. Security Considerations

### 9.1 Key Separation

All implementations MUST enforce that `agent_pk != agent_sign_pk`.
Using the same key pair for both ECDH and signing enables dual-use
attacks [DualUse15].

### 9.2 Nonce Reuse

MCC_BIND_REQUEST and MCC_BIND_RESPONSE nonces MUST be generated from a
CSPRNG and MUST NOT be reused. Nonce reuse allows replay attacks.

### 9.3 Clock Skew

Implementations MUST reject frames with timestamp outside the
CLOCK_SKEW_MS window. The server SHOULD return `server_time_ms` in
TASK_ERROR(0x0C) to allow clock correction.

### 9.4 Anti-Replay

Each frame's `frame_id` combined with `anti_replay_ttl_ms` (default 20s)
prevents simple replay attacks. Implementations SHOULD maintain a
bloom filter of recently seen frame_ids.

### 9.5 Demo Mode

The `demo_mode` flag disables authority signature verification (§4.6
steps 5-6). This is INTENDED for testing and multi-machine demos.
Production deployments MUST set `demo_mode = False`.

---

## 10. Implementation Status

- **Python 3.12+**: Complete implementation (10 modules, 4000+ lines)
- **SDK**: Pip-installable Python package at `sdk/`
- **Dashboard**: PySide6 real-time GUI (5 tabs)
- **Tests**: 70+ unit tests, 104 SAST/DAST checks, 10-task integration

---

## 11. References

### 11.1 Normative References

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", RFC 2119
- [RFC4122] Leach, P., "A Universally Unique IDentifier (UUID) URN Namespace", RFC 4122
- [RFC8446] Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446
- [RFC8610] Birkholz, H., "Concise Data Definition Language (CDDL)", RFC 8610
- [RFC8949] Bormann, C., "Concise Binary Object Representation (CBOR)", RFC 8949
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", RFC 8174

### 11.2 Informative References

- [BLAKE3] Aumasson, J.P., et al., "BLAKE3: One Function, Fast Everywhere", 2020
- [DualUse15] Degabriele, J.P., "Leakage-Resilient Cryptography", 2015
- [Ed25519] Bernstein, D.J., et al., "High-speed high-security signatures", Journal of Cryptographic Engineering, 2012

---

*This document is maintained at https://github.com/brainbooster30-code/ATP-Protocol*
