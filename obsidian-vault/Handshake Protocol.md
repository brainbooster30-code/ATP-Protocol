---
tags:
  - protocol
  - handshake
---

# Handshake Protocol

## 5-Phase Handshake

### Phase 1 — TLS
TCP connection with self-signed Ed25519 TLS.

### Phase 2 — Version Negotiation
- Initiator → `VERSION_PROPOSE (0x30)`: `atp_versions`, `max_batch_bytes`, `clock_skew_ms`, `anti_replay_ttl_ms`, `rate_limit_rps`
- Responder → `VERSION_ACK (0x31)`: chosen version, negotiated params

### Phase 3 — MCC Exchange & Identity Binding
- Initiator → `MCC_BIND_REQUEST (0x40)`: MCC + `nonce_i` (16 bytes CSPRNG)
- Responder → verifies MCC, sends `MCC_BIND_RESPONSE (0x41)`: own MCC + `nonce_r` + `Ed25519_sign(sk, nonce_i || "atp-bind-response")`
- Initiator → verifies, sends `MCC_BIND_CONFIRM (0x42)`: `Ed25519_sign(sk, nonce_r || "atp-bind-confirm")`
- Binding complete (bidirectional identity verified)

### Phase 4 — Capability Exchange
- `CAPABILITY_EXCHANGE (0x50)`: max_tasks, supports_deepseek, atp_version

### Phase 5 — Task Streams
Parallel task streams (sequential in demo).

## Proof-of-Possession Strings
```
MCC_BIND_RESPONSE sig: Ed25519_sign(sk, nonce_i + "atp-bind-response")
MCC_BIND_CONFIRM  sig: Ed25519_sign(sk, nonce_r + "atp-bind-confirm")
```
