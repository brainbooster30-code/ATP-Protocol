---
tags:
  - mcc
  - identity
  - crypto
---

# MCC and Identity

## Merkle-Claim Card (MCC)

Each agent possesses an MCC — a Merkle tree (MAST) built with BLAKE3, CBOR-encoded, and signed by an authority.

### Leaf Hash Formula
```
L_i = BLAKE3(0x00 || salt_16 || uint16_BE(len(key)) || key_utf8 || uint32_BE(len(value)) || value)
```

### Internal Node
```
Node = BLAKE3(0x01 || Left || Right)
```

### Key Properties
- Leaves are **sorted by key** for deterministic root hash
- Padding: if N not power of 2, duplicate last leaf
- N=1: `root_hash = L_0`
- **leaf_hash is NEVER transmitted** — receiver MUST recompute

## 8-Step Verification

1. `mcc_version == 1`
2. `expiry_date > now`
3. All `critical_mask` fields present in leaves
4. Recompute `leaf_hash` and `root_hash`
5. Fetch `authority_pk` from RootStore
6. Verify Ed25519 signature on commitment CBOR (5 fields)
7. (optional) `agent_pk` matches TLS identity
8. (ATP-Full) `serial_number` not revoked via CuckooFilter

## Key Separation (ATP-Full)
- `agent_pk` (X25519, 32 bytes) → ECDH TLS only
- `agent_sign_pk` (Ed25519, 32 bytes) → MCC signatures and proof-of-possession only
- `agent_pk ≠ agent_sign_pk` **mandatory**

## Critical Mask
```
["agent_pk", "agent_sign_pk", "expiry_date", "authority_id", "mcc_version", "serial_number"]
```
