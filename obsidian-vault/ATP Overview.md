---
tags:
  - atp
  - protocol
  - overview
---

# ATP v1.7+ — Agent Transport Protocol

## Overview

ATP is a secure application-layer protocol for autonomous agent communication, combining:

- **Merkle-Claim Cards (MCC)** — cryptographic identity without central PKI
- **TLS 1.3 mutual** — Ed25519 self-signed CA with cert rotation
- **Cuckoo Filter** + Ed25519-signed gossip for distributed revocation
- **Federation v2.0** — mesh network with peer discovery, heartbeat, task forwarding
- **E2E X25519 ECDH + AES-256-GCM** — encrypt-then-sign payload authentication

## Architecture

```
Agent A (Client)          Agent B (Server)
─────┬─────                ─────┬─────
     │  1. TLS handshake        │
     │◄────────────────────────►│
     │  2. VERSION_PROPOSE/ACK  │
     │─────────────────────────►│
     │  3. MCC_BIND_REQUEST     │
     │─────────────────────────►│
     │  MCC_BIND_RESPONSE       │
     │◄─────────────────────────│
     │  MCC_BIND_CONFIRM        │
     │─────────────────────────►│
     │  4. CAPABILITY_EXCHANGE  │
     │◄────────────────────────►│
     │  5. TASK_REQUEST/ACK/RESP│
     │◄────────────────────────►│
     │  + ROOT_STORE_UPDATE (agent-signed)
     │  + PEER_DISCOVERY/HEARTBEAT/FORWARD
```

## Key Components

- [[MCC and Identity]] — Merkle-Claim Cards, key separation, 8-step verification
- [[Handshake Protocol]] — 5-phase binding with proof-of-possession, 30s deadline
- [[Revocation System]] — CuckooFilter, RootStore, DegradationPolicy, Gossip (Ed25519 signed)
- [[Frame Wire Format]] — CBOR encoding, 24 frame types, 15 error codes
- [[Dashboard]] — PySide6 GUI with 5 tabs, real-time monitoring
- [[DeepSeek Integration]] — aiohttp API calls with circuit breaker + registry fallback

## Quality

- **Score architetturale:** 9.5/10
- **Test:** 52 pytest (45 core + 7 SDK), fixture isolate, ~2.8s esecuzione
- **Graph:** 836 nodes, 1,556 edges, 59 communities
- **Security:** Ed25519/X25519 key separation, BLAKE3 hard-fail, mTLS CERT_REQUIRED,
  check_revoked sempre attivo, agent-signed RootStore push, gossip Ed25519 auth
