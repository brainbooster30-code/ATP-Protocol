---
tags:
  - revocation
  - security
---

# Revocation System

## Components

### Cuckoo Filter (`revocation.py:37-154`)
- Approximate set membership query
- Parameters: 1024 buckets, 4 slots, 16-bit fingerprints
- False-positive rate: ~2.3×10⁻³¹
- Operations: `insert()`, `contains()`, `remove()`
- Thread-safe con `threading.Lock()` (critical section <1μs)
- Cuckoo kicks for collision resolution

### Root Store (`revocation.py:169-376`)
- Thread-safe trusted authority storage
- Authority registration with TTL (365 days default)
- Idempotent `add_authority`: non incrementa versione per duplicati
- Chain-of-manifests con anti-replay (nonce + timestamp 5min)
- Backend: JSON flat file (`root_store.json`) o SQLite WAL (`revocation_sqlite.py`)

### Degradation Policy (`revocation.py:382-436`)
- Three states: `CONFIRMED` / `STALE` / `UNCERTAIN`
- Freshness window: 1 hour (FRESHNESS_S)
- Grace period: 24 hours (GRACE_S)
- UNCERTAIN → connection refused for unknown authorities

### Gossip Protocol (`revocation.py:442-627`)
- Fanout-based serial_number distribution (fanout 3, interval 5s)
- **Ed25519 signed payloads** — `GossipProtocol._sign_sk` firma ogni round
- `GossipServer._on_gossip_connect` verifica firma se sender_pk nota
- Backward compat: formato flat list v1 e dict unsigned accettati
- TCP porta 8444, length-prefixed CBOR

### RootStore push (agent-signed)
- `ROOT_STORE_UPDATE` (0x21) firmato con `identity.ed25519_sk`
- Ricevente verifica con `_peer_ed25519_pk` dall'MCC (handshake)
- Eliminata vulnerabilità authority key leak

## Global API
- `revoke_serial(serial)` — add to filter + gossip
- `check_revoked(serial)` — query filter
- Singleton pattern with double-checked locking (per-modulo)
- Reset automatico via conftest.py nei test pytest
