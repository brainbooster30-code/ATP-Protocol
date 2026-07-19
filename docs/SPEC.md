# ATP v1.6.1 — Specifica Tecnica

**Agent Transport Protocol — Technical Specification**

*Versione: 1.6.1*
*Stato: Stabile*
*Linguaggio di implementazione: Python 3.12+*

---

## 1. Convenzioni

- `uint16_BE`: unsigned 16-bit big-endian
- `uint32_BE`: unsigned 32-bit big-endian
- `bstr .size N`: byte string di esattamente N byte
- `BLAKE3(x)`: output BLAKE3-256 di x (32 byte)
- `Ed25519_sign(sk, data)`: firma Ed25519 su data (64 byte output)
- Tutti i numeri in notazione esadecimale sono prefissati con `0x`
- I frame CBOR usano encoding canonico (RFC 8949 §4.2, sorted maps)

---

## 2. Merkle-Claim Card (MCC)

### 2.1 Struttura

Un MCC è un documento di identità costruito come albero di Merkle.

```
MCC = {
    mcc_version:    uint,         # deve essere 1
    root_hash:      bstr .size 32,  # root dell'albero di Merkle
    expiry_date:    uint,         # Unix timestamp (secondi)
    critical_mask:  [tstr],       # lista di chiavi obbligatorie
    authority_id:   tstr,         # 1..256 caratteri UTF-8
    serial_number:  bstr .size 16,  # identificatore univoco
    leaves:         [MCCLeaf],    # foglie dell'albero
    authority_sig:  bstr .size 64   # firma Ed25519 sul commitment CBOR
}

MCCLeaf = {
    key:    tstr,                  # nome della claim
    value:  bstr,                  # valore della claim
    salt:   bstr .size 16          # salt CSPRNG per preimage resistance
}
```

### 2.2 Leaf Hash Formula

```
leaf_hash = BLAKE3(
    0x00                              # prefisso leaf
    || salt                           # 16 byte
    || uint16_BE(len(key_utf8))      # lunghezza chiave
    || key_utf8                       # chiave in UTF-8
    || uint32_BE(len(value))          # lunghezza valore
    || value                          # valore binario
)
```

### 2.3 Internal Node Formula

```
node_hash = BLAKE3(
    0x01                              # prefisso internal node
    || left_hash                      # 32 byte
    || right_hash                     # 32 byte
)
```

### 2.4 Albero di Merkle

- Le foglie sono **ordinate per chiave** (`sorted(leaves, key=lambda l: l.key)`)
- Se N non è potenza di 2, l'ultima foglia viene duplicata
- Se N = 1, `root_hash = leaf_0`
- Se N = 0, `root_hash = 0x00 * 32`

### 2.5 Commitment CBOR

Il commitment è un CBOR canonico dei 5 campi che vengono firmati:

```
_commitment = {
    "root_hash":     bstr .size 32,
    "expiry_date":   uint,
    "mcc_version":   uint,
    "authority_id":  tstr,
    "serial_number": bstr .size 16,
}
authority_sig = Ed25519_sign(authority_sk, _commitment_cbor)
```

NOTA: `leaf_hash` NON è presente nel CBOR trasmesso. Il ricevente lo
ricalcola dalle foglie ricevute.

### 2.6 Critical Mask

```
["agent_pk", "agent_sign_pk", "expiry_date", "authority_id",
 "mcc_version", "serial_number"]
```

Tutti i campi in critical_mask devono essere presenti tra le foglie.

### 2.7 Verifica in 8 Step

1. `mcc_version == 1`
2. `expiry_date > time.time()`
3. Ogni chiave in `critical_mask` è presente in `leaves`
4. Ricalcola `leaf_hash` per ogni foglia, poi `root_hash`
   (ignora eventuali hash trasmessi — devono essere ricalcolati)
5. Recupera `authority_pk` dal RootStore usando `authority_id`
6. Verifica `Ed25519_verify(authority_pk, authority_sig, commitment_cbor)`
7. (Opzionale) `agent_pk == TLS certificate public key`
8. (ATP-Full) `check_revoked(serial_number) == False`

---

## 3. Frame Wire Format

### 3.1 Encoding

Ogni frame è trasmesso come:

```
4 byte: uint32_BE(len(cbor_payload))
N byte: CBOR canonical encoded dict
```

### 3.2 Header comune

```
header = {
    "frame_type":  uint,       # vedi §3.3
    "frame_id":    bstr .size 16,  # UUID v4
    "task_id":     bstr .size 16,  # nil UUID per frame di controllo
    "timestamp":   uint,       # Unix epoch ms
    "atp_version": tstr,       # "1.6.1"
}
```

### 3.3 Tipi di Frame (14)

| Codice | Nome | Descrizione | Fase |
|--------|------|-------------|------|
| 0x01 | TASK_REQUEST | Richiesta di task | Task |
| 0x02 | TASK_RESPONSE | Risposta a task | Task |
| 0x03 | TASK_ACK | Conferma ricezione task | Task |
| 0x04 | TASK_ERROR | Errore task | Task |
| 0x10 | CONTROL_SHUTDOWN | Shutdown graceful | Control |
| 0x11 | CONTROL_REVOKE_NOTIFY | Notifica revoca | Control |
| 0x20 | ERROR | Errore di protocollo | Error |
| 0x21 | ROOT_STORE_UPDATE | Aggiornamento RootStore | Control |
| 0x30 | VERSION_PROPOSE | Proposta versione | Handshake (P2) |
| 0x31 | VERSION_ACK | Conferma versione | Handshake (P2) |
| 0x40 | MCC_BIND_REQUEST | Richiesta binding identità | Handshake (P3) |
| 0x41 | MCC_BIND_RESPONSE | Risposta binding | Handshake (P3) |
| 0x42 | MCC_BIND_CONFIRM | Conferma binding | Handshake (P3) |
| 0x50 | CAPABILITY_EXCHANGE | Scambio capacità | Handshake (P4) |

### 3.4 TASK_REQUEST (0x01)

```
{
    "header": Header,
    "task_type": tstr,             # "deepseek_chat", "echo", o custom
    "task_payload": bstr,          # payload UTF-8 o binario
    "deadline_ms": uint,           # timeout in ms
    "?metadata": {tstr: any},      # opzionale
    "?priority_hint": uint,        # opzionale, default 4
}
```

### 3.5 TASK_RESPONSE (0x02)

```
{
    "header": Header,
    "status": uint,                # 0 = success, >0 = errore
    "result_payload": bstr,        # risultato
    "?partial": bool,              # true se risposta parziale
    "?sequence": uint,             # numero sequenza per streaming
}
```

### 3.6 TASK_ACK (0x03)

```
{ "header": Header }
```

### 3.7 TASK_ERROR (0x04)

```
{
    "header": Header,
    "error_code": uint,            # codice errore
    "error_message": tstr,         # messaggio leggibile
    "?retry_after_ms": uint,       # opzionale
    "?server_time_ms": uint,       # per clock skew fallback
}
```

### 3.8 Frame di Handshake

VERSION_PROPOSE (0x30):
```
{
    "header": Header,
    "atp_versions": [tstr],
    "max_batch_bytes": uint,
    "clock_skew_ms": uint,
    "anti_replay_ttl_ms": uint,
    "rate_limit_rps": uint,
}
```

VERSION_ACK (0x31):
```
{
    "header": Header,
    "selected_version": tstr,
    "max_batch_bytes": uint,
    "clock_skew_ms": uint,
    "anti_replay_ttl_ms": uint,
    "rate_limit_rps": uint,
}
```

MCC_BIND_REQUEST (0x40):
```
{
    "header": Header,
    "mcc_cbor": bstr,              # MCC.cbor()
    "nonce": bstr .size 16,        # CSPRNG nonce
}
```

MCC_BIND_RESPONSE (0x41):
```
{
    "header": Header,
    "mcc_cbor": bstr,
    "nonce": bstr .size 16,
    "signature": bstr .size 64,    # Ed25519_sign(sk, peer_nonce || "atp-bind-response")
}
```

MCC_BIND_CONFIRM (0x42):
```
{
    "header": Header,
    "signature": bstr .size 64,    # Ed25519_sign(sk, peer_nonce || "atp-bind-confirm")
}
```

CAPABILITY_EXCHANGE (0x50):
```
{
    "header": Header,
    "max_tasks": uint,
    "supports_deepseek": bool,
    "atp_version": tstr,
}
```

---

## 4. Error Codes (14)

| Codice | Nome | Disposizione | Descrizione |
|--------|------|-------------|-------------|
| 0x01 | ERR_ATP_VERSION_UNSUPPORTED | close | Versione ATP non supportata |
| 0x02 | ERR_INVALID_ROOT | close | Root hash MCC non valido |
| 0x03 | ERR_MISSING_CRITICAL_CLAIM | close | Claim critica mancante |
| 0x04 | ERR_IDENTITY_MISMATCH | close | Identità non corrispondente |
| 0x05 | ERR_BAD_SIGNATURE | close | Firma non valida |
| 0x06 | ERR_REVOKED | close | Agente o seriale revocato |
| 0x07 | ERR_IDENTITY_NOT_BOUND | close | Identità non ancora vincolata |
| 0x08 | ERR_STREAM_PROTOCOL_VIOLATION | close | Violazione protocollo stream |
| 0x09 | ERR_TASK_TOO_LARGE | close_stream | Task troppo grande |
| 0x0A | ERR_UNSUPPORTED_TASK_TYPE | close_stream | Tipo task non supportato |
| 0x0B | ERR_TASK_TIMEOUT | close_stream | Task scaduto |
| 0x0C | ERR_CLOCK_SKEW | close_stream | Differenza clock eccessiva |
| 0x0D | ERR_RATE_LIMITED | recoverable | Rate limit superato |
| 0x0E | ERR_STREAM_VIOLATION_MINOR | close_stream | Violazione minore dello stream |

**Disposizioni:**
- `close`: chiude la connessione immediatamente
- `close_stream`: chiude solo lo stream task, la connessione resta attiva
- `recoverable`: il client può ritentare dopo `retry_after_ms`

---

## 5. Handshake (5 Fasi)

### 5.1 Fase 1: TLS

Connessione TCP con TLS 1.3. I certificati auto-firmati Ed25519 sono
generati all'avvio (modo demo). In produzione, certificati firmati da CA.

### 5.2 Fase 2: Version Negotiation

```
Initiator → Responder: VERSION_PROPOSE {atp_versions: ["1.6.1"], ...}
Responder → Initiator: VERSION_ACK {selected_version: "1.6.1", ...}
```

I parametri negoziati includono: max_batch_bytes, clock_skew_ms,
anti_replay_ttl_ms, rate_limit_rps.

### 5.3 Fase 3: MCC Exchange & Identity Binding

```
Initiator → Responder: MCC_BIND_REQUEST {mcc: MCC_i, nonce: nonce_i}
Responder verifica MCC_i (8 step)
Responder → Initiator: MCC_BIND_RESPONSE {mcc: MCC_r, nonce: nonce_r,
  signature: Ed25519_sign(sk_r, nonce_i + "atp-bind-response")}
Initiator verifica MCC_r (8 step)
Initiator verifica signature su nonce_i
Initiator → Responder: MCC_BIND_CONFIRM {
  signature: Ed25519_sign(sk_i, nonce_r + "atp-bind-confirm")}
Responder verifica signature su nonce_r
```

**Proof-of-possession strings:**
```
"atp-bind-response"  → firmato da Responder
"atp-bind-confirm"   → firmato da Initiator
```

### 5.4 Fase 4: Capability Exchange

```
Initiator → Responder: CAPABILITY_EXCHANGE {max_tasks, supports_deepseek, ...}
Responder → Initiator: CAPABILITY_EXCHANGE {max_tasks, supports_deepseek, ...}
```

### 5.5 Fase 5: Task Streams

Dopo il binding, i task possono essere inviati in qualsiasi momento.
Il server esegue `handle_task_loop()` che legge frame in arrivo e li
smista agli handler registrati.

---

## 6. Key Separation (ATP-Full)

ATP impone la separazione delle chiavi:

- `agent_pk` (X25519, 32 byte): usata solo per ECDH/TLS
- `agent_sign_pk` (Ed25519, 32 byte): usata solo per firme e proof-of-possession
- `agent_pk != agent_sign_pk` è **obbligatorio** e verificato

Questo elimina il rischio di dual-use attacks (uso improprio della stessa
coppia di chiavi per scopi diversi).

---

## 7. Revocation Subsystem

### 7.1 Cuckoo Filter

- 1024 bucket, 4 slot per bucket, 16-bit fingerprint
- False positive rate: ~2.3 × 10⁻³¹
- Operazioni: insert, contains, remove
- Thread-safe con locking

### 7.2 Root Store

- Authority PKI distribuita
- Ogni autorità registrata con TTL (default 365 giorni)
- Chain-of-manifests per audit trail
- Recupero thread-safe con expiry check

### 7.3 Degradation Policy

| Stato | Finestra | Azione |
|-------|----------|--------|
| CONFIRMED | < 1 ora | Connessione permessa |
| STALE | < 24 ore | Connessione permessa con warning |
| UNCERTAIN | > 24 ore | Connessione rifiutata |

### 7.4 Gossip Protocol

- Fanout: 3 peer
- Intervallo: 5 secondi
- Scambio di serial_number revocati
- Tracciamento dei seriali già noti per evitare loop

---

## 8. Parametri di Configurazione

| Parametro | Default | Descrizione |
|-----------|---------|-------------|
| ATP_VERSION | "1.6.1" | Versione del protocollo |
| SERVER_HOST | "127.0.0.1" | Indirizzo di default |
| SERVER_PORT | 8443 | Porta TLS di default |
| CLOCK_SKEW_MS | 10.000 | Tolleranza clock (10s) |
| ANTI_REPLAY_TTL_MS | 20.000 | Finestra anti-replay (20s) |
| RATE_LIMIT_RPS | 100 | Richieste al secondo massime |
| MAX_BATCH_BYTES | 1.048.576 | Payload massimo (1 MiB) |
| CONNECTION_SETUP_TIMEOUT_MS | 10.000 | Timeout connessione (10s) |
| DEEPSEEK_MODEL | "deepseek-chat" | Modello DeepSeek |
| DEEPSEEK_MAX_TOKENS | 1024 | Token massimi risposta |
| DEEPSEEK_TIMEOUT_S | 60 | Timeout chiamata DeepSeek |

---

## 9. Considerazioni sulla sicurezza

### 9.1 Threat model

- **Attaccante passivo**: non può decifrare il traffico (TLS 1.3)
- **Attaccante attivo (MITM)**: non può falsificare un MCC senza la chiave
  privata dell'autorità
- **Attaccante con chiave compromessa**: può essere revocato via CuckooFilter,
  la revoca si propaga via gossip
- **Replay attack**: prevenuto da nonce challenge e anti-replay TTL (20s)

### 9.2 Limitazioni note

- I certificati auto-firmati non proteggono contro MITM in demo mode
  (accettabile per demo, richiede CA reale in produzione)
- La revoca via gossip è eventualmente consistente: un peer potrebbe non
  ricevere la revoca immediatamente
- La DegradationPolicy è basata su tempo assoluto, non su frequenza di
  aggiornamento

---

*Riferimenti: DRAFT.md (design rationale), authority_system.md (autorità),
docs/code/ (implementazione), start.txt (specifica estesa)*
