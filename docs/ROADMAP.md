# ATP v1.8 — Roadmap

**Agent Transport Protocol — Dettaglio lavori per la versione 1.8**

*Versione: 1.8 (Roadmap)*
*Stato: Pianificazione*
*Data: Luglio 2026*

---

## Panoramica

ATP v1.7.1 ha completato il ciclo di debug e messa in sicurezza:
- Identità MCC con key separation
- Mutual TLS con CA condivisa
- Revoca distribuita con gossip TCP reale
- E2E X25519 ECDH + AES-256-GCM
- Multi-authority chain-of-manifests

v1.8 si concentra su **scalabilità, interoperabilità e maturità** per
deploy su internet con 3+ nodi.

---

## Lotti di Lavoro

### 🥇 Lotto 1 — Authenticated E2E (Alta priorità)

L'E2E ECDH attuale è vulnerabile a MITM che controlla TLS:
un attaccante può sostituire il ciphertext (non decifrarlo, ma
corromperlo). Serve firma Ed25519 sul ciphertext.

**Task:**
- [ ] `_e2e_sign(ciphertext, ed25519_sk)` → signature 64 byte
- [ ] `_e2e_verify(ciphertext, signature, ed25519_pk)` → bool
- [ ] Wrapper AES-GCM + Ed25519: encrypt-then-sign, verify-then-decrypt
- [ ] Aggiornare `send_task` e `_handle_task_request`

**Dipendenze:** Nessuna. Solo cryptography stdlib.

---

### 🥇 Lotto 2 — Multi-Authority Bootstrap (Alta priorità)

Due server ATP indipendenti hanno autorità diverse (`atp-mock-ca`)
e non possono verificare le MCC dell'altro. Serve un protocollo
per scambiarsi i manifest del RootStore.

**Task:**
- [ ] `ROOT_STORE_UPDATE` (0x21) handler implementato in `_dispatch_frame`
- [ ] Client pull: richiedere RootStore al peer dopo handshake
- [ ] Server push: inviare RootStore manifest dopo capability exchange
- [ ] Trust on first use (TOFU): accettare il RootStore del peer
    se non se ne ha uno proprio (bootstrap)

**Dipendenze:** Nessuna. Frame 0x21 già definito in FRAME_TYPES.

---

### 🥈 Lotto 3 — Task Streaming (Media priorità)

TASK_RESPONSE ha già un campo `partial` e `sequence` (SPEC.md §3.5)
ma non sono mai implementati. Task lunghi (DeepSeek, ricerca)
possono inviare risposte parziali.

**Task:**
- [ ] Server: dopo TASK_RESPONSE(partial=true), inviare chunk successivi
- [ ] Client: accumulare chunk finché partial=false
- [ ] Timeout per chunk intermedio (non per task completo)
- [ ] Aggiornare `send_task` per supportare streaming

**Dipendenze:** Lotto 1 (firma E2E per ogni chunk).

---

### 🥈 Lotto 4 — Raw Public Key (RFC 7250) (Media priorità)

La specifica ATP richiede Raw Public Keys (RFC 7250) invece di
certificati X.509. Attualmente usiamo X.509 self-signed per via
del modulo `ssl` standard che non supporta RFC 7250.

**Task:**
- [ ] Valutare `aioquic` che supporta nativamente RFC 7250
- [ ] In alternativa: patch al modulo `ssl` via `PyOpenSSL`
- [ ] Generare chiavi X25519/Ed25519 raw al posto di X.509
- [ ] Verificare interoperabilità tra agenti con e senza RFC 7250

**Dipendenze:** `aioquic` o `pyopenssl`.

---

### 🥉 Lotto 5 — QUIC Migration (Bassa priorità, high effort)

Sostituire TCP + TLS 1.3 con QUIC (RFC 9000). Questo abilita:
- Multiplexing nativo (stream QUIC indipendenti)
- 0-RTT handshake
- Stream migration (connessione mobile)
- No head-of-line blocking
- Native RFC 7250 support

**Task:**
- [ ] Installare `aioquic` come dipendenza opzionale
- [ ] Creare `QUICTransport` che implementa la stessa interfaccia di TCP
- [ ] Adattare `ATPServer` e `ATPClient` per usare QUIC o TCP
- [ ] Mantenere backward compat: TCP per fallback, QUIC preferito
- [ ] Benchmark: latenza, throughput, multiplexing

**Dipendenze:** `aioquic` (Rust, può richiedere build tools su Windows).

---

### 🥉 Lotto 6 — Federation Protocol (Bassa priorità)

Permettere a 3+ nodi ATP di formare una rete federata:
- Scoperta di peer (automatica o manuale)
- Gossip di presenza (heartbeat)
- Routing di task tra nodi (non solo peer-to-peer diretto)

**Task:**
- [ ] `PEER_DISCOVERY` frame per annunciare peer conosciuti
- [ ] Heartbeat periodico tra nodi federati
- [ ] Routing table: instradare task attraverso intermediari
- [ ] Limitare routing a hop count (TTL)

**Dipendenze:** Lotto 2 (RootStore condiviso), Lotto 5 (QUIC).

---

## Timeline stimata

| Lotto | Giorni | Dipende da |
|-------|--------|------------|
| 1 — Authenticated E2E | 1 | — |
| 2 — Multi-authority bootstrap | 2 | — |
| 3 — Task streaming | 2 | Lotto 1 |
| 4 — Raw Public Key | 3 | aioquic disponibile |
| 5 — QUIC Migration | 5-7 | Lotto 4 |
| 6 — Federation Protocol | 4-5 | Lotto 2, Lotto 5 |

**Totale stimato: 17-20 giorni**

---

## Criteri di rilascio v1.8

- [ ] Test: 85+ (75 attuali + 10 nuovi)
- [ ] Almeno 2 nodi indipendenti che si autenticano (multi-authority)
- [ ] Task streaming funzionante (partial=true accumulato)
- [ ] Authenticated E2E attivo di default
- [ ] QUIC funzionante su localhost (aioquic opzionale, TCP fallback)
- [ ] Documentazione aggiornata
