# ATP v1.8 — Agent Transport Protocol

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-60%20passing-brightgreen)]()
[![Stress](https://img.shields.io/badge/stress-200%20t%2Fs%200%25%20error-brightgreen)]()

**ATP (Agent Transport Protocol) è un protocollo crittografico peer-to-peer per la comunicazione tra agenti software autonomi.** Fornisce un canale cifrato e verificabile dove ogni agente possiede una identità autocertificata (MCC) e ogni messaggio è firmato — senza server centrale, senza intermediari.

---

## Il protocollo in una frase

Due agenti software vogliono comunicare in modo sicuro. Non si fidano l'uno dell'altro, non condividono un server centrale, potrebbero essere su continenti diversi. ATP permette loro di:

1. **Identificarsi** — ogni agente presenta un documento di identità crittografico (MCC)
2. **Verificarsi** — dimostrano il possesso delle proprie chiavi private (proof-of-possession)
3. **Comunicare** — si scambiano task e risposte in modo cifrato e firmato
4. **Revocarsi** — se un agente è compromesso, la sua identità viene revocata e la revoca si propaga a tutti i peer

Tutto senza server centrale, senza intermediari, senza configurazione di rete.

---

## Cooperazione agentica a ogni livello

ATP è progettato per abilitare la cooperazione tra agenti autonomi a qualsiasi scala: dal singolo ricercatore al governo nazionale.

### 🧑 Livello Individuale / Open

Un ricercatore, uno sviluppatore, un hobbista — chiunque può far comunicare i propri agenti AI senza chiedere permessi a nessuno.

```
AgenteA (locale) ──ATP──→ AgenteB (locale)     → test, debug, prototipi
AgenteC (casa)    ──ATP──→ AgenteD (cloud)      → uso personale, assistenti
```

- **Zero configurazione** — tunnel UPnP nativo integrato, niente firewall
- **Zero costi** — protocollo open source, infrastructure-free
- **Zero dipendenze** — funziona su una singola macchina o tra due

```python
# Due agenti che collaborano in 10 righe
from atp_sdk import SimpleATPServer, SimpleATPClient

server = SimpleATPServer(); await server.start()
client = SimpleATPClient("mio-agente"); await client.connect()
risultato = await client.chat("Cerca su DeepSeek le ultime scoperte sulle reti neurali")
```

---

### 🏢 Livello Aziendale

Un'azienda ha reparti diversi (R&D, Operations, Security, HR, Finance). Ogni reparto ha il proprio agente AI specializzato. Con ATP comunicano direttamente, senza un backend centrale che intermedi:

```
Agente R&D  ──ATP──→ Agente Operations     → chiede dati di produzione
Agente Ops  ──ATP──→ Agente Security       → segnala anomalia in tempo reale
Agente HR   ──ATP──→ Database dipendenti   → aggiorna ferie in forma anonima
Agente Finanza ──ATP──→ Agente R&D         → approva budget progetto
```

Due sedi aziendali con abbonamenti AI diversi (es. Sede A con ChatGPT, Sede B con Claude) possono condividere le rispettive AI via ATP — ogni sede espone la propria AI tramite il proprio server ATP, l'altra sede la chiama in modo sicuro e verificabile, senza condividere le chiavi API:

```
Sede A (Roma, ChatGPT) ──ATP──→ Sede B (Milano, Claude)
Sede B (Milano, Claude) ──ATP──→ Sede A (Roma, ChatGPT)
```

Vedi `sdk/examples/azienda.py` — esempio funzionante con chiamate DeepSeek reali.

---

### 🏛️ Livello Governativo / Pubblica Amministrazione

Enti diversi (Comune, ASL, Agenzia delle Entrate, INPS, Ministeri) hanno ciascuno il proprio agente AI. Devono scambiarsi dati e verifiche in modo sicuro, senza un intermediario centrale che veda tutti i dati:

```
Comune           ──ATP──→ ASL              → verifica residenza per esenzione ticket
ASL              ──ATP──→ Agenzia Entrate  → verifica ISEE
INPS             ──ATP──→ Comune           → verifica stato occupazionale
Ministero Istruzione ──ATP──→ Scuola Futura → aggiornamento albo docenti
```

Ogni ente mantiene il controllo dei propri dati. Le comunicazioni sono peer-to-peer, cifrate, firmate. Nessun intermediario può leggere, bloccare o alterare lo scambio.

---

### 🏠 Livello Privato / Personale

Un professionista (medico, avvocato, commercialista) gestisce i propri agenti AI personali. Questi agenti comunicano con i sistemi dei clienti, degli studi associati, delle banche — sempre in modo sicuro e verificabile:

```
Avvocato (studio)    ──ATP──→ Agente Cliente   → scambio documenti riservati
Medico (ambulatorio) ──ATP──→ ASL              → referti digitali firmati
Commercialista        ──ATP──→ Agente Azienda   → bilancio, dichiarazioni
```

---

### 🏫 Livello Educativo

Scuola, università, enti di formazione. Un insegnante a casa comunica col server scolastico per inviare piani didattici, consultare voti, assegnare compiti, segnalare incidenti — tutto via internet senza VPN né configurazione di rete:

```
Prof. Rossi (casa) ──ATP──→ Scuola Futura
```

Vedi `sdk/examples/teacher_school.py` — 5 use case reali con tunnel internet zero-config.

---

## Architettura

```
┌──────────────────────┐     TLS 1.3     ┌──────────────────────┐
│      Agente A        │ ◄─────────────► │      Agente B        │
│  ┌────────────────┐  │                 │  ┌────────────────┐  │
│  │  MCC identità  │  │  MCC exchange   │  │  MCC identità  │  │
│  │  Ed25519+X25519│  │  + handshake    │  │  Ed25519+X25519│  │
│  └────────────────┘  │                 │  └────────────────┘  │
│  ┌────────────────┐  │  Task Request   │  ┌────────────────┐  │
│  │  send_task()   │  │  → ACK → Resp  │  │  handle_task() │  │
│  └────────────────┘  │                 │  └────────────────┘  │
└──────────────────────┘                 └──────────────────────┘
          │                                        │
          │  ┌──────────────────────────────────┐  │
          │  │  Revocation (Cuckoo + Gossip)    │  │
          │  │  RootStore (JSON o SQLite)       │  │
          │  │  DegradationPolicy (freschezza)  │  │
          │  └──────────────────────────────────┘  │
          │                                        │
          │  ┌──────────────────────────────────┐  │
          │  │  Federation (v2.0)               │  │
          │  │  PEER_DISCOVERY (firmato)        │  │
          │  │  TASK_FORWARD (firmato)          │  │
          │  │  Heartbeat / Routing Table       │  │
          │  └──────────────────────────────────┘  │
```

## Quick Start

### 1. Installa l'SDK

```bash
# Dalla directory principale del progetto ATP
cd sdk
pip install -e .                    # installazione base (core + tunnel UPnP nativo)
pip install -e ".[all]"             # tutto (dashboard, tunnel completo)
pip install aioquic                 # QUIC transport (opzionale, v1.8+)
```

L'SDK installa automaticamente tutte le dipendenze necessarie:
`aiohttp`, `blake3`, `cbor2`, `cryptography`.

### 2. Usa l'SDK

```python
from atp_sdk import SimpleATPClient, SimpleATPServer

# Server
server = SimpleATPServer()
await server.start(port=8443)

# Client
client = SimpleATPClient("mio-agente")
await client.connect(port=8443)
response = await client.chat("Quali sono i vantaggi di ATP?")
print(response)
```

Il bootstrap della fiducia è `strict` di default. Per demo controllate tra
macchine diverse usa `trust_bootstrap_mode="tofu"` su client/server; per
produzione pre-provisiona il RootStore o distribuisci manifest
`authority-chain` firmati da una authority già fidata.

### 3. Esegui gli esempi

Tutti gli esempi sono in `sdk/examples/`:

```bash
cd sdk/examples

# Due sedi aziendali che condividono AI via ATP (DeepSeek reale)
python azienda.py both

# Insegnante ↔ Scuola (3 agenti: research → factcheck → summarize)
python research_assistant.py

# Code review pipeline (3 agenti: dev → review → fix)
python code_review_pipeline.py

# Governance distribuita (4 agenti votano con attestazione MCC)
python agent_voting.py

# Rete federata 3 nodi
python federation_example.py

# Server scolastico standalone + client interattivo
python school_server.py
python teacher_client.py

# Connessione via internet (tunnel UPnP locale)
python teacher_client.py 192.168.1.50:8443
```

| Esempio | Agenti | Scenario |
|---------|--------|----------|
| `azienda.py` | 2 | Due sedi condividono AI via ATP (DeepSeek reale) |
| `research_assistant.py` | 3 | Researcher → FactChecker → Summarizer |
| `code_review_pipeline.py` | 3 | Developer → Reviewer → Fixer |
| `agent_voting.py` | 4 | Governance distribuita con attestazione MCC |
| `teacher_school.py` | 2 | Insegnante ↔ scuola via internet |
| `school_server.py` | 1 | Server scolastico con tunnel internet |
| `teacher_client.py` | 1 | Client insegnante con menu interattivo |
| `quic_example.py` | 2 | Server + client QUIC (RFC 9000) |
| `federation_example.py` | 3 | Rete federata 3 nodi |

---

## Documentazione

| Documento | Contenuto |
|-----------|-----------|
| `docs/DRAFT.md` | Design rationale, motivazioni, decisioni chiave |
| `docs/SPEC.md` | Specifica tecnica completa, CDDL, frame, error codes |
| `docs/RFC.md` | RFC formale con RFC2119, riferimenti normativi |
| `docs/SDK_SPEC.md` | **Cross-language SDK spec** — implementa ATP in Go, Rust, JS |
| `docs/ROADMAP.md` | Stato avanzamento v1.8 (100% completata) |
| `docs/authority_system.md` | Sistema delle autorità (5 livelli: lab → internet) |
| `sdk/DOCS.md` | Guida all'uso dell'SDK |
| `sdk/API.md` | Reference completa di ogni classe e metodo |
| `sdk/DEPLOY.md` | Guida deploy su due macchine |

---

## Features v1.8

### 🔐 Crittografia
- **Ed25519** — firme digitali, certificati, proof-of-possession
- **X25519** — ECDH key agreement per crittografia end-to-end
- **AES-256-GCM** — cifratura simmetrica dei payload task (X25519 ECDH + BLAKE3 KDF)
- **Authenticated E2E** — encrypt-then-sign: AES-256-GCM + Ed25519 firma sul ciphertext
- **BLAKE3** — hash veloce (obbligatorio, **nessun fallback**)
- **Key separation** — X25519 ≠ Ed25519 obbligatoria (anti dual-use)
- **Mutual TLS** — CA condivisa, CERT_REQUIRED su entrambi i lati
- **mTLS cert rotation** automatica con hot-reload (`reload_ssl()`)

### 🆔 Merkle-Claim Card
- Documento di identità verificabile come albero di Merkle
- Foglie con salt individuali (resistenza pre-immagine)
- 8 step di verifica: versione, scadenza, signature, **revoca sempre obbligatoria**
- `leaf_hash` mai trasmesso — il ricevente lo ricalcola
- **Key separation obbligatoria** verificata in `MCC.verify()` step 7.5

### 🤝 Handshake 5 fasi: TLS → Version → MCC → Capability → Task

### ⚡ Task lifecycle
- **24 frame types**, 15 error codes, CBOR canonical encoding
- Antireplay (20s), rate limiting (100 RPS), handshake rate limiter (10/s IP)
- Clock skew (10s con fallback server_time_ms)
- **Multiplexing per task_id** — task concorrenti sulla stessa connessione
- **Task streaming** — partial=true / sequence, risposte parziali accumulate
- **Errori strutturati** — send_task ritorna {status, data, error_code, error_message}

### 🔄 Revoca distribuita
- **Cuckoo Filter** (FPR ≈2.3e⁻³¹) — filtraggio probabilistico
- **RootStore** — PKI distribuita con chain-of-manifests
  - Backend **JSON** (default) o **SQLite** (WAL mode, multi-processo)
  - Stato runtime fuori repo: default `~/.atp/root_store.json` o `.db`
  - `add_authority` idempotente — stessa chiave = nessun version drift
- **Gossip TCP** — seriali revocati trasmessi a peer su porta 8444
- **Degradation Policy** — CONFIRMED → STALE → UNCERTAIN

### ⚡ I/O Buffering
- **`BufferedFrameReader`** — lettura chunk 64KB, buffer interno
- Riduce le syscall di lettura da 2 a ~1 per frame
- Attivo di default (`USE_BUFFERED_READER=True`)
- **Throughput misurato: 200+ task/s**, P50 31ms, P99 95ms, 0% errori

### 🚀 QUIC Transport (RFC 9000)
- Multiplexing nativo (stream QUIC indipendenti, no head-of-line blocking)
- 0-RTT handshake, stream migration, ECN support
- aioquic 1.3.0 (opzionale, TCP fallback automatico)
- `QUICServer` e `QUICClient` in `atp_quic.py`

### 🔗 Federation Protocol (v2.0)
- **PEER_DISCOVERY (0x60)** — firmato Ed25519, verificato su ricezione
- **PEER_HEARTBEAT (0x61)** — keepalive 15s, timeout 90s
- **TASK_FORWARD (0x62)** — firmato Ed25519, TTL ≤ 5 hop
- **Routing table** — max 100 peer, auto-pulizia peer morti
- **Connection pool** — outbound pool, idle timeout 300s
- **No unsigned fallback** — discovery e forwarding non firmati vengono ignorati

### 🌐 Tunnel internet zero-config
- UPnP nativo (pure Python, zero dipendenze)
- Key Card Ed25519 per connessione diretta (zero servizi esterni)

### 📊 Dashboard e metriche
- Dashboard PySide6 (5 tab: Overview, Traffic, Connections, Agents, Tasks)
- **Metriche Prometheus** — headless-ready su `/metrics`
- **Health check HTTP** — `/health`, `/ready`, `/metrics`
- **JSON structured logging** — ELK-ready
- **Graceful shutdown** — SIGTERM, drain 15s
- **Circuit breaker** — DeepSeek (soglia 5, reset 30s)
- **Connection limiter** — default 100 connessioni

### 🔗 Multi-authority bootstrap
- **ROOT_STORE_UPDATE (0x21)** — scambio di manifest firmati dopo handshake
- `rootstore-advertisement` è firmato dall'agente autenticato ed è solo informativo
- `authority-chain` è firmato da una authority già fidata ed è l'unico manifest che può aggiungere authority
- Default `strict`; `trust_bootstrap_mode="tofu"` abilita pinning esplicito via `authority_pk`

### 📐 Cross-language SDK SPEC
- `docs/SDK_SPEC.md` — wire format esatto con CDDL, esempi byte-level
- Implementabile in Go, Rust, Node.js, Java, C#
- Checklist implementativa di 20 punti

---

## Integrazione con Hermes Agent

ATP è disponibile come skill per **Hermes Agent** (by Nous Research).
Per attivarla in una sessione Hermes:

```bash
skill_view(name='atp-protocol-skill')
```

---

## Metriche

| Metrica | Valore |
|---------|--------|
| Test pytest | 60/60 ✅ |
| Security test | PASS ✅ |
| Federation test | PASS ✅ |
| Warning runtime | 1 warning Pydantic esterno |

---

## Progetti correlati

- **SDK Python** — `pip install -e .[all]` in `sdk/` — SimpleATPClient, SimpleATPServer, Tunnel
- **SDK_SPEC** — `docs/SDK_SPEC.md` — cross-language implementation guide
- **Documenti RFC/Spec** — `docs/RFC.md`, `docs/SPEC.md`, `docs/DRAFT.md`
- **Roadmap** — `docs/ROADMAP.md` — **100% completata**

## Licenza

MIT — vedi [LICENSE](LICENSE).

---

*ATP permette agli agenti AI di cooperare a ogni livello: personale, aziendale, governativo, globale. Senza server centrale, senza intermediari, senza compromessi sulla sicurezza.*
