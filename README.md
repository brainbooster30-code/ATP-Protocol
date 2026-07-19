# ATP v1.7 — Agent Transport Protocol

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

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

- **Zero configurazione** — tunnel ngrok integrato, niente firewall
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

**Vantaggi per l'azienda:**
- Le chiavi API AI non vengono condivise tra sedi
- Ogni transazione è firmata e verificabile (non ripudio)
- Zero infrastruttura centralizzata (nessun server da mantenere)
- Ogni agente opera con la propria identità e le proprie credenziali

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

**Vantaggi per la PA:**
- **Sovranità dei dati** — ogni ente mantiene il controllo dei propri dati
- **Interoperabilità senza intermediario** — non serve un "hub" centrale
- **Audit trail forense** — ogni scambio è firmato, tracciabile, non ripudiabile
- **Resilienza** — se un ente cade, gli altri continuano a comunicare

---

### 🏠 Livello Privato / Personale

Un professionista (medico, avvocato, commercialista) gestisce i propri agenti AI personali. Questi agenti comunicano con i sistemi dei clienti, degli studi associati, delle banche — sempre in modo sicuro e verificabile:

```
Avvocato (studio)    ──ATP──→ Agente Cliente   → scambio documenti riservati
Medico (ambulatorio) ──ATP──→ ASL              → referti digitali firmati
Commercialista        ──ATP──→ Agente Azienda   → bilancio, dichiarazioni
```

**Vantaggi per il privato:**
- I dati sensibili non passano per server centrali
- Ogni scambio è firmato con la propria identità crittografica
- Il professionista mantiene il pieno controllo dei propri dati

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
          │  │  RootStore (authority PKI)       │  │
          │  │  DegradationPolicy (freschezza)  │  │
          │  └──────────────────────────────────┘  │
```

## Quick Start

### 1. Installa l'SDK

```bash
# Dalla directory principale del progetto ATP
cd sdk
pip install -e .                    # installazione base
pip install -e ".[all]"             # tutto (dashboard, tunnel)
pip install -e ".[tunnel]"          # solo tunnel internet (ngrok)
```

L'SDK installa automaticamente tutte le dipendenze necessarie:
`aiohttp`, `blake3`, `cbor2`, `cryptography`.

Se vuoi il tunnel internet zero-config (ngrok):
```bash
pip install pyngrok
setx NGROK_AUTH_TOKEN "tuo_token"   # Windows
# export NGROK_AUTH_TOKEN=tuo_token # Linux/macOS
```

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

# Server scolastico standalone + client interattivo
python school_server.py            # terminale 1: avvia server
python teacher_client.py           # terminale 2: menu interattivo

# Connessione via internet (tunnel auto)
python teacher_client.py 2.tcp.ngrok.io:12345
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

---

## Documentazione

| Documento | Contenuto |
|-----------|-----------|
| `docs/DRAFT.md` | Design rationale, motivazioni, decisioni chiave |
| `docs/SPEC.md` | Specifica tecnica completa, CDDL, frame, error codes |
| `docs/RFC.md` | RFC formale con RFC2119, riferimenti normativi |
| `docs/authority_system.md` | Sistema delle autorità (5 livelli: lab → internet) |
| `sdk/DOCS.md` | Guida all'uso dell'SDK |
| `sdk/API.md` | Reference completa di ogni classe e metodo |
| `sdk/DEPLOY.md` | Guida deploy su due macchine |

---

## Features

### 🔐 Crittografia
- **Ed25519** — firme digitali, certificati, proof-of-possession
- **X25519** — key agreement (ECDH, riservato per crittografia end-to-end futura)
- **BLAKE3** — hash veloce (fallback BLAKE2b-256)
- **Key separation** — X25519 ≠ Ed25519 obbligatoria (anti dual-use)

### 🆔 Merkle-Claim Card
- Documento di identità verificabile come albero di Merkle
- Foglie con salt individuali (resistenza pre-immagine)
- 8 step di verifica: versione, scadenza, signature, revoca
- `leaf_hash` mai trasmesso — il ricevente lo ricalcola

### 🤝 Handshake 5 fasi: TLS → Version → MCC → Capability → Task

### ⚡ Task lifecycle
- 14 frame types, 14 error codes, CBOR canonical encoding
- Anti-replay (20s), rate limiting (100 RPS), clock skew (10s)

### 🔄 Revoca distribuita
- Cuckoo Filter (FPR ~2.3e-31), RootStore, Degradation Policy, Gossip

### 🌐 Tunnel internet zero-config
- Connessione tra agenti su internet senza aprire firewall

### 📊 Dashboard PySide6
- 5 tab: Overview, Traffic, Connections, Agents, Tasks

---

## Integrazione con Hermes Agent

ATP è disponibile come skill per **Hermes Agent** (by Nous Research).
Per attivarla in una sessione Hermes:

```bash
# Carica la skill utente (raccomandato — esempi, SDK, tunnel)
skill_view(name='atp-protocol-skill')

# Oppure la skill tecnica (specifica protocollo, pitfall)
skill_view(name='atp-protocol')
```

Le skill includono: installazione SDK, quick start, pattern di cooperazione
multi-agente, tunnel internet zero-config e API reference completa.

---

## Progetti correlati

- **SDK Python** — `pip install -e .[all]` in `sdk/` — SimpleATPClient, SimpleATPServer, Tunnel
- **Documenti RFC/Spec** — `docs/RFC.md`, `docs/SPEC.md`, `docs/DRAFT.md`
- **Graphify Graph** — `graphify-out/` — knowledge graph (285 nodi, 559 edge)

## Licenza

MIT — vedi [LICENSE](LICENSE).

---

*ATP permette agli agenti AI di cooperare a ogni livello: personale, aziendale, governativo, globale. Senza server centrale, senza intermediari, senza compromessi sulla sicurezza.*
