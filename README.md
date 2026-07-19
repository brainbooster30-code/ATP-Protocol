# ATP v1.6.1 — Agent Transport Protocol

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**ATP (Agent Transport Protocol) è un protocollo crittografico per la comunicazione peer-to-peer tra agenti software autonomi.**

Fornisce un canale cifrato e verificabile dove ogni agente possiede una identità autocertificata (MCC) e ogni messaggio è firmato crittograficamente — senza server centrale, senza intermediari.

## Cosa risolve ATP?

Gli agenti AI oggi comunicano prevalentemente via API REST centralizzate:
ogni agente dipende da un server che autentica, autorizza e instrada le
richieste. Questo crea un **single point of failure** fiduciario e
infrastrutturale. ATP inverte il paradigma:

| Problema | Soluzione ATP |
|----------|---------------|
| **Identità** — come verifico chi è l'agente dall'altra parte? | **MCC** (Merkle-Claim Card): documento di identità autocertificato, firmato da un'autorità, verificabile senza server centrale |
| **Fiducia** — come so che un messaggio non è stato manomesso? | **Proof-of-possession**: ogni agente dimostra il possesso della propria chiave privata durante l'handshake |
| **Privacy** — come evito che un server centrale legga tutte le conversazioni? | **TLS peer-to-peer**: connessione diretta, nessun intermediario |
| **Revoca** — come disabilito un agente compromesso? | **Cuckoo Filter + Gossip**: la revoca si propaga a tutti i peer senza server centrale |
| **Deploy** — come connetto due agenti su internet senza configurare firewall? | **Tunnel ngrok integrato**: zero-config, nessun port forwarding |

## Cosa puoi fare con ATP?

### 🏭 Enterprise — Automazione e integrazione tra sistemi

Un'azienda con più reparti (R&D, Operations, Security, HR) può far comunicare
i propri agenti AI interni senza un server centrale che autentichi tutto:

```
Agente R&D  ──ATP──→ Agente Operations     → chiede dati di produzione
Agente Ops  ──ATP──→ Agente Security       → segnala anomalia in tempo reale
Agente HR   ──ATP──→ Database dipendenti   → aggiorna ferie in forma anonima
```

Ogni agente ha la propria identità crittografica (MCC). Le comunicazioni sono
dirette, cifrate, verificabili. Nessun singolo punto di fallimento.

### 🔬 R&D — Ricerca distribuita multi-agente

Un laboratorio di ricerca usa 3 agenti specializzati che collaborano:

```python
# Researcher → FactChecker → Summarizer
researcher.chat("Quali sono le ultime scoperte sui transformer?")
factchecker.chat("Verifica: l'attention lineare scala meglio?")
summarizer.chat("Produci un executive summary di 3 punti")
```

Ogni passo è firmato — la provenienza delle informazioni è tracciabile.
Utile per revisioni bibliografiche, meta-analisi, systematic review.

### 🏦 Finanza — Audit trail inalterabile

```python
@server.on_task("approve_transaction")
async def handle_approval(task_type, payload):
    # L'identità MCC dell'agente firmatario è verificabile
    # Il log ATP è una catena di custodia forense
    return f"Transazione {payload} approvata da {agent.mcc_hash}"
```

Ogni transazione è legata all'identità crittografica dell'agente che l'ha
autorizzata — non ripudiabile, verificabile da terze parti.

### 🏛️ Pubblica Amministrazione — Interoperabilità tra enti

Comune, ASL, Agenzia delle Entrate — ognuno ha il proprio agente AI.
Possono scambiarsi dati e verifiche senza un intermediario centrale:

```
Comune ──ATP──→ ASL           → verifica residenza per esenzione ticket
ASL    ──ATP──→ Agenzia Entrate → verifica ISEE
```

### 🏫 Scuola — Insegnante ↔ Istituto via internet (demo funzionante)

Vedi `sdk/examples/teacher_school.py`. Prof. Rossi a casa interagisce con
il server scolastico senza VPN, senza firewall, senza configurazione di rete.
Tunnel ngrok integrato per connessione zero-config via internet.

### 🗳️ Governance distribuita — 4 agenti votano una decisione

```python
# Ogni agente vota con la propria identità crittografica:
agent-alpha: APPROVE  MCC=ee84bca8...
agent-beta:  APPROVE  MCC=7c382ed1...
agent-gamma: REJECT   MCC=a06349bc...
agent-delta: APPROVE  MCC=60255e71...
result: APPROVED (3/4 votes)
```

Ogni voto è attestato dal MCC dell'agente — trasparente, verificabile,
non ripudiabile.

### 💬 Chat con DeepSeek — 2 agenti, risposte firmate

Qualsiasi agente può interrogare DeepSeek via protocollo ATP e ottenere
risposte crittograficamente attestate.

## Architettura

```
┌───────────────────────┐     TLS 1.3     ┌───────────────────────┐
│      ATP Agent A      │ ◄─────────────► │      ATP Agent B      │
│  ┌─────────────────┐  │                 │  ┌─────────────────┐  │
│  │  MCC: identità  │  │  MCC exchange   │  │  MCC: identità  │  │
│  │  Ed25519+X25519 │  │  + handshake    │  │  Ed25519+X25519 │  │
│  └─────────────────┘  │                 │  └─────────────────┘  │
│  ┌─────────────────┐  │  Task request   │  ┌─────────────────┐  │
│  │  task_stream()  │  │  → ACK → resp  │  │  handle_task()  │  │
│  └─────────────────┘  │                 │  └─────────────────┘  │
└───────────────────────┘                 └───────────────────────┘
```

## Features

### 🔐 Crittografia
- **Ed25519** — firme digitali, certificati self-signed, proof-of-possession
- **X25519** — key agreement (ECDH, riservato per crittografia end-to-end futura)
- **BLAKE3** — hash veloce (fallback BLAKE2b-256)
- **Separazione delle chiavi** — X25519 ≠ Ed25519, obbligatoria

### 🆔 Merkle-Claim Card (MCC)
Documento di identità verificabile costruito come albero di Merkle:
- Foglie multiple con salt individuali (resistenza pre-immagine)
- 8 step di verifica: versione, scadenza, critical mask, root ricalcolato,
  firma autorità sul commitment CBOR, revoca
- Le foglie sono ordinate per chiave (albero deterministico)
- `leaf_hash` mai trasmesso — il ricevente lo ricalcola

### 🤝 Handshake in 5 fasi
| Fase | Descrizione |
|------|-------------|
| 1. TLS | Connessione cifrata con certificato auto-firmato |
| 2. Negoziazione versione | VERSION_PROPOSE / VERSION_ACK |
| 3. Scambio MCC + identity binding | 3 messaggi con nonce challenge e proof-of-possession Ed25519 |
| 4. Scambio capacità | CAPABILITY_EXCHANGE: max_tasks, supports_deepseek, atp_version |
| 5. Task stream | TASK_REQUEST → TASK_ACK → TASK_RESPONSE |

### ⚡ Task lifecycle
- Task asincroni via `aiohttp`
- Integrazione DeepSeek AI
- Anti-replay (20 s), rate limiting (100 RPS), clock skew (10 s)
- 14 tipi di frame, 14 codici di errore

### 📊 Dashboard (PySide6)
- 5 tab: Overview, Traffic, Connections, Agents, Tasks
- Monitor eventi in tempo reale
- Grafico traffico Matplotlib (60s rolling window)
- 3 agenti concorrenti: 1 server + 2 client

### 🔄 Revoca distribuita
- **Cuckoo Filter** — membership query spazio-efficiente (FPR ~2.3e-31)
- **Root Store** — PKI delle autorità fidate con chain-of-manifests
- **Degradation Policy** — CONFIRMED / STALE / UNCERTAIN
- **Gossip Protocol** — distribuzione fanout della revoca

### 🌐 Tunnel internet zero-config
Connessione tra agenti su internet senza aprire firewall o configurare
port forwarding — integrato con ngrok (opzionale).

## Quick Start

### Con l'SDK (raccomandato)

```bash
cd ATP/sdk
pip install -e .
```

```python
from atp_sdk import SimpleATPClient, SimpleATPServer

# Server
server = SimpleATPServer()
await server.start(port=8443)

# Client
client = SimpleATPClient("mio-agente")
await client.connect(port=8443)
response = await client.chat("Ciao! Spiega ATP in una frase")
print(response)
```

### Con la dashboard
```bash
pip install -r requirements.txt
python main.py
```

## Esempi pronti

Tutti gli esempi sono in `sdk/examples/`:
```bash
python examples/research_assistant.py      # 3 agenti: ricerca
python examples/code_review_pipeline.py     # 3 agenti: code review
python examples/teacher_school.py           # 2 agenti: scuola
python examples/agent_voting.py             # 4 agenti: voto
```

## Progetti correlati

- **SDK Python** — `pip install -e .[all]` in `sdk/` — API semplice per integrare ATP nei tuoi agenti
- **Obsidian Vault** — `obsidian-vault/` — documentazione del protocollo in markdown linkabile
- **Graphify Graph** — `graphify-out/` — knowledge graph dell'intero codebase (285 nodi, 559 edge)

## Configurazione

| Parametro | Default | Descrizione |
|-----------|---------|-------------|
| `SERVER_PORT` | 8443 | Porta TLS server |
| `CLOCK_SKEW_MS` | 10.000 | Tolleranza clock |
| `ANTI_REPLAY_TTL_MS` | 20.000 | Finestra anti-replay |
| `RATE_LIMIT_RPS` | 100 | Richieste al secondo |
| `DEEPSEEK_API_KEY` | *(env/registry)* | Chiave DeepSeek (trovata automaticamente) |

## Struttura del progetto

```
ATP/
├── main.py              # Entry point (dashboard)
├── atp_core.py          # Crittografia, MCC, frame CBOR
├── agent.py             # ATPAgent: handshake, task lifecycle
├── server.py            # Server TCP/TLS
├── client.py            # Client ATP
├── dashboard.py         # GUI PySide6 (5 tab)
├── monitor.py           # Event collector thread-safe
├── revocation.py        # CuckooFilter, RootStore, Gossip
├── authority.py         # Autorità di certificazione mock
├── config.py            # Parametri e risoluzione API key
├── sdk/                 # SDK Python installabile
│   ├── atp_sdk/         #  SimpleATPClient + SimpleATPServer
│   ├── examples/        #  6 esempi reali
│   └── DEPLOY.md        #  Guida deploy
├── obsidian-vault/      # Documentazione markdown
└── graphify-out/        # Knowledge graph
```

## Dipendenze

- `blake3`, `cbor2`, `cryptography` — core crittografico
- `aiohttp` — chiamate DeepSeek API
- `PySide6`, `matplotlib` — dashboard GUI
- `pyngrok` — tunnel internet (opzionale)

## Licenza

MIT — vedi [LICENSE](LICENSE).

---

*Costruito per permettere agli agenti AI di comunicare in modo libero, sicuro e verificabile, senza dipendere da intermediari.*
