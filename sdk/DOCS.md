# ATP SDK v1.8 — Documentation

Python SDK per il protocollo ATP (Agent Transport Protocol) v1.8. Connette agenti AI
in reti federate sicure in poche righe di codice.

## Installazione

```bash
```
pip install -e .              # core + tunnel UPnP nativo: aiohttp, blake3, cbor2, cryptography
pip install -e ".[all]"       # tutto incluso dashboard
pip install aioquic           # QUIC transport (opzionale, v1.8+)

# Federation è nativa — nessuna dipendenza extra
```

**Il tunnel internet non richiede dipendenze esterne** — UPnP nativo
pure Python. Se il router supporta UPnP, apre la porta automaticamente.

## Architettura

```
┌──────────────────────────────────────┐
│           atp_sdk (SDK)              │
│  ┌────────────┐  ┌────────────────┐  │
│  │   client   │  │     server     │  │
│  │ .connect() │  │ .start()       │  │
│  │ .chat()    │  │ .stop()        │  │
│  │ .send()    │  │ .on_task()     │  │
│  │ .close()   │  │ .register()    │  │
│  └─────┬──────┘  └───────┬────────┘  │
│        │                 │           │
├────────┴─────────────────┴───────────┤
│        ATP Protocol (parent)         │
│  agent │ atp_core │ authority │ ...  │
└──────────────────────────────────────┘
```

L'SDK importa il protocollo padre aggiungendo `sys.path`. Non modifica il codice originale.

---

# API Reference

## SimpleATPClient

Client asincrono. Gestisce automaticamente TLS, MCC, handshake ATP in 5 fasi.

### Costruttore

```python
SimpleATPClient(agent_name: str = "atp-sdk-client",
                monitor: Optional[Monitor] = None)
```

| Parametro | Default | Descrizione |
|-----------|---------|-------------|
| `agent_name` | `"atp-sdk-client"` | Nome dell'agente (inserito nell'MCC) |
| `monitor` | `None` | Monitor opzionale per eventi di protocollo |

---

### connect()

```python
await client.connect(host: str = "127.0.0.1",
                     port: int = 8443,
                     timeout: float | None = None) -> bool
```

Connette al server ATP ed esegue l'handshake completo:
1. Connessione TLS mutuo (certificati firmati da CA condivisa, verifica obbligatoria)
2. Creazione identità + MCC con chiavi Ed25519/X25519
3. Negoziazione versione
4. Scambio MCC e identity binding con proof-of-possession
5. Scambio capacità

| Parametro | Default | Descrizione |
|-----------|---------|-------------|
| `host` | `"127.0.0.1"` | IP o hostname del server |
| `port` | `8443` | Porta TLS del server |
| `timeout` | da config | Timeout connessione in secondi |

Restituisce `True` se connesso e vincolato, `False` altrimenti.

---

### chat()

```python
await client.chat(prompt: str) -> str
```

Invia un prompt a DeepSeek tramite il server ATP e restituisce la risposta.

```python
response = await client.chat("Spiega la crittografia asimmetrica")
print(response)
# → "La crittografia asimmetrica usa una coppia di chiavi..."
```

Restituisce la risposta testuale del modello, o `"[Error: ...]"` in caso di errore.

---

### send()

```python
await client.send(task_type: str,
                  payload: str,
                  deadline_ms: int = 30_000) -> dict | None
```

Invia un task generico al server. Supporta tipi di task personalizzati.

| Parametro | Default | Descrizione |
|-----------|---------|-------------|
| `task_type` | — | Tipo task (`"deepseek_chat"`, `"echo"`, o custom) |
| `payload` | — | Payload stringa (max 64 KB) |
| `deadline_ms` | `30000` | Timeout task in millisecondi |

Restituisce `{"status": int, "result": str, "raw": dict}` o `None`.

La risposta JSON del server viene automaticamente estratta: `{"result": "testo"}` → `result = "testo"`.

---

### echo()

```python
await client.echo(message: str) -> str
```

Test di connettività — invia un messaggio e lo riceve indietro.

```python
assert await client.echo("ping") == "ping"
```

---

### close()

```python
await client.close() -> None
```

Chiude la connessione con shutdown TLS corretto. Sicuro da chiamare più volte.

---

### Proprietà

| Proprietà | Tipo | Descrizione |
|-----------|------|-------------|
| `connected` | `bool` | `True` se connesso e vincolato |
| `peer_mcc_hash` | `str \| None` | Hash hex del MCC root del peer |

---

### Context Manager

```python
async with SimpleATPClient("agent") as client:
    await client.connect()
    response = await client.chat("Hello")
# close() automatico all'uscita
```

---

## SimpleATPServer

Server asincrono. Ascolta connessioni TLS, gestisce handshake e dispatch dei task.

### Costruttore

```python
SimpleATPServer(agent_name: str = "atp-sdk-server",
                monitor: Optional[Monitor] = None)
```

---

### start()

```python
await server.start(host: str = "127.0.0.1",
                   port: int = 8443) -> None
```

Avvia il server. Crea automaticamente certificato TLS auto-firmato e MCC.
Il server gira in background come task asyncio.

Lancia `RuntimeError` se già in esecuzione.

---

### stop()

```python
await server.stop() -> None
```

Ferma il server, chiude tutte le connessioni, cancella i file TLS temporanei.

---

### on_task() — Decorator

```python
@server.on_task("my_task_type")
async def handler(task_type: str, payload: str) -> str:
    return f"Processed: {payload}"
```

Registra un handler per un tipo di task personalizzato.
L'handler riceve `(task_type, payload)` e restituisce una stringa.

---

### register_handler()

```python
server.register_handler("my_task_type", handler_function)
```

Equivalente programmatico del decorator.

---

### Task types built-in

| Tipo | Descrizione |
|------|-------------|
| `deepseek_chat` | Chiama l'API DeepSeek col payload come prompt |
| `echo` | Restituisce il payload al client |

---

### Proprietà

| Proprietà | Tipo | Descrizione |
|-----------|------|-------------|
| `running` | `bool` | `True` se il server accetta connessioni |

---

### Context Manager

```python
async with SimpleATPServer() as server:
    await server.start()
    # ... il server gira in background ...
# stop() automatico all'uscita
```

---

## AutoTunnel

Tunnel internet zero-config con **UPnP nativo** (pure Python, zero dipendenze).
Sceglie automaticamente: UPnP → locale (fallback).

```python
from atp_sdk.tunnel import AutoTunnel

tunnel = AutoTunnel()
public_url = await tunnel.start(8443)
# → "84.123.45.67:8443" (UPnP) o "127.0.0.1:8443" (locale)

print(f"Metodo: {tunnel.method}")   # "UPNP" o "local"
await tunnel.stop()
```

| Proprietà | Tipo | Descrizione |
|-----------|------|-------------|
| `public_url` | `str` | URL pubblico (`host:port`) o vuoto |
| `method` | `str` | Metodo attivo: `"UPNP"` o `"local"` |

## Key Exchange Ed25519

Scambio chiavi fuori banda tramite Key Card — nessun servizio esterno.
Un file `.card` firmato Ed25519 contiene le credenziali dell'agente.

```python
from atp_sdk.key_exchange import export_key_card, import_key_card, connect_with_key_card

# Export: crea Key Card firmata
card_file = export_key_card(
    agent_name="scuola-futura",
    ed25519_sk=identity_sk,
    ed25519_pk=identity_pk,
    host="192.168.1.50", port=8443,
    mcc_hash=mcc_hash,
)
# → atp_key_scuola_futura.card

# Import: verifica firma + restituisce credenziali
peer = import_key_card(card_file)
print(peer["agent_name"], peer["host"], peer["port"])

# Connect: import + connect in un passo
client = await connect_with_key_card(card_file)
if client:
    print(await client.chat("Ciao!"))
```

Raises `ValueError` se la firma Ed25519 non è valida.

---

## SyncATPClient (sincrono)

Wrapper sincrono per chi non vuole usare `async/await`.

```python
from atp_sdk.client import SyncATPClient

client = SyncATPClient("my-agent")
client.connect("127.0.0.1", 8443)
print(client.chat("Hello!"))
client.close()
```

Tutti i metodi di `SimpleATPClient` sono disponibili in versione sincrona.

---

## SyncATPServer (sincrono)

```python
from atp_sdk.server import SyncATPServer

server = SyncATPServer()
server.start(port=8443)
# ... il server gira in un thread daemon ...
server.stop()
```

---

## Federation (v2.0)

La federazione ATP permette a 3+ server di formare una rete. Ogni nodo
scopre automaticamente gli altri via gossip ed è in grado di inoltrare
task attraverso la rete con TTL (max 5 hop).

### Come attivarla

La federazione è **attiva di default** su `ATPServer`. Ogni server avvia
automaticamente:

- `PeerDiscovery` — gossip PEER_DISCOVERY ogni 60s, fanout 3
- `HeartbeatManager` — PEER_HEARTBEAT ogni 15s, timeout 90s
- `FederationRouter` — routing table, max 100 peer, eviction automatica

I frame PEER_DISCOVERY (0x60) e TASK_FORWARD (0x62) sono **firmati Ed25519**
dal mittente. Il ricevente verifica la firma usando la chiave pubblica
dell'MCC ottenuta durante l'handshake. Frame senza firma sono accettati
durante la migrazione (backward compat).

### Connessioni federate

Per connettere due server ATP in federazione:

```python
from client import ATPClient
from atp_core import build_header, ed25519_sign
import cbor2

# Connetti alpha → beta
cli = ATPClient()
await cli.connect("127.0.0.1", 18951)

# Invia PEER_DISCOVERY firmato
peers = [{"peer_id": "node-alpha", "host": "127.0.0.1", "port": 18950,
          "ed25519_pk": alpha_ed25519_pk, "capabilities": []}]
payload = cbor2.dumps({"node_id": "node-alpha", "peers": peers}, canonical=True)
sig = ed25519_sign(cli.agent.identity.ed25519_sk, payload)
disc = {"header": build_header(0x60), "peers": peers,
        "node_id": "node-alpha", "signature": sig}
await cli.agent._send_frame(disc)
```

### Task forwarding

Inviando un TASK_FORWARD (0x62) firmato, il task viene inoltrato
attraverso la rete fino al nodo target (entro il TTL):

```python
inner = {"header": build_header(0x01), "task_type": "echo",
         "task_payload": b"hello", "deadline_ms": 5000}
fwd_payload = cbor2.dumps({
    "target_peer_id": "node-gamma", "ttl": 5,
    "task_frame": inner, "forwarder_id": my_name,
}, canonical=True)
fwd_sig = ed25519_sign(my_sk, fwd_payload)
fwd = {"header": build_header(0x62), "target_peer_id": "node-gamma",
       "ttl": 5, "task_frame": inner, "signature": fwd_sig,
       "forwarder_id": my_name}
await cli.agent._send_frame(fwd)
```

### Esempio completo

Vedi `sdk/examples/federation_example.py` — 3 nodi, peer discovery,
task forwarding con connection pool.

---

# Esempi

Tutti gli esempi sono in `sdk/examples/`.

| File | Agenti | Descrizione |
|------|--------|-------------|
| `research_assistant.py` | 3 | Researcher → FactChecker → Summarizer |
| `code_review_pipeline.py` | 3 | Developer → Reviewer → Fixer |
| `agent_voting.py` | 4 | Governance distribuita con attestazione MCC |
| `teacher_school.py` | 2 | Insegnante ↔ Scuola, 5 use case |
| `school_server.py` | 1 | Server scolastico standalone con tunnel internet |
| `teacher_client.py` | 1 | Client insegnante con menu interattivo |

### Eseguire un esempio

```bash
cd ATP/sdk/examples
python research_assistant.py          # 3 agenti, pipeline ricerca
python school_server.py               # avvia server
python teacher_client.py              # menu interattivo (localhost)
python teacher_client.py 192.168.1.50:8443  # via tunnel UPnP
```

---

# Quick Start

### Server + Client sulla stessa macchina

```python
import asyncio
from atp_sdk import SimpleATPServer, SimpleATPClient

async def main():
    # Avvia il server
    server = SimpleATPServer()
    await server.start(port=8443)

    # Connetti il client
    client = SimpleATPClient("agente-1")
    await client.connect(port=8443)

    # Invia un prompt a DeepSeek
    risposta = await client.chat("Cosa sono gli agenti autonomi?")
    print(risposta)

    # Cleanup
    await client.close()
    await server.stop()

asyncio.run(main())
```

### Server + Client su due macchine diverse via internet

```bash
# Macchina 1 (server): installazione base (UPnP nativo, senza dipendenze extra)
pip install -e .
python school_server.py
# Output: 🌐 Indirizzo pubblico: 84.123.45.67:8443 (UPnP)
#
# Se il router non supporta UPnP, installa pyngrok come fallback:
# pip install pyngrok
# setx NGROK_AUTH_TOKEN "tuo_token"
# python school_server.py

# Macchina 2 (client):
python teacher_client.py 84.123.45.67:8443
```

Nessun firewall, nessun port forwarding, nessuna VPN, nessuna dipendenza obbligatoria.

### Custom task handler

```python
server = SimpleATPServer()

@server.on_task("translate")
async def handle_translate(task_type: str, payload: str) -> str:
    # payload è il testo da tradurre
    return await call_translation_api(payload)

await server.start()
```

Il client invoca: `await client.send("translate", "Hello world")`

---

# Protocollo

ATP v1.7 — Agent Transfer Protocol. Protocollo crittografico per comunicazione
sicura e verificabile tra agenti AI.

### Fasi dell'handshake

1. **TLS** — connessione TCP cifrata con certificati auto-firmati
2. **Version Negotiation** — `VERSION_PROPOSE` / `VERSION_ACK`
3. **MCC Exchange & Identity Binding** — scambio Merkle-Claim Card con proof-of-possession
4. **Capability Exchange** — `CAPABILITY_EXCHANGE`
5. **Task Streams** — `TASK_REQUEST` → `TASK_ACK` → `TASK_RESPONSE`

### Task built-in

- `deepseek_chat`: prompt → DeepSeek API → risposta
- `echo`: messaggio → stesso messaggio (test connettività)

---

# Configurazione

### DeepSeek API Key

La chiave viene risolta automaticamente:
1. `os.environ["DEEPSEEK_API_KEY"]`
2. Registry Windows `HKCU\Environment` (per git-bash/MSYS2)
3. Se assente: risposta mock `[ATP v1.7 Mock Response]`

### Verifica identità

L'SDK verifica sempre l'MCC del peer in 8 step: versione, scadenza, foglie critiche,
root hash, firma dell'autorità, chiave separata, revoca. Nessuna modalità demo bypassabile.

### Modalità produzione

1. Sostituire i certificati TLS con certificati reali firmati da una CA riconosciuta
   (es. Let's Encrypt) se si vuole uscire dal modello CA condivisa
2. Configurare il RootStore con le chiavi pubbliche delle autorità di fiducia
3. Aggiungere peer gossip per la propagazione delle revoche (configurazione automatica
   se i server ATP condividono la stessa rete)

---

# Requisiti

- Python ≥ 3.10
- `aiohttp` ≥ 3.8 — HTTP client per DeepSeek
|- `blake3` ≥ 0.3 — hash crittografico (obbligatorio, nessun fallback)
|- `cbor2` ≥ 5.4 — codifica frame
|- `aioquic` ≥ 1.3.0 — QUIC transport (opzionale)

## QUIC Transport (v1.8+)

ATP supporta QUIC (RFC 9000) come alternativa a TCP+TLS.
Il modulo `atp_quic.py` fornisce `QUICServer` e `QUICClient`
con API identica a TCP.

```python
import asyncio
from atp_quic import QUICServer, QUICClient

async def main():
    server = QUICServer()
    await server.start('127.0.0.1', 18901)
    
    client = QUICClient()
    await client.connect('127.0.0.1', 18901)
    
    result = await client.send_task('echo', 'hello')
    print(result['status'])  # 'ok'

asyncio.run(main())
```

### Differenze da TCP

| TCP | QUIC |
|-----|------|
| TLS con CA Ed25519 condivisa | RSA 2048 per aioquic |
| Multiplexing via asyncio.Future | Stream QUIC nativi |
| 0-RTT: No | Sì |
| `SimpleATPServer`/`SimpleATPClient` | `QUICServer`/`QUICClient` |

### Requisiti

```bash
pip install aioquic
```
- `cryptography` ≥ 41.0 — TLS, chiavi, firme Ed25519/X25519
- Tunnel internet: **UPnP nativo** (zero dipendenze, standard library pure Python)
- `pyngrok` (opzionale) — solo se UPnP non disponibile
