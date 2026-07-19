# ATP SDK v1.7 — Documentation

Python SDK per il protocollo ATP (Agent Transport Protocol). Connette agenti AI
in reti federate sicure in poche righe di codice.

## Installazione

```bash
cd ATP/sdk
pip install -e .              # core: aiohttp, blake3, cbor2, cryptography
pip install -e ".[tunnel]"    # + ngrok per tunnel internet zero-config
pip install -e ".[all]"       # tutto incluso dashboard
```

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
1. Connessione TLS (certificati auto-firmati accettati in demo)
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

## Tunnel

Zero-config internet connectivity via ngrok.

```python
from atp_sdk.tunnel import Tunnel

tunnel = Tunnel()
public_url = await tunnel.start(8443)
# → "2.tcp.ngrok.io:12345"

await tunnel.stop()
```

Se `pyngrok` non è installato, fa fallback a `127.0.0.1:8443`.

Richiede: `pip install pyngrok` + `NGROK_AUTH_TOKEN` (gratuito da ngrok.com).

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
python teacher_client.py 2.tcp.ngrok.io:12345  # via tunnel internet
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
# Macchina 1 (server): installa pyngrok, imposta NGROK_AUTH_TOKEN
pip install pyngrok
setx NGROK_AUTH_TOKEN "tuo_token"
python school_server.py
# Output: 🌐 Indirizzo pubblico: 2.tcp.ngrok.io:12345

# Macchina 2 (client):
python teacher_client.py 2.tcp.ngrok.io:12345
```

Nessun firewall, nessun port forwarding, nessuna VPN.

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

### Demo mode

L'SDK usa `demo_mode=True` di default — salta la verifica della firma dell'autorità
nell'handshake (necessario quando server e client sono su macchine diverse con
Authority separate). Disattivare per produzione.

### Modalità produzione

1. Sostituire i certificati TLS auto-firmati con certificati reali (Let's Encrypt)
2. Impostare `client.demo_mode = False`
3. Registrare le chiavi pubbliche delle autorità nel RootStore

---

# Requisiti

- Python ≥ 3.10
- `aiohttp` ≥ 3.8 — HTTP client per DeepSeek
- `blake3` ≥ 0.3 — hash crittografico (fallback BLAKE2b)
- `cbor2` ≥ 5.4 — codifica frame
- `cryptography` ≥ 41.0 — TLS, chiavi, firme Ed25519/X25519
- `pyngrok` ≥ 7.0 (opzionale) — tunnel internet zero-config
