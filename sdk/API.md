# ATP SDK v1.7 — API Reference

---

## Module: `atp_sdk`

```python
from atp_sdk import SimpleATPClient, SimpleATPServer
```

Aggiunge automaticamente il progetto ATP padre a `sys.path`.
Espone le classi pubbliche `SimpleATPClient` e `SimpleATPServer`.

| Name | Type | Description |
|------|------|-------------|
| `SimpleATPClient` | `class` | Client ATP asincrono — connect, chat, send, echo, close |
| `SimpleATPServer` | `class` | Server ATP asincrono — start, stop, on_task, register_handler |
| `__version__` | `str` | `"1.7"` |

---

## Class: `SimpleATPClient`

```python
class SimpleATPClient:
    def __init__(self, agent_name="atp-sdk-client", monitor=None)
    async def connect(self, host="127.0.0.1", port=8443, timeout=None) -> bool
    async def send(self, task_type, payload, deadline_ms=30000) -> dict | None
    async def chat(self, prompt) -> str
    async def echo(self, message) -> str
    async def close() -> None
    connected: bool
    peer_mcc_hash: str | None
    demo_mode: bool
    async def __aenter__() -> "SimpleATPClient"
    async def __aexit__(*args) -> None
```

High-level ATP client con API minimali. Gestisce automaticamente TLS,
creazione identità, MCC, handshake in 5 fasi, e dispatch task DeepSeek.

### `__init__(agent_name="atp-sdk-client", monitor=None)`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `agent_name` | `str` | `"atp-sdk-client"` | Nome agente, inserito nell'MCC come identità |
| `monitor` | `Monitor \| None` | `None` | Monitor opzionale per log eventi protocollo |

Crea il client. La connessione non avviene finché non si chiama `connect()`.

---

### `async connect(host="127.0.0.1", port=8443, timeout=None) -> bool`

Connette al server ATP ed esegue l'handshake completo in 5 fasi:

1. Connessione TCP + TLS (cert auto-firmati accettati in demo mode)
2. Creazione `AgentIdentity` con chiavi X25519 + Ed25519
3. Negoziazione versione (`VERSION_PROPOSE` → `VERSION_ACK`)
4. Scambio MCC + identity binding con proof-of-possession
5. Scambio capacità (`CAPABILITY_EXCHANGE`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | `str` | `"127.0.0.1"` | IP o hostname del server ATP |
| `port` | `int` | `8443` | Porta TLS del server |
| `timeout` | `float \| None` | da config | Timeout connessione in secondi |

| Returns | Description |
|---------|-------------|
| `bool` | `True` se connesso e vincolato, `False` altrimenti |

Non lancia eccezioni — gli errori vengono loggati e restituisce `False`.

```python
client = SimpleATPClient("prof-rossi")
ok = await client.connect("192.168.1.50", 8443)
if ok:
    print("Connesso")
```

---

### `async send(task_type, payload, deadline_ms=30000) -> dict | None`

Invia un task ATP al server e restituisce la risposta.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `task_type` | `str` | *required* | Tipo task: `"deepseek_chat"`, `"echo"`, o custom |
| `payload` | `str` | *required* | Payload stringa (max 64 KB) |
| `deadline_ms` | `int` | `30000` | Timeout task in millisecondi |

| Returns | Description |
|---------|-------------|
| `dict` | `{"status": int, "result": str, "raw": dict}` — risposta estratta |
| `None` | Non connesso, payload troppo grande o errore protocollo |

Il campo `result` viene automaticamente estratto dal JSON del server:
`{"result": "testo"}` → `"testo"`, `{"echo": "..."}` → `"..."`, `{"error": "..."}` → `"..."`.

```python
resp = await client.send("check_grades", json.dumps({"student": "Giulia"}))
if resp:
    print(resp["result"])   # testo pulito
    print(resp["status"])   # status code
```

---

### `async chat(prompt) -> str`

Convenience method: invia un prompt a DeepSeek via server ATP.

| Parameter | Type | Description |
|-----------|------|-------------|
| `prompt` | `str` | Prompt da inviare al modello DeepSeek |

| Returns | Description |
|---------|-------------|
| `str` | Risposta testuale del modello, o `"[Error: ...]"` |

Equivalente a `(await send("deepseek_chat", prompt))["result"]`.

```python
answer = await client.chat("Spiega la crittografia asimmetrica")
```

---

### `async echo(message) -> str`

Test di connettività: invia un messaggio e lo riceve indietro.

| Parameter | Type | Description |
|-----------|------|-------------|
| `message` | `str` | Messaggio da echo-are |

| Returns | Description |
|---------|-------------|
| `str` | Il messaggio ricevuto indietro, o `"[Error: ...]"` |

```python
assert await client.echo("ping") == "ping"
```

---

### `async close() -> None`

Chiude la connessione con shutdown TLS corretto.

Chiama `ATPAgent.close_async()` per il shutdown SSL, poi chiude il writer TCP.
Sicura da chiamare più volte — operazione idempotente.

```python
await client.close()
```

---

### `connected: bool` (property)

`True` se il client è connesso e l'handshake è completato con successo.

---

### `peer_mcc_hash: str | None` (property)

Hash esadecimale del Merkle root del MCC del peer, o `None` se non ancora vincolato.

```python
if client.connected:
    print(f"Peer MCC: {client.peer_mcc_hash[:16]}...")
```

---

### `demo_mode: bool` (attribute)

Default `True`. Quando attivo, salta la verifica della firma dell'autorità nel MCC
del peer (trust-on-first-use). Necessario per deployment multi-macchina dove ogni
processo ha la propria istanza Authority con chiavi diverse.

```python
client = SimpleATPClient("prod-agent")
client.demo_mode = False   # produzione: verifica firma autorità
```

---

### `async __aenter__() -> SimpleATPClient`
### `async __aexit__(*args) -> None`

Supporto context manager asincrono.

```python
async with SimpleATPClient("agent") as client:
    await client.connect()
    print(await client.chat("Hello"))
# close() automatico
```

---

## Class: `SimpleATPServer`

```python
class SimpleATPServer:
    def __init__(self, agent_name="atp-sdk-server", monitor=None)
    async def start(self, host="127.0.0.1", port=8443) -> None
    async def stop() -> None
    def on_task(self, task_type) -> Callable
    def register_handler(self, task_type, handler) -> None
    running: bool
    async def __aenter__() -> "SimpleATPServer"
    async def __aexit__(*args) -> None
```

Server ATP che accetta connessioni TLS, esegue l'handshake completo e
dispatcha i task ai gestori registrati.

### `__init__(agent_name="atp-sdk-server", monitor=None)`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `agent_name` | `str` | `"atp-sdk-server"` | Nome del server, inserito nell'MCC |
| `monitor` | `Monitor \| None` | `None` | Monitor per log eventi |

---

### `async start(host="127.0.0.1", port=8443) -> None`

Avvia il server ATP.

1. Genera certificato TLS auto-firmato (Ed25519)
2. Crea identità MCC per il server
3. Avvia `asyncio.start_server` con `reuse_address=True`
4. Lancia `serve_forever` in un task asyncio in background

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | `str` | `"127.0.0.1"` | Indirizzo di bind |
| `port` | `int` | `8443` | Porta TLS |

| Raises | Description |
|--------|-------------|
| `RuntimeError` | Se il server è già in esecuzione |

```python
server = SimpleATPServer()
await server.start(port=8443)
```

---

### `async stop() -> None`

Ferma il server: cancella il task `serve_forever`, chiude il socket TCP,
rimuove i file TLS temporanei (`_sdk_server_cert.pem`, `_sdk_server_key.pem`).

```python
await server.stop()
```

---

### `on_task(task_type) -> Callable[[TaskHandler], TaskHandler]` (decorator)

Registra un handler per un tipo di task personalizzato.

| Parameter | Type | Description |
|-----------|------|-------------|
| `task_type` | `str` | Nome del tipo task da gestire |

| Returns | Description |
|---------|-------------|
| `Callable` | Decorator che registra la funzione e la restituisce |

La funzione decorata deve avere firma:
```python
async def handler(task_type: str, payload: str) -> str
```

```python
@server.on_task("capitalize")
async def handle_capitalize(task_type: str, payload: str) -> str:
    return payload.upper()
```

---

### `register_handler(task_type, handler) -> None`

Versione programmatica di `on_task()`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `task_type` | `str` | Tipo task |
| `handler` | `TaskHandler` | `async (str, str) -> str` |

```python
server.register_handler("reverse", lambda t, p: p[::-1])
```

---

### Task types built-in

| Task Type | Handler | Description |
|-----------|---------|-------------|
| `deepseek_chat` | `ATPAgent.call_deepseek()` | Chiama l'API DeepSeek |
| `echo` | `payload → payload` | Echo del payload |

Task sconosciuti restituiscono `{"error": "Unsupported task type: ..."}`.

---

### `running: bool` (property)

`True` se il server sta accettando connessioni.

---

### `async __aenter__() -> SimpleATPServer`
### `async __aexit__(*args) -> None`

```python
async with SimpleATPServer() as server:
    await server.start()
    # server in esecuzione
# stop() automatico
```

---

## Class: `Tunnel`

```python
from atp_sdk.tunnel import Tunnel

class Tunnel:
    def __init__(self)
    async def start(self, local_port=8443) -> str
    async def stop() -> None
    public_url: str
```

Tunnel internet zero-config via ngrok. Crea un URL pubblico per il server senza
aprire firewall o configurare port forwarding.

### `__init__()`

Inizializza il tunnel (non ancora attivo).

---

### `async start(local_port=8443) -> str`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `local_port` | `int` | `8443` | Porta locale da esporre |

| Returns | Description |
|---------|-------------|
| `str` | URL pubblico (`"2.tcp.ngrok.io:12345"`) o `"127.0.0.1:8443"` (fallback) |

Se `pyngrok` è installato e `NGROK_AUTH_TOKEN` è impostato, crea un tunnel TCP
pubblico. Altrimenti fa fallback a localhost.

---

### `async stop() -> None`

Chiude il tunnel ngrok.

---

### `public_url: str` (property)

URL pubblico attuale (es. `"2.tcp.ngrok.io:12345"`) o stringa vuota.

```python
tunnel = Tunnel()
url = await tunnel.start(8443)
print(f"Indirizzo pubblico: {url}")   # 2.tcp.ngrok.io:12345
await tunnel.stop()
```

---

## Type Alias

### `TaskHandler`

```python
TaskHandler = Callable[[str, str], Awaitable[str]]
```

Firma degli handler registrabili con `on_task()` / `register_handler()`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `task_type` | `str` | Tipo task ricevuto |
| `payload` | `str` | Payload decodificato |
| **Returns** | `str` | Risultato stringa (viene wrappato in `{"result": ...}`) |

---

## Class: `SyncATPClient`

```python
class SyncATPClient:
    def __init__(self, agent_name="atp-sdk-client", monitor=None)
    def connect(self, host="127.0.0.1", port=8443) -> bool
    def send(self, task_type, payload, deadline_ms=30000) -> dict | None
    def chat(self, prompt) -> str
    def echo(self, message) -> str
    def close() -> None
    connected: bool
    def __enter__() -> "SyncATPClient"
    def __exit__(*args) -> None
```

Wrapper sincrono di `SimpleATPClient`. Stessa API, chiamate bloccanti.
Crea un event loop asyncio internamente.

```python
with SyncATPClient("sync-agent") as client:
    client.connect("127.0.0.1", 8443)
    print(client.chat("Hello!"))
```

---

## Class: `SyncATPServer`

```python
class SyncATPServer:
    def __init__(self, agent_name="atp-sdk-server", monitor=None)
    def start(self, host="127.0.0.1", port=8443) -> None
    def stop() -> None
    running: bool
    def __enter__() -> "SyncATPServer"
    def __exit__(*args) -> None
```

Wrapper sincrono di `SimpleATPServer`. Il server gira in un thread daemon.

```python
with SyncATPServer() as server:
    server.start(port=8443)
    # ... usa il server ...
# stop() automatico
```
