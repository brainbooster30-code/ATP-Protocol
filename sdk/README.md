# ATP SDK v1.8

**Easy-to-use Python SDK for the Agent Transport Protocol.**

Build federated AI-agent networks in just a few lines of code. The SDK wraps the full ATP v1.8 protocol — TLS, MCC (Merkle-Claim Card), identity binding, handshake, task dispatch, federation, and revocation — behind a clean, minimal API.

## Features

- 🔐 **Zero-config crypto** — X25519 + Ed25519 keypairs, TLS, MCC creation, all automatic
- 🤖 **DeepSeek integration** — send chat prompts via `client.chat("prompt")`
- 🧩 **Custom task handlers** — register handlers with `@server.on_task("name")`
- ⚡ **Async + Sync APIs** — `SimpleATPClient` (async) + `SyncATPClient` (sync)
- 🔗 **Federation built-in** — multi-node networks, signed peer discovery, task forwarding
- 🔌 **Context managers** — `async with` / `with` for automatic cleanup
- 📦 **Pip-installable** — `pip install -e .`

## Quick Start

### Install

```bash
cd path/to/ATP/sdk
pip install -e .

# With dashboard support:
pip install -e ".[dashboard]"

# Everything:
pip install -e ".[all]"
```

### Server

```python
import asyncio
from atp_sdk import SimpleATPServer

async def main():
    server = SimpleATPServer()
    await server.start(port=8443)
    # Server runs forever, handling connections
    # Press Ctrl+C to stop

asyncio.run(main())
```

### Client

```python
import asyncio
from atp_sdk import SimpleATPClient

async def main():
    client = SimpleATPClient("my-agent")
    await client.connect("127.0.0.1", 8443)

    response = await client.chat("Explain quantum computing")
    print(response)

    await client.close()

asyncio.run(main())
```

### Synchronous API

```python
from atp_sdk.client import SyncATPClient

client = SyncATPClient("sync-agent")
client.connect("127.0.0.1", 8443)
print(client.chat("Hello world!"))
client.close()
```

## Custom Task Handlers

```python
from atp_sdk import SimpleATPServer

server = SimpleATPServer()

@server.on_task("capitalize")
async def handle_capitalize(task_type: str, payload: str) -> str:
    return payload.upper()

@server.on_task("add_numbers")
async def handle_add_numbers(task_type: str, payload: str) -> str:
    import json
    nums = json.loads(payload)
    return str(sum(nums))

await server.start(port=8443)
```

Clients can then call:

```python
await client.send("capitalize", "hello world")
await client.send("add_numbers", "[1, 2, 3, 4]")
```

## API Reference

### `SimpleATPClient`

| Method | Description |
|--------|-------------|
| `await connect(host, port)` | Connect and perform ATP handshake |
| `await chat(prompt)` | Send a DeepSeek chat prompt → get response |
| `await send(task_type, payload)` | Send a generic task → get result dict |
| `await echo(message)` | Echo test — returns the message |
| `await close()` | Gracefully disconnect |
| `connected` (property) | `True` if connected and bound |
| `peer_mcc_hash` (property) | Hex digest of peer's MCC root |

### `SimpleATPServer`

| Method | Description |
|--------|-------------|
| `await start(host, port)` | Start listening for connections |
| `await stop()` | Gracefully shut down |
| `on_task(task_type)` | Decorator for custom handlers |
| `register_handler(task_type, fn)` | Programmatic handler registration |
| `running` (property) | `True` if accepting connections |

### Built-in Task Types

| Task Type | Description |
|-----------|-------------|
| `deepseek_chat` | Calls the DeepSeek API with the payload as prompt |
| `echo` | Echoes the payload back to the client |

## Examples

Run the examples (from the `sdk/` directory):

```bash
# Basic chat: server + client exchanging a DeepSeek prompt
python examples/basic_chat.py

# Multi-agent: custom handlers, multiple clients
python examples/multi_agent.py

# Federation: 3-node network with peer discovery
python examples/federation_example.py
```

## Architecture

```
┌────────────────────────────────────────┐
│           atp_sdk (this package)       │
│  ┌──────────┐  ┌────────────────────┐  │
│  │  client  │  │       server       │  │
│  │ .connect │  │ .start / .stop     │  │
│  │ .chat    │  │ .on_task()         │  │
│  │ .send    │  │ .register_handler  │  │
│  │ .close   │  │                    │  │
│  └────┬─────┘  └─────────┬──────────┘  │
│       │                  │             │
├───────┴──────────────────┴─────────────┤
│        Parent ATP project              │
│  ┌──────────────────────────────────┐  │
│  │ agent  │ client │ server         │  │
│  │ atp_core │ config │ authority    │  │
│  │ monitor │ revocation │ federation│  │
│  │ atp_quic │ production            │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
```

The SDK imports from the parent ATP project by adding it to `sys.path` — no copying or modifying of the original protocol code is needed.

## Requirements

- Python ≥ 3.10
- `aiohttp` ≥ 3.8 (HTTP client for DeepSeek API)
- `blake3` ≥ 0.3 (cryptographic hashing — **required, no fallback**)
- `cbor2` ≥ 5.4 (frame encoding)
- `cryptography` ≥ 41.0 (TLS, key generation, Ed25519/X25519)

Optional:
- `PySide6` ≥ 6.5 + `matplotlib` ≥ 3.7 (dashboard)
- `aioquic` ≥ 1.3.0 (QUIC transport)

All dependencies are installed automatically via `pip install -e .[all]`

## Protocol

ATP v1.8 — Agent Transport Protocol. A cryptographic protocol for secure, verifiable communication between AI agents. Features include:

- **MCC** (Merkle-Claim Card) — verifiable identity credentials
- **5-phase handshake** — version → MCC → binding → capability → tasks
- **Task lifecycle** — request → ack → response, multiplexed, with E2E encryption
- **Revocation** — Cuckoo filter + RootStore + gossip + degradation policy
- **Federation** — multi-node peer discovery + task forwarding (Ed25519 signed)
- **QUIC transport** — optional RFC 9000 support via aioquic
- **DeepSeek integration** — built-in support for DeepSeek chat model

## License

MIT
