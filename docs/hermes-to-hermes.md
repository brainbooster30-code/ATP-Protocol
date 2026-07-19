# Come connettere due Hermes Agent via ATP v1.7

Guida passo-passo per far comunicare due agenti Hermes su PC diversi
via internet, usando il protocollo ATP. **Nessuna configurazione di
rete, firewall o port forwarding richiesta.**

---

## Indice

1. [Architettura](#1-architettura)
2. [Prerequisiti](#2-prerequisiti)
3. [Installazione SDK su entrambi i PC](#3-installazione-sdk)
4. [Configurazione tunnel internet](#4-configurazione-tunnel)
5. [PC A — Avvio server ATP](#5-pc-a--avvio-server)
6. [PC B — Connessione client](#6-pc-b--connessione-client)
7. [Cooperazione: invio task](#7-cooperazione)
8. [Script pronto all'uso](#8-script-pronto)
9. [Caricare la skill in Hermes](#9-caricare-la-skill)
10. [Risoluzione problemi](#10-risoluzione-problemi)

---

## 1. Architettura

```
┌──────────────────────────┐       ┌──────────────────────────┐
│  PC A — Hermes Server    │       │  PC B — Hermes Client    │
│                          │       │                          │
│  ATP Server ────:8443    │──────→│  ATP Client              │
│  SimpleATPServer()       │ internet │  SimpleATPClient()       │
│                          │       │                          │
│  Attendiamo task...      │←──────│  Inviamo task...         │
│  │                       │       │  │                       │
│  │ MCC: identità firma   │       │  │ MCC: identità firma   │
│  └───────────────────────┘       │  └───────────────────────┘
│         ▲                        │
│         │                        │
│    Tunnel ngrok                  │
│    2.tcp.ngrok.io:12345          │
└──────────────────────────┘       └──────────────────────────┘
         ▲                                     │
         └─────────── ATP v1.7 ────────────────┘
                 TLS + MCC + CBOR
```

La connessione è:
- **Cifrata** — TLS 1.3 tra i due peer
- **Verificabile** — ogni agente presenta un MCC (Merkle-Claim Card)
- **Peer-to-peer** — nessun server centrale, nessun intermediario
- **Zero-config** — il tunnel ngrok evita firewall/port forwarding

---

## 2. Prerequisiti

### Su entrambi i PC

- **Python 3.10+** — [scarica da python.org](https://www.python.org/downloads/)
- **Git** — [scarica da git-scm.com](https://git-scm.com/downloads)
- **Progetto ATP** — clonato o copia locale

### Su PC A (quello che fa da server)

- **Account ngrok gratuito** — [registrati su ngrok.com](https://dashboard.ngrok.com/signup)
- **Token ngrok** — prendilo da [dashboard.ngrok.com](https://dashboard.ngrok.com/get-started/your-authtoken)

---

## 3. Installazione SDK

Esegui questi comandi su **entrambi i PC**:

```bash
# Clona il progetto
git clone https://github.com/brainbooster30-code/ATP-Protocol.git
cd ATP-Protocol

# Installa l'SDK con dipendenze
cd sdk
pip install -e .[all]
```

### Verifica installazione

```bash
python -c "from atp_sdk import SimpleATPClient, SimpleATPServer; print('✅ SDK OK')"
```

Output atteso:
```
✅ SDK OK
```

---

## 4. Configurazione tunnel internet

Solo su **PC A** (quello che fa da server):

```bash
# Installa pyngrok
pip install pyngrok

# Imposta il token ngrok
# Windows (Prompt dei comandi come Amministratore):
setx NGROK_AUTH_TOKEN "tuo_token_qui"

# Linux/macOS:
export NGROK_AUTH_TOKEN="tuo_token_qui"
# Aggiungi a ~/.bashrc per persistenza:
echo 'export NGROK_AUTH_TOKEN="tuo_token_qui"' >> ~/.bashrc
```

Il token si trova su https://dashboard.ngrok.com/get-started/your-authtoken

---

## 5. PC A — Avvio server ATP

Su **PC A** (chi fa da server, es. casa):

```bash
cd ATP-Protocol/sdk/examples
python school_server.py
```

Output atteso:
```
═════════════════════════════════════════════════
  🏫  ATP School Server — scuola-futura
  Listening on 127.0.0.1:8443
═════════════════════════════════════════════════

  🌐 TUNNEL INTERNET ATTIVO
  Indirizzo pubblico: 2.tcp.ngrok.io:12345
  Client: python teacher_client.py 2.tcp.ngrok.io:12345
```

📌 **Prendi nota dell'indirizzo pubblico** — lo darai a PC B.
    Sarà qualcosa come `2.tcp.ngrok.io:12345`.

Il server resta in esecuzione. Premi `Ctrl+C` per fermarlo.

---

## 6. PC B — Connessione client

Su **PC B** (chi si connette, es. ufficio):

```bash
cd ATP-Protocol/sdk/examples
python teacher_client.py 2.tcp.ngrok.io:12345
```

Output atteso:
```
🏠  ATP Teacher Client — prof-rossi
  Connessione a: 2.tcp.ngrok.io:12345

✅ Connesso!
   Scuola: 2.tcp.ngrok.io:12345
   MCC:    ee84bca8fa43549f2594...
```

Sei connesso. Ora puoi usare il menu interattivo:

```
═════════════════════════════════════════
  🏠  Prof. Rossi — Connesso a 2.tcp.ngrok.io:12345
  MCC scuola: ee84bca8fa43549f...
═════════════════════════════════════════
  1. 📋  Invia piano didattico
  2. 📊  Consulta voti studente
  3. 📝  Assegna compito
  4. 📚  Richiedi risorse didattiche
  5. 🚨  Segnala incidente
  6. 💬  Chat con AI scolastica (DeepSeek)
  0. 🚪  Esci
─────────────────────────────────────────
  Scelta:
```

---

## 7. Cooperazione via codice Python

Se vuoi scrivere il tuo script di cooperazione invece di usare il menu:

### Script minimo (PC B invia task a PC A)

```python
import asyncio
from atp_sdk import SimpleATPClient

async def main():
    # Connetti a PC A via tunnel
    client = SimpleATPClient("hermes-b")
    ok = await client.connect("2.tcp.ngrok.io", 12345)
    if not ok:
        print("❌ Connessione fallita")
        return

    print(f"✅ Connesso! MCC peer: {client.peer_mcc_hash[:16]}...")

    # Invia un task a DeepSeek sul server
    risposta = await client.chat(
        "Ciao! Sono Hermes B. "
        "Rispondi in italiano: qual è il tuo scopo?"
    )
    print(f"📩 {risposta}")

    await client.close()

asyncio.run(main())
```

### Pipeline a 2 agenti (in Python)

```python
import asyncio
from atp_sdk import SimpleATPClient, SimpleATPServer

# ── PC A (server) ──────────────────────────────────────────
server = SimpleATPServer("hermes-a")
await server.start(port=8443)

# ── PC B (client, via tunnel) ──────────────────────────────
client = SimpleATPClient("hermes-b")
await client.connect("2.tcp.ngrok.io", 12345)

# Task 1: PC B chiede a PC A di fare una ricerca
risultato1 = await client.chat("Cerca: ultime scoperte su RNA messaggero")
print(f"PC A risponde: {risultato1[:200]}...")

# Task 2: PC B chiede verifica
risultato2 = await client.send("echo", "Verifica completata")
print(f"PC A conferma: {risultato2['result']}")

# Cleanup
await client.close()
await server.stop()
```

### Custom task handler su PC A

```python
from atp_sdk import SimpleATPServer

server = SimpleATPServer("hermes-a")

@server.on_task("analizza")
async def handle_analizza(task_type: str, payload: str) -> str:
    # Questa funzione gira su PC A
    # payload arriva da PC B via internet
    return f"Analisi completata: {payload.upper()}"

await server.start(port=8443)
```

PC B invoca:
```python
await client.send("analizza", "dati produzione Q3")
# → "Analisi completata: DATI PRODUZIONE Q3"
```

---

## 8. Script pronto all'uso

Salva questo script su **PC B** come `coopera.py`:

```python
#!/usr/bin/env python3
"""
Connetti due Hermes via ATP — script minimo.
Uso: python coopera.py 2.tcp.ngrok.io:12345
"""
import asyncio, sys
sys.path.insert(0, "sdk")
from atp_sdk import SimpleATPClient

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
if ":" in HOST:
    host, port = HOST.rsplit(":", 1)
    port = int(port)
else:
    host, port = HOST, 8443

async def main():
    client = SimpleATPClient("hermes-remoto")
    ok = await client.connect(host, port)
    if not ok:
        print(f"❌ Impossibile connettersi a {host}:{port}")
        return 1

    print(f"✅ Connesso a {host}:{port}")
    print(f"   MCC peer: {client.peer_mcc_hash[:16]}...")
    print()

    while True:
        try:
            prompt = input("🧑 Tu > ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not prompt:
            continue
        if prompt.lower() in ("exit", "quit", "esci"):
            break

        print("🤖 ATP in attesa risposta...")
        response = await client.chat(prompt)
        print(f"🤖 Agent > {response}")
        print()

    await client.close()
    print("👋 Disconnesso.")
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
```

Esecuzione:
```bash
python coopera.py 2.tcp.ngrok.io:12345
```

---

## 9. Caricare la skill in Hermes

In **entrambi gli agenti Hermes**, carica la skill per usare ATP:

```
# In una sessione Hermes, esegui:
skill_view(name='atp-protocol-skill')
```

La skill fornisce: installazione SDK, quick start, pattern di cooperazione,
tunnel internet zero-config, e API reference completa.

La skill sarà attiva per tutta la durata della sessione.

---

## 10. Risoluzione problemi

### Il client non si connette

```bash
# 1. Il server è in esecuzione? (PC A)
#    Dovresti vedere "🌐 TUNNEL INTERNET ATTIVO"

# 2. L'indirizzo è corretto? (PC B)
python teacher_client.py 2.tcp.ngrok.io:12345

# 3. Test ping di base:
python -c "import socket; socket.setdefaulttimeout(5); \
  s=socket.socket(); s.connect(('2.tcp.ngrok.io',12345)); print('✅ TCP OK')"
```

### "Handshake failed"

```
Causa più comune: i due PC hanno Authority diverse.
Soluzione: l'SDK usa demo_mode=True di default, che salta la
verifica della firma dell'autorità. Se hai impostato
demo_mode=False, registra le authority nel RootStore.
```

### Tunnel non disponibile

```
Se pyngrok non è installato o NGROK_AUTH_TOKEN non è impostato,
il server fa fallback a localhost (127.0.0.1:8443).
Il client deve connettersi sulla stessa macchina.

Soluzione: pip install pyngrok + imposta NGROK_AUTH_TOKEN
```

### "SSL connection is closed"

```
Warning innocuo: la connessione TCP è stata chiusa dall'altro capo.
Non è un errore di protocollo. Se dà fastidio, silenzialo con:
  logging.getLogger("asyncio").setLevel(logging.ERROR)
```

---

## Riepilogo comandi

| Passo | Comando | Dove |
|-------|---------|------|
| Clone | `git clone https://github.com/brainbooster30-code/ATP-Protocol.git` | Entrambi |
| Installa SDK | `cd ATP-Protocol/sdk && pip install -e .[all]` | Entrambi |
| Installa tunnel | `pip install pyngrok && set NGROK_AUTH_TOKEN=...` | PC A (server) |
| Avvia server | `cd ATP-Protocol/sdk/examples && python school_server.py` | PC A |
| Connetti client | `python teacher_client.py 2.tcp.ngrok.io:12345` | PC B |
| Script custom | `python coopera.py 2.tcp.ngrok.io:12345` | PC B |

---

*Con ATP, due Hermes Agent su PC diversi possono cooperare via internet
in modo sicuro, verificabile e senza configurazione di rete.*
