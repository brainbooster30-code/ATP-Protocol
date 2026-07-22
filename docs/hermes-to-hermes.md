# Come connettere due Hermes Agent via ATP v1.8

Guida passo-passo per far comunicare due agenti Hermes su PC diversi
via internet, usando il protocollo ATP. **Nessuna configurazione di
rete, firewall o port forwarding richiesta.**

---

## Indice

1. [Architettura](#1-architettura)
2. [Prerequisiti](#2-prerequisiti)
3. [Installazione SDK su entrambi i PC](#3-installazione-sdk)
4. [Opzione A — Tunnel UPnP (automatico, zero dipendenze)](#4-opzione-a--tunnel-upnp-automatico)
5. [Opzione B — Key Card Ed25519 (zero servizi esterni)](#5-opzione-b--key-card-ed25519)
6. [Opzione C — ngrok fallback](#6-opzione-c--ngrok-fallback)
7. [PC A — Avvio server ATP](#7-pc-a--avvio-server)
8. [PC B — Connessione client](#8-pc-b--connessione-client)
9. [Cooperazione: invio task](#9-cooperazione)
10. [Script pronto all'uso](#10-script-pronto)
11. [Caricare la skill in Hermes](#11-caricare-la-skill)
12. [Risoluzione problemi](#12-risoluzione-problemi)

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
│   Tunnel UPnP nativo             │
│   84.123.45.67:8443              │
│   Oppure Key Card: .card         │
└──────────────────────────┘       └──────────────────────────┘
         ▲                                     │
         └─────────── ATP v1.8 ────────────────┘
                 TLS + MCC + CBOR
```

La connessione è:
- **Cifrata** — TLS 1.3 tra i due peer
- **Verificabile** — ogni agente presenta un MCC (Merkle-Claim Card)
- **Peer-to-peer** — nessun server centrale, nessun intermediario
- **Zero-config** — tunnel UPnP nativo o Key Card Ed25519, nessuna dipendenza esterna

---

## 2. Prerequisiti

### Su entrambi i PC

- **Python 3.10+** — [scarica da python.org](https://www.python.org/downloads/)
- **Git** — [scarica da git-scm.com](https://git-scm.com/downloads)
- **Progetto ATP** — clonato o copia locale

---

## 3. Installazione SDK

Esegui questi comandi su **entrambi i PC**:

```bash
# Clona il progetto
git clone https://github.com/brainbooster30-code/ATP-Protocol.git
cd ATP-Protocol

# Installa l'SDK (tunnel UPnP nativo incluso — zero dipendenze extra)
cd sdk
pip install -e .
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

## 4. Opzione A — Tunnel UPnP (automatico)

**Non serve configurare nulla.** Il tunnel UPnP nativo (pure Python, zero
dipendenze esterne) scopre automaticamente il router sulla rete locale,
apre la porta tramite UPnP IGD e restituisce l'IP pubblico.

Basta avviare il server — il tunnel è integrato nell'SDK.

---

## 5. Opzione B — Key Card Ed25519

Per connessione diretta senza UPnP né ngrok: due agenti si scambiano
le chiavi pubbliche fuori banda tramite un file `.card` firmato Ed25519.

### PC A — esporta la Key Card

```python
from atp_sdk.key_exchange import export_key_card

card_file = export_key_card(
    agent_name="scuola-futura",
    ed25519_sk=identity_sk,   # chiave segreta Ed25519
    ed25519_pk=identity_pk,   # chiave pubblica Ed25519
    host="192.168.1.50",      # IP del server
    port=8443,
    mcc_hash=mcc_hash,
)
print(f"Consegna questo file: {card_file}")
# → atp_key_scuola_futura.card
```

Consegna il file a PC B via USB, email, QR code, WhatsApp...

### PC B — connetti con la Key Card

```python
from atp_sdk.key_exchange import connect_with_key_card

client = await connect_with_key_card("atp_key_scuola_futura.card")
if client:
    print(await client.chat("Ciao scuola!"))
```

Il file `.card` è firmato Ed25519 — se la firma non è valida, il client
rifiuta la connessione con `ValueError`.

---

## 6. Opzione C — ngrok fallback

Se il router non supporta UPnP, puoi usare ngrok come alternativa:

Solo su **PC A** (quello che fa da server):

```bash
pip install pyngrok
setx NGROK_AUTH_TOKEN "tuo_token_qui"
```

Il token si trova su https://dashboard.ngrok.com/get-started/your-authtoken

---

## 7. PC A — Avvio server ATP

Su **PC A** (chi fa da server, es. casa):

```bash
cd ATP-Protocol/sdk/examples
python school_server.py
```

Output atteso (UPnP):
```
═════════════════════════════════════════════════
  🏫  ATP School Server — scuola-futura
  Listening on 127.0.0.1:8443
═════════════════════════════════════════════════

  🌐 TUNNEL UPnP ATTIVO
  Indirizzo pubblico: 84.123.45.67:8443
  Client: python teacher_client.py 84.123.45.67:8443

  🗝️  KEY CARD ESPORTATA: atp_key_scuola_futura.card
  Consegna questo file all'insegnante (USB, email, QR code...)
```

Output atteso (ngrok fallback):
```
  🌐 TUNNEL NGROK ATTIVO
  Indirizzo pubblico: 2.tcp.ngrok.io:12345
  Client: python teacher_client.py 2.tcp.ngrok.io:12345
```

📌 **Prendi nota dell'indirizzo pubblico** o del file `.card`.

Il server resta in esecuzione. Premi `Ctrl+C` per fermarlo.

---

## 8. PC B — Connessione client

Su **PC B** (chi si connette, es. ufficio):

### Via UPnP / IP pubblico
```bash
cd ATP-Protocol/sdk/examples
python teacher_client.py 84.123.45.67:8443
```

### Via Key Card (zero servizi esterni)
```bash
python teacher_client.py atp_key_scuola_futura.card
```

### Via ngrok
```bash
python teacher_client.py 2.tcp.ngrok.io:12345
```

Output atteso:
```
🏠  ATP Teacher Client — prof-rossi
  Connessione a: 84.123.45.67:8443

✅ Connesso!
   Scuola: 84.123.45.67:8443
   MCC:    ee84bca8fa43549f2594...
```

Sei connesso. Ora puoi usare il menu interattivo:

```
═════════════════════════════════════════
  🏠  Prof. Rossi — Connesso a 84.123.45.67:8443
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

## 9. Cooperazione via codice Python

Se vuoi scrivere il tuo script di cooperazione invece di usare il menu:

### Script minimo (PC B invia task a PC A)

```python
import asyncio
from atp_sdk import SimpleATPClient

async def main():
    # Connetti a PC A via UPnP / IP pubblico
    client = SimpleATPClient("hermes-b")
    ok = await client.connect("84.123.45.67", 8443)
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

### Connessione con Key Card

```python
import asyncio
from atp_sdk.key_exchange import connect_with_key_card

async def main():
    client = await connect_with_key_card("atp_key_scuola_futura.card")
    if not client:
        print("❌ Connessione fallita")
        return

    print(f"✅ Connesso via Key Card!")
    risposta = await client.chat("Ciao scuola!")
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

# ── PC B (client, via internet) ────────────────────────────
client = SimpleATPClient("hermes-b")
await client.connect("84.123.45.67", 8443)

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

## 10. Script pronto all'uso

Salva questo script su **PC B** come `coopera.py`:

```python
#!/usr/bin/env python3
"""
Connetti due Hermes via ATP — script minimo.
Uso: python coopera.py 84.123.45.67:8443
     python coopera.py atp_key_scuola_futura.card
"""
import asyncio, sys, os
sys.path.insert(0, "sdk")
from atp_sdk import SimpleATPClient
from atp_sdk.key_exchange import connect_with_key_card

if len(sys.argv) < 2:
    print("Uso: python coopera.py <host:port|key_card.card>")
    sys.exit(1)

async def main():
    arg = sys.argv[1]

    # Key Card mode
    if arg.endswith(".card") and os.path.isfile(arg):
        client = await connect_with_key_card(arg)
    else:
        # Host:port mode
        if ":" in arg:
            host, port = arg.rsplit(":", 1)
            port = int(port)
        else:
            host, port = arg, 8443
        client = SimpleATPClient("hermes-remoto")
        ok = await client.connect(host, port)
        if not ok:
            print(f"❌ Impossibile connettersi a {host}:{port}")
            return 1

    print(f"✅ Connesso!")
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
python coopera.py 84.123.45.67:8443       # via UPnP / IP pubblico
python coopera.py atp_key_scuola_futura.card  # via Key Card
```

---

## 11. Caricare la skill in Hermes

In **entrambi gli agenti Hermes**, carica la skill per usare ATP:

```
# In una sessione Hermes, esegui:
skill_view(name='atp-protocol-skill')
```

La skill fornisce: installazione SDK, quick start, pattern di cooperazione,
tunnel UPnP/Key Card/ngrok, e API reference completa.

La skill sarà attiva per tutta la durata della sessione.

---

## 12. Risoluzione problemi

### Il client non si connette

```bash
# 1. Il server è in esecuzione? (PC A)
#    Dovresti vedere "🌐 TUNNEL UPnP ATTIVO" o "Key Card esportata"

# 2. L'indirizzo è corretto? (PC B)
python teacher_client.py 84.123.45.67:8443

# 3. Test ping di base:
python -c "import socket; socket.setdefaulttimeout(5); \
  s=socket.socket(); s.connect(('84.123.45.67',8443)); print('✅ TCP OK')"
```

### "Handshake failed"

```
Causa più comune: i due PC hanno authority diverse e il bootstrap è in
modalità `strict`.
Soluzione per demo controllate: usa `trust_bootstrap_mode="tofu"` su
client e server. Soluzione per produzione: registra le authority nel
RootStore o usa un manifest `authority-chain` firmato da una authority già
fidata.
```

### UPnP non disponibile / Tunnel locale

```
Se il router non supporta UPnP, il server fa fallback a localhost.
Soluzioni:
  - Installa pyngrok per tunnel ngrok alternativo
  - Usa la Key Card Ed25519 sulla stessa rete locale (nessun servizio esterno)
  - Configura port forwarding manuale sul router

Per ngrok:
  pip install pyngrok
  setx NGROK_AUTH_TOKEN "tuo_token"
  python school_server.py
```

### "SSL connection is closed"

```
Warning innocuo: la connessione TCP è stata chiusa dall'altro capo.
Non è un errore di protocollo. Se dà fastidio, silenzialo con:
  logging.getLogger("asyncio").setLevel(logging.ERROR)
```

### Firma Key Card non valida

```
"ValueError: Firma Key Card non valida! L'agente non è fidato."
→ Il file .card è stato manomesso o non appartiene all'agente che dice di essere.
→ Richiedi un nuovo file .card all'altro agente.
```

---

## Riepilogo comandi

| Passo | Comando | Dove |
|-------|---------|------|
| Clone | `git clone https://github.com/brainbooster30-code/ATP-Protocol.git` | Entrambi |
| Installa SDK | `cd ATP-Protocol/sdk && pip install -e .` | Entrambi |
| Avvia server | `cd ATP-Protocol/sdk/examples && python school_server.py` | PC A |
| Connetti (IP) | `python teacher_client.py 84.123.45.67:8443` | PC B |
| Connetti (Key Card) | `python teacher_client.py atp_key_scuola_futura.card` | PC B |
| Connetti (ngrok) | `python teacher_client.py 2.tcp.ngrok.io:12345` | PC B |
| Script custom | `python coopera.py 84.123.45.67:8443` | PC B |

---

*Con ATP, due Hermes Agent su PC diversi possono cooperare via internet
in modo sicuro, verificabile e senza configurazione di rete.*
