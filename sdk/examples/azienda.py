"""
ATP SDK — Real-World Example: Two Company Branches Sharing AI via ATP
=====================================================================

Scenario:
  Sede A (Roma) — abbonamento ChatGPT (OpenAI)
  Sede B (Milano) — abbonamento Claude (Anthropic)

  Ogni sede ha il proprio server ATP. Le due sedi si connettono via internet
  tramite **Key Card Ed25519** (zero servizi esterni) e condividono le
  rispettive AI aziendali senza esporre le chiavi API all'altra sede.

  Use case:
    1. Sede A chiede una risposta da Claude (AI di Sede B)
    2. Sede B chiede una risposta da ChatGPT (AI di Sede A)
    3. Ciascuna sede può interrogare la propria AI locale
    4. Le richieste passano tutte attraverso il protocollo ATP, con identità
       crittografica verificabile (MCC)

  Ogni sede esporta una Key Card firmata Ed25519.
  Le Key Card vengono scambiate fuori banda (USB, email, QR, WhatsApp...)
  e usate per la connessione diretta — niente ngrok, niente UPnP.

  Esegui su Sede A:  python azienda.py sede_a <ip_sede_b>
  Esegui su Sede B:  python azienda.py sede_b <ip_sede_a>
  Demo locale:       python azienda.py both
"""
import asyncio, sys, os, json, logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_SDK = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_ATP = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
for p in (_SDK, _ATP):
    if p not in sys.path: sys.path.insert(0, p)

from atp_sdk import SimpleATPServer, SimpleATPClient

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("azienda")

# ── Porte ─────────────────────────────────────────────────────────────────────
PORTA_SEDE_A = 8480  # server Sede A
PORTA_SEDE_B = 8481  # server Sede B

# ── AI calls (reali via DeepSeek) ──────────────────────────────────────────────

SYSTEM_CHATGPT = "Sei ChatGPT di OpenAI, assistente AI conversazionale. Rispondi in italiano in modo chiaro e diretto."
SYSTEM_CLAUDE = "Sei Claude di Anthropic, assistente AI con prosa elegante e riflessiva. Rispondi in italiano con stile articolato."

async def call_openai(task_type: str, prompt: str) -> str:
    """Chiamata reale a DeepSeek con system prompt ChatGPT."""
    from agent import ATPAgent
    result = await ATPAgent.call_deepseek(
        f"{SYSTEM_CHATGPT}\n\nUtente: {prompt}"
    )
    return f"[ChatGPT-4o via DeepSeek] {result}" if result else "[ERRORE] Nessuna risposta da DeepSeek"


async def call_claude(task_type: str, prompt: str) -> str:
    """Chiamata reale a DeepSeek con system prompt Claude."""
    from agent import ATPAgent
    result = await ATPAgent.call_deepseek(
        f"{SYSTEM_CLAUDE}\n\nUtente: {prompt}"
    )
    return f"[Claude 3.5 Sonnet via DeepSeek] {result}" if result else "[ERRORE] Nessuna risposta da DeepSeek"

# ── Sede A — Server + Client ──────────────────────────────────────────────────

async def run_sede_a(sede_b_host: str, sede_b_port: int):
    print("═" * 60)
    print("  🏢 SEDE A — Roma (ChatGPT / OpenAI)")
    print("═" * 60)
    print()

    # ── Avvia server Sede A (offre ChatGPT) ─────────────────────────
    server_a = SimpleATPServer(agent_name="sede-a-roma", trust_bootstrap_mode="tofu")
    server_a.register_handler("ask_chatgpt", call_openai)
    await server_a.start(port=PORTA_SEDE_A)
    print(f"  [SEDE A] Server attivo su :{PORTA_SEDE_A}")
    print(f"  [SEDE A] AI offerta: ChatGPT (OpenAI)")

    # Esporta Key Card di Sede A
    from atp_sdk.key_exchange import export_key_card
    card_a = export_key_card(
        agent_name="sede-a-roma",
        ed25519_sk=server_a.identity_sk,
        ed25519_pk=server_a.identity_pk,
        host="127.0.0.1", port=PORTA_SEDE_A,
        mcc_hash=server_a.identity_mcc_hash,
        output_path="sede_a_roma.card",
    )
    print(f"  🗝️  Key Card Sede A: {card_a}")
    print(f"     Da consegnare a Sede B (USB/email/QR/WhatsApp)")
    print()

    # ── Connetti a Sede B per ottenere Claude ───────────────────────
    # Prova connessione diretta host:port
    client_b = SimpleATPClient("sede-a-roma → sede-b-milano", trust_bootstrap_mode="tofu")
    ok = await client_b.connect(host=sede_b_host, port=sede_b_port)
    if not ok:
        print(f"  ❌ Impossibile connettersi a Sede B ({sede_b_host}:{sede_b_port})")
        print("     Verifica che Sede B sia online e raggiungibile.")
        await server_a.stop()
        return

    print(f"  ✅ Connesso a Sede B (Milano) — MCC: {client_b.peer_mcc_hash[:16]}...")
    print()

    # ── Use case 1: Sede A usa la propria AI (ChatGPT — locale) ──
    print("─" * 60)
    print("  📋 UC1: Sede A usa ChatGPT (locale — server proprio)")
    print("─" * 60)
    prompt = "Spiega il concetto di agenti autonomi"
    print(f"  Prompt: \"{prompt}\"")
    # Chiama il proprio server locale su ask_chatgpt
    chatgpt_local = SimpleATPClient("sede-a-locale", trust_bootstrap_mode="tofu")
    await chatgpt_local.connect(port=PORTA_SEDE_A)
    resp = await chatgpt_local.send("ask_chatgpt", prompt)
    print(f"  Risposta: {resp['result'][:200] if resp else 'ERRORE'}")
    await chatgpt_local.close()
    print()

    # ── Use case 2: Sede A usa Claude di Sede B (via ATP) ────────
    print("─" * 60)
    print("  📋 UC2: Sede A usa Claude (AI di Sede B via ATP)")
    print("─" * 60)
    prompt = "Analizza il bilancio aziendale del Q3"
    print(f"  Prompt: \"{prompt}\"")
    resp = await client_b.send("ask_claude", prompt)
    print(f"  Risposta:\n{resp['result'][:300] if resp else 'ERRORE'}")
    print()

    # ── Use case 3: Confronto diretto su stesso prompt ────────────
    print("─" * 60)
    print("  📋 UC3: Confronto ChatGPT vs Claude su stesso prompt")
    print("─" * 60)
    prompt = "Quali sono i vantaggi della crittografia asimmetrica?"
    print(f"  Prompt: \"{prompt}\"")
    # Interroga entrambe le AI contemporaneamente
    chatgpt_local2 = SimpleATPClient("sede-a-locale2", trust_bootstrap_mode="tofu")
    await chatgpt_local2.connect(port=PORTA_SEDE_A)
    chatgpt, claude = await asyncio.gather(
        chatgpt_local2.send("ask_chatgpt", prompt),
        client_b.send("ask_claude", prompt),
    )
    print(f"  ChatGPT: {chatgpt['result'][:120] if chatgpt else 'ERRORE'}...")
    print(f"  Claude:  {claude['result'][:120] if claude else 'ERRORE'}...")
    await chatgpt_local2.close()
    print()

    # ── Cleanup ─────────────────────────────────────────────────────
    await client_b.close()
    await server_a.stop()
    print("  [SEDE A] Connessione chiusa. Server fermato.")
    print()

# ── Sede B — Server + Client ──────────────────────────────────────────────────

async def run_sede_b(sede_a_host: str, sede_a_port: int):
    print("═" * 60)
    print("  🏢 SEDE B — Milano (Claude / Anthropic)")
    print("═" * 60)
    print()

    # ── Avvia server Sede B (offre Claude) ─────────────────────────
    server_b = SimpleATPServer(agent_name="sede-b-milano", trust_bootstrap_mode="tofu")
    server_b.register_handler("ask_claude", call_claude)
    await server_b.start(port=PORTA_SEDE_B)
    print(f"  [SEDE B] Server attivo su :{PORTA_SEDE_B}")
    print(f"  [SEDE B] AI offerta: Claude (Anthropic)")

    # Esporta Key Card di Sede B
    from atp_sdk.key_exchange import export_key_card
    card_b = export_key_card(
        agent_name="sede-b-milano",
        ed25519_sk=server_b.identity_sk,
        ed25519_pk=server_b.identity_pk,
        host="127.0.0.1", port=PORTA_SEDE_B,
        mcc_hash=server_b.identity_mcc_hash,
        output_path="sede_b_milano.card",
    )
    print(f"  🗝️  Key Card Sede B: {card_b}")
    print(f"     Da consegnare a Sede A (USB/email/QR/WhatsApp)")
    print()

    # ── Connetti a Sede A per ottenere ChatGPT ─────────────────────
    # Prova connessione diretta host:port (o Key Card tramite import_key_card)
    client_a = SimpleATPClient("sede-b-milano → sede-a-roma", trust_bootstrap_mode="tofu")
    ok = await client_a.connect(host=sede_a_host, port=sede_a_port)
    if not ok:
        print(f"  ❌ Impossibile connettersi a Sede A ({sede_a_host}:{sede_a_port})")
        print("     Verifica che Sede A sia online e raggiungibile.")
        await server_b.stop()
        return

    print(f"  ✅ Connesso a Sede A (Roma) — MCC: {client_a.peer_mcc_hash[:16]}...")
    print()

    # ── Use case 1: Sede B usa la propria AI (Claude — locale) ──
    print("─" * 60)
    print("  📋 UC1: Sede B usa Claude (locale — server proprio)")
    print("─" * 60)
    prompt = "Spiega il concetto di agenti autonomi"
    print(f"  Prompt: \"{prompt}\"")
    claude_local = SimpleATPClient("sede-b-locale", trust_bootstrap_mode="tofu")
    await claude_local.connect(port=PORTA_SEDE_B)
    resp = await claude_local.send("ask_claude", prompt)
    print(f"  Risposta: {resp['result'][:200] if resp else 'ERRORE'}")
    await claude_local.close()
    print()

    # ── Use case 2: Sede B usa ChatGPT di Sede A (via ATP) ─────
    print("─" * 60)
    print("  📋 UC2: Sede B usa ChatGPT (AI di Sede A via ATP)")
    print("─" * 60)
    prompt = "Genera un report sulle vendite del mese"
    print(f"  Prompt: \"{prompt}\"")
    resp = await client_a.send("ask_chatgpt", prompt)
    print(f"  Risposta:\n{resp['result'][:300] if resp else 'ERRORE'}")
    print()

    # ── Use case 3: Richieste concorrenti ───────────────────────
    print("─" * 60)
    print("  📋 UC3: Richieste concorrenti (ChatGPT + Claude)")
    print("─" * 60)
    prompt_a = "Scrivi una email formale per un cliente"
    prompt_b = "Riassumi il verbale della riunione"
    # ChatGPT via Sede A, Claude via server locale
    claude_local = SimpleATPClient("sede-b-locale2", trust_bootstrap_mode="tofu")
    await claude_local.connect(port=PORTA_SEDE_B)
    chatgpt, claude = await asyncio.gather(
        client_a.send("ask_chatgpt", prompt_a),
        claude_local.send("ask_claude", prompt_b),
    )
    print(f"  ChatGPT: {chatgpt['result'][:120] if chatgpt else 'ERRORE'}...")
    print(f"  Claude:  {claude['result'][:120] if claude else 'ERRORE'}...")
    await claude_local.close()
    print()

    # ── Cleanup ─────────────────────────────────────────────────────
    await client_a.close()
    await server_b.stop()
    print("  [SEDE B] Connessione chiusa. Server fermato.")
    print()


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    print("═" * 64)
    print("  🏢 Condivisione AI tra sedi aziendali via ATP")
    print("═" * 64)
    print()
    print("  Sede A (Roma): ChatGPT (OpenAI)")
    print("  Sede B (Milano): Claude (Anthropic)")
    print()
    print("  Due server ATP si scambiano richieste AI in modo sicuro,")
    print("  ciascuno espone solo la propria AI senza condividere chiavi API.")
    print()

    # Determina chi sono (sede_a / sede_b / both)
    role = sys.argv[1] if len(sys.argv) > 1 else "both"

    if role == "sede_a":
        host_b = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        port_b = PORTA_SEDE_B
        await run_sede_a(host_b, port_b)

    elif role == "sede_b":
        host_a = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        port_a = PORTA_SEDE_A
        await run_sede_b(host_a, port_a)

    elif role == "both":
        # Demo locale: avvia entrambe le sedi in parallelo
        async with asyncio.TaskGroup() as tg:
            tg.create_task(run_sede_a("127.0.0.1", PORTA_SEDE_B))
            tg.create_task(run_sede_b("127.0.0.1", PORTA_SEDE_A))

    else:
        print("  Usa: python azienda.py [sede_a | sede_b | both] [ip_sede_remota]")
        print("  Esempi:")
        print("    python azienda.py both                              # demo locale")
        print("    python azienda.py sede_a 192.168.1.100              # Sede A → B via LAN")
        print("    python azienda.py sede_b 192.168.1.50               # Sede B → A via LAN")
        print("")
        print("  🗝️  Ogni sede esporta automaticamente la propria Key Card (.card)")
        print("     per connessione diretta senza servizi esterni: scambiate il file")
        print("     via USB/email/QR/WhatsApp e usate connect_with_key_card().")

if __name__ == "__main__":
    asyncio.run(main())
