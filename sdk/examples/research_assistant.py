"""
ATP SDK — Real-World Example #1: Distributed Research Assistant

Three agents collaborate:
  1. Researcher — calls DeepSeek with the research question
  2. FactChecker — verifies key claims from the research
  3. Summarizer — produces an executive summary

Run: python examples/research_assistant.py
"""
import asyncio, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from atp_sdk import SimpleATPServer, SimpleATPClient

PORT = 8450

ASSISTANT_PROMPT = (
    "Agisci come ricercatore accademico. Rispondi alla domanda in modo preciso "
    "e tecnico, citando concetti e terminologia appropriata. Domanda: "
)


async def main():
    print("=" * 60)
    print(" ATP SDK — Distributed Research Assistant")
    print("=" * 60)
    print()

    # ── 1. Start Server ──────────────────────────────────────────────────
    server = SimpleATPServer()
    await server.start(port=PORT)
    print("[SERVER] Listening on port", PORT)

    # ── 2. Researcher Agent — queries DeepSeek ───────────────────────────
    researcher = SimpleATPClient("researcher")
    await researcher.connect(port=PORT)

    question = "Quali sono le differenze fondamentali tra transformer encoder e decoder?"
    print(f"\n[RESEARCHER] Question: {question}")
    print("[RESEARCHER] Querying DeepSeek...")
    response = await researcher.chat(ASSISTANT_PROMPT + question)
    print(f"[RESEARCHER] Answer received ({len(response)} chars):")
    print("  " + response[:120] + "...")

    # ── 3. FactChecker Agent — validates key claims ──────────────────────
    factchecker = SimpleATPClient("factchecker")
    await factchecker.connect(port=PORT)

    claim = (
        "Verifica questa affermazione: 'I transformer encoder usano self-attention "
        "bidirezionale, mentre i decoder usano masked self-attention.' "
        "Rispondi solo CONFERMATO o NON CONFERMATO con breve spiegazione."
    )
    print(f"\n[FACTCHECKER] Verifying claim...")
    verification = await factchecker.chat(claim)
    print(f"[FACTCHECKER] Result: {verification[:150]}...")

    # ── 4. Summarizer Agent — executive summary ──────────────────────────
    summarizer = SimpleATPClient("summarizer")
    await summarizer.connect(port=PORT)

    summary_prompt = (
        f"Produci un riassunto esecutivo di 3 punti basato su questa ricerca:\n\n"
        f"RICERCA: {response[:500]}\n\n"
        f"VERIFICA: {verification}\n\n"
        f"Formato: elenco puntato con 3 punti chiave."
    )
    print(f"\n[SUMMARIZER] Generating executive summary...")
    summary = await summarizer.chat(summary_prompt)
    print(f"[SUMMARIZER] Summary:")
    for line in summary.split("\n"):
        if line.strip().startswith("-") or line.strip().startswith("*"):
            print(f"  {line.strip()}")

    # ── Cleanup ──────────────────────────────────────────────────────────
    await researcher.close()
    await factchecker.close()
    await summarizer.close()
    await server.stop()

    print()
    print("=" * 60)
    print(" All 3 agents completed: Research → Verify → Summarize")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
