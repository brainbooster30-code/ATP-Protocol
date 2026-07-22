"""
ATP SDK — Real-World Example #2: Distributed Code Review Pipeline

Three agents collaborate:
  1. Developer — generates a code snippet via DeepSeek
  2. Reviewer  — reviews the code for bugs, style, and security
  3. Fixer     — applies the reviewer's suggestions

Run: python examples/code_review_pipeline.py
"""
import asyncio, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from atp_sdk import SimpleATPServer, SimpleATPClient

PORT = 8451


async def main():
    print("=" * 60)
    print(" ATP SDK — Distributed Code Review Pipeline")
    print("=" * 60)
    print()

    server = SimpleATPServer(trust_bootstrap_mode="tofu")
    await server.start(port=PORT)

    # ── 1. Developer: generate code ──────────────────────────────────────
    dev = SimpleATPClient("developer", trust_bootstrap_mode="tofu")
    await dev.connect(port=PORT)

    spec = "Scrivi una funzione Python che calcola il checksum SHA-256 di un file, con gestione errori e type hints."
    print("[DEVELOPER] Spec:", spec[:80] + "...")
    code = await dev.chat(spec)
    print(f"[DEVELOPER] Generated code ({len(code)} chars)")
    # Extract code block
    if "```python" in code:
        snippet = code.split("```python")[1].split("```")[0]
    elif "```" in code:
        snippet = code.split("```")[1].split("```")[0]
    else:
        snippet = code
    print("  " + snippet[:120].replace("\n", "\n  ") + "...\n")

    # ── 2. Reviewer: review the code ─────────────────────────────────────
    reviewer = SimpleATPClient("reviewer", trust_bootstrap_mode="tofu")
    await reviewer.connect(port=PORT)

    review_prompt = (
        f"Rivedi il seguente codice Python. Cerca: bug, problemi di sicurezza, "
        f"mancata gestione errori, stile non pythonico, type hints mancanti.\n\n"
        f"```python\n{snippet}\n```\n\n"
        f"Rispondi con elenco puntato di problemi trovati (max 5)."
    )
    print("[REVIEWER] Reviewing code...")
    review = await reviewer.chat(review_prompt)
    print(f"[REVIEWER] Review ({len(review)} chars):")
    for line in review.split("\n"):
        if line.strip().startswith("-"):
            print(f"  {line.strip()}")

    # ── 3. Fixer: apply fixes ────────────────────────────────────────────
    fixer = SimpleATPClient("fixer", trust_bootstrap_mode="tofu")
    await fixer.connect(port=PORT)

    fix_prompt = (
        f"Correggi il seguente codice Python applicando TUTTE queste modifiche:\n\n"
        f"CODICE ORIGINALE:\n```python\n{snippet}\n```\n\n"
        f"REVIEW:\n{review}\n\n"
        f"Restituisci SOLO il codice corretto in un blocco ```python, nient'altro."
    )
    print(f"\n[FIXER] Applying fixes...")
    fixed = await fixer.chat(fix_prompt)
    if "```python" in fixed:
        fixed_code = fixed.split("```python")[1].split("```")[0]
    else:
        fixed_code = fixed
    print(f"[FIXER] Fixed code ({len(fixed_code)} chars):")
    print("  " + fixed_code[:200].replace("\n", "\n  ") + "...")

    # ── Cleanup ──────────────────────────────────────────────────────────
    await dev.close()
    await reviewer.close()
    await fixer.close()
    await server.stop()

    print()
    print("=" * 60)
    print(" Pipeline complete: Develop → Review → Fix")
    print(f" Original: {len(snippet)} chars → Fixed: {len(fixed_code)} chars")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
