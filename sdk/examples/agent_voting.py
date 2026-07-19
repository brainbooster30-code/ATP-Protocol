"""
ATP SDK — Real-World Example #3: Secure Multi-Agent Voting with Attestation

Four agents vote on a decision. Each agent:
  1. Receives the proposal
  2. Produces a reasoned vote (approve/reject) with DeepSeek
  3. Returns an attested response via ATP identity binding

The orchestrator tallies votes and announces the result.

Run: python examples/agent_voting.py
"""
import asyncio, sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from atp_sdk import SimpleATPServer, SimpleATPClient

PORT = 8452

PROPOSAL = (
    "PROPOSTA: Il sistema di autenticazione degli agenti deve migrare "
    "da password singole a autenticazione a due fattori basata su MCC + TOTP. "
    "Costo stimato: 2 settimane di sviluppo. Impatto: tutti gli agenti esistenti "
    "dovranno aggiornare il proprio MCC entro 30 giorni."
)

VOTE_PROMPT = (
    "Sei un agente di voto in un sistema di governance distribuita. "
    "Analizza la proposta seguente e vota APPROVE o REJECT con una "
    "motivazione tecnica di massimo 2 frasi.\n\n"
    + PROPOSAL +
    "\n\nRispondi nel formato JSON: {\"vote\": \"APPROVE|REJECT\", \"reason\": \"...\"}"
)


async def main():
    print("=" * 60)
    print(" ATP SDK — Secure Multi-Agent Voting")
    print("=" * 60)
    print(f"\n[ORCHESTRATOR] Proposal:\n  {PROPOSAL[:120]}...\n")

    server = SimpleATPServer()
    await server.start(port=PORT)

    # ── Voting round ─────────────────────────────────────────────────────
    agents = ["agent-alpha", "agent-beta", "agent-gamma", "agent-delta"]
    votes = {}

    for name in agents:
        voter = SimpleATPClient(name)
        await voter.connect(port=PORT)
        print(f"[{name.upper()}] Connected. Voting...")

        response = await voter.chat(VOTE_PROMPT)
        try:
            # Parse JSON vote
            result = json.loads(response)
            vote = result.get("vote", "UNKNOWN")
            reason = result.get("reason", "")
            votes[name] = {"vote": vote, "reason": reason, "mcc": voter.peer_mcc_hash}
            print(f"  → {vote}: {reason[:100]}...")
        except json.JSONDecodeError:
            votes[name] = {"vote": "ERROR", "reason": response[:100], "mcc": voter.peer_mcc_hash}
            print(f"  → ERROR parsing vote")

        await voter.close()

    # ── Tally ────────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print(" VOTING RESULTS")
    print("=" * 60)
    approve = sum(1 for v in votes.values() if v["vote"] == "APPROVE")
    reject = sum(1 for v in votes.values() if v["vote"] == "REJECT")

    for name, v in votes.items():
        emoji = "✅" if v["vote"] == "APPROVE" else "❌" if v["vote"] == "REJECT" else "⚠️"
        print(f"  {emoji} {name:20s} {v['vote']:8s} MCC={v['mcc'][:8]}...")
        print(f"     {v['reason'][:100]}")

    print()
    if approve > reject:
        print(f"🏆 RESULT: APPROVED ({approve}/{len(agents)} votes)")
    elif reject > approve:
        print(f"🏆 RESULT: REJECTED ({reject}/{len(agents)} votes)")
    else:
        print(f"🏆 RESULT: TIE ({approve}-{reject})")

    await server.stop()
    print()
    print("=" * 60)
    print(" All votes cryptographically attested via ATP identity binding")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
