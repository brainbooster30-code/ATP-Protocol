"""
ATP v1.8 — Esempio QUIC Transport

Avvia un server QUIC e un client che si scambiano task.
Richiede: pip install aioquic

Esecuzione:
    python quic_example.py

Output atteso:
    QUIC handshake: ✅
    QUIC echo: ✅
    QUIC streaming (3 chunks): ✅
"""

import asyncio, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

try:
    from atp_quic import QUICServer, QUICClient
except ImportError:
    print("❌ aioquic non installato. Esegui: pip install aioquic")
    sys.exit(1)


async def main():
    # ── Server ─────────────────────────────────────────────────────
    server = QUICServer()
    srv_task = asyncio.create_task(server.start(host="127.0.0.1", port=18900))
    await asyncio.sleep(0.5)
    print(f"⚡ Server QUIC in ascolto su 127.0.0.1:18900")

    # ── Client ─────────────────────────────────────────────────────
    client = QUICClient()
    ok = await client.connect(host="127.0.0.1", port=18900)
    print(f"QUIC handshake: {'✅' if ok else '❌'}")
    if not ok:
        return

    # ── Task echo ──────────────────────────────────────────────────
    result = await client.send_task("echo", "Ciao dal QUIC!", deadline_ms=5000)
    status = result.get("status") if isinstance(result, dict) else "?"
    payload = result.get("data", {}).get("result_payload", b"") if isinstance(result, dict) else b""
    if status == "ok":
        print(f"QUIC echo: ✅  → {payload.decode('utf-8', errors='replace')[:60]}")
    else:
        print(f"QUIC echo: ❌  status={status}")

    # ── Task streaming (3 chunk) ───────────────────────────────────
    stream_result = await client.send_task(
        "echo", "a|b|c", deadline_ms=5000
    )
    s_status = stream_result.get("status") if isinstance(stream_result, dict) else "?"
    print(f"QUIC streaming: {'✅' if s_status == 'ok' else '❌'}  "
          f"(status={s_status})")

    # ── Cleanup ────────────────────────────────────────────────────
    await client.disconnect()
    srv_task.cancel()
    try:
        await srv_task
    except (asyncio.CancelledError, Exception):
        pass
    print("✅ Fatto.")


if __name__ == "__main__":
    asyncio.run(main())
