"""
ATP v1.8 — Stress Test (production readiness)

Esegue:
  1. Test di carico: N connessioni parallele → K task ciascuna
  2. Misura: latenza media, throughput, errori
  3. Verifica che nessuna connessione causi deadlock

Uso:
    python stress_test.py               # 20 connessioni, 10 task
    python stress_test.py 50 20         # 50 connessioni, 20 task
"""

import asyncio, sys, time, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

N_CONNS = int(sys.argv[1]) if len(sys.argv) > 1 else 20
K_TASKS = int(sys.argv[2]) if len(sys.argv) > 2 else 10


async def client_worker(port: int, worker_id: int) -> dict:
    """One client: connect, run K_TASKS, disconnect, return stats."""
    from client import ATPClient

    stats = {"id": worker_id, "ok": 0, "fail": 0, "latencies": []}
    cli = ATPClient()
    try:
        ok = await cli.connect("127.0.0.1", port)
    except Exception as e:
        stats["fail"] = K_TASKS
        stats["error"] = str(e)
        return stats

    if not ok:
        stats["fail"] = K_TASKS
        stats["error"] = "handshake_fail"
        return stats

    for i in range(K_TASKS):
        t0 = time.time()
        try:
            result = await cli.send_task("echo", f"load-{worker_id}-{i}", deadline_ms=3000)
            if result.get("status") == "ok":
                stats["ok"] += 1
            else:
                stats["fail"] += 1
                stats.setdefault("last_error", result.get("status"))
        except Exception as e:
            stats["fail"] += 1
            stats.setdefault("last_error", str(e))
        stats["latencies"].append((time.time() - t0) * 1000)

    await cli.disconnect()
    return stats


async def main():
    from server import ATPServer

    port = 18700
    print(f"=== ATP Stress Test === N={N_CONNS} conns × {K_TASKS} tasks = {N_CONNS * K_TASKS} total")

    # Start server
    server = ATPServer()
    srv_task = asyncio.create_task(server.start("127.0.0.1", port))
    await asyncio.sleep(0.5)
    t_start = time.time()

    # Run all clients concurrently
    tasks = [client_worker(port, i) for i in range(N_CONNS)]
    results = await asyncio.gather(*tasks)

    t_end = time.time()
    elapsed = t_end - t_start

    # Aggregate stats
    total_ok = sum(r["ok"] for r in results)
    total_fail = sum(r["fail"] for r in results)
    all_latencies = []
    for r in results:
        all_latencies.extend(r["latencies"])
    all_latencies.sort()

    tp = total_ok / elapsed if elapsed > 0 else 0
    p50 = all_latencies[len(all_latencies) // 2] if all_latencies else 0
    p99 = all_latencies[int(len(all_latencies) * 0.99)] if len(all_latencies) > 1 else p50
    max_lat = max(all_latencies) if all_latencies else 0

    print(f"\n{'='*60}")
    print(f"RESULTS:")
    print(f"  Total time:          {elapsed:.2f}s")
    print(f"  Tasks OK:            {total_ok}")
    print(f"  Tasks FAIL:          {total_fail}")
    print(f"  Throughput:          {tp:.1f} tasks/s")
    print(f"  Latency P50:         {p50:.1f}ms")
    print(f"  Latency P99:         {p99:.1f}ms")
    print(f"  Latency MAX:         {max_lat:.1f}ms")
    print(f"{'='*60}")

    # Verdict
    if total_fail == 0 and p99 < 2000:
        print(f"✅ PRODUCTION READY — 0 errori, P99 < 2s")
    elif total_fail == 0:
        print(f"✅ OK — 0 errori (P99 ottimizzabile)")
    elif total_fail <= N_CONNS * 0.01:
        print(f"⚠️  ACCEPTABLE — {total_fail} errori su {total_ok + total_fail} task")
    else:
        print(f"❌ FAIL — {total_fail} errori. Produzione sconsigliata.")

    # Cleanup
    srv_task.cancel()
    try:
        await srv_task
    except (asyncio.CancelledError, Exception):
        pass


if __name__ == "__main__":
    asyncio.run(main())
