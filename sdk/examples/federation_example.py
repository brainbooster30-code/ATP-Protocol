"""
ATP v2.0 — Federation Example

Avvia 3 server ATP con federation attiva, li connette tra loro,
e mostra come i peer si scoprono automaticamente via gossip.

Esecuzione:  python federation_example.py
"""

import asyncio, sys, os, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from server import ATPServer
from client import ATPClient
from atp_core import build_header
import config


async def main():
    print("=== ATP Federation Example ===\n")

    # 3 server su porte diverse
    PORTS = (18950, 18951, 18952)
    NAMES = ("alpha", "beta", "gamma")
    servers = []
    tasks = []
    orig_gossip = config.GOSSIP_PORT

    # Avvio server
    print("Avvio 3 server ATP con federation...")
    for i, (port, name) in enumerate(zip(PORTS, NAMES)):
        config.GOSSIP_PORT = 18960 + i  # isolate gossip ports
        srv = ATPServer()
        srv.identity.agent_name = f"node-{name}"
        servers.append(srv)
        tasks.append(asyncio.create_task(srv.start("127.0.0.1", port, block=False)))
        await asyncio.sleep(0.3)
    config.GOSSIP_PORT = orig_gossip
    print("   ✅ 3 server online\n")

    # Connessioni: alpha → beta → gamma
    print("Connessioni federate...")
    clients = []
    for src, dst in [(0, 1), (1, 2)]:
        cli = ATPClient()
        ok = await cli.connect("127.0.0.1", PORTS[dst])
        if ok:
            await cli.send_task("echo", f"hello-from-{NAMES[src]}", deadline_ms=3000)
            # Share peer list
            disc = {
                "header": build_header(0x60),
                "peers": [
                    {"peer_id": servers[src].identity.agent_name,
                     "host": "127.0.0.1", "port": PORTS[src],
                     "ed25519_pk": servers[src].identity.ed25519_pk,
                     "capabilities": []},
                    {"peer_id": servers[dst].identity.agent_name,
                     "host": "127.0.0.1", "port": PORTS[dst],
                     "ed25519_pk": servers[dst].identity.ed25519_pk,
                     "capabilities": []},
                ],
                "node_id": servers[src].identity.agent_name,
            }
            await cli.agent._send_frame(disc)
            print(f"   {NAMES[src]} → {NAMES[dst]}: ✅")
        clients.append(cli)
    await asyncio.sleep(1.0)
    print()

    # Routing table
    print("Routing table dopo discovery:")
    for i, name in enumerate(NAMES):
        pc = servers[i]._fed_router.peer_count
        peers = []
        async with servers[i]._fed_router._peers_lock:
            peers = list(servers[i]._fed_router._peers.keys())
        print(f"   node-{name}: {pc} peer — {[p[:12] for p in peers]}")
    print()

    # Echo su tutti
    print("Echo test su tutti i nodi:")
    for i, name in enumerate(NAMES):
        cli = ATPClient()
        ok = await cli.connect("127.0.0.1", PORTS[i])
        if ok:
            r = await cli.send_task("echo", f"ping-{name}", deadline_ms=3000)
            print(f"   node-{name}: {'✅' if r.get('status') == 'ok' else '❌'}")
        await cli.disconnect()

    # Forward task
    print("\nTask forwarding alpha → gamma (via beta):")
    fwd = {
        "header": build_header(0x62),
        "target_peer_id": "node-gamma",
        "ttl": 5,
        "task_frame": {
            "header": build_header(0x01),
            "task_type": "echo",
            "task_payload": b"forwarded-across-federation",
            "deadline_ms": 5000,
        },
    }
    try:
        await clients[0].agent._send_frame(fwd)
        print("   ✅ TASK_FORWARD inviato")
    except Exception:
        print("   ❌ TASK_FORWARD fallito")

    # Cleanup
    print("\nCleanup...")
    for c in clients:
        await c.disconnect()
    for t in tasks:
        t.cancel()
        try: await t
        except: pass
    for s in servers:
        try: await asyncio.wait_for(s.stop(), timeout=2.0)
        except: pass
    print("✅ Fatto.\n")


if __name__ == "__main__":
    asyncio.run(main())
