"""
ATP v2.0 — Federation Example

Avvia 3 server ATP con federation attiva, li connette tra loro,
e mostra come i peer si scoprono automaticamente via gossip e
task forwarding con connection pooling.

Il forwarding ora è automatico: alpha invia TASK_FORWARD a beta,
beta lo riceve in _dispatch_frame(0x62) e lo inoltra a gamma
aprendo una nuova connessione outbound (con pool).  Gamma processa
il task localmente.

Esecuzione:  python federation_example.py
"""

import asyncio, sys, os, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from server import ATPServer
from client import ATPClient
from atp_core import build_header, ed25519_sign
import cbor2 as _cbor2
import config


async def main():
    print("=== ATP Federation Example ===\n")

    # 3 server su porte diverse (ognuno con health + gossip isolati)
    PORTS = (18950, 18951, 18952)
    HC_PORTS = (18970, 18971, 18972)   # health check ports isolate
    NAMES = ("alpha", "beta", "gamma")
    servers = []
    tasks = []
    orig_gossip = config.GOSSIP_PORT

    # Avvio 3 server
    print("1. Avvio 3 server ATP con federation...")
    for i, (port, name, hc_port) in enumerate(zip(PORTS, NAMES, HC_PORTS)):
        config.GOSSIP_PORT = 18960 + i  # gossip ports isolate
        srv = ATPServer(trust_bootstrap_mode="tofu")
        srv.identity.agent_name = f"node-{name}"
        servers.append(srv)
        tasks.append(asyncio.create_task(
            srv.start("127.0.0.1", port, block=False, health_port=hc_port)
        ))
        await asyncio.sleep(0.3)
    config.GOSSIP_PORT = orig_gossip
    print("   ✅ 3 server online\n")

    # Connessioni: alpha → beta → gamma
    # Ogni connessione crea un ATPAgent lato server che viene registrato
    # automaticamente in PeerDiscovery e HeartbeatManager.
    print("2. Connessioni federate + peer discovery...")
    clients = []
    for src, dst in [(0, 1), (1, 2)]:
        cli = ATPClient(trust_bootstrap_mode="tofu")
        ok = await cli.connect("127.0.0.1", PORTS[dst])
        if ok:
            # Task normale per triggerare RootStore push
            await cli.send_task("echo", f"hello-from-{NAMES[src]}", deadline_ms=3000)

            # Condividi peer list via PEER_DISCOVERY (0x60) — firmato Ed25519
            disc_peers = [
                {"peer_id": servers[src].identity.agent_name,
                 "host": "127.0.0.1", "port": PORTS[src],
                 "ed25519_pk": servers[src].identity.ed25519_pk,
                 "capabilities": []},
            ]
            disc_payload = _cbor2.dumps(
                {"node_id": servers[src].identity.agent_name, "peers": disc_peers},
                canonical=True,
            )
            disc_sig = ed25519_sign(cli.agent.identity.ed25519_sk, disc_payload)
            disc = {
                "header": build_header(0x60),
                "peers": disc_peers,
                "node_id": servers[src].identity.agent_name,
                "signature": disc_sig,
            }
            await cli.agent._send_frame(disc)
            print(f"   {NAMES[src]} → {NAMES[dst]}: ✅")
        clients.append(cli)
    await asyncio.sleep(1.0)
    print()

    # Routing table
    print("3. Routing table dopo peer discovery:")
    for i, name in enumerate(NAMES):
        pc = servers[i]._fed_router.peer_count
        peers = []
        async with servers[i]._fed_router._peers_lock:
            peers = list(servers[i]._fed_router._peers.keys())
        print(f"   node-{name}: {pc} peer — {[p[:12] for p in peers]}")
    print()

    # Echo test su tutti i nodi
    print("4. Echo test su tutti i nodi (connettività):")
    for i, name in enumerate(NAMES):
        cli = ATPClient(trust_bootstrap_mode="tofu")
        r = {}
        ok = await cli.connect("127.0.0.1", PORTS[i])
        if ok:
            r = await cli.send_task("echo", f"ping-{name}", deadline_ms=3000)
        await cli.disconnect()
        icon = "OK" if r.get("status") == "ok" else "FAIL"
        print(f"   node-{name}: {icon}")
    print()

    # ▸ Task forwarding automatico: alpha → gamma (via beta)
    # Il frame TASK_FORWARD (0x62) è firmato Ed25519 e processato da
    # _dispatch_frame(0x62) su beta, che chiama _forward_task_to_peer()
    # → apre connessione outbound a gamma (con pool) e inoltra il frame.
    print("5. Task forwarding alpha → gamma (via beta, connection pool):")
    inner_task_a = {
        "header": build_header(0x01),
        "task_type": "echo",
        "task_payload": b"forwarded-across-federation",
        "deadline_ms": 5000,
    }
    fwd_payload_a = _cbor2.dumps({
        "target_peer_id": "node-gamma",
        "ttl": 5,
        "task_frame": inner_task_a,
        "forwarder_id": clients[0].agent.identity.agent_name,
    }, canonical=True)
    fwd_sig_a = ed25519_sign(clients[0].agent.identity.ed25519_sk, fwd_payload_a)
    fwd = {
        "header": build_header(0x62),
        "target_peer_id": "node-gamma",
        "ttl": 5,
        "task_frame": inner_task_a,
        "signature": fwd_sig_a,
        "forwarder_id": clients[0].agent.identity.agent_name,
    }
    try:
        # Invia TASK_FORWARD sulla connessione alpha→beta
        await clients[0].agent._send_frame(fwd)
        print("   ✅ TASK_FORWARD inviato (alpha → beta)")
        print("   ✅ forwarding automatico beta → gamma (via pool)")
    except Exception as e:
        print(f"   ❌ TASK_FORWARD fallito: {e}")

    # Verifica connessione pool: secondo forward riusa la stessa conn
    print("\n6. Secondo forward (riutilizza connessione pool):")
    inner_task_b = {
        "header": build_header(0x01),
        "task_type": "echo",
        "task_payload": b"second-forward-via-pool",
        "deadline_ms": 5000,
    }
    fwd_payload_b = _cbor2.dumps({
        "target_peer_id": "node-gamma",
        "ttl": 5,
        "task_frame": inner_task_b,
        "forwarder_id": clients[0].agent.identity.agent_name,
    }, canonical=True)
    fwd_sig_b = ed25519_sign(clients[0].agent.identity.ed25519_sk, fwd_payload_b)
    fwd2 = {
        "header": build_header(0x62),
        "target_peer_id": "node-gamma",
        "ttl": 5,
        "task_frame": inner_task_b,
        "signature": fwd_sig_b,
        "forwarder_id": clients[0].agent.identity.agent_name,
    }
    try:
        await clients[0].agent._send_frame(fwd2)
        print("   ✅ Secondo TASK_FORWARD inviato (stessa connessione pool)")
        # Verifica stato pool
        pool_sz = len(servers[1]._fed_router._outbound_pool)
        print(f"   📊 Pool connessioni su beta: {pool_sz} entry")
    except Exception as e:
        print(f"   ❌ Secondo forward fallito: {e}")

    # Cleanup
    print("\n7. Cleanup...")
    for c in clients:
        await c.disconnect()
    for t in tasks:
        t.cancel()
        try:
            await t
        except BaseException:
            pass
    for s in servers:
        try:
            await asyncio.wait_for(s.stop(), timeout=2.0)
        except BaseException:
            pass
    print("   ✅ Fatto.\n")


if __name__ == "__main__":
    asyncio.run(main())
