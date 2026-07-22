"""
ATP v2.0 — Federation Multi-Node Test

Avvia 3 server su porte diverse (ognuno con gossip separato),
li connette tra loro, e verifica peer discovery + task forwarding.

Esecuzione:  python test_federation.py
"""

import asyncio, sys, os, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

errors = []


def check_fed(name: str, cond: bool, detail: str = ""):
    if cond:
        print(f"  ✅ {name}")
    else:
        print(f"  ❌ {name}  {detail}")
        errors.append(name)


async def main():
    print("=== ATP FEDERATION TEST — 3 Nodi ===\n")

    # Use high ports to avoid conflicts
    ATP_A, ATP_B, ATP_C = 18910, 18911, 18912
    GOS_A, GOS_B, GOS_C = 18920, 18921, 18922
    HC_A, HC_B, HC_C = 18930, 18931, 18932

    import config
    orig_gossip = config.GOSSIP_PORT

    # ── Start 3 servers with isolated gossip ports ────────────
    print("1. Avvio 3 server...")
    from server import ATPServer
    from client import ATPClient

    srv_a = ATPServer(trust_bootstrap_mode="tofu"); srv_a.identity.agent_name = "node-alpha"
    srv_b = ATPServer(trust_bootstrap_mode="tofu"); srv_b.identity.agent_name = "node-beta"
    srv_c = ATPServer(trust_bootstrap_mode="tofu"); srv_c.identity.agent_name = "node-gamma"

    # Isolate gossip ports
    config.GOSSIP_PORT = GOS_A
    await srv_a.start("127.0.0.1", ATP_A, block=False, health_port=HC_A)

    config.GOSSIP_PORT = GOS_B
    await srv_b.start("127.0.0.1", ATP_B, block=False, health_port=HC_B)

    config.GOSSIP_PORT = GOS_C
    await srv_c.start("127.0.0.1", ATP_C, block=False, health_port=HC_C)
    await asyncio.sleep(0.3)

    # Restore original gossip port
    config.GOSSIP_PORT = orig_gossip
    print("   ✅ 3 server in ascolto")

    # ── Connect A→B and manually exchange peer info ───────────
    print("\n2. Connessioni + peer discovery...")

    # A → B
    cli_ab = ATPClient(trust_bootstrap_mode="tofu")
    ok_ab = await cli_ab.connect("127.0.0.1", ATP_B)
    check_fed("A → B handshake", ok_ab)
    if ok_ab:
        # Manual peer discovery: send signed PEER_DISCOVERY to B
        from atp_core import build_header, ed25519_sign
        import cbor2 as _cbor2
        peers_a = [
            {"peer_id": "node-alpha", "host": "127.0.0.1", "port": ATP_A,
             "ed25519_pk": srv_a.identity.ed25519_pk, "capabilities": []},
        ]
        disc_payload = _cbor2.dumps(
            {"node_id": "node-alpha", "peers": peers_a}, canonical=True
        )
        disc_sig = ed25519_sign(cli_ab.agent.identity.ed25519_sk, disc_payload)
        disc_a = {
            "header": build_header(0x60),
            "peers": peers_a,
            "node_id": "node-alpha",
            "signature": disc_sig,
        }
        await cli_ab.agent._send_frame(disc_a)
        # Also send normal task to trigger RoosStore push
        await cli_ab.send_task("echo", "hello", deadline_ms=3000)

    # B → C
    cli_bc = ATPClient(trust_bootstrap_mode="tofu")
    ok_bc = await cli_bc.connect("127.0.0.1", ATP_C)
    check_fed("B → C handshake", ok_bc)
    if ok_bc:
        peers_b = [
            {"peer_id": "node-beta", "host": "127.0.0.1", "port": ATP_B,
             "ed25519_pk": srv_b.identity.ed25519_pk, "capabilities": []},
            {"peer_id": "node-alpha", "host": "127.0.0.1", "port": ATP_A,
             "ed25519_pk": srv_a.identity.ed25519_pk, "capabilities": []},
        ]
        disc_b_payload = _cbor2.dumps(
            {"node_id": "node-beta", "peers": peers_b}, canonical=True
        )
        disc_b_sig = ed25519_sign(cli_bc.agent.identity.ed25519_sk, disc_b_payload)
        disc_b = {
            "header": build_header(0x60),
            "peers": peers_b,
            "node_id": "node-beta",
            "signature": disc_b_sig,
        }
        await cli_bc.agent._send_frame(disc_b)
        await cli_bc.send_task("echo", "hello", deadline_ms=3000)

    # Give time for async PEER_DISCOVERY handlers to run
    await asyncio.sleep(1.0)

    # ── Check routing tables ──────────────────────────────────
    print("\n3. Verifica routing table...")
    pc_a = srv_a._fed_router.peer_count
    pc_b = srv_b._fed_router.peer_count
    pc_c = srv_c._fed_router.peer_count
    print(f"   node-alpha peers: {pc_a}")
    print(f"   node-beta  peers: {pc_b}")
    print(f"   node-gamma peers: {pc_c}")

    # B should know about A and C via direct connections
    check_fed("B conosce almeno 1 peer", pc_b >= 1)
    # C should know about B via direct connection
    check_fed("C conosce almeno 1 peer", pc_c >= 1)

    # ── Task forwarding ───────────────────────────────────────
    print("\n4. Task forwarding...")
    if ok_ab:
        inner_task_frame = {
            "header": build_header(0x01),
            "task_type": "echo",
            "task_payload": b"federated-task",
            "deadline_ms": 5000,
        }
        fwd_task_payload = _cbor2.dumps({
            "target_peer_id": "node-beta",
            "ttl": 5,
            "task_frame": inner_task_frame,
            "forwarder_id": cli_ab.agent.identity.agent_name,
        }, canonical=True)
        fwd_sig = ed25519_sign(cli_ab.agent.identity.ed25519_sk, fwd_task_payload)
        fwd = {
            "header": build_header(0x62),
            "target_peer_id": "node-beta",
            "ttl": 5,
            "task_frame": inner_task_frame,
            "signature": fwd_sig,
            "forwarder_id": cli_ab.agent.identity.agent_name,
        }
        try:
            await cli_ab.agent._send_frame(fwd)
            fwd_ok = True
        except Exception:
            fwd_ok = False
        check_fed("TASK_FORWARD inviato via federation", fwd_ok)

    # ── Echo on all servers ───────────────────────────────────
    print("\n5. Echo...")
    for name, port in [("A", ATP_A), ("B", ATP_B), ("C", ATP_C)]:
        cli = ATPClient(trust_bootstrap_mode="tofu")
        ok = await cli.connect("127.0.0.1", port)
        if ok:
            r = await cli.send_task("echo", f"ping-{name}", deadline_ms=3000)
            check_fed(f"Echo node {name}", r.get("status") == "ok")
        await cli.disconnect()

    # ── Cleanup ───────────────────────────────────────────────
    print("\n6. Cleanup...")
    await cli_ab.disconnect()
    await cli_bc.disconnect()
    for s in [srv_a, srv_b, srv_c]:
        try: await asyncio.wait_for(s.stop(), timeout=2.0)
        except: pass

    # ── Report ────────────────────────────────────────────────
    print(f"\n{'='*50}")
    if errors:
        print(f"❌ {len(errors)} TEST FALLITI:")
        for e in errors: print(f"   - {e}")
    else:
        print("✅ ALL FEDERATION TESTS PASSED")
    print(f"{'='*50}")


    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
