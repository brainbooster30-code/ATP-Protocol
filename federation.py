"""
ATP v2.0 — Federation Protocol.
Peer discovery via gossip, heartbeat, task forwarding with TTL.

Design:
- PEER_DISCOVERY (0x60): gossip di peer conosciuti tra nodi federati
- PEER_HEARTBEAT (0x61): keepalive periodico, mantiene la routing table fresca
- TASK_FORWARD (0x62): inoltra un task attraverso la rete federata (TTL-bounded)
- PEER_DISCOVERY_ACK (0x63): conferma ricezione discovery
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from typing import Optional

from atp_core import build_header

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
#  Configuration
# ═══════════════════════════════════════════════════════════════════════════════

FED_HEARTBEAT_INTERVAL_S = 15      # intervallo heartbeat tra nodi
FED_DISCOVERY_INTERVAL_S = 60      # intervallo gossip di peer list
FED_DISCOVERY_FANOUT = 3           # quanti peer contattare per gossip
FED_MAX_TASK_TTL = 5               # max hop count per TASK_FORWARD
FED_PEER_TIMEOUT_S = 90            # dopo quanto un peer è considerato morto
FED_MAX_PEERS_TRACKED = 100        # cap massimo nella routing table
FED_PORT = 8450                    # porta TCP per connessioni federate
FED_POOL_IDLE_TIMEOUT = 300        # secondi prima di chiudere una connessione outbound in pool


# ═══════════════════════════════════════════════════════════════════════════════
#  PeerRecord — un peer nella routing table
# ═══════════════════════════════════════════════════════════════════════════════

class PeerRecord:
    """Informazioni su un peer nella rete federata."""

    def __init__(self, peer_id: str, host: str, port: int,
                 ed25519_pk: bytes, x25519_pk: bytes,
                 capabilities: Optional[list] = None):
        self.peer_id = peer_id
        self.host = host
        self.port = port
        self.ed25519_pk = ed25519_pk
        self.x25519_pk = x25519_pk
        self.capabilities = capabilities or []
        self.last_seen = time.time()
        self.discovered_by = ""  # chi ci ha parlato di questo peer
        self.hop_count = 0      # distanza da noi

    @property
    def is_alive(self) -> bool:
        return (time.time() - self.last_seen) < FED_PEER_TIMEOUT_S

    def to_dict(self) -> dict:
        return {
            "peer_id": self.peer_id,
            "host": self.host,
            "port": self.port,
            "ed25519_pk": self.ed25519_pk,
            "capabilities": self.capabilities,
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  FederationRouter — gestisce la routing table e inoltra i task
# ═══════════════════════════════════════════════════════════════════════════════

class FederationRouter:
    """Routing table + discovery + heartbeat per la rete federata."""

    def __init__(self, node_id: str, host: str = "0.0.0.0", port: int = FED_PORT):
        self.node_id = node_id
        self.host = host
        self.port = port
        self._peers: dict[str, PeerRecord] = {}       # peer_id → PeerRecord
        self._peers_lock = asyncio.Lock()
        self._forward_hops: deque = deque(maxlen=100)  # recent forward attempts
        # Outbound connection pool for task forwarding
        self._outbound_pool: dict[str, tuple] = {}    # "host:port" → (ATPClient, last_used_ts)
        self._pool_lock = asyncio.Lock()

    @property
    def peer_count(self) -> int:
        return len(self._peers)

    async def add_or_update_peer(self, record: PeerRecord, discovered_by: str = ""):
        """Add a new peer or update last_seen if already known.

        *discovered_by* is the peer_id that gossiped this peer to us.
        When set, the new peer's hop_count is discoverer's hop_count + 1.
        """
        async with self._peers_lock:
            if record.peer_id == self.node_id:
                return  # don't add self
            existing = self._peers.get(record.peer_id)
            if existing:
                existing.last_seen = time.time()
                existing.host = record.host or existing.host
                existing.port = record.port or existing.port
                # Keep the shortest known hop distance
                if discovered_by:
                    discoverer = self._peers.get(discovered_by)
                    via_hop = (discoverer.hop_count + 1) if discoverer else 1
                    if via_hop < existing.hop_count:
                        existing.hop_count = via_hop
                        existing.discovered_by = discovered_by
            else:
                if len(self._peers) >= FED_MAX_PEERS_TRACKED:
                    # Evict dead peer
                    dead = [k for k, v in self._peers.items() if not v.is_alive]
                    if dead:
                        del self._peers[dead[0]]
                    else:
                        return  # table full
                # Calculate hop distance: discoverer's hop + 1, or direct (1)
                if discovered_by:
                    discoverer = self._peers.get(discovered_by)
                    record.hop_count = (discoverer.hop_count + 1) if discoverer else 1
                else:
                    record.hop_count = 1  # direct discovery
                record.discovered_by = discovered_by
                self._peers[record.peer_id] = record
                logger.info("Federation: discovered peer %s at %s:%s (hop=%d)",
                            record.peer_id[:16], record.host, record.port,
                            record.hop_count)

    async def remove_peer(self, peer_id: str):
        async with self._peers_lock:
            self._peers.pop(peer_id, None)

    async def get_live_peers(self) -> list[PeerRecord]:
        """Return all peers considered alive."""
        async with self._peers_lock:
            return [p for p in self._peers.values() if p.is_alive]

    async def get_peer_list(self) -> list[dict]:
        """Return list of peer dicts for gossip."""
        peers = await self.get_live_peers()
        return [p.to_dict() for p in peers[:FED_DISCOVERY_FANOUT]]

    async def forward_task(self, task: dict, ttl: int = FED_MAX_TASK_TTL) -> Optional[PeerRecord]:
        """Find the best peer to forward a TASK_FORWARD frame to.

        Looks up *target_peer_id* in the routing table and returns the
        PeerRecord if the peer is alive and *ttl > 0*.  Returns *None*
        when no route is available — the caller should drop the frame.

        The caller is responsible for opening a connection and sending
        the TASK_FORWARD frame to the returned PeerRecord's host:port.
        """
        if ttl <= 0:
            return None
        target_id = task.get("target_peer_id", "")
        if not target_id:
            return None
        async with self._peers_lock:
            peer = self._peers.get(target_id)
            if peer is None or not peer.is_alive:
                return None
            return peer

    # ── Outbound connection pool ────────────────────────────────────

    async def get_outbound_connection(self, host: str, port: int):
        """Get a cached outbound connection or create a new one.

        Returns an ATPClient whose *agent* is ready to send frames.
        The caller MUST call *return_connection* when done so the
        connection is returned to the pool instead of being closed.
        """
        from client import ATPClient
        key = f"{host}:{port}"
        async with self._pool_lock:
            entry = self._outbound_pool.get(key)
            if entry is not None:
                client, _ = entry
                if client.agent and client.agent._writer:
                    # Connection still alive
                    self._outbound_pool[key] = (client, time.time())
                    return client
                # Dead entry — discard
                del self._outbound_pool[key]

        # Create new connection
        client = ATPClient()
        ok = await client.connect(host, port)
        if not ok:
            return None
        async with self._pool_lock:
            self._outbound_pool[key] = (client, time.time())
        return client

    async def return_connection(self, host: str, port: int):
        """Return a connection to the pool (no-op — managed by get_outbound_connection).

        Call this in a finally block after using a pooled connection.
        The pool keeps the connection alive; it will be cleaned up
        by *cleanup_pool* after the idle timeout.
        """
        pass  # connection is already stored in pool

    async def cleanup_pool(self):
        """Close and remove idle connections from the pool."""
        now = time.time()
        async with self._pool_lock:
            dead_keys = []
            for key, (client, last_used) in self._outbound_pool.items():
                if now - last_used > FED_POOL_IDLE_TIMEOUT:
                    try:
                        await client.disconnect()
                    except Exception:
                        pass
                    dead_keys.append(key)
            for k in dead_keys:
                del self._outbound_pool[k]
            if dead_keys:
                logger.debug("Federation: pool cleanup — closed %d idle connections", len(dead_keys))


# ═══════════════════════════════════════════════════════════════════════════════
#  HeartbeatManager — mantiene vive le connessioni federate
# ═══════════════════════════════════════════════════════════════════════════════

class HeartbeatManager:
    """Periodic heartbeat verso peer connessi per mantenere la routing table fresca.

    Invia PEER_HEARTBEAT (0x61) a ogni agente connesso.  Il ricevente
    aggiorna last_seen nella routing table (gestito in _dispatch_frame).
    """

    def __init__(self, router: FederationRouter, interval_s: float = FED_HEARTBEAT_INTERVAL_S):
        self._router = router
        self._interval = interval_s
        self._running = False
        # Connected agents to heartbeat (populated by ATPServer)
        self._peer_agents: list = []  # list of ATPAgent references

    def add_peer_agent(self, agent):
        """Register a connected agent for heartbeat."""
        if agent not in self._peer_agents:
            self._peer_agents.append(agent)

    def remove_peer_agent(self, agent):
        """Unregister a disconnected agent."""
        try:
            self._peer_agents.remove(agent)
        except ValueError:
            pass

    async def loop(self):
        """Send PEER_HEARTBEAT to connected peers and prune dead ones."""
        self._running = True
        while self._running:
            await asyncio.sleep(self._interval)
            try:
                # Prune dead peers from routing table
                async with self._router._peers_lock:
                    dead = [k for k, v in self._router._peers.items() if not v.is_alive]
                    for k in dead:
                        del self._router._peers[k]

                # Send heartbeat to all connected agents
                frame = {
                    "header": build_header(0x61),
                    "node_id": self._router.node_id,
                    "timestamp": int(time.time()),
                }
                agents = list(self._peer_agents)
                for agent in agents:
                    try:
                        await agent._send_frame(frame)
                    except Exception:
                        pass  # best-effort heartbeat
                if agents:
                    logger.debug("Federation: heartbeat sent to %d agents", len(agents))
            except Exception as exc:
                logger.debug("Federation: heartbeat error — %s", exc)

    def stop(self):
        self._running = False


# ═══════════════════════════════════════════════════════════════════════════════
#  PeerDiscovery — gossip di peer conosciuti tra nodi federati
# ═══════════════════════════════════════════════════════════════════════════════

class PeerDiscovery:
    """Gossip protocol for peer discovery — propagates known peers across the federation."""

    def __init__(self, router: FederationRouter,
                 interval_s: float = FED_DISCOVERY_INTERVAL_S,
                 fanout: int = FED_DISCOVERY_FANOUT):
        self._router = router
        self._interval = interval_s
        self._fanout = fanout
        self._running = False
        # Connected agents to broadcast to (populated by ATPServer)
        self._peer_agents: list = []  # list of ATPAgent references

    def add_peer_agent(self, agent):
        """Register a connected agent for PEER_DISCOVERY broadcasts."""
        if agent not in self._peer_agents:
            self._peer_agents.append(agent)

    def remove_peer_agent(self, agent):
        """Unregister a disconnected agent."""
        try:
            self._peer_agents.remove(agent)
        except ValueError:
            pass

    async def broadcast_peer_list(self, agent):
        """Send PEER_DISCOVERY with our peer list to a connected federation peer.
        
        The frame is Ed25519-signed by the sender for authenticity.
        """
        peer_list = await self._router.get_peer_list()
        if not peer_list:
            return
        # Add Ed25519 signature for authenticity
        from atp_core import ed25519_sign
        import cbor2 as _cbor2
        payload = _cbor2.dumps(
            {"node_id": self._router.node_id, "peers": peer_list},
            canonical=True,
        )
        sig = ed25519_sign(agent.identity.ed25519_sk, payload)
        frame = {
            "header": build_header(0x60),
            "peers": peer_list,
            "node_id": self._router.node_id,
            "signature": sig,
        }
        await agent._send_frame(frame)
        logger.debug("Federation: broadcast peer list (%d peers) signed", len(peer_list))

    async def loop(self):
        """Periodically gossip peer list to all connected federation peers."""
        self._running = True
        while self._running:
            await asyncio.sleep(self._interval)
            # Snapshot the list to avoid mutation during iteration
            agents = list(self._peer_agents)
            for agent in agents:
                try:
                    await self.broadcast_peer_list(agent)
                except Exception as exc:
                    logger.debug("Federation: discovery broadcast error — %s", exc)

    def stop(self):
        self._running = False
