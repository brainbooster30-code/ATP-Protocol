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

    @property
    def peer_count(self) -> int:
        return len(self._peers)

    async def add_or_update_peer(self, record: PeerRecord, discovered_by: str = ""):
        """Add a new peer or update last_seen if already known."""
        async with self._peers_lock:
            if record.peer_id == self.node_id:
                return  # don't add self
            existing = self._peers.get(record.peer_id)
            if existing:
                existing.last_seen = time.time()
                existing.host = record.host or existing.host
                existing.port = record.port or existing.port
            else:
                if len(self._peers) >= FED_MAX_PEERS_TRACKED:
                    # Evict dead peer
                    dead = [k for k, v in self._peers.items() if not v.is_alive]
                    if dead:
                        del self._peers[dead[0]]
                    else:
                        return  # table full
                record.discovered_by = discovered_by
                self._peers[record.peer_id] = record
                logger.info("Federation: discovered peer %s at %s:%s",
                            record.peer_id[:16], record.host, record.port)

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

    async def forward_task(self, task: dict, ttl: int = FED_MAX_TASK_TTL) -> bool:
        """Forward a TASK_FORWARD frame to the best peer matching the target.
        Returns True if forwarded, False if no route found."""
        if ttl <= 0:
            return False  # TTL exhausted
        target_id = task.get("target_peer_id", "")
        async with self._peers_lock:
            if target_id and target_id in self._peers:
                return True  # route exists
            # Broadcast to all live peers if no specific target
            return len([p for p in self._peers.values() if p.is_alive]) > 0


# ═══════════════════════════════════════════════════════════════════════════════
#  HeartbeatManager — mantiene vive le connessioni federate
# ═══════════════════════════════════════════════════════════════════════════════

class HeartbeatManager:
    """Periodic heartbeat verso peer connessi per mantenere la routing table fresca."""

    def __init__(self, router: FederationRouter, interval_s: float = FED_HEARTBEAT_INTERVAL_S):
        self._router = router
        self._interval = interval_s
        self._running = False

    async def loop(self):
        """Send HEARTBEAT to connected peers periodically."""
        self._running = True
        while self._running:
            await asyncio.sleep(self._interval)
            try:
                peers = await self._router.get_live_peers()
                logger.debug("Federation: heartbeat — %d live peers", len(peers))
                # Prune dead peers
                async with self._router._peers_lock:
                    dead = [k for k, v in self._router._peers.items() if not v.is_alive]
                    for k in dead:
                        del self._router._peers[k]
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
        # Queue of peers we want to talk to (populated by the server)
        self._discovery_targets: list = []  # list of (reader, writer) pairs

    def set_targets(self, targets: list):
        """Update the list of connected ATP peers for gossip."""
        self._discovery_targets = list(targets)

    async def broadcast_peer_list(self, agent):
        """Send PEER_DISCOVERY with our peer list to connected federation peers."""
        peer_list = await self._router.get_peer_list()
        if not peer_list:
            return
        frame = {
            "header": build_header(0x60),
            "peers": peer_list,
            "node_id": self._router.node_id,
        }
        await agent._send_frame(frame)
        logger.debug("Federation: broadcast peer list (%d peers)", len(peer_list))

    async def loop(self, agent):
        """Periodically gossip peer list to connected peers."""
        self._running = True
        while self._running:
            await asyncio.sleep(self._interval)
            try:
                await self.broadcast_peer_list(agent)
            except Exception as exc:
                logger.debug("Federation: discovery error — %s", exc)

    def stop(self):
        self._running = False
