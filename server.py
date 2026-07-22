"""
ATP v1.8 — TCP/TLS Server (production grade).
Graceful shutdown, health checks, connection limiting, structured logging.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import logging
from typing import Optional

from config import (
    SERVER_HOST, SERVER_PORT, CONNECTION_SETUP_TIMEOUT_MS, MAX_CONCURRENT_CONNS,
)
from agent import ATPAgent, AgentIdentity, make_ssl_context
from monitor import Monitor, ERROR_OCCURRED
from atp_core import decode_frame, build_header, send_frame
from production import (
    setup_logging, GracefulShutdown, HealthCheckServer, ConnectionLimiter,
    deepseek_circuit,
)

logger = logging.getLogger(__name__)


class ATPServer:
    """
    ATP server that accepts TLS connections and runs an ATPAgent per peer.
    Runs inside its own asyncio event loop.
    """

    def __init__(self, monitor: Optional[Monitor] = None,
                 conn_limiter: Optional[ConnectionLimiter] = None,
                 shutdown: Optional[GracefulShutdown] = None,
                 health: Optional[HealthCheckServer] = None):
        self.monitor = monitor
        self._server: Optional[asyncio.AbstractServer] = None
        self._gossip_task: Optional[asyncio.Task] = None
        self._gossip_server_task: Optional[asyncio.Task] = None
        self._gossip_server = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False
        self.identity = AgentIdentity(agent_name="atp-server")
        self._conn_limiter = conn_limiter or ConnectionLimiter(max_conns=MAX_CONCURRENT_CONNS)
        self._shutdown = shutdown or GracefulShutdown()
        self._health = health

    async def start(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        """Start the TCP/TLS server, gossip, health checks — ready for production."""
        self._loop = asyncio.get_running_loop()

        # Structured logging
        setup_logging()

        # Signal handlers for graceful shutdown
        self._shutdown.register(self._loop)

        # Build SSL context
        ssl_ctx = make_ssl_context(server_side=True, cn=f"atp-server-{host}:{port}")

        self._server = await asyncio.start_server(
            self._on_connect, host=host, port=port,
            ssl=ssl_ctx, reuse_address=True,
        )
        self._running = True
        addr = self._server.sockets[0].getsockname()
        logger.info("ATP Server listening on %s:%s (TLS mutual, max_conns=%d)",
                     addr[0], addr[1], self._conn_limiter.max)

        # Health check endpoint
        if self._health is None:
            self._health = HealthCheckServer(conn_limiter=self._conn_limiter)
        health_task = asyncio.create_task(self._health.start())
        self._shutdown.track(health_task)

        # Gossip protocol
        from revocation import get_gossip, GossipServer
        gossip = get_gossip(node_id=f"server-{host}:{port}")
        self._gossip_task = asyncio.create_task(gossip.gossip_loop(interval_s=5))
        self._shutdown.track(self._gossip_task)

        from config import GOSSIP_PORT
        self._gossip_server = GossipServer(monitor=self.monitor)
        self._gossip_server_task = asyncio.create_task(
            self._gossip_server.start(host=host, port=GOSSIP_PORT)
        )
        self._shutdown.track(self._gossip_server_task)

        # Mark ready for Kubernetes readiness probe
        self._health.ready = True
        logger.info("ATP Server ready — health check on :%s", self._health._port)

        try:
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            logger.info("ATP server serve_forever cancelled (shutdown)")
        finally:
            self._running = False
            await self._shutdown.drain()
            await self._health.stop()
            if self._gossip_server:
                await self._gossip_server.stop()
            logger.info("ATP Server stopped gracefully")

    async def stop(self):
        """Gracefully stop and drain — called by external orchestrator."""
        self._running = False
        self._shutdown._shutting_down = True
        if self._server:
            self._server.close()
        await self._shutdown.shutdown_server(self._server)
        if self._health:
            self._health.ready = False
            await self._health.stop()
        logger.info("ATP Server stopped")

    async def _on_connect(self, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter):
        """Handle one incoming connection with rate limiting + connection capping."""
        from config import RateLimiter, AntiReplay, HandshakeRateLimiter

        # Check shutdown state
        if self._shutdown.shutting_down:
            writer.close()
            return

        # Global connection limiter (backpressure)
        if not await self._conn_limiter.acquire():
            logger.warning("Connection rejected — server at capacity (%d/%d)",
                           self._conn_limiter.active, self._conn_limiter.max)
            writer.close()
            return

        try:
            # Handshake rate limiter (per IP)
            peer_ip, peer_port = writer.get_extra_info("peername", ("0.0.0.0", 0))[:2]
            if not hasattr(ATPServer, "_hs_limiter"):
                ATPServer._hs_limiter = HandshakeRateLimiter()
            if not await ATPServer._hs_limiter.allow(str(peer_ip)):
                logger.warning("Handshake rate limit exceeded for %s", peer_ip)
                writer.close()
                return

            agent = ATPAgent(
                identity=self.identity, is_server=True, monitor=self.monitor,
                task_handler=self._default_task_handler,
                rate_limiter=RateLimiter(), anti_replay=AntiReplay(),
            )
            try:
                ok = await agent.perform_handshake(reader, writer)
                if ok:
                    if hasattr(ATPServer, "_hs_limiter"):
                        ATPServer._hs_limiter.reset(str(peer_ip))
                    await agent.handle_task_loop()
            except Exception as exc:
                logger.exception("Connection handler error")
                if self.monitor:
                    self.monitor.add_event("ERROR_OCCURRED", {
                        "conn_id": getattr(agent, '_conn_id', ""),
                        "error_message": str(exc),
                    })
            finally:
                await agent.close_async()
                try:
                    writer.close()
                except Exception:
                    pass
        finally:
            self._conn_limiter.release()

    async def _default_task_handler(self, frame: dict) -> dict:
        """Default handler: echo or DeepSeek with circuit breaker."""
        task_payload = frame.get("task_payload", b"")
        task_type = frame.get("task_type", "unknown")

        if task_type == "deepseek_chat":
            if not deepseek_circuit.allow():
                return {"error": "DeepSeek temporarily unavailable (circuit open)"}
            prompt = task_payload.decode("utf-8", errors="replace")
            result = await ATPAgent.call_deepseek(prompt, self.monitor)
            if result:
                return {"result": result}
            return {"error": "DeepSeek returned no result"}
        return {"echo": task_payload.decode("utf-8", errors="replace")}
