"""
ATP v1.7 — TCP/TLS Server.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import logging
from typing import Optional

from config import SERVER_HOST, SERVER_PORT, CONNECTION_SETUP_TIMEOUT_MS
from agent import ATPAgent, AgentIdentity, make_ssl_context
from monitor import Monitor, ERROR_OCCURRED
from atp_core import decode_frame, build_header, send_frame

logger = logging.getLogger(__name__)


class ATPServer:
    """
    ATP server that accepts TLS connections and runs an ATPAgent per peer.
    Runs inside its own asyncio event loop.
    """

    def __init__(self, monitor: Optional[Monitor] = None):
        self.monitor = monitor
        self._server: Optional[asyncio.AbstractServer] = None
        self._gossip_task: Optional[asyncio.Task] = None
        self._gossip_server_task: Optional[asyncio.Task] = None
        self._gossip_server = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False
        self.identity = AgentIdentity(agent_name="atp-server")

    async def start(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        """Start the TCP/TLS server, background gossip loop, and gossip server."""
        self._loop = asyncio.get_running_loop()

        # Build SSL context with CA-signed cert (mutual TLS)
        ssl_ctx = make_ssl_context(server_side=True, cn=f"atp-server-{host}:{port}")

        self._server = await asyncio.start_server(
            self._on_connect,
            host=host,
            port=port,
            ssl=ssl_ctx,
            reuse_address=True,
        )
        self._running = True
        addr = self._server.sockets[0].getsockname()
        logger.info("ATP Server listening on %s:%s (TLS mutual)", addr[0], addr[1])

        # Start background gossip protocol
        from revocation import get_gossip, GossipServer
        gossip = get_gossip(node_id=f"server-{host}:{port}")
        self._gossip_task = asyncio.create_task(gossip.gossip_loop(interval_s=5))
        logger.info("Gossip protocol started (interval=5s, fanout=3)")

        # Start gossip TCP server for incoming revocation data
        from config import GOSSIP_PORT
        self._gossip_server = GossipServer(monitor=self.monitor)
        self._gossip_server_task = asyncio.create_task(
            self._gossip_server.start(host=host, port=GOSSIP_PORT)
        )

        # Keep running until cancelled
        try:
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            logger.info("ATP server serve_forever cancelled")
        finally:
            self._running = False
            if self._gossip_task:
                self._gossip_task.cancel()
            if self._gossip_server_task:
                self._gossip_server_task.cancel()

    async def stop(self):
        """Gracefully stop the server, gossip loop, and gossip server."""
        self._running = False
        if self._gossip_server:
            await self._gossip_server.stop()
        if self._gossip_task:
            self._gossip_task.cancel()
        if self._gossip_server_task:
            self._gossip_server_task.cancel()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("ATP Server stopped")

    async def _on_connect(self, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter):
        """Handle one incoming connection."""
        from config import RateLimiter, AntiReplay
        rate_limiter = RateLimiter()
        anti_replay = AntiReplay()

        agent = ATPAgent(
            identity=self.identity,
            is_server=True,
            monitor=self.monitor,
            task_handler=self._default_task_handler,
            rate_limiter=rate_limiter,
            anti_replay=anti_replay,
        )
        try:
            ok = await agent.perform_handshake(reader, writer)
            if ok:
                await agent.handle_task_loop()
        except Exception as exc:
            logger.exception("Connection handler error")
            if self.monitor:
                self.monitor.add_event("ERROR_OCCURRED", {
                    "conn_id": agent._conn_id if hasattr(agent, '_conn_id') else "",
                    "error_message": str(exc),
                })
        finally:
            await agent.close_async()
            try:
                writer.close()
            except Exception:
                pass  # nosec — cleanup, connection already closing

    async def _default_task_handler(self, frame: dict) -> dict:
        """Default handler: echo payload or call DeepSeek."""
        task_payload = frame.get("task_payload", b"")
        task_type = frame.get("task_type", "unknown")

        if task_type == "deepseek_chat":
            prompt = task_payload.decode("utf-8", errors="replace")
            result = await ATPAgent.call_deepseek(prompt, self.monitor)
            if result:
                return {"result": result}
            else:
                return {"error": "DeepSeek returned no result"}
        else:
            return {"echo": task_payload.decode("utf-8", errors="replace")}
