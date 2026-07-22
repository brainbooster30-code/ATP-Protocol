"""
ATP v1.8 — TCP/TLS Client.
"""

from __future__ import annotations

import asyncio
import ssl
import json
import os
import logging
from typing import Optional

from config import SERVER_HOST, SERVER_PORT, CONNECTION_SETUP_TIMEOUT_MS
from agent import ATPAgent, AgentIdentity, make_ssl_context
from monitor import Monitor

logger = logging.getLogger(__name__)


class ATPClient:
    """
    ATP client that connects to an ATP server, performs handshake,
    and can send tasks. Runs inside its own asyncio event loop.
    """

    def __init__(self, monitor: Optional[Monitor] = None,
                 trust_bootstrap_mode: Optional[str] = None):
        self.monitor = monitor
        self.trust_bootstrap_mode = trust_bootstrap_mode
        self.agent: Optional[ATPAgent] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected = False
        self.identity = AgentIdentity(agent_name="atp-client")

    async def connect(self, host: str = SERVER_HOST, port: int = SERVER_PORT) -> bool:
        """Connect to the server and perform the ATP handshake."""
        self._loop = asyncio.get_running_loop()

        # Build SSL context with CA-signed cert (mutual TLS)
        ssl_ctx = make_ssl_context(server_side=False, cn=f"atp-client-{host}:{port}")

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=CONNECTION_SETUP_TIMEOUT_MS / 1000,
            )
        except Exception as exc:
            logger.error("Client connect failed: %s", exc)
            return False

        self.agent = ATPAgent(
            identity=self.identity,
            is_server=False,
            monitor=self.monitor,
            trust_bootstrap_mode=self.trust_bootstrap_mode,
        )

        ok = await self.agent.perform_handshake(self._reader, self._writer)
        self._connected = ok
        if ok:
            logger.info("ATP Client connected and bound to %s:%s", host, port)
        else:
            logger.error("ATP Client handshake failed")
            await self.disconnect()
        return ok

    async def send_task(
        self,
        task_type: str,
        payload: str,
        deadline_ms: int = 30_000,
    ) -> Optional[dict]:
        """Send a task to the server and return the response."""
        if not self._connected or not self.agent:
            logger.error("send_task: not connected")
            return None
        return await self.agent.send_task(
            task_type=task_type,
            payload=payload.encode("utf-8"),
            deadline_ms=deadline_ms,
        )

    async def disconnect(self):
        """Close the connection with proper SSL shutdown."""
        if self.agent:
            await self.agent.close_async()
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass  # nosec — cleanup on disconnect
        self._connected = False
        logger.info("ATP Client disconnected")
