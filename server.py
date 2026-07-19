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
from agent import ATPAgent, AgentIdentity, get_self_signed_cert
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
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False
        self.identity = AgentIdentity(agent_name="atp-server")

    async def start(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        """Start the TCP/TLS server."""
        self._loop = asyncio.get_running_loop()

        # Build SSL context with self-signed cert
        cert_pem, key_pem = get_self_signed_cert()
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE  # self-signed demo

        # Write cert+key to persistent temp files (SSLContext needs file paths)
        cert_path = os.path.join(os.path.dirname(__file__), "server_cert.pem")
        key_path = os.path.join(os.path.dirname(__file__), "server_key.pem")
        with open(cert_path, "wb") as cf:
            cf.write(cert_pem)
        with open(key_path, "wb") as kf:
            kf.write(key_pem)
        ssl_ctx.load_cert_chain(cert_path, key_path)

        self._server = await asyncio.start_server(
            self._on_connect,
            host=host,
            port=port,
            ssl=ssl_ctx,
            reuse_address=True,
        )
        self._running = True
        addr = self._server.sockets[0].getsockname()
        logger.info("ATP Server listening on %s:%s", addr[0], addr[1])

        # Keep running until cancelled
        try:
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            logger.info("ATP server serve_forever cancelled")
        finally:
            self._running = False

    async def stop(self):
        """Gracefully stop the server."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("ATP Server stopped")

    async def _on_connect(self, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter):
        """Handle one incoming connection."""
        agent = ATPAgent(
            identity=self.identity,
            is_server=True,
            monitor=self.monitor,
            task_handler=self._default_task_handler,
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
                pass

    async def _default_task_handler(self, frame: dict) -> dict:
        """Default handler: echo payload or call DeepSeek."""
        task_payload = frame.get("task_payload", b"")
        task_type = frame.get("task_type", "unknown")

        if task_type == "deepseek_chat":
            prompt = task_payload.decode("utf-8", errors="replace")
            result = await ATPAgent.call_deepseek(prompt, self.monitor)
            return {"result": result or "no response"}
        else:
            return {"echo": task_payload.decode("utf-8", errors="replace")}
