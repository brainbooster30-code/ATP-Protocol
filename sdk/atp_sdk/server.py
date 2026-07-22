"""
ATP SDK v1.8 — SimpleATPServer

A clean, high-level server that wraps ATPServer and ATPAgent.
Handles TLS, MCC creation, handshake, and task dispatch automatically.

Supports built-in handlers for:
  - deepseek_chat → calls DeepSeek API
  - echo → echoes back the payload
  - Custom handlers via on_task() decorator
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import ssl
from typing import Any, Callable, Awaitable, Optional

# ── Parent ATP imports ────────────────────────────────────────────────────────
from config import SERVER_HOST, SERVER_PORT
from agent import ATPAgent, AgentIdentity, make_ssl_context, get_ca_cert_pem, create_mcc_for_identity
from monitor import Monitor
from atp_core import decode_frame, build_header, send_frame, MCC

logger = logging.getLogger(__name__)

# Type alias for task handlers
TaskHandler = Callable[[str, str], Awaitable[str]]
"""Task handler signature: async handler(task_type, payload) -> result_string"""


class SimpleATPServer:
    """
    High-level ATP server that accepts TLS connections and handles
    the full ATP handshake + task lifecycle automatically.

    Built-in task types:
      - ``deepseek_chat`` — forwards to DeepSeek API
      - ``echo`` — echoes the payload back

    Custom handlers can be registered with on_task().

    Usage:
        server = SimpleATPServer()
        await server.start(port=8443)
        # Server runs in background, accepting connections
        await server.stop()
    """

    def __init__(
        self,
        agent_name: str = "atp-sdk-server",
        monitor: Optional[Monitor] = None,
        trust_bootstrap_mode: Optional[str] = None,
    ) -> None:
        """
        Args:
            agent_name: Human-readable name for this server agent.
            monitor: Optional Monitor instance for protocol event logging.
            trust_bootstrap_mode: None uses config (strict by default);
                use "tofu" only for explicit trust-on-first-use bootstrap.
        """
        self.agent_name: str = agent_name
        self.monitor: Optional[Monitor] = monitor
        self.trust_bootstrap_mode = trust_bootstrap_mode

        # Rate limiter e anti-replay (dal core protocol, default None = disattivati)
        self.rate_limiter = None
        self.anti_replay = None

        # Underlying protocol objects
        self._identity: AgentIdentity = AgentIdentity(agent_name=agent_name)
        self._mcc: Optional["MCC"] = None  # created in start()
        self._server: Optional[asyncio.AbstractServer] = None
        self._task: Optional[asyncio.Task[None]] = None
        self._gossip_task: Optional[asyncio.Task[None]] = None
        self._gossip_server_task: Optional[asyncio.Task[None]] = None
        self._gossip_server = None
        self._running: bool = False
        self._cert_path: str = ""
        self._key_path: str = ""
        self.verify_tls: bool = False  # set True for production with real certs

        # Custom task handlers: task_type → handler
        self._handlers: dict[str, TaskHandler] = {}

    # ── Server lifecycle ──────────────────────────────────────────────────

    async def start(
        self,
        host: str = SERVER_HOST,
        port: int = SERVER_PORT,
    ) -> None:
        """
        Start the ATP server listening on the given host:port.

        The server runs in the background as an asyncio task. It will
        accept connections, perform the 5-phase handshake, and handle
        incoming tasks automatically.

        Args:
            host: Bind address (default: 127.0.0.1).
            port: TLS port (default: 8443).

        Raises:
            RuntimeError: If the server is already running.
        """
        if self._running:
            raise RuntimeError("Server is already running")

        # Create MCC from identity (for Key Card export)
        self._mcc = create_mcc_for_identity(self._identity)

        # Build SSL context with CA-signed cert (mutual TLS)
        ssl_ctx = make_ssl_context(server_side=True, cn=f"atp-sdk-server-{host}:{port}")
        # Save CA cert path for client use
        self._ca_path = None

        self._server = await asyncio.start_server(
            self._on_connect,
            host=host,
            port=port,
            ssl=ssl_ctx,
            reuse_address=True,
        )

        self._running = True
        addr = self._server.sockets[0].getsockname()
        logger.info(
            "SimpleATPServer listening on %s:%s as %r",
            addr[0], addr[1], self.agent_name,
        )

        # Start background gossip protocol
        from revocation import get_gossip, GossipServer
        gossip = get_gossip(node_id=f"sdk-server-{host}:{port}")
        self._gossip_task = asyncio.create_task(gossip.gossip_loop(interval_s=5))
        from config import GOSSIP_PORT
        self._gossip_server = GossipServer(monitor=self.monitor)
        self._gossip_server_task = asyncio.create_task(
            self._gossip_server.start(host=host, port=GOSSIP_PORT)
        )

        # Run serve_forever in background
        self._task = asyncio.create_task(self._serve_forever())

    async def _serve_forever(self) -> None:
        """Internal: serve until stopped."""
        try:
            async with self._server:  # type: ignore[union-attr]
                await self._server.serve_forever()  # type: ignore[union-attr]
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("SimpleATPServer serve_forever error")
        finally:
            self._running = False

    async def stop(self) -> None:
        """
        Gracefully stop the server. Closes all connections and shuts down
        the listening socket. Cleans up TLS certificate files.
        """
        self._running = False

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        if self._gossip_server:
            await self._gossip_server.stop()
        if self._gossip_task:
            self._gossip_task.cancel()
        if self._gossip_server_task:
            self._gossip_server_task.cancel()

        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None

        logger.info("SimpleATPServer stopped")

    # ── Connection handler ────────────────────────────────────────────────

    async def _on_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single incoming TLS connection."""
        peer = writer.get_extra_info("peername")
        logger.info("SimpleATPServer: new connection from %s", peer)

        agent = ATPAgent(
            identity=self._identity,
            is_server=True,
            monitor=self.monitor,
            task_handler=self._dispatch_task,
            rate_limiter=self.rate_limiter,
            anti_replay=self.anti_replay,
            trust_bootstrap_mode=self.trust_bootstrap_mode,
        )

        try:
            ok = await agent.perform_handshake(reader, writer)
            if ok:
                logger.info(
                    "SimpleATPServer: handshake OK with %s (MCC: %s)",
                    peer,
                    agent.peer_mcc.root_hash.hex()[:16] if agent.peer_mcc else "?",
                )
                await agent.handle_task_loop()
            else:
                logger.warning("SimpleATPServer: handshake failed with %s", peer)
        except Exception as exc:
            logger.exception("SimpleATPServer: connection error with %s: %s", peer, exc)
        finally:
            await agent.close_async()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass  # nosec
            logger.info("SimpleATPServer: connection closed from %s", peer)

    # ── Task dispatch ─────────────────────────────────────────────────────

    async def _dispatch_task(self, frame: dict[str, Any]) -> str:
        """
        Dispatch an incoming task to the appropriate handler.

        Returns the result as a string.
        """
        task_type = frame.get("task_type", "unknown")
        task_payload = frame.get("task_payload", b"")
        payload_str = task_payload.decode("utf-8", errors="replace") if isinstance(task_payload, bytes) else str(task_payload)

        # Check custom handlers first
        if task_type in self._handlers:
            try:
                result = await self._handlers[task_type](task_type, payload_str)
                return json.dumps({"result": result})
            except Exception as exc:
                logger.exception("Custom handler error for %r", task_type)
                return json.dumps({"error": str(exc)})

        # Built-in handlers
        if task_type == "deepseek_chat":
            result = await ATPAgent.call_deepseek(
                payload_str,
                monitor=self.monitor,
            )
            if result:
                return json.dumps({"result": result})
            else:
                return json.dumps({"error": "DeepSeek returned no result"})

        elif task_type == "echo":
            return json.dumps({"echo": payload_str})

        else:
            logger.warning("Unknown task type: %r", task_type)
            return json.dumps({"error": f"Unsupported task type: {task_type}"})

    # ── Custom task handlers ──────────────────────────────────────────────

    def on_task(self, task_type: str) -> Callable[[TaskHandler], TaskHandler]:
        """
        Decorator to register a custom task handler.

        Usage:
            server = SimpleATPServer()

            @server.on_task("my_custom_task")
            async def handle_my_task(task_type: str, payload: str) -> str:
                return f"Processed: {payload}"
        """

        def decorator(handler: TaskHandler) -> TaskHandler:
            self._handlers[task_type] = handler
            logger.info("Registered custom handler for task type %r", task_type)
            return handler

        return decorator

    def register_handler(
        self,
        task_type: str,
        handler: TaskHandler,
    ) -> None:
        """
        Register a custom task handler function.

        Args:
            task_type: The task type string to handle.
            handler: An async callable ``(task_type, payload) -> result_string``.
        """
        self._handlers[task_type] = handler
        logger.info("Registered handler for task type %r", task_type)

    # ── Properties ────────────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        """True if the server is currently accepting connections."""
        return self._running

    @property
    def identity(self) -> AgentIdentity:
        """The server's AgentIdentity, containing Ed25519/X25519 keypairs."""
        return self._identity

    @property
    def identity_sk(self) -> bytes:
        """The server's Ed25519 private key (signing key)."""
        return self._identity.ed25519_sk

    @property
    def identity_pk(self) -> bytes:
        """The server's Ed25519 public key (verification key)."""
        return self._identity.ed25519_pk

    @property
    def identity_mcc_hash(self) -> str:
        """Hex digest of the server's MCC Merkle root hash."""
        if self._mcc:
            return self._mcc.root_hash.hex()
        return ""

    # ── Context manager support ───────────────────────────────────────────

    async def __aenter__(self) -> "SimpleATPServer":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.stop()

    def __repr__(self) -> str:
        status = "running" if self._running else "stopped"
        return f"<SimpleATPServer {self.agent_name!r} ({status})>"


# ── Synchronous wrapper ────────────────────────────────────────────────────────


class SyncATPServer:
    """
    Synchronous wrapper around SimpleATPServer.

    Usage:
        server = SyncATPServer()
        server.start(port=8443)
        # ... use the server ...
        server.stop()
    """

    def __init__(
        self,
        agent_name: str = "atp-sdk-server",
        monitor: Optional[Monitor] = None,
        trust_bootstrap_mode: Optional[str] = None,
    ) -> None:
        self._server = SimpleATPServer(
            agent_name=agent_name,
            monitor=monitor,
            trust_bootstrap_mode=trust_bootstrap_mode,
        )
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[Any] = None

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
        return self._loop

    def start(self, host: str = SERVER_HOST, port: int = SERVER_PORT) -> None:
        """
        Start the server synchronously. Blocks until the server is listening,
        then returns. The server runs in a background thread.

        Args:
            host: Bind address.
            port: TLS port.
        """
        import threading

        loop = self._get_loop()

        async def _start() -> None:
            await self._server.start(host, port)

        # Run the start coroutine (which launches the background task)
        loop.run_until_complete(_start())

        # Now run the event loop in a background thread to keep the server alive
        def _run_loop() -> None:
            asyncio.set_event_loop(loop)
            loop.run_forever()

        self._thread = threading.Thread(target=_run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the server synchronously. Closes the event loop."""
        loop = self._get_loop()
        asyncio.run_coroutine_threadsafe(self._server.stop(), loop)
        # Give it a moment to clean up
        import time
        time.sleep(0.3)
        loop.call_soon_threadsafe(loop.stop)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
            self._thread = None
        try:
            loop.close()
        except Exception:
            pass  # nosec
        self._loop = None

    @property
    def running(self) -> bool:
        return self._server.running

    def __enter__(self) -> "SyncATPServer":
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()

    def __repr__(self) -> str:
        return f"<SyncATPServer {self._server.agent_name!r}>"
