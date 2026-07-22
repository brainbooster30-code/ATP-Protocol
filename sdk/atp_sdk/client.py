"""
ATP SDK v1.7 — SimpleATPClient

A clean, high-level client that wraps ATPClient and ATPAgent.
Handles TLS, MCC creation, handshake, and task sending automatically.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

# ── Parent ATP imports ────────────────────────────────────────────────────────
from config import SERVER_HOST, SERVER_PORT, CONNECTION_SETUP_TIMEOUT_MS
from agent import ATPAgent, AgentIdentity, make_ssl_context, create_mcc_for_identity
from monitor import Monitor
from atp_core import MCC

logger = logging.getLogger(__name__)


class SimpleATPClient:
    """
    High-level ATP client with a clean, minimal API.

    Handles connection, TLS, identity creation, MCC generation,
    5-phase handshake, and DeepSeek task dispatch automatically.

    Usage:
        client = SimpleATPClient("my-agent")
        await client.connect("127.0.0.1", 8443)
        response = await client.chat("Hello, world!")
        await client.close()
    """

    def __init__(
        self,
        agent_name: str = "atp-sdk-client",
        monitor: Optional[Monitor] = None,
    ) -> None:
        """
        Args:
            agent_name: Human-readable name for this agent (goes into the MCC).
            monitor: Optional Monitor instance for protocol event logging.
        """
        self.agent_name: str = agent_name
        self.monitor: Optional[Monitor] = monitor

        # Underlying protocol objects — created on connect()
        self._identity: Optional[AgentIdentity] = None
        self._mcc: Optional[MCC] = None
        self._agent: Optional[ATPAgent] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected: bool = False
        self._host: str = ""
        self._port: int = 0
        self.rate_limiter = None  # rate limiter (core ATP), None = off
        self.anti_replay = None  # anti-replay (core ATP), None = off

    # ── Connection lifecycle ──────────────────────────────────────────────

    async def connect(
        self,
        host: str = SERVER_HOST,
        port: int = SERVER_PORT,
        timeout: Optional[float] = None,
    ) -> bool:
        """
        Connect to an ATP server and perform the full 5-phase handshake.

        This handles:
          1. TLS connection (self-signed certs accepted for demo)
          2. AgentIdentity + MCC creation
          3. Version negotiation
          4. MCC exchange & identity binding
          5. Capability exchange

        Args:
            host: Server hostname or IP (default: 127.0.0.1).
            port: Server TLS port (default: 8443).
            timeout: Connection timeout in seconds (default: from config).

        Returns:
            True if connected and bound, False otherwise.
        """
        self._host = host
        self._port = port

        if timeout is None:
            timeout = CONNECTION_SETUP_TIMEOUT_MS / 1000.0

        # Create identity (generates fresh X25519 + Ed25519 keypairs)
        self._identity = AgentIdentity(agent_name=self.agent_name)
        # Create MCC from identity (for Key Card export)
        self._mcc = create_mcc_for_identity(self._identity)

        # Build SSL context with CA-signed cert (mutual TLS)
        ssl_ctx = make_ssl_context(server_side=False, cn=f"atp-sdk-client-{host}:{port}")

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=timeout,
            )
        except Exception as exc:
            logger.error("SimpleATPClient.connect failed: %s", exc)
            self._connected = False
            return False

        # Create the protocol agent and perform handshake
        self._agent = ATPAgent(
            identity=self._identity,
            is_server=False,
            monitor=self.monitor,
            rate_limiter=self.rate_limiter,
            anti_replay=self.anti_replay,
        )

        ok = await self._agent.perform_handshake(self._reader, self._writer)
        self._connected = ok

        if ok:
            logger.info(
                "SimpleATPClient connected and bound to %s:%s as %r",
                host, port, self.agent_name,
            )
        else:
            logger.error("SimpleATPClient handshake failed")
            await self.close()

        return ok

    # ── Task sending ──────────────────────────────────────────────────────

    async def send(
        self,
        task_type: str,
        payload: str,
        deadline_ms: int = 30_000,
    ) -> Optional[dict[str, Any]]:
        """
        Send a task to the server and return the response frame.

        Args:
            task_type: Task type string (e.g. "deepseek_chat", "echo").
            payload: The task payload as a string (max 64 KB).
            deadline_ms: Task deadline in milliseconds (default: 30s).

        Returns:
            The response frame as a dict, or None on error.
        """
        if not self._connected or not self._agent:
            logger.error("SimpleATPClient.send: not connected")
            return None

        if len(payload) > 65536:
            logger.error("SimpleATPClient.send: payload too large (%d bytes)", len(payload))
            return None

        raw = await self._agent.send_task(
            task_type=task_type,
            payload=payload.encode("utf-8"),
            deadline_ms=deadline_ms,
        )

        if raw is None:
            return None

        # Decode result payload if present, try to parse JSON
        result_payload = raw.get("result_payload", b"")
        if isinstance(result_payload, bytes):
            text = result_payload.decode("utf-8", errors="replace")
        else:
            text = str(result_payload)

        # Try to unwrap JSON: {"result": "...", "echo": "...", "error": "..."}
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                for key in ("result", "echo", "error"):
                    if key in parsed:
                        text = str(parsed[key])
                        break
        except (json.JSONDecodeError, TypeError):
            pass

        return {
            "status": raw.get("status", 0),
            "result": text,
            "raw": raw,
        }

    async def chat(self, prompt: str) -> str:
        """
        Convenience method: send a DeepSeek chat task and return the text result.

        Args:
            prompt: The user prompt to send to the DeepSeek model.

        Returns:
            The model's response text, or an error string.
        """
        response = await self.send("deepseek_chat", prompt)

        if response is None:
            return "[Error: no response from server]"

        return response.get("result", "") or "[Error: empty result]"

    async def echo(self, message: str) -> str:
        """
        Send an echo task — useful for connectivity testing.

        Args:
            message: The message to echo back.

        Returns:
            The echoed message.
        """
        response = await self.send("echo", message)
        if response is None:
            return "[Error: no response]"
        return response.get("result", "")

    # ── Connection teardown ───────────────────────────────────────────────

    async def close(self) -> None:
        """
        Close the connection gracefully with proper TLS shutdown.
        Safe to call multiple times.
        """
        if self._agent:
            await self._agent.close_async()
            self._agent = None

        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass  # nosec
            self._writer = None

        self._reader = None
        self._connected = False
        logger.info("SimpleATPClient disconnected")

    # ── Properties ────────────────────────────────────────────────────────

    @property
    def connected(self) -> bool:
        """True if the client is connected and bound."""
        return self._connected

    @property
    def identity(self) -> Optional[AgentIdentity]:
        """The client's AgentIdentity, containing Ed25519/X25519 keypairs."""
        return self._identity

    @property
    def identity_sk(self) -> bytes:
        """The client's Ed25519 private key (signing key)."""
        if self._identity:
            return self._identity.ed25519_sk
        return b""

    @property
    def identity_pk(self) -> bytes:
        """The client's Ed25519 public key (verification key)."""
        if self._identity:
            return self._identity.ed25519_pk
        return b""

    @property
    def identity_mcc_hash(self) -> str:
        """Hex digest of the client's MCC Merkle root hash."""
        if self._mcc:
            return self._mcc.root_hash.hex()
        return ""

    @property
    def peer_mcc_hash(self) -> Optional[str]:
        """Hex digest of the peer's MCC root hash, if bound."""
        if self._agent and self._agent.peer_mcc:
            return self._agent.peer_mcc.root_hash.hex()
        return None

    # ── Context manager support ───────────────────────────────────────────

    async def __aenter__(self) -> "SimpleATPClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    def __repr__(self) -> str:
        status = "connected" if self._connected else "disconnected"
        return f"<SimpleATPClient {self.agent_name!r} ({status})>"


# ── Synchronous wrapper ────────────────────────────────────────────────────────


class SyncATPClient:
    """
    Synchronous wrapper around SimpleATPClient.

    Usage:
        client = SyncATPClient("my-agent")
        client.connect("127.0.0.1", 8443)
        response = client.chat("Hello!")
        client.close()
    """

    def __init__(
        self,
        agent_name: str = "atp-sdk-client",
        monitor: Optional[Monitor] = None,
    ) -> None:
        self._client = SimpleATPClient(agent_name=agent_name, monitor=monitor)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop

    def connect(self, host: str = SERVER_HOST, port: int = SERVER_PORT) -> bool:
        """Synchronous connect. See SimpleATPClient.connect."""
        loop = self._get_loop()
        return loop.run_until_complete(self._client.connect(host, port))

    def send(self, task_type: str, payload: str,
             deadline_ms: int = 30_000) -> Optional[dict[str, Any]]:
        """Synchronous send. See SimpleATPClient.send."""
        loop = self._get_loop()
        return loop.run_until_complete(
            self._client.send(task_type, payload, deadline_ms)
        )

    def chat(self, prompt: str) -> str:
        """Synchronous chat. See SimpleATPClient.chat."""
        loop = self._get_loop()
        return loop.run_until_complete(self._client.chat(prompt))

    def echo(self, message: str) -> str:
        """Synchronous echo. See SimpleATPClient.echo."""
        loop = self._get_loop()
        return loop.run_until_complete(self._client.echo(message))

    def close(self) -> None:
        """Synchronous close. See SimpleATPClient.close."""
        loop = self._get_loop()
        loop.run_until_complete(self._client.close())

    @property
    def connected(self) -> bool:
        return self._client.connected

    def __enter__(self) -> "SyncATPClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<SyncATPClient {self._client.agent_name!r}>"
