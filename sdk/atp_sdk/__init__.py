"""
ATP SDK v1.7 — Easy-to-use Python SDK for the Agent Transfer Protocol.

Provides simple wrappers around the core ATP implementation so you can
build federated AI-agent networks in just a few lines of code.

Usage:
    from atp_sdk import SimpleATPClient, SimpleATPServer

    # Client side
    client = SimpleATPClient("my-agent")
    await client.connect("127.0.0.1", 8443)
    response = await client.chat("Explain quantum computing")
    await client.close()

    # Server side
    server = SimpleATPServer()
    await server.start(port=8443)
    # ... handles connections automatically ...
    await server.stop()
"""

from __future__ import annotations

# ── Ensure the parent ATP package is importable ───────────────────────────────
import sys
import os as _os

_PARENT = _os.path.normpath(_os.path.join(_os.path.dirname(__file__), "..", ".."))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

# ── Public API ─────────────────────────────────────────────────────────────────
from .client import SimpleATPClient
from .server import SimpleATPServer
from .key_exchange import export_key_card, import_key_card, connect_with_key_card

try:
    from .tunnel import AutoTunnel
except ImportError:
    AutoTunnel = None

__all__ = [
    "SimpleATPClient",
    "SimpleATPServer",
]

__version__ = "1.7"
