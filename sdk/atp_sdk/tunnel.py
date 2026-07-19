"""
ATP SDK — Tunnel internet zero-config.

Due modalità:
1. **UPnP** (predefinita, pure Python) — apre una porta sul router via UPnP IGD.
   Il client si connette direttamente all'IP pubblico del server.
   Nessuna dipendenza esterna.

2. **Locale** (fallback) — 127.0.0.1:porta quando il router non supporta UPnP.

Il tunnel sceglie automaticamente.
"""
import asyncio, logging
from typing import Optional
from atp_sdk.upnp_native import UPNPTunnel as NativeUPnP

logger = logging.getLogger(__name__)


class AutoTunnel:
    """
    Tunnel internet zero-config. Sceglie automaticamente UPnP → locale.

    Usage:
        tunnel = AutoTunnel()
        url = await tunnel.start(8443)
        print(f"Indirizzo pubblico: {url}")
        await tunnel.stop()
    """

    def __init__(self):
        self._tunnel: Optional[NativeUPnP] = None
        self._public_host: str = ""
        self._public_port: int = 0
        self._method: str = "none"

    @property
    def public_url(self) -> str:
        if self._public_host and self._public_port:
            return f"{self._public_host}:{self._public_port}"
        return ""

    @property
    def method(self) -> str:
        return self._method

    async def start(self, local_port: int = 8443) -> str:
        # UPnP (pure Python, zero dipendenze)
        tunnel = NativeUPnP()
        url = await tunnel.start(local_port)
        if "127.0.0.1" not in url:
            self._tunnel = tunnel
            self._public_host, port_str = url.split(":")
            self._public_port = int(port_str)
            self._method = "UPNP"
            return url

        # Fallback locale
        self._public_host = "127.0.0.1"
        self._public_port = local_port
        self._method = "local"
        return self.public_url

    async def stop(self):
        if self._tunnel:
            await self._tunnel.stop()
            self._tunnel = None
        self._public_host = ""
        self._public_port = 0

