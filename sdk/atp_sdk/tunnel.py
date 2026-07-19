"""
ATP SDK — Tunnel internet zero-config.

Due modalità:
1. **UPnP** (predefinita) — apre una porta sul router via UPnP.
   Il client si connette direttamente all'IP pubblico del server.
   Installa: pip install miniupnpc

2. **ngrok** (fallback) — crea un tunnel TCP via ngrok.
   Il client si connette all'URL ngrok.
   Installa: pip install pyngrok

Il tunnel viene scelto automaticamente: UPnP se disponibile, ngrok altrimenti,
localhost se nessuno dei due è installato.
"""
import asyncio, logging
from typing import Optional

logger = logging.getLogger(__name__)

# Check disponibilità
try:
    import miniupnpc
    HAS_UPNP = True
except ImportError:
    HAS_UPNP = False

try:
    import ngrok
    HAS_NGROK = True
except ImportError:
    try:
        from pyngrok import ngrok
        HAS_NGROK = True
    except ImportError:
        HAS_NGROK = False


def get_public_ip() -> str:
    """Get public IP from external service."""
    import urllib.request
    for url in ["https://api.ipify.org", "https://icanhazip.com", "https://checkip.amazonaws.com"]:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
                if ip:
                    return ip
        except Exception:
            continue
    return ""


class AutoTunnel:
    """
    Tunnel internet zero-config. Sceglie automaticamente UPnP → ngrok → locale.

    Usage:
        tunnel = AutoTunnel()
        url = await tunnel.start(8443)
        print(f"Indirizzo pubblico: {url}")
        await tunnel.stop()
    """

    def __init__(self):
        self._public_host: str = ""
        self._public_port: int = 0
        self._method: str = "none"
        self._upnp = None
        self._ngrok_tunnel = None

    @property
    def public_url(self) -> str:
        if self._public_host and self._public_port:
            return f"{self._public_host}:{self._public_port}"
        return ""

    @property
    def method(self) -> str:
        return self._method

    async def start(self, local_port: int = 8443) -> str:
        """
        Avvia il tunnel.
        Prova UPnP, poi ngrok, poi fallback a locale.

        Returns: indirizzo pubblico "host:port" o "127.0.0.1:port" (locale)
        """
        # 1. Prova UPnP
        if HAS_UPNP:
            try:
                url = await asyncio.get_event_loop().run_in_executor(
                    None, self._do_upnp, local_port
                )
                if url:
                    return url
            except Exception as e:
                logger.debug("UPnP non disponibile: %s", e)

        # 2. Prova ngrok
        if HAS_NGROK:
            try:
                url = await self._do_ngrok(local_port)
                if url:
                    return url
            except Exception as e:
                logger.debug("ngrok non disponibile: %s", e)

        # 3. Fallback locale
        self._public_host = "127.0.0.1"
        self._public_port = local_port
        self._method = "local"
        logger.info("Tunnel non disponibile. Modalità locale: 127.0.0.1:%s", local_port)
        return self.public_url

    def _do_upnp(self, local_port: int) -> str:
        """Port forwarding via UPnP (bloccante)."""
        import miniupnpc
        u = miniupnpc.UPnP()
        u.discoverdelay = 2000
        if u.discover() == 0:
            raise RuntimeError("Nessun dispositivo UPnP trovato")
        u.selectigd()

        # IP pubblico
        self._public_ip = u.externalipaddress() or get_public_ip()
        if not self._public_ip or self._public_ip == "0.0.0.0":
            raise RuntimeError("Impossibile determinare IP pubblico")

        # Port forwarding
        self._public_port = local_port
        u.addportmapping(
            self._public_port, "TCP",
            u.lanaddr, local_port,
            f"ATP v1.7 Server ({local_port})", ""
        )
        self._upnp = u
        self._method = "upnp"
        self._public_host = self._public_ip
        logger.info("UPnP: %s:%s → %s:%s", self._public_ip, self._public_port, u.lanaddr, local_port)
        return self.public_url

    async def _do_ngrok(self, local_port: int) -> str:
        """Tunnel via ngrok."""
        from pyngrok import ngrok as ng
        token = os.environ.get("NGROK_AUTH_TOKEN", "")
        if token:
            ng.set_auth_token(token)

        self._ngrok_tunnel = ng.connect(local_port, "tcp")
        addr = self._ngrok_tunnel.public_url.replace("tcp://", "")
        self._public_host, port_str = addr.split(":")
        self._public_port = int(port_str)
        self._method = "ngrok"
        logger.info("ngrok: %s:%s → localhost:%s", self._public_host, self._public_port, local_port)
        return self.public_url

    async def stop(self):
        """Chiude il tunnel."""
        if self._upnp:
            try:
                self._upnp.deleteportmapping(self._public_port, "TCP")
            except Exception:
                pass
            self._upnp = None
        if self._ngrok_tunnel:
            try:
                from pyngrok import ngrok as ng
                ng.disconnect(self._ngrok_tunnel.public_url)
            except Exception:
                pass
            self._ngrok_tunnel = None
        self._public_host = ""
        self._public_port = 0
