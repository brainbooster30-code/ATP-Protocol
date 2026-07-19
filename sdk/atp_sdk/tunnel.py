"""
ATP SDK — Internet Tunnel helper
=================================
Zero-config internet connectivity via ngrok.
School server gets a public URL automatically.
Teacher client connects to that URL.
"""
import asyncio, sys, os, json, logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

logger = logging.getLogger("tunnel")


class Tunnel:
    """Zero-config internet tunnel. Creates a public URL for the server."""

    def __init__(self):
        self._public_host: str = ""
        self._public_port: int = 0
        self._tunnel = None

    @property
    def public_url(self) -> str:
        if self._public_host and self._public_port:
            return f"{self._public_host}:{self._public_port}"
        return ""

    async def start(self, local_port: int = 8443) -> str:
        """
        Start tunnel. Returns the public URL.
        Tries pyngrok first, falls back to local-only.
        """
        # Try pyngrok (free ngrok tunnel — no network config needed)
        try:
            from pyngrok import ngrok, conf
            conf.get_default().monitor_thread = False  # silence monitor thread

            token = os.environ.get("NGROK_AUTH_TOKEN", "")
            if token:
                ngrok.set_auth_token(token)

            self._tunnel = ngrok.connect(local_port, "tcp")
            addr = self._tunnel.public_url.replace("tcp://", "")
            self._public_host, port_str = addr.split(":")
            self._public_port = int(port_str)
            logger.info("Tunnel attivo: %s:%s (→ localhost:%s)", self._public_host, self._public_port, local_port)
            return self.public_url

        except ImportError:
            pass  # pyngrok not installed
        except Exception as e:
            logger.debug("ngrok non disponibile: %s", e)

        # Fallback: localhost only
        self._public_host = "127.0.0.1"
        self._public_port = local_port
        logger.info("Modalità locale: 127.0.0.1:%s (installa pyngrok per tunnel internet)", local_port)
        return self.public_url

    async def stop(self):
        """Close the tunnel."""
        if self._tunnel:
            try:
                from pyngrok import ngrok
                ngrok.disconnect(self._tunnel.public_url)
            except Exception:
                pass
            self._tunnel = None


# ── CLI helper ────────────────────────────────────────────────────────────────

async def tunnel_info(port: int = 8443):
    """Print public connection info."""
    t = Tunnel()
    url = await t.start(port)
    print(f"  🌐 Indirizzo pubblico: {url}")
    print(f"  📋 Client: python teacher_client.py {url}")
    await t.stop()
