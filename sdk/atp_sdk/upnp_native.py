"""
ATP SDK — UPnP Port Forwarding (pure Python, no miniupnpc)
===========================================================
Implementa il port forwarding UPnP IGD (Internet Gateway Device)
usando solo Python standard library. Nessuna dipendenza esterna.

Il server apre una porta sul router automaticamente.
Il client si connette direttamente all'IP pubblico.
Nessuna configurazione di rete, firewall o port forwarding manuale.
"""
import asyncio, logging, socket, struct, http.client, time, re
from xml.etree import ElementTree
from typing import Optional

logger = logging.getLogger(__name__)

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
SSDP_TIMEOUT = 3


def _discover_igd() -> Optional[dict]:
    """Scopre il router UPnP sulla rete locale tramite SSDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(SSDP_TIMEOUT)
    ttl = struct.pack("b", 4)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

    # Invia richiesta M-SEARCH
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"ST: {SSDP_ST}\r\n"
        "MX: 3\r\n"
        "\r\n"
    )
    sock.sendto(msg.encode(), (SSDP_ADDR, SSDP_PORT))

    # Ricevi risposte
    igd = None
    start = time.time()
    while time.time() - start < SSDP_TIMEOUT:
        try:
            data, addr = sock.recvfrom(2048)
            body = data.decode("utf-8", errors="replace")
            # Cerca location del device description XML
            for line in body.split("\r\n"):
                if line.lower().startswith("location:"):
                    url = line.split(":", 1)[1].strip()
                    igd = _parse_device_desc(url, addr[0])
                    if igd:
                        igd["gateway"] = addr[0]
                        sock.close()
                        return igd
        except socket.timeout:
            break
        except Exception:
            continue
    sock.close()
    return igd


def _parse_device_desc(url: str, gateway_ip: str) -> Optional[dict]:
    """Scarica e analizza il device description XML."""
    try:
        conn = http.client.HTTPConnection(gateway_ip, timeout=3)
        conn.request("GET", url)
        resp = conn.getresponse()
        xml = resp.read()
        conn.close()

        root = ElementTree.fromstring(xml)
        ns = {"ns": "urn:schemas-upnp-org:device-1-0"}

        # Trova il servizio WANIPConnection
        services = root.findall(".//ns:service", ns)
        for svc in services:
            svc_id = svc.find("ns:serviceId", ns)
            if svc_id is not None and "WANIPConnection" in svc_id.text:
                ctrl_url = svc.find("ns:controlURL", ns)
                if ctrl_url is not None:
                    return {
                        "control_url": ctrl_url.text,
                        "gateway": gateway_ip,
                        "service_type": svc.find("ns:serviceType", ns).text if svc.find("ns:serviceType", ns) else "",
                    }
    except Exception:
        pass
    return None


def _soap_request(igd: dict, action: str, body_xml: str) -> bool:
    """Invia una richiesta SOAP al router UPnP."""
    import urllib.parse
    ctrl_url = igd["control_url"]
    if not ctrl_url.startswith("/"):
        ctrl_url = "/" + ctrl_url

    service_type = igd.get("service_type",
        "urn:schemas-upnp-org:service:WANIPConnection:1")

    soap = (
        f'<?xml version="1.0"?>\r\n'
        f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\r\n'
        f'<s:Body>\r\n'
        f'{body_xml}\r\n'
        f'</s:Body>\r\n'
        f'</s:Envelope>\r\n'
    )

    try:
        conn = http.client.HTTPConnection(igd["gateway"], timeout=5)
        headers = {
            "SOAPAction": f'"{service_type}#{action}"',
            "Content-Type": "text/xml; charset=utf-8",
            "Content-Length": str(len(soap)),
        }
        conn.request("POST", ctrl_url, soap, headers)
        resp = conn.getresponse()
        conn.close()
        return resp.status == 200
    except Exception:
        return False


def upnp_add_port(local_port: int, description: str = "ATP") -> tuple[Optional[str], int]:
    """
    Apre una porta sul router via UPnP.
    
    Returns: (public_ip, public_port) o (None, 0) in caso di fallimento.
    """
    igd = _discover_igd()
    if not igd:
        logger.warning("Nessun router UPnP trovato sulla rete")
        return None, 0

    # Ottieni IP pubblico dal router
    pub_ip = _get_external_ip(igd)
    if not pub_ip:
        pub_ip = _get_public_ip_http()

    # Ottieni IP locale
    local_ip = _get_local_ip(igd["gateway"])

    # Add port mapping
    body = (
        f'<u:AddPortMapping xmlns:u="{igd["service_type"]}">\r\n'
        f"<NewRemoteHost></NewRemoteHost>\r\n"
        f"<NewExternalPort>{local_port}</NewExternalPort>\r\n"
        f"<NewProtocol>TCP</NewProtocol>\r\n"
        f"<NewInternalPort>{local_port}</NewInternalPort>\r\n"
        f"<NewInternalClient>{local_ip}</NewInternalClient>\r\n"
        f"<NewEnabled>1</NewEnabled>\r\n"
        f"<NewPortMappingDescription>{description}</NewPortMappingDescription>\r\n"
        f"<NewLeaseDuration>0</NewLeaseDuration>\r\n"
        f"</u:AddPortMapping>\r\n"
    )

    if _soap_request(igd, "AddPortMapping", body):
        logger.info("UPnP: porta %s aperta → %s:%s (IP pub: %s)", local_port, local_ip, local_port, pub_ip)
        return pub_ip, local_port
    else:
        logger.warning("UPnP: AddPortMapping fallito")
        return None, 0


def upnp_remove_port(local_port: int, igd_info: Optional[dict] = None):
    """Chiude una porta sul router via UPnP."""
    if not igd_info:
        igd = _discover_igd()
        if not igd:
            return
    else:
        igd = igd_info

    body = (
        f'<u:DeletePortMapping xmlns:u="{igd["service_type"]}">\r\n'
        f"<NewRemoteHost></NewRemoteHost>\r\n"
        f"<NewExternalPort>{local_port}</NewExternalPort>\r\n"
        f"<NewProtocol>TCP</NewProtocol>\r\n"
        f"</u:DeletePortMapping>\r\n"
    )
    _soap_request(igd, "DeletePortMapping", body)
    logger.info("UPnP: porta %s chiusa", local_port)


def _get_external_ip(igd: dict) -> Optional[str]:
    """Ottiene l'IP pubblico dal router via SOAP."""
    body = '<u:GetExternalIPAddress xmlns:u="{}"></u:GetExternalIPAddress>'.format(
        igd["service_type"])
    try:
        ctrl_url = igd["control_url"]
        if not ctrl_url.startswith("/"):
            ctrl_url = "/" + ctrl_url
        conn = http.client.HTTPConnection(igd["gateway"], timeout=5)
        headers = {
            "SOAPAction": f'"{igd["service_type"]}#GetExternalIPAddress"',
            "Content-Type": "text/xml; charset=utf-8",
        }
        soap = (
            '<?xml version="1.0"?>\r\n'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\r\n'
            '<s:Body>\r\n'
            f'{body}\r\n'
            '</s:Body>\r\n'
            '</s:Envelope>\r\n'
        )
        headers["Content-Length"] = str(len(soap))
        conn.request("POST", ctrl_url, soap, headers)
        resp = conn.getresponse()
        data = resp.read().decode()
        conn.close()
        m = re.search(r"<NewExternalIPAddress>(.*?)</NewExternalIPAddress>", data)
        if m:
            ip = m.group(1)
            if ip and ip != "0.0.0.0":
                return ip
    except Exception:
        pass
    return None


def _get_local_ip(gateway_ip: str) -> str:
    """Ottiene l'IP locale sulla stessa interfaccia del gateway."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((gateway_ip, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _get_public_ip_http() -> Optional[str]:
    """Fallback: IP pubblico via API esterna."""
    import urllib.request
    for url in ["https://api.ipify.org", "https://icanhazip.com"]:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
                if ip:
                    return ip
        except Exception:
            continue
    return None


class UPNPTunnel:
    """
    Tunnel internet via UPnP (zero-config, pure Python).
    
    Usage:
        tunnel = UPNPTunnel()
        url = await tunnel.start(8443)
        print(f"Indirizzo pubblico: {url}")
        await tunnel.stop()
    """

    def __init__(self):
        self._public_ip: str = ""
        self._public_port: int = 0
        self._igd: Optional[dict] = None

    @property
    def public_url(self) -> str:
        if self._public_ip and self._public_port:
            return f"{self._public_ip}:{self._public_port}"
        return ""

    async def start(self, local_port: int = 8443) -> str:
        """
        Avvia tunnel UPnP. Apre la porta sul router.
        Restituisce "IP:pubblica:porta" o "127.0.0.1:porta" in fallback.
        """
        ip, port = await asyncio.get_event_loop().run_in_executor(
            None, upnp_add_port, local_port, "ATP v1.7 Server"
        )
        if ip and port:
            self._public_ip = ip
            self._public_port = port
            logger.info("UPnP attivo: %s", self.public_url)
        else:
            self._public_ip = "127.0.0.1"
            self._public_port = local_port
            logger.warning("UPnP fallito. Modalità locale: %s", self.public_url)
        return self.public_url

    async def stop(self):
        """Chiude il port forwarding."""
        if self._public_ip and self._public_ip != "127.0.0.1":
            await asyncio.get_event_loop().run_in_executor(
                None, upnp_remove_port, self._public_port
            )
