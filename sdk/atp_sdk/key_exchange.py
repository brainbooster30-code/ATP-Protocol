"""
ATP SDK — Key Exchange per connessione diretta
================================================
Nessun servizio esterno: né UPnP, né ngrok, né port forwarding.
Due agenti si scambiano le chiavi pubbliche (Ed25519) fuori banda
e poi si connettono direttamente via TCP.

Come funziona:
1. Ogni agente esporta una Key Card (file JSON firmato)
2. I due agenti si scambiano le Key Card (USB, email, QR, ecc.)
3. Ogni agente importa la Key Card dell'altro
4. La connessione TCP usa le chiavi pre-condivise per autenticarsi
"""
import json, os, time, asyncio, logging
from typing import Optional

logger = logging.getLogger(__name__)


def export_key_card(
    agent_name: str,
    ed25519_sk: bytes,
    ed25519_pk: bytes,
    host: str,
    port: int,
    mcc_hash: str,
    output_path: str = "",
) -> str:
    """
    Esporta una Key Card firmata contenente le credenziali dell'agente.
    Questa card viene data all'altro agente (USB, email, QR, ecc.).

    Args:
        agent_name: Nome dell'agente (es. "scuola-futura")
        ed25519_sk: Chiave segreta Ed25519 (per firmare la card)
        ed25519_pk: Chiave pubblica Ed25519
        host: IP pubblico o hostname su cui l'agente è in ascolto
        port: Porta su cui l'agente è in ascolto
        mcc_hash: Hash MCC dell'agente (opzionale per verifica)
        output_path: Dove salvare il file (vuoto = genera nome automatico)

    Returns:
        Percorso del file Key Card creato
    """
    from atp_core import ed25519_sign

    # Contenuto della card
    card = {
        "version": 1,
        "type": "ATP_KEY_CARD",
        "agent_name": agent_name,
        "ed25519_pk": ed25519_pk.hex(),
        "host": host,
        "port": port,
        "mcc_hash": mcc_hash,
        "created_at": int(time.time()),
    }

    # Firma con Ed25519
    card_json = json.dumps(card, separators=(",", ":"), sort_keys=True)
    card_bytes = card_json.encode("utf-8")
    signature = ed25519_sign(ed25519_sk, card_bytes)

    # Pacchetto completo
    packet = {
        "card": card,
        "signature": signature.hex(),
    }

    # Salva su file
    if not output_path:
        filename = f"atp_key_{agent_name.lower().replace(' ', '_')}.card"
        output_path = os.path.join(os.getcwd(), filename)

    with open(output_path, "w") as f:
        json.dump(packet, f, indent=2)

    logger.info("Key Card esportata: %s", output_path)
    return output_path


def import_key_card(card_path: str) -> dict:
    """
    Importa una Key Card. Verifica la firma Ed25519.

    Args:
        card_path: Percorso del file .card ricevuto dall'altro agente

    Returns:
        dict con: agent_name, ed25519_pk, host, port, mcc_hash

    Raises:
        ValueError: Se la firma non è valida o il formato è errato
    """
    from atp_core import ed25519_verify

    with open(card_path) as f:
        packet = json.load(f)

    card = packet["card"]
    signature = bytes.fromhex(packet["signature"])
    ed25519_pk = bytes.fromhex(card["ed25519_pk"])

    # Verifica firma
    card_json = json.dumps(card, separators=(",", ":"), sort_keys=True)
    card_bytes = card_json.encode("utf-8")

    if not ed25519_verify(ed25519_pk, signature, card_bytes):
        raise ValueError("⚠️  Firma Key Card non valida! L'agente non è fidato.")

    logger.info("Key Card importata: %s (agente: %s)", card_path, card["agent_name"])
    return {
        "agent_name": card["agent_name"],
        "ed25519_pk": ed25519_pk,
        "host": card["host"],
        "port": card["port"],
        "mcc_hash": card.get("mcc_hash", ""),
    }


async def connect_with_key_card(
    card_path: str,
    timeout: float = 30.0,
) -> Optional[object]:
    """
    Connette a un agente ATP usando la sua Key Card.
    Nessun servizio esterno, nessuna configurazione di rete.

    Dopo la connessione, verifica che l'MCC del peer
    contenga la chiave pubblica Ed25519 presente nella card.

    Args:
        card_path: Percorso del file .card dell'altro agente
        timeout: Timeout di connessione in secondi

    Returns:
        SimpleATPClient connesso, o None se fallisce
    """
    from atp_sdk import SimpleATPClient

    peer = import_key_card(card_path)

    client = SimpleATPClient(f"hermes-{peer['agent_name']}")
    ok = await client.connect(peer["host"], peer["port"])
    if not ok:
        logger.error("Connessione a %s:%s fallita", peer["host"], peer["port"])
        return None

    # Verify peer MCC matches Key Card Ed25519 public key
    if client._agent and client._agent.peer_mcc:
        card_ed25519_pk = peer["ed25519_pk"]  # bytes, 32
        peer_leaves = {l.key: l.value for l in client._agent.peer_mcc.leaves}
        mcc_ed25519_pk = peer_leaves.get("agent_sign_pk")
        if mcc_ed25519_pk is None or mcc_ed25519_pk != card_ed25519_pk:
            logger.error(
                "Key Card mismatch: peer Ed25519 key differs from card"
            )
            await client.close()
            return None
        logger.info("Key Card verified: peer Ed25519 key matches card")

    logger.info("Connesso a %s (%s:%s)", peer["agent_name"], peer["host"], peer["port"])
    return client


def quick_export(agent_name: str, identity_sk: bytes, identity_pk: bytes,
                 host: str = "0.0.0.0", port: int = 8443,
                 mcc_hash: str = "") -> str:
    """
    Esportazione rapida della Key Card.
    Il file va consegnato all'altro agente.

    Returns:
        Percorso del file .card
    """
    return export_key_card(
        agent_name=agent_name,
        ed25519_sk=identity_sk,
        ed25519_pk=identity_pk,
        host=host,
        port=port,
        mcc_hash=mcc_hash,
    )
