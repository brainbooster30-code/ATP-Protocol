"""
ATP v1.8 — I/O helpers for frame send/receive and TLS peer key extraction.
Extracted from agent.py for separation of concerns.
"""
from __future__ import annotations

import time
import logging
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from atp_core import decode_frame, send_frame, build_header, FRAME_TYPES

logger = logging.getLogger(__name__)


def get_tls_peer_pk(writer) -> Optional[bytes]:
    """Extract the TLS peer certificate's raw public key bytes.

    Returns the public key bytes from the peer's TLS certificate, or None
    if the peer certificate is not available (e.g. no TLS, anonymous).
    Used for TLS-ATP binding verification.
    """
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return None
        cert_der = ssl_obj.getpeercert(binary_form=True)
        if cert_der is None:
            return None
        cert = x509.load_der_x509_certificate(cert_der)
        pub_key = cert.public_key()
        return pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except Exception:
        logger.debug("Could not extract TLS peer public key", exc_info=True)
        return None


async def send_frame_to(agent, payload: dict):
    """Send a frame via the agent's transport and log the event."""
    ft = payload.get("header", {}).get("frame_type")
    if agent.monitor:
        agent.monitor.add_event("FRAME_SENT", {
            "conn_id": agent._conn_id,
            "frame_type": ft,
            "frame_name": FRAME_TYPES.get(ft, f"0x{ft:02x}"),
        })
    await send_frame(agent._writer, payload)


async def read_frame_from(agent) -> Optional[dict]:
    """Read a frame from the agent's transport.

    Applies anti-replay and clock skew checks (server side only).
    Uses BufferedFrameReader when available for higher throughput.
    """
    try:
        if agent._buffered_reader:
            frame = await agent._buffered_reader.read_frame()
        else:
            frame = await decode_frame(agent._reader)
    except Exception:
        return None

    if frame is None:
        return None

    header = frame.get("header", {})
    ft = header.get("frame_type")
    ts = header.get("timestamp", 0)
    frame_id = header.get("frame_id", b"")

    # Anti-replay check (server side, control and task frames only)
    if agent.anti_replay and agent.is_server and frame_id and ft not in (
        0x30, 0x31, 0x40, 0x41, 0x42, 0x50,
    ):
        now_ms = int(time.time() * 1000)
        if not await agent.anti_replay.is_new(frame_id, now_ms):
            logger.warning(
                "Anti-replay: duplicate frame_id %s", frame_id.hex()[:8],
            )
            return None

    # Clock skew check (server side only)
    if ts and agent.is_server and ft:
        from config import CLOCK_SKEW_MS
        now_ms = int(time.time() * 1000)
        if abs(now_ms - ts) > CLOCK_SKEW_MS:
            logger.warning(
                "Clock skew: %d ms (limit %d)", abs(now_ms - ts), CLOCK_SKEW_MS,
            )
            if ft == 0x01:  # only for task requests
                try:
                    task_id_skew = header.get("task_id", b"\x00" * 16)
                    err_header = build_header(0x04, task_id_skew)
                    error_frame = {
                        "header": err_header,
                        "error_code": 0x0C,
                        "error_message": (
                            f"Clock skew {abs(now_ms - ts)}ms "
                            f"exceeds limit {CLOCK_SKEW_MS}ms"
                        ),
                        "server_time_ms": now_ms,
                    }
                    await send_frame(agent._writer, error_frame)
                except Exception:
                    pass
            return None

    if agent.monitor:
        agent.monitor.add_event("FRAME_RECEIVED", {
            "conn_id": agent._conn_id,
            "frame_type": ft,
            "frame_name": FRAME_TYPES.get(ft, f"0x{ft:02x}"),
        })
    return frame
