"""
ATP v1.8 — Task lifecycle helpers.
Extracted from agent.py: _handle_task_request and related utilities.
"""
from __future__ import annotations

import asyncio
import json
import time
import logging
from typing import Optional

from atp_core import build_header, FRAME_TYPES, ERROR_CODES
from monitor import TASK_START, TASK_COMPLETE, TASK_ERROR, RATE_LIMIT_HIT
from config import get_deepseek_api_key, DEEPSEEK_MODEL, DEEPSEEK_API_URL

logger = logging.getLogger(__name__)


async def handle_task_request(agent, frame: dict):
    """Process an incoming task request and send response.

    Extracted from ATPAgent._handle_task_request for modularity.
    *agent* is the ATPAgent instance (provides state, crypto, I/O).
    """
    header = frame.get("header", {})
    task_type = frame.get("task_type", "unknown")
    task_payload = frame.get("task_payload", b"")

    task_id_from_req = header.get("task_id", header.get("frame_id", b"\x00" * 16))

    # Rate limiter check
    if agent.rate_limiter and not await agent.rate_limiter.allow():
        logger.warning("Rate limit exceeded for %s", agent._conn_id)
        err_header = build_header(0x04, task_id_from_req)
        error_frame = {
            "header": err_header,
            "error_code": 0x0D,
            "error_message": "Rate limit exceeded",
            "retry_after_ms": 1000,
        }
        await agent._send_frame(error_frame)
        if agent.monitor:
            agent.monitor.add_event(RATE_LIMIT_HIT, {"conn_id": agent._conn_id})
        return

    if agent.monitor:
        agent.monitor.add_event(TASK_START, {
            "conn_id": agent._conn_id,
            "task_type": task_type,
            "direction": "incoming",
        })

    # Send TASK_ACK immediately
    ack_header = build_header(0x03, task_id_from_req)
    await agent._send_frame({"header": ack_header})

    # Process the task
    async def _process():
        try:
            actual_payload = task_payload
            if agent._e2e_key and agent._peer_ed25519_pk:
                decrypted = agent._e2e_decrypt_verify(
                    task_payload, agent._e2e_key, agent._peer_ed25519_pk,
                )
                if decrypted is not None:
                    actual_payload = decrypted
            elif agent._e2e_key:
                decrypted = agent._e2e_decrypt(task_payload, agent._e2e_key)
                if decrypted is not None:
                    actual_payload = decrypted

            result_bytes = actual_payload
            if agent.task_handler:
                result = await agent.task_handler({
                    **frame, "task_payload": actual_payload,
                })
                if isinstance(result, dict):
                    result_bytes = json.dumps(result).encode("utf-8")
                elif isinstance(result, bytes):
                    result_bytes = result
                else:
                    result_bytes = str(result).encode("utf-8")
            elif task_type == "deepseek_chat":
                prompt = actual_payload.decode("utf-8", errors="replace")
                from agent import ATPAgent
                result_text = await ATPAgent.call_deepseek(
                    prompt, agent.monitor, agent._conn_id,
                )
                if result_text:
                    result = {"result": result_text}
                else:
                    result = {"error": "DeepSeek returned no result"}
                result_bytes = json.dumps(result).encode("utf-8")

            resp_header = build_header(0x02, task_id_from_req)
            if isinstance(result_bytes, list) and len(result_bytes) > 1:
                for idx, chunk in enumerate(result_bytes):
                    is_last = (idx == len(result_bytes) - 1)
                    if agent._e2e_key and agent._peer_ed25519_pk:
                        enc = agent._e2e_encrypt_signed(
                            chunk, agent._e2e_key, agent.identity.ed25519_sk,
                        )
                    elif agent._e2e_key:
                        enc = agent._e2e_encrypt(chunk, agent._e2e_key)
                    else:
                        enc = chunk
                    chunk_resp = {
                        "header": build_header(0x02, task_id_from_req),
                        "status": 0,
                        "result_payload": enc,
                        "partial": not is_last,
                        "sequence": idx + 1,
                    }
                    await agent._send_frame(chunk_resp)
                    if not is_last:
                        await asyncio.sleep(0)
                encrypted_result = b""
            else:
                if isinstance(result_bytes, list):
                    result_bytes = result_bytes[0] if result_bytes else b""
                if agent._e2e_key and agent._peer_ed25519_pk:
                    encrypted_result = agent._e2e_encrypt_signed(
                        result_bytes, agent._e2e_key, agent.identity.ed25519_sk,
                    )
                elif agent._e2e_key:
                    encrypted_result = agent._e2e_encrypt(
                        result_bytes, agent._e2e_key,
                    )
                else:
                    encrypted_result = result_bytes

            response = {
                "header": resp_header,
                "status": 0,
                "result_payload": encrypted_result,
            }
            if not (isinstance(result_bytes, list) and len(result_bytes) > 1):
                await agent._send_frame(response)

            if agent.monitor:
                agent.monitor.add_event(TASK_COMPLETE, {
                    "conn_id": agent._conn_id,
                    "task_type": task_type,
                })
                agent.monitor.add_task({
                    "task_id": (header.get("frame_id") or b"\x00" * 16).hex()[:8],
                    "task_type": task_type,
                    "request": task_payload.decode("utf-8", errors="replace")[:80],
                    "response": result_bytes.decode("utf-8", errors="replace")[:200],
                    "status": "completed",
                    "error_code": None,
                    "latency_ms": 0,
                    "agent": agent.identity.agent_name,
                    "direction": "received",
                    "timestamp": time.time(),
                })

        except asyncio.CancelledError:
            logger.info("Task cancelled via TASK_CANCEL")
            err_header = build_header(0x04, task_id_from_req)
            error_frame = {
                "header": err_header,
                "error_code": 0x0F,
                "error_message": "Task cancelled by peer",
            }
            try:
                await agent._send_frame(error_frame)
            except Exception:
                pass
            if agent.monitor:
                agent.monitor.add_event(TASK_ERROR, {
                    "conn_id": agent._conn_id,
                    "error_code": 0x0F,
                    "error_message": "Task cancelled by peer",
                })

        except Exception as exc:
            logger.exception("Task processing error")
            err_header = build_header(0x04, task_id_from_req)
            error_frame = {
                "header": err_header,
                "error_code": 0x0B,
                "error_message": str(exc),
            }
            await agent._send_frame(error_frame)
            if agent.monitor:
                agent.monitor.add_event(TASK_ERROR, {
                    "conn_id": agent._conn_id,
                    "error_code": 0x0B,
                    "error_message": str(exc),
                })
                agent.monitor.add_task({
                    "task_id": (header.get("frame_id") or b"\x00" * 16).hex()[:8],
                    "task_type": task_type,
                    "request": task_payload.decode("utf-8", errors="replace")[:80],
                    "response": str(exc)[:200],
                    "status": "error",
                    "error_code": 0x0B,
                    "latency_ms": 0,
                    "agent": agent.identity.agent_name,
                    "direction": "received",
                    "timestamp": time.time(),
                })

    agent._current_task = asyncio.create_task(_process())
    agent._current_task.add_done_callback(
        lambda t: setattr(agent, '_current_task', None)
    )


async def forward_task_to_peer(agent, task_frame: dict, target: str, ttl: int):
    """Forward a task to the next hop in the federation (v2.0).

    Extracted from ATPAgent._forward_task_to_peer.
    """
    if not hasattr(agent, "_fed_router") or not agent._fed_router:
        return
    try:
        fwd_task = {"target_peer_id": target}
        target_peer = await agent._fed_router.forward_task(fwd_task, ttl)
        if not target_peer:
            logger.warning(
                "Federation: target peer %s not in routing table", target[:16],
            )
            return
        proxy = await agent._fed_router.get_outbound_connection(
            target_peer.host, target_peer.port,
        )
        if proxy is None:
            logger.warning(
                "Federation: cannot connect to target %s at %s:%s",
                target[:16], target_peer.host, target_peer.port,
            )
            return
        try:
            import cbor2 as _cbor2
            from atp_core import ed25519_sign
            fwd_payload = _cbor2.dumps({
                "target_peer_id": target,
                "ttl": ttl,
                "task_frame": task_frame,
                "forwarder_id": agent.identity.agent_name,
            }, canonical=True)
            fwd_sig = ed25519_sign(agent.identity.ed25519_sk, fwd_payload)
            fwd = {
                "header": build_header(0x62),
                "target_peer_id": target,
                "ttl": ttl,
                "task_frame": task_frame,
                "signature": fwd_sig,
                "forwarder_id": agent.identity.agent_name,
            }
            await proxy.agent._send_frame(fwd)
            logger.info(
                "Federation: forwarded signed task to %s at %s:%s (ttl=%d)",
                target[:16], target_peer.host, target_peer.port, ttl,
            )
        finally:
            await agent._fed_router.return_connection(
                target_peer.host, target_peer.port,
            )
    except Exception as exc:
        logger.debug("Federation: forward failed — %s", exc)
