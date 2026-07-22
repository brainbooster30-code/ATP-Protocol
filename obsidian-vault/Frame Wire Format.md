---
tags:
  - protocol
  - format
---

# Frame Wire Format

## Header (common to all frames)
```
frame_header = {
    "frame_type": uint,
    "frame_id": bstr .size 16,     # UUID v4
    "task_id": bstr .size 16,      # nil UUID for control frames
    "timestamp": uint,             # Unix epoch ms
    "atp_version": tstr
}
```

## Encoding
- 4-byte big-endian length prefix
- CBOR canonical encoding (RFC 8949 §4.2)
- `leaf_hash` NEVER in wire format
- Max payload: 2 MiB (2 × 1024 × 1024)

## All 24 Frame Types
| Code | Name | Phase |
|------|------|-------|
| 0x01 | TASK_REQUEST | Task |
| 0x02 | TASK_RESPONSE | Task |
| 0x03 | TASK_ACK | Task |
| 0x04 | TASK_ERROR | Task |
| 0x05 | TASK_CANCEL | Task |
| 0x10 | CONTROL_SHUTDOWN | Control |
| 0x11 | CONTROL_REVOKE_NOTIFY | Control |
| 0x12 | CONTROL_SHUTDOWN_ACK | Control |
| 0x13 | CONTROL_HEALTH | Control |
| 0x14 | CONTROL_HEALTH_RESP | Control |
| 0x15 | CONTROL_PING | Control (keepalive) |
| 0x16 | CONTROL_PONG | Control (keepalive) |
| 0x20 | ERROR | Error |
| 0x21 | ROOT_STORE_UPDATE | Control |
| 0x30 | VERSION_PROPOSE | Handshake P2 |
| 0x31 | VERSION_ACK | Handshake P2 |
| 0x40 | MCC_BIND_REQUEST | Handshake P3 |
| 0x41 | MCC_BIND_RESPONSE | Handshake P3 |
| 0x42 | MCC_BIND_CONFIRM | Handshake P3 |
| 0x50 | CAPABILITY_EXCHANGE | Handshake P4 |
| 0x60 | PEER_DISCOVERY | Federation |
| 0x61 | PEER_HEARTBEAT | Federation |
| 0x62 | TASK_FORWARD | Federation |
| 0x63 | PEER_DISCOVERY_ACK | Federation |

## All 15 Error Codes
| Code | Name | Disposition |
|------|------|-------------|
| 0x01 | ERR_ATP_VERSION_UNSUPPORTED | close |
| 0x02 | ERR_INVALID_ROOT | close |
| 0x03 | ERR_MISSING_CRITICAL_CLAIM | close |
| 0x04 | ERR_IDENTITY_MISMATCH | close |
| 0x05 | ERR_BAD_SIGNATURE | close |
| 0x06 | ERR_REVOKED | close |
| 0x07 | ERR_IDENTITY_NOT_BOUND | close |
| 0x08 | ERR_STREAM_PROTOCOL_VIOLATION | close |
| 0x09 | ERR_TASK_TOO_LARGE | close_stream |
| 0x0A | ERR_UNSUPPORTED_TASK_TYPE | close_stream |
| 0x0B | ERR_TASK_TIMEOUT | close_stream |
| 0x0C | ERR_CLOCK_SKEW | close_stream |
| 0x0D | ERR_RATE_LIMITED | recoverable |
| 0x0E | ERR_STREAM_VIOLATION_MINOR | close_stream |
| 0x0F | ERR_TASK_CANCELLED | close_stream |

## Task Request/Response
```
TASK_REQUEST: {header, task_type, task_payload, deadline_ms, ?metadata, ?priority_hint}
TASK_RESPONSE: {header, status, result_payload, ?partial, ?sequence}
TASK_ACK: {header}
TASK_ERROR: {header, error_code, error_message, ?retry_after_ms, ?server_time_ms}
```

## Federation Frames (v2.0)
```
PEER_DISCOVERY (0x60): {header, peers[], node_id, ?signature}  → Ed25519 signed
PEER_HEARTBEAT (0x61): {header, node_id, timestamp}
TASK_FORWARD (0x62): {header, target_peer_id, ttl, task_frame, ?signature, forwarder_id} → Ed25519 signed
PEER_DISCOVERY_ACK (0x63): {header, node_id}
```
