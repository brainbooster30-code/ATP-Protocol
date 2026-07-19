"""
ATP v1.7 — Event monitor with observer pattern + Qt signal bridge.
"""

from __future__ import annotations

import time
import logging
import threading
from collections import deque
from typing import Callable, Optional

from PySide6.QtCore import QObject, Signal

from config import MONITOR_EVENT_LIMIT

logger = logging.getLogger(__name__)

# ── Event type constants ──────────────────────────────────────────────────────

CONNECTION_OPEN             = "CONNECTION_OPEN"
CONNECTION_CLOSE            = "CONNECTION_CLOSE"
HANDSHAKE_START             = "HANDSHAKE_START"
HANDSHAKE_COMPLETE          = "HANDSHAKE_COMPLETE"
HANDSHAKE_FAILED            = "HANDSHAKE_FAILED"
FRAME_SENT                  = "FRAME_SENT"
FRAME_RECEIVED              = "FRAME_RECEIVED"
TASK_START                  = "TASK_START"
TASK_COMPLETE               = "TASK_COMPLETE"
TASK_ERROR                  = "TASK_ERROR"
MCC_VERIFICATION_SUCCESS    = "MCC_VERIFICATION_SUCCESS"
MCC_VERIFICATION_FAILED     = "MCC_VERIFICATION_FAILED"
BINDING_SUCCESS             = "BINDING_SUCCESS"
BINDING_FAILED              = "BINDING_FAILED"
DEEPSEEK_CALL_START         = "DEEPSEEK_CALL_START"
DEEPSEEK_CALL_END           = "DEEPSEEK_CALL_END"
RATE_LIMIT_HIT              = "RATE_LIMIT_HIT"
BAN_TRIGGERED               = "BAN_TRIGGERED"
ERROR_OCCURRED              = "ERROR_OCCURRED"

EVENT_TYPES = frozenset({
    CONNECTION_OPEN, CONNECTION_CLOSE,
    HANDSHAKE_START, HANDSHAKE_COMPLETE, HANDSHAKE_FAILED,
    FRAME_SENT, FRAME_RECEIVED,
    TASK_START, TASK_COMPLETE, TASK_ERROR,
    MCC_VERIFICATION_SUCCESS, MCC_VERIFICATION_FAILED,
    BINDING_SUCCESS, BINDING_FAILED,
    DEEPSEEK_CALL_START, DEEPSEEK_CALL_END,
    RATE_LIMIT_HIT, BAN_TRIGGERED,
    ERROR_OCCURRED,
})


# ── Qt signal bridge ──────────────────────────────────────────────────────────

class MonitorSignals(QObject):
    """
    Thread-safe Qt signal bridge.
    Emit from any thread; PySide6 delivers the slot on the main (GUI) thread.
    """
    event_received = Signal(object)  # dict payload
    metric_update = Signal(object)   # dict metrics
    connection_update = Signal(object)  # list[dict]


# ── Monitor ───────────────────────────────────────────────────────────────────

class Monitor:
    """
    Thread-safe event collector with observer notification.
    Keeps a circular buffer of the last N events.
    """

    def __init__(self, max_events: int = MONITOR_EVENT_LIMIT):
        self._max_events = max_events
        self._events: deque[dict] = deque(maxlen=max_events)
        self._lock = threading.RLock()
        self._observers: list[Callable[[dict], None]] = []
        self._qt_signals = MonitorSignals()  # always created on the main thread

        # metric accumulators
        self._tasks_sent = 0
        self._tasks_received = 0
        self._tasks_completed = 0
        self._tasks_failed = 0
        self._errors_by_type: dict[str, int] = {}
        self._avg_latency_ms: float = 0.0  # exponential moving average
        self._latency_count: int = 0
        self._connections: dict[str, dict] = {}  # conn_id -> state
        self._rate_limit_hits = 0
        self._ban_count = 0
        self._agents: dict[str, dict] = {}  # agent_name -> identity info
        self._tasks: list[dict] = []  # task history for dashboard

    # ── observer management ──────────────────────────────────────────────

    def add_observer(self, callback: Callable[[dict], None]):
        with self._lock:
            self._observers.append(callback)

    def remove_observer(self, callback: Callable[[dict], None]):
        with self._lock:
            self._observers.remove(callback)

    # ── event ingestion ──────────────────────────────────────────────────

    def add_event(self, event_type: str, data: Optional[dict] = None):
        if data is None:
            data = {}
        event = {
            "type": event_type,
            "timestamp": time.time(),
            "data": data,
        }
        with self._lock:
            self._events.append(event)
            self._update_metrics(event)
            observers = list(self._observers)

        # notify observers outside the lock
        for cb in observers:
            try:
                cb(event)
            except Exception:
                logger.exception("Observer callback failed")

        # emit Qt signal (thread-safe)
        try:
            self._qt_signals.event_received.emit(event)
        except RuntimeError:
            pass  # signals not wired yet

    # ── queries ──────────────────────────────────────────────────────────

    def get_events(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(self._events)[-limit:]

    def get_metrics(self) -> dict:
        with self._lock:
            return {
                "tasks_sent": self._tasks_sent,
                "tasks_received": self._tasks_received,
                "tasks_completed": self._tasks_completed,
                "tasks_failed": self._tasks_failed,
                "errors_count": sum(self._errors_by_type.values()),
                "errors_by_type": dict(self._errors_by_type),
                "avg_latency_ms": round(self._avg_latency_ms, 2),
                "active_connections": sum(
                    1 for c in self._connections.values()
                    if c.get("state") == "BOUND"
                ),
                "total_connections": len(self._connections),
                "rate_limit_hits": self._rate_limit_hits,
                "ban_count": self._ban_count,
                "event_count": len(self._events),
            }

    def get_connections(self) -> list[dict]:
        with self._lock:
            return list(self._connections.values())

    # ── internal metric tracking ─────────────────────────────────────────

    def _update_metrics(self, event: dict):
        et = event["type"]
        d = event.get("data", {})

        if et == TASK_START:
            self._tasks_sent += 1
        elif et == TASK_COMPLETE:
            self._tasks_received += 1
            self._tasks_completed += 1
            if "latency_ms" in d:
                lat = d["latency_ms"]
                self._latency_count += 1
                alpha = 0.1  # EMA smoothing factor
                if self._latency_count == 1:
                    self._avg_latency_ms = float(lat)
                else:
                    self._avg_latency_ms = alpha * lat + (1 - alpha) * self._avg_latency_ms
        elif et == TASK_ERROR:
            self._tasks_received += 1
            self._tasks_failed += 1
        elif et == ERROR_OCCURRED:
            ec = d.get("error_code", "unknown")
            self._errors_by_type[ec] = self._errors_by_type.get(ec, 0) + 1
        elif et == CONNECTION_OPEN:
            conn_id = d.get("conn_id", str(id(d)))
            self._connections[conn_id] = {
                "conn_id": conn_id,
                "agent": d.get("agent", "?"),
                "mcc_hash": d.get("mcc_hash", ""),
                "state": d.get("state", "CONNECTED"),
                "last_event": event["type"],
                "connected_since": event["timestamp"],
            }
        elif et == CONNECTION_CLOSE:
            conn_id = d.get("conn_id", "")
            if conn_id in self._connections:
                self._connections[conn_id]["state"] = "CLOSED"
                self._connections[conn_id]["last_event"] = event["type"]
        elif et == BINDING_SUCCESS:
            conn_id = d.get("conn_id", "")
            if conn_id in self._connections:
                self._connections[conn_id]["state"] = "BOUND"
                self._connections[conn_id]["last_event"] = event["type"]
                self._connections[conn_id]["mcc_hash"] = d.get("mcc_hash", "")
        elif et == RATE_LIMIT_HIT:
            self._rate_limit_hits += 1
        elif et == BAN_TRIGGERED:
            self._ban_count += 1

    def update_connection(self, conn_id: str, **fields):
        with self._lock:
            if conn_id not in self._connections:
                self._connections[conn_id] = {
                    "conn_id": conn_id,
                    "agent": "",
                    "mcc_hash": "",
                    "state": "PENDING",
                    "last_event": "",
                    "connected_since": time.time(),
                }
            self._connections[conn_id].update(fields)

    # ── agent identity tracking ──────────────────────────────────────────

    def register_agent(self, agent_name: str, role: str = "",
                       x25519_pk: str = "", ed25519_pk: str = "",
                       mcc_hash: str = "", status: str = "inactive"):
        """Register or update an agent's identity."""
        with self._lock:
            self._agents[agent_name] = {
                "name": agent_name,
                "role": role,
                "x25519_pk": x25519_pk,
                "ed25519_pk": ed25519_pk,
                "mcc_hash": mcc_hash,
                "status": status,
                "last_seen": time.time(),
            }

    def get_agents(self) -> list[dict]:
        with self._lock:
            return list(self._agents.values())

    def add_task(self, task_info: dict):
        """Record a completed task for the dashboard."""
        with self._lock:
            self._tasks.append(task_info)
            # Keep last 200 tasks
            if len(self._tasks) > 200:
                self._tasks = self._tasks[-200:]

    def get_tasks(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return list(self._tasks)[-limit:]
