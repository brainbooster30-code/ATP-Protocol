"""
ATP v1.8 — Production module.
Graceful shutdown, circuit breaker, health checks, structured logging.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
from collections import deque
from typing import Optional, Callable, Awaitable

from config import (
    DRAIN_TIMEOUT_S, HEALTH_CHECK_PORT,
    CIRCUIT_BREAKER_THRESHOLD, CIRCUIT_BREAKER_RESET_S,
    RETRY_MAX_ATTEMPTS, RETRY_BACKOFF_BASE_S, RETRY_BACKOFF_MAX_S,
    LOG_FORMAT,
)

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
#  Structured JSON Logging
# ═══════════════════════════════════════════════════════════════════════════════

class JSONFormatter(logging.Formatter):
    """Log record as JSON for log aggregation (ELK, Loki, CloudWatch)."""

    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            base["exception"] = str(record.exc_info[1])
        if hasattr(record, "conn_id"):
            base["conn_id"] = record.conn_id
        if hasattr(record, "task_id"):
            base["task_id"] = record.task_id
        return json.dumps(base, default=str)


def setup_logging():
    """Configure root logger: JSON or text based on LOG_FORMAT."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    if LOG_FORMAT == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        ))
    # Remove existing handlers to avoid duplicates
    root.handlers.clear()
    root.addHandler(handler)


# ═══════════════════════════════════════════════════════════════════════════════
#  Circuit Breaker
# ═══════════════════════════════════════════════════════════════════════════════

class CircuitBreaker:
    """Fail-fast when a downstream service is unhealthy."""

    def __init__(self, name: str,
                 threshold: int = CIRCUIT_BREAKER_THRESHOLD,
                 reset_s: float = CIRCUIT_BREAKER_RESET_S):
        self.name = name
        self.threshold = threshold
        self.reset_s = reset_s
        self._failures = 0
        self._last_failure_ts: float = 0.0
        self._open_ts: float = 0.0
        self._state = "CLOSED"  # CLOSED → OPEN → HALF_OPEN → CLOSED

    @property
    def state(self) -> str:
        return self._state

    def _maybe_transition(self):
        """OPEN → HALF_OPEN after reset_s, HALF_OPEN → CLOSED on success."""
        if self._state == "OPEN" and time.monotonic() - self._open_ts > self.reset_s:
            self._state = "HALF_OPEN"
            logger.info("Circuit %s → HALF_OPEN (reset timeout elapsed)", self.name)

    def record_success(self):
        self._maybe_transition()
        if self._state == "HALF_OPEN":
            self._state = "CLOSED"
            self._failures = 0
            logger.info("Circuit %s → CLOSED (recovery)", self.name)
        elif self._state == "CLOSED":
            self._failures = 0

    def record_failure(self):
        self._failures += 1
        self._last_failure_ts = time.monotonic()
        if self._state in ("CLOSED", "HALF_OPEN") and self._failures >= self.threshold:
            self._state = "OPEN"
            self._open_ts = time.monotonic()
            logger.warning("Circuit %s → OPEN (%d consecutive failures)", self.name, self._failures)

    def allow(self) -> bool:
        self._maybe_transition()
        return self._state in ("CLOSED", "HALF_OPEN")


# Global circuit breaker for DeepSeek
deepseek_circuit = CircuitBreaker("deepseek")


# ═══════════════════════════════════════════════════════════════════════════════
#  Retry with Exponential Backoff
# ═══════════════════════════════════════════════════════════════════════════════

async def retry_with_backoff(
    fn: Callable[..., Awaitable],
    *args,
    max_attempts: int = RETRY_MAX_ATTEMPTS,
    base_s: float = RETRY_BACKOFF_BASE_S,
    max_s: float = RETRY_BACKOFF_MAX_S,
    circuit: Optional[CircuitBreaker] = None,
    **kwargs,
):
    """Call *fn* with exponential backoff on transient failures."""
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            result = await fn(*args, **kwargs)
            if circuit:
                circuit.record_success()
            return result
        except (asyncio.TimeoutError, ConnectionError, OSError) as exc:
            last_exc = exc
            if circuit:
                circuit.record_failure()
            if attempt == max_attempts:
                raise
            delay = min(base_s * (2 ** (attempt - 1)), max_s)
            logger.debug("Retry %d/%d after %.1fs (exc: %s)", attempt, max_attempts, delay, exc)
            await asyncio.sleep(delay)
    raise last_exc  # unreachable, satisfies type checker


# ═══════════════════════════════════════════════════════════════════════════════
#  Connection limiter
# ═══════════════════════════════════════════════════════════════════════════════

class ConnectionLimiter:
    """Cap max concurrent connections with backpressure."""

    def __init__(self, max_conns: int = 100):
        self._max = max_conns
        self._sem = asyncio.Semaphore(max_conns)
        self._active = 0

    @property
    def active(self) -> int:
        return self._active

    @property
    def max(self) -> int:
        return self._max

    async def acquire(self) -> bool:
        """Try to acquire a slot. Returns False if at capacity."""
        if self._active >= self._max:
            return False
        await self._sem.acquire()
        self._active += 1
        return True

    def release(self):
        self._active = max(0, self._active - 1)
        self._sem.release()


# ═══════════════════════════════════════════════════════════════════════════════
#  Graceful Shutdown
# ═══════════════════════════════════════════════════════════════════════════════

class GracefulShutdown:
    """Handle SIGTERM/SIGINT: drain in-flight tasks, close connections."""

    def __init__(self, drain_timeout_s: float = DRAIN_TIMEOUT_S):
        self._shutting_down = False
        self._drain_timeout = drain_timeout_s
        self._tasks: set[asyncio.Task] = set()

    @property
    def shutting_down(self) -> bool:
        return self._shutting_down

    def register(self, loop: Optional[asyncio.AbstractEventLoop] = None):
        """Install signal handlers for graceful shutdown."""
        loop = loop or asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._trigger)
            except NotImplementedError:
                # Windows non supporta add_signal_handler
                pass

    def _trigger(self):
        if not self._shutting_down:
            self._shutting_down = True
            logger.warning("Graceful shutdown initiated — draining in-flight tasks...")

    def track(self, task: asyncio.Task):
        """Track a background task for drain."""
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def drain(self):
        """Wait for tracked tasks to complete, with timeout."""
        if not self._tasks:
            return
        deadline = time.monotonic() + self._drain_timeout
        pending = set(self._tasks)
        while pending and time.monotonic() < deadline:
            done, pending = await asyncio.wait(
                pending, timeout=1.0, return_when=asyncio.FIRST_COMPLETED
            )
        if pending:
            logger.warning("Force-cancelling %d tasks after drain timeout", len(pending))
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    async def shutdown_server(self, server):
        """Close a server and drain."""
        if server:
            server.close()
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=5.0)
            except Exception:
                pass
        await self.drain()


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP Health Check (lightweight, no aiohttp)
# ═══════════════════════════════════════════════════════════════════════════════

class HealthCheckServer:
    """Minimal HTTP server for /health and /ready endpoints (no deps)."""

    def __init__(self, host: str = "0.0.0.0", port: int = HEALTH_CHECK_PORT,
                 conn_limiter: Optional[ConnectionLimiter] = None):
        self._host = host
        self._port = port
        self._server: Optional[asyncio.AbstractServer] = None
        self._ready = False
        self._conn_limiter = conn_limiter

    @property
    def ready(self) -> bool:
        return self._ready

    @ready.setter
    def ready(self, val: bool):
        self._ready = val

    async def start(self):
        async def handler(reader, writer):
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                path = line.decode(errors='replace').split()[1] if line else "/"
                if path == "/health":
                    body = b'{"status":"ok"}\n'
                    code = b'200 OK'
                elif path == "/ready":
                    if self._ready:
                        body = b'{"status":"ready"}\n'
                        code = b'200 OK'
                    else:
                        body = b'{"status":"not_ready"}\n'
                        code = b'503 Service Unavailable'
                elif path == "/metrics":
                    conns = self._conn_limiter.active if self._conn_limiter else 0
                    max_c = self._conn_limiter.max if self._conn_limiter else 0
                    body = json.dumps({
                        "active_connections": conns,
                        "max_connections": max_c,
                    }).encode() + b'\n'
                    code = b'200 OK'
                else:
                    body = b'{"status":"not_found"}\n'
                    code = b'404 Not Found'
                resp = b'HTTP/1.1 ' + code + b'\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
                writer.write(resp)
                await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
        self._server = await asyncio.start_server(handler, self._host, self._port)
        logger.info("Health check listening on %s:%s", self._host, self._port)

    async def stop(self):
        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=3.0)
            except Exception:
                pass
