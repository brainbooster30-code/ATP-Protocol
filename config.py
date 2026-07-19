"""
ATP v1.7 — Configuration module.
All tunable parameters live here; load via `from config import *`.
"""

import os

# ── Protocol version ──────────────────────────────────────────────────────────
ATP_VERSION = "1.7"

# ── Transport / framing ───────────────────────────────────────────────────────
MAX_BATCH_BYTES      = 1024 * 1024    # 1 MiB max frame payload
CLOCK_SKEW_MS        = 10_000         # 10 s allowed clock difference
ANTI_REPLAY_TTL_MS   = 20_000         # 20 s anti-replay window
RATE_LIMIT_RPS       = 100            # requests / second
ACK_WINDOW_MS        = 200            # ack timeout

# ── Timeouts (ms) ─────────────────────────────────────────────────────────────
CONNECTION_SETUP_TIMEOUT_MS = 10_000
STREAM_CLOSE_TIMEOUT_MS     = 5_000
GRACE_PERIOD_S              = 300

# ── Gossip (structure reserved for future) ────────────────────────────────────
GOSSIP_INTERVAL_S = 5
GOSSIP_FANOUT     = 3

# ── Network ───────────────────────────────────────────────────────────────────
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8443

# ── DeepSeek API ──────────────────────────────────────────────────────────────
DEEPSEEK_API_KEY  = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_MODEL    = "deepseek-chat"
DEEPSEEK_API_URL  = "https://api.deepseek.com/v1/chat/completions"


def get_deepseek_api_key() -> str:
    """Read DeepSeek API key from env var or Windows registry (fallback).

    On Windows, git-bash/MSYS2 shells often don't inherit user environment
    variables from the registry, so os.environ.get() returns nothing even
    when the variable is set in the Windows UI. This function reads the
    registry as fallback to cover that case.
    """
    key = os.environ.get("DEEPSEEK_API_KEY", "")
    if key and key not in ("sk-placeholder", ""):
        return key

    # Fallback: Windows registry (HKCU\Environment)
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            val, _ = winreg.QueryValueEx(k, "DEEPSEEK_API_KEY")
            if val and val not in ("sk-placeholder", ""):
                return val
    except (FileNotFoundError, OSError, ImportError):
        pass

    return ""  # not found anywhere

# ── Event ring-buffer ─────────────────────────────────────────────────────────
MONITOR_EVENT_LIMIT = 1000

# ── Rate Limiter / Anti-Replay ─────────────────────────────────────────────────
import threading, time, collections

class RateLimiter:
    """Sliding window rate limiter per connection (O(1) average)."""
    def __init__(self, max_rps: int = RATE_LIMIT_RPS):
        self.max_rps = max_rps
        self._lock = threading.Lock()
        self._timestamps: collections.deque = collections.deque(maxlen=max_rps + 10)

    def allow(self) -> bool:
        with self._lock:
            now = time.time()
            while self._timestamps and self._timestamps[0] < now - 1.0:
                self._timestamps.popleft()
            if len(self._timestamps) >= self.max_rps:
                return False
            self._timestamps.append(now)
            return True

class AntiReplay:
    """Anti-replay filter for frame_id (16 bytes, sliding window TTL)."""
    def __init__(self, window_ms: int = ANTI_REPLAY_TTL_MS, max_ids: int = 10000):
        self.window_ms = window_ms
        self._max_ids = max_ids
        self._lock = threading.Lock()
        self._seen: dict[bytes, float] = {}

    def is_new(self, frame_id: bytes, now_ms: float) -> bool:
        if len(frame_id) != 16:
            return False
        with self._lock:
            cutoff = now_ms - self.window_ms
            expired = [k for k, v in self._seen.items() if v < cutoff]
            for k in expired:
                del self._seen[k]
            if frame_id in self._seen:
                return False
            if len(self._seen) >= self._max_ids:
                # evict oldest
                oldest = min(self._seen, key=self._seen.get)
                del self._seen[oldest]
            self._seen[frame_id] = now_ms
            return True
