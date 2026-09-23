"""Demo Mode engine: rate-limiting per IP, daily LLM call counters, and endpoint guards (§10)."""

from collections import defaultdict
from datetime import datetime, timezone
import logging
import os
import threading
import time
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# Defaults
DEFAULT_GENERAL_LIMIT_PER_MINUTE = 30
DEFAULT_STRICT_LIMIT_PER_MINUTE = 5
DEFAULT_MAX_DAILY_LLM_CALLS = 200

# Strict endpoints (e.g. scenarios, evaluations, and anything that invokes agent or LLM directly)
STRICT_PATHS = {
    "/api/agent/run",
    "/api/eval/run",
    "/api/redteam/run",
}


def is_demo_mode() -> bool:
    """Check if DEMO_MODE=1 is set in the environment."""
    return os.environ.get("DEMO_MODE", "0").strip() == "1"


class DemoQuotaManager:
    """Thread-safe global manager for daily LLM call limits and IP rate limits."""

    def __init__(self):
        self._lock = threading.Lock()
        self._current_date = self._get_utc_date()
        self._daily_llm_calls = 0

        # Rate limiter storage: key -> list of timestamps
        # key format: f"{ip}:{rate_tier}"
        self._ip_request_timestamps: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = time.time()

    def _get_utc_date(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _check_and_reset_day(self) -> None:
        today = self._get_utc_date()
        if today != self._current_date:
            self._current_date = today
            self._daily_llm_calls = 0
            logger.info("Demo Mode: Daily LLM counter reset for new UTC date: %s", today)

    def get_max_daily_llm_calls(self) -> int:
        try:
            return int(os.environ.get("DEMO_MAX_DAILY_LLM_CALLS", str(DEFAULT_MAX_DAILY_LLM_CALLS)))
        except (ValueError, TypeError):
            return DEFAULT_MAX_DAILY_LLM_CALLS

    def can_call_llm(self) -> bool:
        """Return True if LLM invocation is allowed under demo quotas."""
        if not is_demo_mode():
            return True

        with self._lock:
            self._check_and_reset_day()
            limit = self.get_max_daily_llm_calls()
            return self._daily_llm_calls < limit

    def record_llm_call(self) -> bool:
        """Record an LLM call against the daily quota. Returns True if recorded within limit."""
        if not is_demo_mode():
            return True

        with self._lock:
            self._check_and_reset_day()
            limit = self.get_max_daily_llm_calls()
            if self._daily_llm_calls < limit:
                self._daily_llm_calls += 1
                logger.info("Demo Mode: Recorded LLM call (%d / %d today)", self._daily_llm_calls, limit)
                return True
            return False

    def get_llm_stats(self) -> dict[str, int]:
        """Get daily LLM quota stats."""
        with self._lock:
            self._check_and_reset_day()
            limit = self.get_max_daily_llm_calls()
            used = self._daily_llm_calls
            return {
                "limit": limit,
                "used": used,
                "remaining": max(0, limit - used),
            }

    def reset_for_tests(self) -> None:
        """Reset internal counters (for testing)."""
        with self._lock:
            self._current_date = self._get_utc_date()
            self._daily_llm_calls = 0
            self._ip_request_timestamps.clear()

    def check_rate_limit(self, client_ip: str, path: str) -> tuple[bool, int]:
        """Check if client IP is within rate limits.
        
        Returns (is_allowed, retry_after_seconds).
        """
        if not is_demo_mode():
            return True, 0

        now = time.time()
        window_seconds = 60.0

        is_strict = path in STRICT_PATHS or any(path.startswith(p) for p in STRICT_PATHS)
        limit = DEFAULT_STRICT_LIMIT_PER_MINUTE if is_strict else DEFAULT_GENERAL_LIMIT_PER_MINUTE
        tier = "strict" if is_strict else "general"
        key = f"{client_ip}:{tier}"

        with self._lock:
            # Periodic cleanup of timestamps older than 2 minutes
            if now - self._last_cleanup > 60.0:
                expired_cutoff = now - 120.0
                for k in list(self._ip_request_timestamps.keys()):
                    self._ip_request_timestamps[k] = [
                        ts for ts in self._ip_request_timestamps[k] if ts > expired_cutoff
                    ]
                    if not self._ip_request_timestamps[k]:
                        del self._ip_request_timestamps[k]
                self._last_cleanup = now

            timestamps = self._ip_request_timestamps[key]
            # Retain only timestamps within window
            cutoff = now - window_seconds
            valid_timestamps = [ts for ts in timestamps if ts > cutoff]
            self._ip_request_timestamps[key] = valid_timestamps

            if len(valid_timestamps) >= limit:
                oldest_in_window = valid_timestamps[0]
                retry_after = max(1, int(window_seconds - (now - oldest_in_window)))
                return False, retry_after

            self._ip_request_timestamps[key].append(now)
            return True, 0


# Singleton instance
demo_quota_manager = DemoQuotaManager()


def get_demo_manager() -> DemoQuotaManager:
    return demo_quota_manager


class DemoRateLimitMiddleware(BaseHTTPMiddleware):
    """Starlette middleware to enforce per-IP rate limits in DEMO_MODE."""

    async def dispatch(self, request: Request, call_next):
        if not is_demo_mode():
            return await call_next(request)

        # Skip rate-limiting for static assets or health checks if desired,
        # but rate limit all API routes.
        path = request.url.path
        if path.startswith("/api/") and path != "/api/health":
            client_ip = request.headers.get("X-Forwarded-For")
            if client_ip:
                client_ip = client_ip.split(",")[0].strip()
            elif request.client and request.client.host:
                client_ip = request.client.host
            else:
                client_ip = "127.0.0.1"

            allowed, retry_after = demo_quota_manager.check_rate_limit(client_ip, path)
            if not allowed:
                is_strict = path in STRICT_PATHS or any(path.startswith(p) for p in STRICT_PATHS)
                limit = DEFAULT_STRICT_LIMIT_PER_MINUTE if is_strict else DEFAULT_GENERAL_LIMIT_PER_MINUTE
                logger.warning(
                    "Rate limit exceeded for IP %s on path %s (%d req/min limit)",
                    client_ip, path, limit
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": (
                            f"Rate limit exceeded. Public demo mode allows up to {limit} requests/min "
                            f"for this endpoint. Please wait {retry_after} seconds."
                        ),
                        "retry_after": retry_after,
                        "limit_per_minute": limit,
                    },
                    headers={"Retry-After": str(retry_after)},
                )

        return await call_next(request)
