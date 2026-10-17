"""In-memory sliding window rate limiter for login attempts.

Note: This rate limiter uses an in-memory sliding window stored in process memory.
It is per-process and resets on restart.
"""

from math import ceil
import threading
import time
from typing import Optional


class SlidingWindowRateLimiter:
    """Tracks failed login attempts per client IP and per username within a sliding window."""

    def __init__(self, max_failures: int = 5, window_seconds: int = 900) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._ip_failures: dict[str, list[float]] = {}
        self._user_failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _clean_window(self, records: dict[str, list[float]], key: str, now: float) -> list[float]:
        threshold = now - self.window_seconds
        valid = [ts for ts in records.get(key, []) if ts > threshold]
        if valid:
            records[key] = valid
        elif key in records:
            del records[key]
        return valid

    def check_rate_limit(self, ip: str, username: str) -> Optional[int]:
        """Check if IP or username has exceeded the allowed failed attempts.

        Returns remaining retry-after duration in seconds if rate-limited, or None if allowed.
        """
        now = time.monotonic()
        with self._lock:
            ip_history = self._clean_window(self._ip_failures, ip, now)
            user_history = self._clean_window(self._user_failures, username, now)

            retry_ip = 0
            if len(ip_history) >= self.max_failures:
                retry_ip = ceil(self.window_seconds - (now - ip_history[0]))

            retry_user = 0
            if len(user_history) >= self.max_failures:
                retry_user = ceil(self.window_seconds - (now - user_history[0]))

            max_retry = max(retry_ip, retry_user)
            if max_retry > 0:
                return max(1, int(max_retry))

            return None

    def record_failure(self, ip: str, username: str) -> None:
        """Record a failed login attempt for the client IP and username."""
        now = time.monotonic()
        with self._lock:
            self._clean_window(self._ip_failures, ip, now)
            self._clean_window(self._user_failures, username, now)

            self._ip_failures.setdefault(ip, []).append(now)
            self._user_failures.setdefault(username, []).append(now)

    def record_success(self, ip: str, username: str) -> None:
        """Reset failed attempts for client IP and username upon successful login."""
        with self._lock:
            self._ip_failures.pop(ip, None)
            self._user_failures.pop(username, None)

    def reset(self) -> None:
        """Clear all rate limiting state (useful for tests)."""
        with self._lock:
            self._ip_failures.clear()
            self._user_failures.clear()


# Global singleton rate limiter instance
login_rate_limiter = SlidingWindowRateLimiter(max_failures=5, window_seconds=900)
