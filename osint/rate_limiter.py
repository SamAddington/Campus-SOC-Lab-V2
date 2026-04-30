"""Per-provider token-bucket rate limiter.

Same shape as ``integrations/rate_limiter.py`` -- kept separate because
OSINT rates are configured differently and we want one place we can
point a reviewer to.
"""

from __future__ import annotations

import threading
import time
from typing import Dict


class TokenBucket:
    def __init__(self, *, rate_per_minute: int, burst: int = None):
        self._rate = max(1, int(rate_per_minute)) / 60.0
        self._capacity = float(burst if burst is not None else max(1, int(rate_per_minute)))
        self._tokens = self._capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                needed = 1.0 - self._tokens
                wait = needed / self._rate
            if time.monotonic() + wait > deadline:
                return False
            time.sleep(min(wait, 0.5))


class RateLimitRegistry:
    def __init__(self):
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def register(self, provider: str, *, rate_per_minute: int) -> None:
        with self._lock:
            self._buckets[provider] = TokenBucket(rate_per_minute=rate_per_minute)

    def acquire(self, provider: str, timeout: float = 30.0) -> bool:
        with self._lock:
            bucket = self._buckets.get(provider)
        if bucket is None:
            return True
        return bucket.acquire(timeout=timeout)
