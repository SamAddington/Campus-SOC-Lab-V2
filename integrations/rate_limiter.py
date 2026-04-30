"""Simple, thread-safe per-provider token bucket.

Each provider has its own bucket. Tokens refill at a configurable rate;
``acquire`` blocks briefly if the bucket is empty. Not a global, coordinated
scheduler -- sized to be correct for a single integrations container and
small enough to read.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    capacity: float
    refill_per_sec: float
    tokens: float
    updated_at: float


class RateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def configure(self, key: str, capacity: int, refill_per_sec: float) -> None:
        with self._lock:
            self._buckets[key] = _Bucket(
                capacity=float(capacity),
                refill_per_sec=float(refill_per_sec),
                tokens=float(capacity),
                updated_at=time.monotonic(),
            )

    def acquire(self, key: str, timeout: float = 5.0) -> bool:
        """Consume one token. Returns True if consumed, False on timeout.

        Callers that get False should back off and retry or surface a
        429-style response to the operator. We never spin-loop: we sleep in
        small increments proportional to the refill rate.
        """
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                bucket = self._buckets.get(key)
                if bucket is None:
                    # No bucket configured for this provider: fail open but
                    # small-capacity to avoid surprises.
                    self.configure(key, capacity=5, refill_per_sec=1.0)
                    bucket = self._buckets[key]

                now = time.monotonic()
                elapsed = now - bucket.updated_at
                bucket.tokens = min(
                    bucket.capacity,
                    bucket.tokens + elapsed * bucket.refill_per_sec,
                )
                bucket.updated_at = now

                if bucket.tokens >= 1.0:
                    bucket.tokens -= 1.0
                    return True

                needed = 1.0 - bucket.tokens
                sleep_for = max(0.02, needed / max(bucket.refill_per_sec, 0.1))

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(sleep_for, remaining))

    def describe(self) -> dict:
        with self._lock:
            return {
                k: {
                    "capacity": b.capacity,
                    "refill_per_sec": b.refill_per_sec,
                    "tokens": round(b.tokens, 2),
                }
                for k, b in self._buckets.items()
            }


limiter = RateLimiter()
