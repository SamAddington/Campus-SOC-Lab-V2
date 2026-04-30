"""Privacy-aware TTL cache for OSINT lookups.

Key design choices:

1. **Keys are HMAC-hashed.** The raw indicator is never stored as a key;
   we store ``hmac(secret, f"{provider}:{kind}:{indicator}")``. This
   means an attacker who reads a cache dump cannot recover the list of
   indicators we've looked up.
2. **Values are the provider's summary, not the raw response.** The
   aggregator produces a compact dict (verdict, evidence counts, short
   notes) that is safe to persist; we never cache full response bodies.
3. **Two TTLs.** Clean results are cached longer than "hit" results,
   because threat-intel data becomes stale much faster once something
   is flagged as malicious.
4. **Bounded size.** A simple FIFO trim keeps memory predictable.

This is in-memory only; processes are cattle. If persistence is needed
later, it belongs next to the audit ledger so retention policy is
consistent.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, Optional, Tuple


def cache_key(secret: str, provider: str, kind: str, value: str) -> str:
    raw = f"{provider}|{kind}|{value}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()[:24]


class TTLCache:
    def __init__(self, *, max_entries: int,
                 ttl_clean_seconds: int, ttl_hit_seconds: int):
        self._max = int(max_entries)
        self._ttl_clean = int(ttl_clean_seconds)
        self._ttl_hit = int(ttl_hit_seconds)
        self._data: "OrderedDict[str, Tuple[float, Dict[str, Any]]]" = OrderedDict()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._stores = 0
        self._expired = 0

    def _pick_ttl(self, value: Dict[str, Any]) -> int:
        verdict = str(value.get("verdict", "unknown")).lower()
        if verdict in ("malicious", "suspicious"):
            return self._ttl_hit
        return self._ttl_clean

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        now = time.time()
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                self._misses += 1
                return None
            expires_at, value = entry
            if now >= expires_at:
                self._data.pop(key, None)
                self._expired += 1
                self._misses += 1
                return None
            # Move to the end so recent gets are held longer under FIFO trim.
            self._data.move_to_end(key)
            self._hits += 1
            return dict(value)

    def set(self, key: str, value: Dict[str, Any]) -> None:
        ttl = self._pick_ttl(value)
        expires_at = time.time() + ttl
        with self._lock:
            self._data[key] = (expires_at, dict(value))
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)
            self._stores += 1

    def clear(self) -> int:
        with self._lock:
            n = len(self._data)
            self._data.clear()
            return n

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "entries": len(self._data),
                "max_entries": self._max,
                "ttl_clean_seconds": self._ttl_clean,
                "ttl_hit_seconds": self._ttl_hit,
                "hits": self._hits,
                "misses": self._misses,
                "stores": self._stores,
                "expired": self._expired,
            }
