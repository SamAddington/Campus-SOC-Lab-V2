"""OpenPhish provider.

OpenPhish publishes a plaintext feed of known phishing URLs. We cache
the full feed in memory for ``TRAFFIC_OPENPHISH_TTL`` seconds (default:
once per hour) and compare submitted URLs against it in O(1).
"""

from __future__ import annotations

import threading
import time
from typing import Optional, Set

from http_client import OSINTCallError, ScopedHTTP

from .base import Finding, OSINTProvider, Verdict


_FEED_TTL = 3600


class OpenPhishProvider(OSINTProvider):
    name = "openphish"
    supports_url = True

    def __init__(self, *, cfg, http: ScopedHTTP):
        self._http = http
        self._feed: Set[str] = set()
        self._loaded_at: float = 0.0
        self._lock = threading.Lock()
        self._last_error: Optional[str] = None

    def _refresh_feed(self) -> None:
        with self._lock:
            if time.time() - self._loaded_at < _FEED_TTL and self._feed:
                return
            try:
                resp = self._http.request(self.name, "GET", "/feed.txt")
            except OSINTCallError as exc:
                self._last_error = str(exc)
                return
            if not resp.ok():
                self._last_error = f"feed HTTP {resp.status_code}"
                return
            entries = {
                line.strip()
                for line in (resp.text or "").splitlines()
                if line.strip() and not line.startswith("#")
            }
            if entries:
                self._feed = entries
                self._loaded_at = time.time()
                self._last_error = None

    def check_url(self, url: str) -> Finding:
        self._refresh_feed()
        if not self._feed:
            return Finding(self.name, Verdict.UNKNOWN, 0.0,
                           f"OpenPhish feed not loaded ({self._last_error or 'empty'})")
        if url in self._feed:
            return Finding(self.name, Verdict.MALICIOUS, 1.0,
                           "URL present in OpenPhish live feed")
        return Finding(self.name, Verdict.UNKNOWN, 0.0,
                       "not present in OpenPhish feed")
