from __future__ import annotations

import base64
import logging
import os
import re
from typing import Any, Dict, List, Optional

from adapters import NormalizedEvent
from http_client import HTTPError, ScopedHTTP
from rate_limiter import limiter

from .base import LMSProvider, SyncResult

log = logging.getLogger("ise")


_USER_RE = re.compile(r"user(?:name)?\\s*[:=]\\s*([\\w.@-]+)", re.IGNORECASE)


class ISEProvider(LMSProvider):
    """Cisco ISE connector (read-only; conservative default).

    By default we pull the active-session list endpoint and emit a single
    summary event. Operators can widen scope with governance sign-off.
    """

    name = "ise"

    def __init__(self, cfg):
        super().__init__(cfg)
        limiter.configure("ise", capacity=5, refill_per_sec=0.5)
        self._http = ScopedHTTP(
            provider="ise",
            base_url=self.cfg.base_url or "",
            allowed_paths=self.cfg.allowed_paths,
        )
        user = self.cfg.raw.get("ISE_USERNAME") or ""
        pwd = self.cfg.raw.get("ISE_PASSWORD") or ""
        if user and pwd:
            basic = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("ascii")
            self._http.session.headers["Authorization"] = f"Basic {basic}"
        self._http.session.headers.setdefault("Accept", "application/json")

    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        if not self.configured:
            return SyncResult(provider=self.name, events=[], warnings=["ISE not configured"])

        warnings: List[str] = []
        events: List[NormalizedEvent] = []

        try:
            _, body = self._http.get("/admin/API/mnt/Session/ActiveList", timeout=30)
        except HTTPError as e:
            warnings.append(f"active sessions failed: {e}")
            return SyncResult(provider=self.name, events=[], warnings=warnings)

        # ISE may respond with JSON or XML depending on deployment. We avoid
        # fragile parsing and emit a coarse summary.
        count = _estimate_session_count(body)
        sample_user = _extract_sample_user(body)
        msg = f"ISE active sessions: approx_count={count}"
        if sample_user:
            msg += f" sample_user={sample_user}"

        events.append(
            NormalizedEvent(
                provider_event_id=str(count),
                message=msg,
                source="ise:active_sessions",
                event_type="active_sessions",
                user_id="",
                email="",
                language="en",
                created_at=None,
                extra={"raw_type": type(body).__name__},
            )
        )

        return SyncResult(provider=self.name, events=events, next_cursor=None, warnings=warnings)


def _estimate_session_count(body: Any) -> int:
    if isinstance(body, dict):
        for k in ("sessions", "results", "items"):
            v = body.get(k)
            if isinstance(v, list):
                return len(v)
        # Sometimes there is a count field.
        for k in ("count", "total", "Total"):
            try:
                return int(body.get(k))
            except Exception:
                pass
        return 1
    if isinstance(body, list):
        return len(body)
    if isinstance(body, str):
        # Crude heuristic: count repeated "Session" markers.
        return max(1, body.lower().count("session"))
    return 1


def _extract_sample_user(body: Any) -> str:
    if isinstance(body, dict):
        for k in ("sessions", "results", "items"):
            v = body.get(k)
            if isinstance(v, list) and v and isinstance(v[0], dict):
                for key in ("userName", "username", "user"):
                    if v[0].get(key):
                        return str(v[0].get(key))
    if isinstance(body, str):
        m = _USER_RE.search(body)
        if m:
            return m.group(1)
    return ""

