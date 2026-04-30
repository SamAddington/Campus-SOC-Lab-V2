from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from adapters import NormalizedEvent
from http_client import HTTPError, ScopedHTTP
from rate_limiter import limiter

from .base import LMSProvider, SyncResult

log = logging.getLogger("umbrella")


class UmbrellaProvider(LMSProvider):
    """Cisco Umbrella Reporting API connector (read-only).

    This is intentionally conservative: we only call allowlisted report endpoints
    and summarize rows into short text messages.
    """

    name = "umbrella"

    def __init__(self, cfg):
        super().__init__(cfg)
        limiter.configure("umbrella", capacity=5, refill_per_sec=1.0)
        self._http = ScopedHTTP(
            provider="umbrella",
            base_url=self.cfg.base_url or "",
            allowed_paths=self.cfg.allowed_paths,
        )
        token = self.cfg.raw.get("UMBRELLA_API_TOKEN") or ""
        if token:
            self._http.session.headers["Authorization"] = f"Bearer {token}"
        self.endpoint = os.getenv("UMBRELLA_REPORT", "security-activity").strip().lower()

    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        if not self.configured:
            return SyncResult(provider=self.name, events=[], warnings=["Umbrella not configured"])

        warnings: List[str] = []
        events: List[NormalizedEvent] = []

        # Umbrella reports vary by tenant. We keep params minimal and tolerate
        # different shapes.
        path = "/reports/v2/security-activity" if self.endpoint != "activity" else "/reports/v2/activity"
        params: Dict[str, Any] = {"limit": min(limit, 200)}
        if since:
            params["since"] = since

        try:
            _, body = self._http.get(path, params=params, timeout=30)
        except HTTPError as e:
            warnings.append(f"report failed: {e}")
            return SyncResult(provider=self.name, events=[], warnings=warnings)

        rows = _extract_rows(body)
        for row in rows[:limit]:
            msg = _row_to_message(row)
            if not msg:
                continue
            rid = str(row.get("id") or row.get("eventId") or row.get("timestamp") or "")
            events.append(
                NormalizedEvent(
                    provider_event_id=rid or msg[:40],
                    message=msg,
                    source=f"umbrella:{self.endpoint}",
                    event_type=self.endpoint,
                    user_id=str(row.get("identity") or row.get("user") or ""),
                    email=str(row.get("email") or ""),
                    language="en",
                    created_at=str(row.get("timestamp") or row.get("time") or ""),
                )
            )

        next_cursor = events[-1].provider_event_id if events else None
        return SyncResult(provider=self.name, events=events, next_cursor=next_cursor, warnings=warnings)


def _extract_rows(body: Any) -> List[Dict[str, Any]]:
    if isinstance(body, list):
        return [b for b in body if isinstance(b, dict)]
    if isinstance(body, dict):
        for key in ("data", "rows", "items", "results"):
            v = body.get(key)
            if isinstance(v, list):
                return [b for b in v if isinstance(b, dict)]
        # Some APIs return a single dict; treat as one row.
        return [body]
    return []


def _row_to_message(row: Dict[str, Any]) -> str:
    # Keep it short and generic: include disposition/category when present.
    ident = row.get("identity") or row.get("user") or row.get("internalIp") or ""
    dom = row.get("domain") or row.get("destination") or row.get("dst") or ""
    disp = row.get("verdict") or row.get("disposition") or row.get("blocked") or ""
    cat = row.get("category") or row.get("categories") or ""
    parts = [p for p in [f"identity={ident}", f"domain={dom}", f"disposition={disp}", f"category={cat}"] if p and not p.endswith("=")]
    return "Umbrella " + " ".join(parts) if parts else ""

