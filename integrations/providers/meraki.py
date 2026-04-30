from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

from adapters import NormalizedEvent
from http_client import HTTPError, ScopedHTTP
from rate_limiter import limiter

from .base import LMSProvider, SyncResult

log = logging.getLogger("meraki")


class MerakiProvider(LMSProvider):
    """Cisco Meraki Dashboard API connector (read-only)."""

    name = "meraki"

    def __init__(self, cfg):
        super().__init__(cfg)
        # Meraki org events can be bursty; keep a modest limiter by default.
        limiter.configure("meraki", capacity=10, refill_per_sec=1.5)
        self._http = ScopedHTTP(
            provider="meraki",
            base_url=self.cfg.base_url or "",
            allowed_paths=self.cfg.allowed_paths,
        )
        api_key = self.cfg.raw.get("MERAKI_API_KEY") or ""
        if api_key:
            self._http.session.headers["X-Cisco-Meraki-API-Key"] = api_key
        self.org_id = (self.cfg.raw.get("MERAKI_ORG_ID") or os.getenv("MERAKI_ORG_ID", "")).strip()
        # Optional filters
        self.event_types = [t.strip() for t in os.getenv("MERAKI_EVENT_TYPES", "").split(",") if t.strip()]
        self.product_types = [t.strip() for t in os.getenv("MERAKI_PRODUCT_TYPES", "").split(",") if t.strip()]
        # Seconds to look back if no cursor exists (safety net for first run).
        self.lookback_seconds = int(os.getenv("MERAKI_LOOKBACK_SECONDS", "3600") or "3600")

    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        if not self.configured:
            return SyncResult(provider=self.name, events=[], warnings=["Meraki not configured"])

        warnings: List[str] = []
        events: List[NormalizedEvent] = []

        org_id = self._resolve_org_id(warnings)
        if not org_id:
            return SyncResult(provider=self.name, events=[], warnings=warnings)

        params = self._build_params(since=since, limit=limit)
        path = f"/api/v1/organizations/{org_id}/events"
        events, warnings = self._pull_events(path=path, params=params, limit=limit, warnings=warnings)

        next_cursor = events[-1].provider_event_id if events else None
        return SyncResult(provider=self.name, events=events, next_cursor=next_cursor, warnings=warnings)

    def _resolve_org_id(self, warnings: List[str]) -> str:
        org_id = self.org_id
        if org_id:
            return org_id
        try:
            _, body = self._http.get("/api/v1/organizations")
            if isinstance(body, list) and body:
                org_id = str(body[0].get("id") or "")
        except HTTPError as e:
            warnings.append(f"organizations failed: {e}")
        if not org_id:
            warnings.append("MERAKI_ORG_ID not set and no organizations returned")
        return org_id

    def _build_params(self, *, since: Optional[str], limit: int) -> Dict[str, Any]:
        params: Dict[str, Any] = {"perPage": min(1000, max(1, limit))}
        if self.event_types:
            params["includedEventTypes[]"] = self.event_types
        if self.product_types:
            params["productType[]"] = self.product_types
        if since:
            params["startingAfter"] = since
        else:
            try:
                params["t0"] = int(time.time()) - max(60, self.lookback_seconds)
            except Exception:
                pass
        return params

    def _pull_events(
        self,
        *,
        path: str,
        params: Dict[str, Any],
        limit: int,
        warnings: List[str],
    ) -> tuple[List[NormalizedEvent], List[str]]:
        events: List[NormalizedEvent] = []
        page_cursor: Optional[str] = None

        while len(events) < limit:
            if page_cursor:
                params["startingAfter"] = page_cursor

            items = self._fetch_events_page(path=path, params=params, warnings=warnings)
            if not items:
                break

            self._append_items(items, events, limit)
            page_cursor = self._next_page_cursor(items, page_cursor)
            if not page_cursor:
                break

        return events, warnings

    def _fetch_events_page(
        self,
        *,
        path: str,
        params: Dict[str, Any],
        warnings: List[str],
    ) -> List[Dict[str, Any]]:
        try:
            _, body = self._http.get(path, params=params, timeout=30)
        except HTTPError as e:
            warnings.append(f"events failed: {e}")
            return []

        if isinstance(body, dict):
            raw = body.get("events", []) or body.get("items", []) or []
            return [x for x in raw if isinstance(x, dict)]
        if isinstance(body, list):
            return [x for x in body if isinstance(x, dict)]
        return []

    @staticmethod
    def _append_items(items: List[Dict[str, Any]], out: List[NormalizedEvent], limit: int) -> None:
        for item in items:
            if len(out) >= limit:
                return
            ev = _to_event(item)
            if ev is not None:
                out.append(ev)

    @staticmethod
    def _next_page_cursor(items: List[Dict[str, Any]], previous: Optional[str]) -> Optional[str]:
        last_raw_id = str(items[-1].get("eventId") or items[-1].get("id") or "").strip()
        if not last_raw_id or last_raw_id == previous:
            return None
        return last_raw_id


def _to_event(item: Dict[str, Any]) -> Optional[NormalizedEvent]:
    ev_id = str(item.get("eventId") or item.get("id") or "").strip()
    ev_type = str(item.get("eventType") or item.get("type") or "event").lower().strip()
    msg = (item.get("description") or item.get("message") or item.get("details") or "").strip()
    if not msg:
        msg = ev_type
    if not msg:
        return None

    actor = item.get("actor") if isinstance(item.get("actor"), dict) else {}
    user_id = str(actor.get("id") or item.get("adminId") or item.get("adminName") or "").strip()
    email = str(actor.get("email") or "").strip()
    created = item.get("occurredAt") or item.get("ts") or item.get("occurred_at")

    return NormalizedEvent(
        provider_event_id=ev_id or f"{ev_type}:{hash(msg)}",
        message=msg,
        source="meraki:event",
        event_type=ev_type,
        user_id=user_id or None,
        email=email or None,
        language="en",
        created_at=created,
    )

