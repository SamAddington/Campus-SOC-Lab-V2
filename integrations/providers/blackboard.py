"""Blackboard Learn provider.

Uses the public REST API with OAuth2 client-credentials. Credentials from
``BLACKBOARD_BASE_URL``, ``BLACKBOARD_APP_KEY``, ``BLACKBOARD_APP_SECRET``.

Access tokens are cached in memory and refreshed a minute before expiry.
"""

from __future__ import annotations

import base64
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import requests

from adapters import NormalizedEvent
from http_client import HTTPError, ScopedHTTP
from rate_limiter import limiter

from .base import LMSProvider, SyncResult

log = logging.getLogger("blackboard")


class BlackboardProvider(LMSProvider):
    name = "blackboard"

    def __init__(self, cfg):
        super().__init__(cfg)
        # Conservative defaults; Blackboard enforces per-course and per-app limits.
        limiter.configure("blackboard", capacity=5, refill_per_sec=1.0)

        self._http = ScopedHTTP(
            provider="blackboard",
            base_url=self.cfg.base_url or "",
            allowed_paths=self.cfg.allowed_paths,
        )
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._lock = threading.Lock()

    # ----- OAuth2 -----

    def _fetch_token(self) -> Optional[str]:
        if not self.configured:
            return None

        key = self.cfg.raw.get("BLACKBOARD_APP_KEY", "")
        secret = self.cfg.raw.get("BLACKBOARD_APP_SECRET", "")
        basic = base64.b64encode(f"{key}:{secret}".encode("utf-8")).decode("ascii")

        # Token endpoint is also scope-checked by ScopedHTTP.
        try:
            _, body = self._http.post(
                "/learn/api/v1/oauth2/token",
                data={"grant_type": "client_credentials"},
                headers={
                    "Authorization": f"Basic {basic}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
        except HTTPError as e:
            log.warning("Blackboard token fetch failed: %s", e)
            return None

        token = body.get("access_token")
        expires_in = int(body.get("expires_in", 300))
        if not token:
            return None

        with self._lock:
            self._token = token
            self._token_expires_at = time.monotonic() + max(60, expires_in - 60)
            # Prime the session with the bearer for subsequent requests.
            self._http.session.headers["Authorization"] = f"Bearer {token}"
        return token

    def _ensure_token(self) -> Optional[str]:
        with self._lock:
            if self._token and time.monotonic() < self._token_expires_at:
                return self._token
        return self._fetch_token()

    # ----- public -----

    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        if not self.configured:
            return SyncResult(provider=self.name, events=[],
                              warnings=["Blackboard not configured"])

        token = self._ensure_token()
        if not token:
            return SyncResult(provider=self.name, events=[],
                              warnings=["Could not obtain Blackboard access token"])

        events: List[NormalizedEvent] = []
        warnings: List[str] = []

        try:
            events.extend(self._pull_announcements(limit=limit))
        except HTTPError as e:
            warnings.append(f"announcements failed: {e}")

        next_cursor = events[-1].provider_event_id if events else None
        return SyncResult(
            provider=self.name,
            events=events,
            next_cursor=next_cursor,
            warnings=warnings,
        )

    def _pull_announcements(self, limit: int) -> List[NormalizedEvent]:
        _, body = self._http.get(
            "/learn/api/public/v1/announcements",
            params={"limit": min(limit, 100)},
        )
        items = body.get("results", []) if isinstance(body, dict) else []
        out: List[NormalizedEvent] = []
        for item in items[:limit]:
            body_obj = item.get("body") or {}
            msg = (
                body_obj.get("rawText")
                or body_obj.get("plainText")
                or item.get("title")
                or ""
            ).strip()
            if not msg:
                continue
            out.append(NormalizedEvent(
                provider_event_id=str(item.get("id") or ""),
                message=msg,
                source="blackboard:announcement",
                event_type="announcement",
                user_id=str(item.get("creator") or ""),
                email=None,
                language="en",
                created_at=item.get("created") or item.get("availability", {}).get("start"),
                extra={"title": item.get("title")},
            ))
        return out
