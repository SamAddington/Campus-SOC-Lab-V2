from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from adapters import NormalizedEvent
from http_client import HTTPError, ScopedHTTP
from rate_limiter import limiter

from .base import LMSProvider, SyncResult

log = logging.getLogger("restconf")


class RESTCONFProvider(LMSProvider):
    """Generic RESTCONF connector (read-only).

    This provider is intentionally narrow: it only GETs a single configured model
    resource under `/restconf/data/{model}` and emits a summarized event.
    """

    name = "restconf"

    def __init__(self, cfg):
        super().__init__(cfg)
        limiter.configure("restconf", capacity=5, refill_per_sec=0.5)
        self._http = ScopedHTTP(
            provider="restconf",
            base_url=self.cfg.base_url or "",
            allowed_paths=self.cfg.allowed_paths,
        )
        token = self.cfg.raw.get("RESTCONF_BEARER_TOKEN") or os.getenv("RESTCONF_BEARER_TOKEN", "")
        if token:
            self._http.session.headers["Authorization"] = f"Bearer {token}"
        self._http.session.headers.setdefault("Accept", "application/yang-data+json, application/json")
        self.model = os.getenv("RESTCONF_MODEL", "ietf-interfaces:interfaces").strip()

    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        if not self.configured:
            return SyncResult(provider=self.name, events=[], warnings=["RESTCONF not configured"])

        warnings: List[str] = []
        events: List[NormalizedEvent] = []

        # Allowed paths restrict to a single segment placeholder, so `model` must
        # not contain slashes. Enforce locally as a governance boundary.
        if "/" in self.model:
            return SyncResult(provider=self.name, events=[], warnings=["RESTCONF_MODEL must not contain '/'"])

        try:
            _, body = self._http.get(f"/restconf/data/{self.model}", timeout=30)
        except HTTPError as e:
            warnings.append(f"RESTCONF get failed: {e}")
            return SyncResult(provider=self.name, events=[], warnings=warnings)

        summary = _summarize(body)
        events.append(
            NormalizedEvent(
                provider_event_id=self.model,
                message=f"RESTCONF snapshot model={self.model} {summary}",
                source="restconf:snapshot",
                event_type="snapshot",
                user_id="",
                email="",
                language="en",
                created_at=None,
            )
        )
        return SyncResult(provider=self.name, events=events, next_cursor=None, warnings=warnings)


def _summarize(body: Any) -> str:
    if isinstance(body, dict):
        keys = list(body.keys())[:10]
        return f"keys={keys}"
    if isinstance(body, list):
        return f"items={len(body)}"
    if isinstance(body, str):
        return f"len={len(body)}"
    return f"type={type(body).__name__}"

