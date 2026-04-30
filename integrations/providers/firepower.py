from __future__ import annotations

import base64
import logging
import os
from typing import Any, Dict, List, Optional

import requests

from adapters import NormalizedEvent
from http_client import HTTPError, ScopedHTTP
from rate_limiter import limiter

from .base import LMSProvider, SyncResult

log = logging.getLogger("firepower")


class FirepowerProvider(LMSProvider):
    """Cisco Firepower Management Center (FMC) connector (read-only).

    This connector is deliberately minimal: it obtains a short-lived access
    token and then pulls audit records. FMC tenants vary; scope is enforced
    by `integrations/scopes.yaml`.
    """

    name = "firepower"

    def __init__(self, cfg):
        super().__init__(cfg)
        limiter.configure("firepower", capacity=3, refill_per_sec=0.2)
        self._http = ScopedHTTP(
            provider="firepower",
            base_url=self.cfg.base_url or "",
            allowed_paths=self.cfg.allowed_paths,
        )
        self.user = self.cfg.raw.get("FMC_USERNAME") or os.getenv("FMC_USERNAME", "")
        self.pwd = self.cfg.raw.get("FMC_PASSWORD") or os.getenv("FMC_PASSWORD", "")
        self.domain_uuid = self.cfg.raw.get("FMC_DOMAIN_UUID") or os.getenv("FMC_DOMAIN_UUID", "")
        self._token: Optional[str] = None

    def _fetch_token(self) -> Optional[str]:
        if not (self.cfg.base_url and self.user and self.pwd):
            return None
        basic = base64.b64encode(f"{self.user}:{self.pwd}".encode("utf-8")).decode("ascii")
        url = f"{self.cfg.base_url.rstrip('/')}/api/fmc_platform/v1/auth/generatetoken"
        try:
            resp = requests.post(
                url,
                headers={"Authorization": f"Basic {basic}"},
                timeout=20,
                verify=os.getenv("FMC_TLS_VERIFY", "1") == "1",
            )
        except requests.RequestException as e:
            log.warning("FMC token request failed: %s", e)
            return None
        if not resp.ok:
            log.warning("FMC token HTTP %s: %s", resp.status_code, resp.text[:200])
            return None
        token = resp.headers.get("X-auth-access-token") or resp.headers.get("X-auth-access-token".lower())
        self._token = token
        return token

    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        if not self.configured:
            return SyncResult(provider=self.name, events=[], warnings=["Firepower not configured"])

        warnings: List[str] = []
        events: List[NormalizedEvent] = []

        token = self._token or self._fetch_token()
        if not token:
            return SyncResult(provider=self.name, events=[], warnings=["Could not obtain FMC access token"])

        path = f"/api/fmc_config/v1/domain/{self.domain_uuid}/audit/auditrecords"
        params: Dict[str, Any] = {"limit": min(limit, 100)}
        if since:
            params["offset"] = 0

        # Use ScopedHTTP for allowlist/rate-limit but inject our bearer token.
        try:
            _, body = self._http.get(path, params=params, headers={"X-auth-access-token": token}, timeout=30)
        except HTTPError as e:
            warnings.append(f"auditrecords failed: {e}")
            return SyncResult(provider=self.name, events=[], warnings=warnings)

        items = []
        if isinstance(body, dict):
            items = body.get("items", []) or body.get("records", []) or []
        elif isinstance(body, list):
            items = body

        for item in (items or [])[:limit]:
            if not isinstance(item, dict):
                continue
            msg = _format_audit(item)
            if not msg:
                continue
            ev_id = str(item.get("id") or item.get("uuid") or "")
            ts = item.get("timestamp") or item.get("time")
            events.append(
                NormalizedEvent(
                    provider_event_id=ev_id or str(ts or ""),
                    message=msg,
                    source="firepower:audit",
                    event_type="audit",
                    user_id=str(item.get("user") or item.get("username") or ""),
                    email="",
                    language="en",
                    created_at=str(ts) if ts is not None else None,
                )
            )

        next_cursor = events[-1].provider_event_id if events else None
        return SyncResult(provider=self.name, events=events, next_cursor=next_cursor, warnings=warnings)


def _format_audit(item: Dict[str, Any]) -> str:
    user = item.get("user") or item.get("username") or ""
    action = item.get("action") or item.get("eventType") or item.get("type") or ""
    detail = item.get("message") or item.get("detail") or ""
    parts = [p for p in [f"user={user}", f"action={action}", f"detail={detail}"] if p and not p.endswith("=")]
    return "FMC audit " + " ".join(parts) if parts else ""

