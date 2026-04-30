"""D2L Brightspace (Valence) provider.

Uses OAuth2 with a refresh-token flow. Credentials:
``BRIGHTSPACE_BASE_URL``, ``BRIGHTSPACE_CLIENT_ID``,
``BRIGHTSPACE_CLIENT_SECRET``, ``BRIGHTSPACE_REFRESH_TOKEN``. The refresh
token is rotated by Brightspace on every refresh; we persist the new one
to our per-provider state file so a restart does not invalidate access.
"""

from __future__ import annotations

import base64
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from adapters import NormalizedEvent
from http_client import HTTPError, ScopedHTTP
from rate_limiter import limiter

from .base import LMSProvider, SyncResult

log = logging.getLogger("brightspace")

_TOKEN_HOST = "https://auth.brightspace.com"
_TOKEN_PATH = "/core/connect/token"


class BrightspaceProvider(LMSProvider):
    name = "brightspace"

    def __init__(self, cfg):
        super().__init__(cfg)
        limiter.configure("brightspace", capacity=5, refill_per_sec=1.0)

        self._http = ScopedHTTP(
            provider="brightspace",
            base_url=self.cfg.base_url or "",
            allowed_paths=self.cfg.allowed_paths,
        )

        self._access_token: Optional[str] = None
        self._expires_at: float = 0.0
        self._lock = threading.Lock()

        self.api_version = os.getenv("BRIGHTSPACE_API_VERSION", "1.26")
        self.org_unit_id = os.getenv("BRIGHTSPACE_ORG_UNIT_ID", "")

        # State path for refresh-token rotation.
        state_dir = Path(os.getenv("INTEGRATION_STATE_DIR", "/app/integration_state"))
        state_dir.mkdir(parents=True, exist_ok=True)
        self._refresh_path = state_dir / "brightspace_refresh.txt"
        self._refresh_token = self._load_refresh_token()

    # ----- token handling -----

    def _load_refresh_token(self) -> str:
        try:
            if self._refresh_path.exists():
                return self._refresh_path.read_text(encoding="utf-8").strip()
        except Exception:
            pass
        return self.cfg.raw.get("BRIGHTSPACE_REFRESH_TOKEN", "")

    def _save_refresh_token(self, token: str) -> None:
        try:
            self._refresh_path.write_text(token, encoding="utf-8")
        except Exception as e:
            log.warning("Could not persist Brightspace refresh token: %s", e)

    def _fetch_access_token(self) -> Optional[str]:
        if not self.configured or not self._refresh_token:
            return None

        client_id = self.cfg.raw.get("BRIGHTSPACE_CLIENT_ID", "")
        client_secret = self.cfg.raw.get("BRIGHTSPACE_CLIENT_SECRET", "")
        basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")

        # NOTE: the token host is distinct from the Brightspace API host, so
        # we use a bare requests call here rather than ScopedHTTP (whose
        # allowlist is keyed to the API host).
        try:
            resp = requests.post(
                f"{_TOKEN_HOST}{_TOKEN_PATH}",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self._refresh_token,
                    "scope": os.getenv("BRIGHTSPACE_SCOPE", "core:*:*"),
                },
                headers={
                    "Authorization": f"Basic {basic}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=20,
            )
        except requests.RequestException as e:
            log.warning("Brightspace token refresh failed: %s", e)
            return None

        if not resp.ok:
            log.warning("Brightspace token refresh HTTP %s: %s",
                        resp.status_code, resp.text[:200])
            return None

        body = resp.json()
        access_token = body.get("access_token")
        new_refresh = body.get("refresh_token")
        expires_in = int(body.get("expires_in", 3600))

        if not access_token:
            return None

        with self._lock:
            self._access_token = access_token
            self._expires_at = time.monotonic() + max(60, expires_in - 60)
            self._http.session.headers["Authorization"] = f"Bearer {access_token}"
            if new_refresh and new_refresh != self._refresh_token:
                self._refresh_token = new_refresh
                self._save_refresh_token(new_refresh)

        return access_token

    def _ensure_token(self) -> Optional[str]:
        with self._lock:
            if self._access_token and time.monotonic() < self._expires_at:
                return self._access_token
        return self._fetch_access_token()

    # ----- public -----

    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        if not self.configured:
            return SyncResult(provider=self.name, events=[],
                              warnings=["Brightspace not configured"])

        token = self._ensure_token()
        if not token:
            return SyncResult(provider=self.name, events=[],
                              warnings=["Could not obtain Brightspace access token"])

        events: List[NormalizedEvent] = []
        warnings: List[str] = []

        try:
            events.extend(self._pull_feed(limit=limit))
        except HTTPError as e:
            warnings.append(f"feed failed: {e}")

        if self.org_unit_id:
            try:
                events.extend(self._pull_news(limit=limit))
            except HTTPError as e:
                warnings.append(f"news failed: {e}")

        next_cursor = events[-1].provider_event_id if events else None
        return SyncResult(
            provider=self.name,
            events=events,
            next_cursor=next_cursor,
            warnings=warnings,
        )

    def _pull_feed(self, limit: int) -> List[NormalizedEvent]:
        path = f"/d2l/api/lp/{self.api_version}/feed"
        _, body = self._http.get(path, params={"pageSize": min(limit, 50)})
        items = body.get("Objects", []) if isinstance(body, dict) else (body or [])
        out: List[NormalizedEvent] = []
        for item in items[:limit]:
            msg = (item.get("Text") or item.get("Title") or "").strip()
            if not msg:
                continue
            out.append(NormalizedEvent(
                provider_event_id=str(item.get("Id") or ""),
                message=msg,
                source=f"brightspace:{(item.get('Type') or 'feed').lower()}",
                event_type=(item.get("Type") or "feed_item").lower(),
                user_id=str(item.get("SourceUserId") or ""),
                email=None,
                language="en",
                created_at=item.get("DateCreated"),
            ))
        return out

    def _pull_news(self, limit: int) -> List[NormalizedEvent]:
        path = f"/d2l/api/le/{self.api_version}/{self.org_unit_id}/news/"
        _, body = self._http.get(path)
        items = body if isinstance(body, list) else (body or {}).get("Items", [])
        out: List[NormalizedEvent] = []
        for item in items[:limit]:
            msg = (item.get("Body", {}).get("Text") or item.get("Title") or "").strip()
            if not msg:
                continue
            out.append(NormalizedEvent(
                provider_event_id=str(item.get("Id") or ""),
                message=msg,
                source="brightspace:news",
                event_type="news",
                user_id=str(item.get("CreatedBy") or ""),
                email=None,
                language="en",
                created_at=item.get("StartDate") or item.get("CreateDate"),
                extra={"org_unit_id": self.org_unit_id},
            ))
        return out
