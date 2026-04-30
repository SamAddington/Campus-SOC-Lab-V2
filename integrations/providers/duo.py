from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse

from adapters import NormalizedEvent
from http_client import HTTPError, ScopedHTTP
from rate_limiter import limiter

from .base import LMSProvider, SyncResult

log = logging.getLogger("duo")


def _rfc2822_date() -> str:
    return time.strftime("%a, %d %b %Y %H:%M:%S -0000", time.gmtime())


def _duo_canon_params(params: Dict[str, Any]) -> str:
    # Duo canonical query string sorts by key and value, URL encoded.
    items: List[tuple[str, str]] = []
    for k, v in (params or {}).items():
        if v is None:
            continue
        if isinstance(v, list):
            for vv in v:
                items.append((str(k), str(vv)))
        else:
            items.append((str(k), str(v)))
    items.sort(key=lambda kv: (kv[0], kv[1]))
    return urlencode(items, doseq=True)


def _duo_sign(ikey: str, skey: str, method: str, host: str, path: str, params: Dict[str, Any], date: str) -> str:
    canon = "\n".join(
        [
            date,
            method.upper(),
            host.lower(),
            path,
            _duo_canon_params(params),
        ]
    )
    sig = hmac.new(skey.encode("utf-8"), canon.encode("utf-8"), hashlib.sha1).hexdigest()
    auth = f"{ikey}:{sig}"
    return base64.b64encode(auth.encode("utf-8")).decode("ascii")


class DuoProvider(LMSProvider):
    """Cisco Duo Admin API connector (read-only)."""

    name = "duo"

    def __init__(self, cfg):
        super().__init__(cfg)
        limiter.configure("duo", capacity=5, refill_per_sec=1.0)
        self._http = ScopedHTTP(
            provider="duo",
            base_url=self.cfg.base_url or "",
            allowed_paths=self.cfg.allowed_paths,
        )
        self.ikey = self.cfg.raw.get("DUO_IKEY") or os.getenv("DUO_IKEY", "")
        self.skey = self.cfg.raw.get("DUO_SKEY") or os.getenv("DUO_SKEY", "")

        parsed = urlparse(self.cfg.base_url or "")
        self._host = parsed.netloc

    def _signed_get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        date = _rfc2822_date()
        p = dict(params or {})
        sig = _duo_sign(self.ikey, self.skey, "GET", self._host, path, p, date)
        headers = {
            "Date": date,
            "Authorization": f"Basic {sig}",
        }
        _, body = self._http.get(path, params=p, headers=headers, timeout=20)
        return body

    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        if not self.configured:
            return SyncResult(provider=self.name, events=[], warnings=["Duo not configured"])
        if not self._host:
            return SyncResult(provider=self.name, events=[], warnings=["DUO_BASE_URL missing host"])

        warnings: List[str] = []
        events: List[NormalizedEvent] = []

        mint = int(os.getenv("DUO_MINTIME_EPOCH", "0") or "0")
        params: Dict[str, Any] = {"limit": min(limit, 1000)}
        # Duo supports min_time in epoch seconds; treat since as epoch if provided.
        if since:
            try:
                params["mintime"] = int(float(since))
            except Exception:
                params["mintime"] = mint
        elif mint:
            params["mintime"] = mint

        # Authentication logs
        try:
            body = self._signed_get("/admin/v2/logs/authentication", params=params)
            items = body.get("authlogs", []) if isinstance(body, dict) else []
            for item in items[:limit]:
                if not isinstance(item, dict):
                    continue
                msg = _format_duo_auth(item)
                if not msg:
                    continue
                ts = item.get("timestamp") or item.get("ts")
                events.append(
                    NormalizedEvent(
                        provider_event_id=str(item.get("txid") or item.get("event_id") or ts or ""),
                        message=msg,
                        source="duo:auth",
                        event_type="authentication",
                        user_id=str(item.get("user") or item.get("username") or ""),
                        email=str(item.get("email") or ""),
                        language="en",
                        created_at=str(ts) if ts is not None else None,
                    )
                )
        except HTTPError as e:
            warnings.append(f"auth logs failed: {e}")

        # Administration logs (optional)
        if os.getenv("DUO_INCLUDE_ADMIN_LOGS", "0") == "1":
            try:
                body = self._signed_get("/admin/v2/logs/administration", params=params)
                items = body.get("administration_logs", []) if isinstance(body, dict) else []
                for item in items[: max(0, limit - len(events))]:
                    if not isinstance(item, dict):
                        continue
                    msg = _format_duo_admin(item)
                    if not msg:
                        continue
                    ts = item.get("timestamp") or item.get("ts")
                    events.append(
                        NormalizedEvent(
                            provider_event_id=str(item.get("txid") or item.get("event_id") or ts or ""),
                            message=msg,
                            source="duo:admin",
                            event_type="administration",
                            user_id=str(item.get("admin") or ""),
                            email="",
                            language="en",
                            created_at=str(ts) if ts is not None else None,
                        )
                    )
            except HTTPError as e:
                warnings.append(f"admin logs failed: {e}")

        next_cursor = None
        # Best-effort: use max timestamp seen if any.
        for ev in reversed(events):
            if ev.created_at:
                next_cursor = ev.created_at
                break
        return SyncResult(provider=self.name, events=events, next_cursor=next_cursor, warnings=warnings)


def _format_duo_auth(item: Dict[str, Any]) -> str:
    user = item.get("user") or item.get("username") or ""
    factor = item.get("factor") or ""
    result = item.get("result") or ""
    ip = item.get("ip") or item.get("access_device", {}).get("ip") or ""
    device = item.get("access_device", {}).get("hostname") or ""
    parts = [p for p in [f"user={user}", f"result={result}", f"factor={factor}", f"ip={ip}", f"device={device}"] if p and p != "user="]
    return "Duo auth " + " ".join(parts) if parts else ""


def _format_duo_admin(item: Dict[str, Any]) -> str:
    action = item.get("action") or item.get("description") or ""
    admin = item.get("admin") or ""
    obj = item.get("object") or ""
    if not (action or admin or obj):
        return ""
    parts = [p for p in [f"admin={admin}", f"action={action}", f"object={obj}"] if p]
    return "Duo admin " + " ".join(parts)

