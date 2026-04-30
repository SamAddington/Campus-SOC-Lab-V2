"""Moodle Web Services provider.

Moodle exposes every function through a single endpoint
(``/webservice/rest/server.php``) so scope enforcement must also cover the
``wsfunction`` query parameter. The ``extra_validator`` hook on
``ScopedHTTP`` is used for this.

Credentials: ``MOODLE_BASE_URL`` and ``MOODLE_WSTOKEN``. A user id for the
``core_message_get_messages`` call must be provided via
``MOODLE_USER_ID``.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from adapters import NormalizedEvent
from http_client import HTTPError, ScopedHTTP
from rate_limiter import limiter

from .base import LMSProvider, SyncResult

log = logging.getLogger("moodle")

_ENDPOINT = "/webservice/rest/server.php"


class MoodleProvider(LMSProvider):
    name = "moodle"

    def __init__(self, cfg):
        super().__init__(cfg)
        limiter.configure("moodle", capacity=5, refill_per_sec=1.0)

        allowed_ws = set(cfg.allowed_wsfunctions or [])

        def _validate(method: str, path: str,
                      params: Optional[Dict[str, Any]] = None,
                      data: Optional[Dict[str, Any]] = None,
                      json_body: Optional[Dict[str, Any]] = None) -> Optional[str]:
            if path != _ENDPOINT:
                return f"Moodle calls must go through {_ENDPOINT}"
            merged = dict(params or {})
            if data:
                merged.update(data)
            wsfn = merged.get("wsfunction")
            if not wsfn:
                return "missing wsfunction parameter"
            if wsfn not in allowed_ws:
                return f"wsfunction {wsfn!r} not in allowlist"
            return None

        self._http = ScopedHTTP(
            provider="moodle",
            base_url=self.cfg.base_url or "",
            allowed_paths=[_ENDPOINT],
            extra_validator=_validate,
        )

        self.user_id = os.getenv("MOODLE_USER_ID", "0")
        self.forum_id = os.getenv("MOODLE_FORUM_ID", "")

    # ----- public -----

    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        if not self.configured:
            return SyncResult(provider=self.name, events=[],
                              warnings=["Moodle not configured"])

        events: List[NormalizedEvent] = []
        warnings: List[str] = []

        # Auth sanity check (verifies token); does not emit events.
        try:
            self._call("core_webservice_get_site_info", {})
        except HTTPError as e:
            return SyncResult(provider=self.name, events=[],
                              warnings=[f"Moodle auth check failed: {e}"])

        try:
            events.extend(self._pull_messages(limit=limit))
        except HTTPError as e:
            warnings.append(f"messages failed: {e}")

        if self.forum_id:
            try:
                events.extend(self._pull_forum(limit=limit))
            except HTTPError as e:
                warnings.append(f"forum failed: {e}")

        next_cursor = events[-1].provider_event_id if events else None
        return SyncResult(
            provider=self.name,
            events=events,
            next_cursor=next_cursor,
            warnings=warnings,
        )

    # ----- internals -----

    def _call(self, wsfunction: str, extra: Dict[str, Any]) -> Any:
        token = self.cfg.raw.get("MOODLE_WSTOKEN", "")
        params: Dict[str, Any] = {
            "wstoken": token,
            "wsfunction": wsfunction,
            "moodlewsrestformat": "json",
        }
        params.update(extra)
        _, body = self._http.get(_ENDPOINT, params=params)
        if isinstance(body, dict) and body.get("exception"):
            raise HTTPError(
                status_code=400,
                message=f"Moodle error: {body.get('errorcode')} {body.get('message')}",
                body=body,
            )
        return body

    def _pull_messages(self, limit: int) -> List[NormalizedEvent]:
        body = self._call("core_message_get_messages", {
            "useridto": self.user_id,
            "type": "conversations",
            "read": 0,
            "limitnum": min(limit, 50),
        })
        items = (body or {}).get("messages", []) if isinstance(body, dict) else []
        out: List[NormalizedEvent] = []
        for item in items[:limit]:
            msg = (item.get("text") or item.get("fullmessage") or item.get("smallmessage") or "").strip()
            if not msg:
                continue
            out.append(NormalizedEvent(
                provider_event_id=str(item.get("id") or ""),
                message=msg,
                source="moodle:message",
                event_type="message",
                user_id=str(item.get("useridfrom") or ""),
                email=None,
                language="en",
                created_at=str(item.get("timecreated") or ""),
                extra={"subject": item.get("subject")},
            ))
        return out

    def _pull_forum(self, limit: int) -> List[NormalizedEvent]:
        body = self._call("mod_forum_get_forum_discussions", {
            "forumid": self.forum_id,
            "perpage": min(limit, 50),
        })
        items = (body or {}).get("discussions", []) if isinstance(body, dict) else []
        out: List[NormalizedEvent] = []
        for item in items[:limit]:
            msg = (item.get("message") or item.get("name") or "").strip()
            if not msg:
                continue
            out.append(NormalizedEvent(
                provider_event_id=str(item.get("discussion") or item.get("id") or ""),
                message=msg,
                source="moodle:forum_discussion",
                event_type="discussion_post",
                user_id=str(item.get("userid") or ""),
                email=None,
                language="en",
                created_at=str(item.get("created") or ""),
                extra={"forum_id": self.forum_id, "subject": item.get("subject")},
            ))
        return out
