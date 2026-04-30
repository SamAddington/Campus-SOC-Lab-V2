"""Canvas LMS provider.

Uses Canvas REST API v1 with a Bearer token. Credentials come from
``CANVAS_BASE_URL`` and ``CANVAS_API_TOKEN``.

We pull three read-only streams:

- ``/api/v1/users/self/activity_stream`` -- the authenticated user's
  unified activity stream (announcements, conversations, discussions).
- ``/api/v1/announcements`` -- global / course announcements.
- ``/api/v1/conversations`` -- the user's inbox messages.

None of these can be used to read grades, submissions, quizzes, or
assignment content.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from adapters import NormalizedEvent
from http_client import HTTPError, ScopedHTTP
from rate_limiter import limiter

from .base import LMSProvider, SyncResult

log = logging.getLogger("canvas")


def _language_hint(locale: Optional[str]) -> str:
    if not locale:
        return "en"
    return str(locale).split("-", 1)[0].lower() or "en"


class CanvasProvider(LMSProvider):
    name = "canvas"

    def __init__(self, cfg):
        super().__init__(cfg)
        # Canvas default: 3000 requests / hour per token ~= 0.83/sec.
        limiter.configure("canvas", capacity=5, refill_per_sec=0.83)

        headers = {}
        token = self.cfg.raw.get("CANVAS_API_TOKEN") or ""
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._http = ScopedHTTP(
            provider="canvas",
            base_url=self.cfg.base_url or "",
            allowed_paths=self.cfg.allowed_paths,
        )
        self._http.session.headers.update(headers)

        self.include_conversations = os.getenv("CANVAS_INCLUDE_CONVERSATIONS", "1") == "1"
        self.include_announcements = os.getenv("CANVAS_INCLUDE_ANNOUNCEMENTS", "1") == "1"

    # ----- public -----

    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        if not self.configured:
            return SyncResult(provider=self.name, events=[],
                              warnings=["Canvas not configured"])

        events: List[NormalizedEvent] = []
        warnings: List[str] = []

        try:
            events.extend(self._pull_activity_stream(limit=limit))
        except HTTPError as e:
            warnings.append(f"activity_stream failed: {e}")

        if self.include_announcements:
            try:
                events.extend(self._pull_announcements(limit=limit))
            except HTTPError as e:
                warnings.append(f"announcements failed: {e}")

        if self.include_conversations:
            try:
                events.extend(self._pull_conversations(limit=limit))
            except HTTPError as e:
                warnings.append(f"conversations failed: {e}")

        next_cursor = events[-1].provider_event_id if events else None
        return SyncResult(
            provider=self.name,
            events=events,
            next_cursor=next_cursor,
            warnings=warnings,
        )

    # ----- internal pullers -----

    def _pull_activity_stream(self, limit: int) -> List[NormalizedEvent]:
        _, body = self._http.get(
            "/api/v1/users/self/activity_stream",
            params={"per_page": min(limit, 50)},
        )
        items = body if isinstance(body, list) else body.get("items", [])
        out: List[NormalizedEvent] = []
        for item in items[:limit]:
            msg = (item.get("message") or item.get("title") or "").strip()
            if not msg:
                continue
            item_type = (item.get("type") or "stream_item").lower()
            out.append(NormalizedEvent(
                provider_event_id=str(item.get("id") or item.get("stream_item_id") or ""),
                message=msg,
                source=f"canvas:{item_type}",
                event_type=item_type,
                user_id=str(item.get("user_id") or item.get("author_id") or ""),
                email=item.get("author_email") or None,
                language=_language_hint(item.get("locale")),
                created_at=item.get("created_at"),
                extra={"canvas_course_id": item.get("course_id")},
            ))
        return out

    def _pull_announcements(self, limit: int) -> List[NormalizedEvent]:
        # ``context_codes[]`` is required by Canvas. Operators provide a
        # comma-separated list via CANVAS_ANNOUNCEMENT_CONTEXTS, e.g.
        # "course_1234,course_5678". Skip if unset.
        contexts_raw = os.getenv("CANVAS_ANNOUNCEMENT_CONTEXTS", "").strip()
        if not contexts_raw:
            return []
        contexts = [c.strip() for c in contexts_raw.split(",") if c.strip()]
        params: Dict[str, Any] = {
            "per_page": min(limit, 50),
            "context_codes[]": contexts,
        }
        _, body = self._http.get("/api/v1/announcements", params=params)
        items = body if isinstance(body, list) else []
        out: List[NormalizedEvent] = []
        for item in items[:limit]:
            msg = (item.get("message") or item.get("title") or "").strip()
            if not msg:
                continue
            out.append(NormalizedEvent(
                provider_event_id=str(item.get("id") or ""),
                message=msg,
                source="canvas:announcement",
                event_type="announcement",
                user_id=str(item.get("author", {}).get("id") or ""),
                email=None,  # announcements do not expose author email
                language="en",
                created_at=item.get("posted_at") or item.get("created_at"),
                extra={"canvas_context": item.get("context_code")},
            ))
        return out

    def _pull_conversations(self, limit: int) -> List[NormalizedEvent]:
        _, body = self._http.get(
            "/api/v1/conversations",
            params={"per_page": min(limit, 50), "scope": "inbox"},
        )
        items = body if isinstance(body, list) else []
        out: List[NormalizedEvent] = []
        for item in items[:limit]:
            msg = (item.get("last_message") or item.get("subject") or "").strip()
            if not msg:
                continue
            out.append(NormalizedEvent(
                provider_event_id=str(item.get("id") or ""),
                message=msg,
                source="canvas:conversation",
                event_type="conversation",
                user_id=str(item.get("last_author_id") or ""),
                email=None,
                language="en",
                created_at=item.get("last_message_at"),
                extra={"participant_count": item.get("participant_count")},
            ))
        return out
