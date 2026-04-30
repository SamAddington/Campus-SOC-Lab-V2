"""Scope-enforcing HTTP client for LMS providers.

Every outbound HTTP call MUST go through ``ScopedHTTP``. The client:

1. Rejects any path that does not match the provider's allowlist in
   ``scopes.yaml``.
2. Applies a per-provider token-bucket rate limit.
3. Retries with exponential backoff on 429 / 5xx.
4. Never logs credentials. Headers with Authorization / x-api-key are
   masked before any log line is emitted.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests

from rate_limiter import limiter

log = logging.getLogger("http_client")


class ScopeError(Exception):
    """Raised when a request targets a path outside the allowlist."""


class HTTPError(Exception):
    def __init__(self, status_code: int, message: str, body: Optional[Any] = None):
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.body = body


# --- Scope matching ---------------------------------------------------------

_BRACE_VAR = re.compile(r"\{[^/]+?\}")


def _pattern_to_regex(pattern: str) -> re.Pattern:
    """Convert ``/api/v1/courses/{course_id}/x`` to a regex that matches one
    segment per brace. No wildcards outside braces are allowed."""
    # Escape literal parts, then replace the brace-placeholders.
    parts = _BRACE_VAR.split(pattern)
    escaped = [re.escape(p) for p in parts]
    regex = "[^/]+".join(escaped)
    return re.compile(f"^{regex}$")


def _path_allowed(path: str, allowed: List[str]) -> bool:
    for pat in allowed:
        if _pattern_to_regex(pat).match(path):
            return True
    return False


# --- Scoped session --------------------------------------------------------

_RETRIABLE = {408, 429, 500, 502, 503, 504}
_MAX_RETRIES = 3


@dataclass
class ScopedHTTP:
    provider: str
    base_url: str
    allowed_paths: List[str]
    # ``extra_validator`` runs additional per-request checks (e.g. Moodle
    # must only use approved ``wsfunction`` values). Returns None if OK,
    # or a string reason to reject.
    extra_validator: Optional[Any] = None
    session: requests.Session = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.session is None:
            self.session = requests.Session()

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 20,
    ) -> Tuple[int, Any]:
        if not self.base_url:
            raise HTTPError(0, f"{self.provider} base_url not configured")

        if not _path_allowed(path, self.allowed_paths):
            raise ScopeError(
                f"{self.provider}: path {path!r} not in allowlist "
                f"({len(self.allowed_paths)} allowed paths)"
            )

        if self.extra_validator is not None:
            reason = self.extra_validator(
                method=method, path=path, params=params, data=data, json_body=json_body
            )
            if reason:
                raise ScopeError(f"{self.provider}: {reason}")

        if not limiter.acquire(self.provider, timeout=10.0):
            raise HTTPError(429, f"{self.provider}: rate-limiter timeout")

        url = f"{self.base_url.rstrip('/')}{path}"
        last_exc: Optional[Exception] = None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = self.session.request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    data=data,
                    json=json_body,
                    headers=headers,
                    timeout=timeout,
                )
            except requests.RequestException as e:
                last_exc = e
                log.warning("%s request %s %s failed (attempt %d): %s",
                            self.provider, method, path, attempt + 1, e)
                if attempt < _MAX_RETRIES:
                    time.sleep(2 ** attempt)
                    continue
                raise HTTPError(0, str(e)) from e

            if resp.status_code in _RETRIABLE and attempt < _MAX_RETRIES:
                backoff = 2 ** attempt
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        backoff = max(backoff, float(retry_after))
                    except ValueError:
                        pass
                log.info("%s got %d, retrying in %.1fs",
                         self.provider, resp.status_code, backoff)
                time.sleep(backoff)
                continue

            try:
                body: Any = resp.json()
            except Exception:
                body = resp.text

            if not resp.ok:
                raise HTTPError(resp.status_code, f"{method} {path}", body=body)
            return resp.status_code, body

        raise HTTPError(0, f"exhausted retries: {last_exc}")

    def get(self, path: str, **kw: Any) -> Tuple[int, Any]:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> Tuple[int, Any]:
        return self.request("POST", path, **kw)
