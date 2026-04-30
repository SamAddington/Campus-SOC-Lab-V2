"""Scope-enforcing HTTP client for OSINT providers.

Mirrors the approach taken by ``integrations/http_client.py``:

- Before any request goes out we check ``(provider, method, path)``
  against ``scopes.yaml``. Anything not explicitly allowed raises.
- The scope check runs on the *path*, not on the caller-supplied full
  URL, so a misconfigured provider cannot stuff a different host into
  the allow check.
- Rate limiting is applied centrally, not by individual provider code.
- Connection errors are surfaced as ``OSINTCallError`` with a short
  message suitable for inclusion in a decision card.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

from config import Config, ProviderConfig
from rate_limiter import RateLimitRegistry


_LOG = logging.getLogger("osint.http_client")


class OSINTCallError(RuntimeError):
    pass


@dataclass
class Response:
    status_code: int
    json: Optional[Any]
    text: str
    elapsed_ms: int

    def ok(self) -> bool:
        return 200 <= self.status_code < 300


class ScopedHTTP:
    def __init__(self, cfg: Config, rate_limits: RateLimitRegistry):
        self._cfg = cfg
        self._rl = rate_limits
        self._session = requests.Session()

    # --- helpers ---------------------------------------------------------

    def _provider(self, name: str) -> ProviderConfig:
        p = self._cfg.providers.get(name)
        if p is None:
            raise OSINTCallError(f"unknown provider: {name}")
        return p

    def _check_scope(self, provider: ProviderConfig, method: str, path: str) -> None:
        method_u = method.upper()
        for rule in provider.allow:
            if str(rule.get("method", "")).upper() != method_u:
                continue
            prefix = str(rule.get("path_prefix", ""))
            if prefix and path.startswith(prefix):
                return
        raise OSINTCallError(
            f"scope violation: provider={provider.name} method={method_u} path={path}"
        )

    # --- public ----------------------------------------------------------

    def request(self, provider_name: str, method: str, path: str, *,
                params: Optional[Dict[str, Any]] = None,
                data: Optional[Dict[str, Any]] = None,
                json_body: Optional[Any] = None,
                headers: Optional[Dict[str, str]] = None) -> Response:
        provider = self._provider(provider_name)
        if not provider.enabled:
            raise OSINTCallError(f"provider disabled: {provider_name}")
        if not provider.base_url:
            raise OSINTCallError(f"provider base_url missing: {provider_name}")

        self._check_scope(provider, method, path)

        # Rate limit *after* scope check so we don't burn tokens on
        # bad requests.
        acquired = self._rl.acquire(
            provider_name, timeout=float(self._cfg.per_provider_timeout)
        )
        if not acquired:
            raise OSINTCallError(f"rate limit wait timeout for provider={provider_name}")

        url = provider.base_url.rstrip("/") + path
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise OSINTCallError(f"invalid url: {url}")

        import time as _time
        start = _time.monotonic()
        try:
            resp = self._session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                json=json_body,
                headers=headers or {},
                timeout=self._cfg.per_provider_timeout,
            )
        except requests.exceptions.RequestException as exc:
            elapsed = int((_time.monotonic() - start) * 1000)
            raise OSINTCallError(f"transport error: {exc}") from None

        elapsed_ms = int((_time.monotonic() - start) * 1000)

        body_json: Optional[Any] = None
        text = resp.text or ""
        try:
            body_json = resp.json()
        except ValueError:
            body_json = None

        return Response(
            status_code=resp.status_code,
            json=body_json,
            text=text,
            elapsed_ms=elapsed_ms,
        )
