from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware


@dataclass(frozen=True)
class RateLimitConfig:
    # Simple in-memory token bucket (per process).
    requests: int = 120
    per_seconds: int = 60


class _TokenBucket:
    def __init__(self, cfg: RateLimitConfig):
        self.cfg = cfg
        self._state: Dict[str, Dict[str, float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        st = self._state.get(key)
        if not st:
            self._state[key] = {"tokens": float(self.cfg.requests), "ts": now}
            return True
        tokens = float(st.get("tokens", 0.0))
        last = float(st.get("ts", now))
        # Refill
        rate = float(self.cfg.requests) / float(self.cfg.per_seconds)
        tokens = min(float(self.cfg.requests), tokens + (now - last) * rate)
        if tokens < 1.0:
            st["tokens"] = tokens
            st["ts"] = now
            return False
        st["tokens"] = tokens - 1.0
        st["ts"] = now
        return True


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # CSP is intentionally minimal because the console is served via nginx;
        # for API services this is safe and non-breaking.
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        return resp


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI, max_bytes: int):
        super().__init__(app)
        self.max_bytes = int(max_bytes)

    async def dispatch(self, request: Request, call_next: Callable):
        cl = request.headers.get("content-length")
        if cl:
            try:
                if int(cl) > self.max_bytes:
                    raise HTTPException(status_code=413, detail="Request body too large")
            except ValueError:
                pass
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI, cfg: RateLimitConfig):
        super().__init__(app)
        self.bucket = _TokenBucket(cfg)

    async def dispatch(self, request: Request, call_next: Callable):
        # Key by client IP (best-effort behind proxies).
        ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "unknown")
        if not self.bucket.allow(ip):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        return await call_next(request)


def apply_hardening(
    app: FastAPI,
    *,
    max_body_bytes: int = 1_000_000,
    rate_limit: Optional[RateLimitConfig] = None,
) -> None:
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=max_body_bytes)
    if rate_limit is not None:
        app.add_middleware(RateLimitMiddleware, cfg=rate_limit)

