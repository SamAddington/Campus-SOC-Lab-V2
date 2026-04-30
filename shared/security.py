from __future__ import annotations

import base64
import json
import hashlib
import hmac
import os
import time
from typing import Any, Callable, Dict, Optional, Sequence

from fastapi import Header, HTTPException
import requests

try:
    from jose import jwt as jose_jwt
except Exception:
    jose_jwt = None


_DEFAULT_DEV_KEY = "change-me-dev-api-key"
_API_KEY = os.getenv("SOC_API_KEY", _DEFAULT_DEV_KEY)

# Optional JWT (HS256) bearer authentication.
# This is a pragmatic step toward commercial-grade auth (OIDC/JWT + RBAC),
# while keeping workshop-friendly API key compatibility.
_JWT_SECRET = (os.getenv("SOC_JWT_SECRET") or "").strip()
_JWT_ISSUER = (os.getenv("SOC_JWT_ISSUER") or "").strip()
_JWT_AUDIENCE = (os.getenv("SOC_JWT_AUDIENCE") or "").strip()
_OIDC_JWKS_URL = (os.getenv("SOC_OIDC_JWKS_URL") or "").strip()
_JWT_TENANT_CLAIM = (os.getenv("SOC_JWT_TENANT_CLAIM") or "tenant").strip() or "tenant"

_JWKS_CACHE: Dict[str, Any] = {"fetched_at": 0, "jwks": None}
_JWKS_TTL_SECONDS = 300


def auth_enabled() -> bool:
    return _API_KEY != _DEFAULT_DEV_KEY


def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8"))


def _jwt_verify_hs256(token: str) -> Optional[Dict[str, Any]]:
    """Verify a compact JWT with HS256 and basic claims.

    Returns the decoded payload dict if valid, otherwise None.
    """
    if not _JWT_SECRET:
        return None
    parts = (token or "").split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    if header.get("alg") != "HS256":
        return None

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(_JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
    if not hmac.compare_digest(str(sig_b64), str(expected)):
        return None

    if not _claims_ok(payload):
        return None
    return payload


def _jwks_get() -> Optional[Dict[str, Any]]:
    if not _OIDC_JWKS_URL:
        return None
    now = int(time.time())
    if _JWKS_CACHE.get("jwks") is not None and (now - int(_JWKS_CACHE.get("fetched_at") or 0)) < _JWKS_TTL_SECONDS:
        v = _JWKS_CACHE.get("jwks")
        return v if isinstance(v, dict) else None
    try:
        resp = requests.get(_OIDC_JWKS_URL, timeout=5)
        if not resp.ok:
            return None
        data = resp.json()
        if not isinstance(data, dict) or "keys" not in data:
            return None
        _JWKS_CACHE["jwks"] = data
        _JWKS_CACHE["fetched_at"] = now
        return data
    except Exception:
        return None


def _jwt_verify_oidc(token: str) -> Optional[Dict[str, Any]]:
    """Verify JWT using OIDC JWKS via python-jose."""
    if not _OIDC_JWKS_URL or jose_jwt is None:
        return None
    jwks = _jwks_get()
    if not jwks:
        return None
    try:
        opts = {"verify_aud": bool(_JWT_AUDIENCE)}
        payload = jose_jwt.decode(
            token,
            jwks,
            options=opts,
            audience=_JWT_AUDIENCE or None,
            issuer=_JWT_ISSUER or None,
        )
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def _claims_ok(payload: Dict[str, Any]) -> bool:
    now = int(time.time())
    exp = _safe_int(payload.get("exp"))
    nbf = _safe_int(payload.get("nbf"))
    if exp is not None and now >= exp:
        return False
    if nbf is not None and now < nbf:
        return False
    if _JWT_ISSUER and payload.get("iss") != _JWT_ISSUER:
        return False
    if _JWT_AUDIENCE and not _aud_ok(payload.get("aud")):
        return False
    return True


def _safe_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except Exception:
        return None


def _aud_ok(aud: Any) -> bool:
    if isinstance(aud, str):
        return aud == _JWT_AUDIENCE
    if isinstance(aud, list):
        try:
            return _JWT_AUDIENCE in aud
        except Exception:
            return False
    return False


def _principal_from_api_key(supplied: str) -> Optional[Dict[str, Any]]:
    if not supplied:
        return None
    if not hmac.compare_digest(str(supplied), str(_API_KEY)):
        return None
    # API key is a shared secret — treat it as admin-equivalent for workshop ops.
    return {"sub": "api_key", "roles": ["admin"], "auth": "api_key"}


def _tenant_from_claims(payload: Dict[str, Any]) -> Optional[str]:
    """Resolve tenant string from common JWT claim shapes."""
    tc = _JWT_TENANT_CLAIM
    v = payload.get(tc)
    if v is not None and str(v).strip():
        return str(v).strip()
    for k in ("tenant_id", "tid", "org_id", "organization_id"):
        v2 = payload.get(k)
        if v2 is not None and str(v2).strip():
            return str(v2).strip()
    return None


def _principal_from_bearer(authorization: Optional[str]) -> Optional[Dict[str, Any]]:
    if not authorization:
        return None
    if not authorization.lower().startswith("bearer "):
        return None
    token = authorization[7:].strip()
    payload = _jwt_verify_oidc(token) or _jwt_verify_hs256(token)
    if payload is None:
        # Backwards compatibility: allow Bearer <SOC_API_KEY> deployments.
        return _principal_from_api_key(token)
    roles = payload.get("roles") or payload.get("role") or []
    if isinstance(roles, str):
        roles = [roles]
    if not isinstance(roles, list):
        roles = []
    roles = [str(r).strip() for r in roles if str(r).strip()]
    tenant = _tenant_from_claims(payload)
    out: Dict[str, Any] = {"sub": payload.get("sub") or "unknown", "roles": roles, "auth": "jwt", "claims": payload}
    if tenant:
        out["tenant"] = tenant
    return out


def try_get_principal(
    *,
    x_api_key: Optional[str],
    authorization: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Return principal if credentials are valid; otherwise None (no exception)."""
    p = _principal_from_bearer(authorization)
    if p is None and x_api_key:
        p = _principal_from_api_key(x_api_key)
    return p


def get_principal(
    *,
    x_api_key: Optional[str],
    authorization: Optional[str],
) -> Dict[str, Any]:
    """Return authenticated principal or raise 401/403."""
    p = try_get_principal(x_api_key=x_api_key, authorization=authorization)
    if p is None:
        raise HTTPException(status_code=401, detail="Missing API credentials.")
    return p


def require_api_key(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> None:
    """Enforce API authentication with either X-API-Key or Bearer token.

    This lightweight control provides a zero-trust baseline for service APIs.
    In production, prefer OIDC/JWT + RBAC and secret store integration.
    """
    _ = get_principal(x_api_key=x_api_key, authorization=authorization)


def require_roles(*allowed_roles: str) -> Callable[..., Dict[str, Any]]:
    """FastAPI dependency factory enforcing role membership.

    Roles come from JWT `roles` (or `role`) claim; API key auth maps to admin.
    """
    allowed = {str(r).strip().lower() for r in allowed_roles if str(r).strip()}

    def _dep(
        x_api_key: Optional[str] = Header(default=None),
        authorization: Optional[str] = Header(default=None),
    ) -> Dict[str, Any]:
        p = get_principal(x_api_key=x_api_key, authorization=authorization)
        roles = [str(r).strip().lower() for r in (p.get("roles") or [])]
        if allowed and not (set(roles) & allowed):
            raise HTTPException(status_code=403, detail="Insufficient role.")
        return p

    return _dep


def record_signature(signing_key: str, payload: str) -> str:
    return hmac.new(signing_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
