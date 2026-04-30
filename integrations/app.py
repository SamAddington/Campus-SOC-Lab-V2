"""Integrations service: pulls events from LMS platforms and forwards them
to the collector using the existing ``/ingest`` contract.

Public endpoints
----------------
GET  /health                 service + HMAC + provider status
GET  /providers              per-provider status (no secrets)
GET  /sources                the allowlisted paths / functions per provider
POST /sync/{provider}        pull recent events once and forward to collector
POST /webhook/{provider}     receive push notifications (best-effort)
GET  /status                 aggregated sync state per provider
GET  /state/{provider}       raw state file for one provider
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

import requests
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from adapters import to_collector_payload
from config import ServiceConfig, hmac_is_keyed, load_config, redact_provider
from providers import PROVIDER_REGISTRY, LMSProvider
from rate_limiter import limiter
import state as state_store
import sys
sys.path.insert(0, "/app")
from shared.security import require_api_key

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("integrations")

app = FastAPI(title="WiCyS Integrations", version="0.1.0")

_CFG: ServiceConfig = load_config()
_PROVIDERS: Dict[str, LMSProvider] = {
    name: cls(_CFG.providers[name])
    for name, cls in PROVIDER_REGISTRY.items()
    if name in _CFG.providers
}


class SyncRequest(BaseModel):
    since: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=200)
    dry_run: bool = False


class SyncResponse(BaseModel):
    provider: str
    configured: bool
    requested_limit: int
    pulled: int
    forwarded: int
    failed: int
    warnings: List[str] = []
    dry_run: bool = False
    first_sample: Optional[Dict[str, Any]] = None


# --- Helpers ---------------------------------------------------------------


def _get_provider(name: str) -> LMSProvider:
    prov = _PROVIDERS.get(name)
    if prov is None:
        raise HTTPException(status_code=404, detail=f"Unknown provider {name!r}")
    return prov


def _forward_to_collector(payload: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{_CFG.collector_url}/ingest"
    resp = requests.post(
        url,
        json=payload,
        timeout=30,
        headers={"X-API-Key": _CFG.api_key},
    )
    try:
        body = resp.json()
    except Exception:
        body = {"detail": resp.text}
    if not resp.ok:
        raise HTTPException(status_code=502, detail={"collector_status": resp.status_code, "body": body})
    return body


# --- Endpoints -------------------------------------------------------------


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "up",
        "hmac_keyed": hmac_is_keyed(_CFG),
        "providers_configured": {
            name: prov.configured for name, prov in _PROVIDERS.items()
        },
        "rate_limits": limiter.describe(),
    }


@app.get("/providers")
def providers(_: None = Depends(require_api_key)) -> Dict[str, Any]:
    return {
        "count": len(_CFG.providers),
        "items": [redact_provider(p) for p in _CFG.providers.values()],
    }


@app.get("/sources")
def sources(_: None = Depends(require_api_key)) -> Dict[str, Any]:
    return {
        "scopes_path": str(_CFG.scopes_path),
        "items": [
            {
                "name": p.name,
                "base_url": p.base_url,
                "allowed_paths": p.allowed_paths,
                "allowed_wsfunctions": p.allowed_wsfunctions,
                "description": p.description,
            }
            for p in _CFG.providers.values()
        ],
    }


@app.get("/status")
def status(_: None = Depends(require_api_key)) -> Dict[str, Any]:
    return {
        "providers": {
            name: state_store.load(_CFG.state_dir, name) for name in _PROVIDERS
        }
    }


@app.get("/state/{provider}")
def state(provider: str, _: None = Depends(require_api_key)) -> Dict[str, Any]:
    _get_provider(provider)
    return state_store.load(_CFG.state_dir, provider)


@app.post("/sync/{provider}", response_model=SyncResponse)
def sync(provider: str, req: SyncRequest, _: None = Depends(require_api_key)) -> SyncResponse:
    prov = _get_provider(provider)

    if not prov.configured:
        state_store.record_sync(
            _CFG.state_dir, provider, ingested=0, last_event_id=None,
            error="provider not configured",
        )
        return SyncResponse(
            provider=provider,
            configured=False,
            requested_limit=req.limit,
            pulled=0,
            forwarded=0,
            failed=0,
            warnings=["provider not configured"],
            dry_run=req.dry_run,
        )

    try:
        result = prov.sync(since=req.since, limit=req.limit)
    except Exception as e:
        log.exception("Provider %s sync failed", provider)
        state_store.record_sync(
            _CFG.state_dir, provider, ingested=0, last_event_id=None,
            error=f"sync_exception: {e.__class__.__name__}",
        )
        raise HTTPException(status_code=502, detail=f"provider sync failed: {e}") from e

    pulled = len(result.events)
    forwarded = 0
    failed = 0
    sample: Optional[Dict[str, Any]] = None

    for ev in result.events:
        payload = to_collector_payload(ev, hmac_secret=_CFG.hmac_secret)
        if sample is None:
            # First-sample preview shows exactly what we would send. No
            # raw identifiers survive to_collector_payload, so this is
            # safe to show to an operator.
            sample = payload
        if req.dry_run:
            continue
        try:
            _forward_to_collector(payload)
            forwarded += 1
        except HTTPException as http_err:
            failed += 1
            log.warning("collector forward failed for %s event %s: %s",
                        provider, ev.provider_event_id, http_err.detail)
        except Exception as e:
            failed += 1
            log.warning("collector forward raised for %s event %s: %s",
                        provider, ev.provider_event_id, e)

    state_store.record_sync(
        _CFG.state_dir,
        provider,
        ingested=forwarded,
        last_event_id=result.next_cursor,
        error=None if not result.warnings else "; ".join(result.warnings[:3]),
    )

    return SyncResponse(
        provider=provider,
        configured=True,
        requested_limit=req.limit,
        pulled=pulled,
        forwarded=forwarded,
        failed=failed,
        warnings=result.warnings,
        dry_run=req.dry_run,
        first_sample=sample,
    )


@app.post("/webhook/{provider}")
async def webhook(provider: str, request: Request, _: None = Depends(require_api_key)) -> Dict[str, Any]:
    """Receive a push notification from an LMS.

    The default implementation only records the notification and does not
    trust it for content; it is used as a trigger to call ``/sync`` for
    the corresponding provider. This is deliberately conservative: webhook
    bodies from LMS vendors have variable signature-verification support,
    and the workshop stack does not yet ship a signature verifier. Do not
    forward webhook bodies directly to the collector.
    """
    _get_provider(provider)
    try:
        body = await request.json()
    except Exception:
        body = {"raw": (await request.body()).decode("utf-8", errors="replace")}

    notif_id = str(uuid.uuid4())
    log.info("Webhook received for %s id=%s keys=%s",
             provider, notif_id, list(body.keys()) if isinstance(body, dict) else "raw")

    return {
        "status": "accepted",
        "provider": provider,
        "notification_id": notif_id,
        "note": "Webhook recorded. Call POST /sync/{provider} to actually pull events.",
    }
