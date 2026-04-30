"""FastAPI application for the OSINT enrichment service.

Endpoints are deliberately narrow:

* ``POST /enrich`` -- caller supplies indicators explicitly. Used by
  tools or the simulator where the indicator list is already known.
* ``POST /enrich_event`` -- caller supplies a message (and optional
  metadata). The service extracts indicators itself, enriches them,
  and returns both the summary and a plain-English explanation. This
  is what the orchestrator calls.
* ``GET /health``, ``GET /status``, ``GET /providers`` -- diagnostics.
* ``GET /cache/stats``, ``POST /cache/clear`` -- cache ops.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

from aggregator import Aggregator
from cache import TTLCache
from config import Config, hmac_is_keyed, load_config
from explainer import explain
from extractors import (
    IndicatorBundle,
    IndicatorKind,
    extract_indicators,
)
from http_client import ScopedHTTP
from providers import build_registry
from rate_limiter import RateLimitRegistry


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
_LOG = logging.getLogger("osint")


CFG: Config = load_config()
CACHE = TTLCache(
    max_entries=CFG.cache_max_entries,
    ttl_clean_seconds=CFG.cache_ttl_clean_seconds,
    ttl_hit_seconds=CFG.cache_ttl_hit_seconds,
)
RATE_LIMITS = RateLimitRegistry()
HTTP = ScopedHTTP(CFG, RATE_LIMITS)
PROVIDERS = build_registry(CFG, HTTP, RATE_LIMITS)
AGGREGATOR = Aggregator(cfg=CFG, providers=PROVIDERS, cache=CACHE)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class EnrichIndicatorList(BaseModel):
    urls: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    ipv4s: List[str] = Field(default_factory=list)
    ipv6s: List[str] = Field(default_factory=list)
    md5s: List[str] = Field(default_factory=list)
    sha1s: List[str] = Field(default_factory=list)
    sha256s: List[str] = Field(default_factory=list)


class EnrichEventIn(BaseModel):
    message: str = ""
    event_type: str = ""
    language: str = "en"
    include_explanation: bool = True
    source: Optional[str] = None


class EnrichExplicitIn(BaseModel):
    indicators: EnrichIndicatorList
    event_type: str = ""
    include_explanation: bool = True


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------


app = FastAPI(title="WiCyS SOC OSINT Enrichment", version="1.0.0")


def _bundle_from_list(lst: EnrichIndicatorList) -> IndicatorBundle:
    return IndicatorBundle(
        urls=list(lst.urls or []),
        domains=list(lst.domains or []),
        ipv4s=list(lst.ipv4s or []),
        ipv6s=list(lst.ipv6s or []),
        md5s=list(lst.md5s or []),
        sha1s=list(lst.sha1s or []),
        sha256s=list(lst.sha256s or []),
    )


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "osint",
        "hmac_keyed": hmac_is_keyed(CFG),
        "providers_enabled": [n for n, p in PROVIDERS.items()],
        "cache_entries": CACHE.stats()["entries"],
    }


@app.get("/status")
def status() -> Dict[str, Any]:
    return {
        "config": {
            "cache_ttl_clean_seconds": CFG.cache_ttl_clean_seconds,
            "cache_ttl_hit_seconds": CFG.cache_ttl_hit_seconds,
            "cache_max_entries": CFG.cache_max_entries,
            "max_urls_per_event": CFG.max_urls_per_event,
            "max_domains_per_event": CFG.max_domains_per_event,
            "max_ips_per_event": CFG.max_ips_per_event,
            "max_hashes_per_event": CFG.max_hashes_per_event,
            "per_provider_timeout": CFG.per_provider_timeout,
            "per_enrichment_deadline": CFG.per_enrichment_deadline,
            "reject_private_ips": CFG.reject_private_ips,
            "scopes_path": CFG.scopes_path,
            "hmac_keyed": hmac_is_keyed(CFG),
        },
        "cache": CACHE.stats(),
        "providers": {
            name: {
                "enabled": CFG.providers[name].enabled if name in CFG.providers else True,
                "rpm": CFG.providers[name].requests_per_minute if name in CFG.providers else None,
                "allowed_endpoints": len(CFG.providers[name].allow) if name in CFG.providers else 0,
                "supports": {
                    "url": prov.supports_url,
                    "domain": prov.supports_domain,
                    "ip": prov.supports_ip,
                    "hash": prov.supports_hash,
                },
            }
            for name, prov in PROVIDERS.items()
        },
    }


@app.get("/providers")
def providers_list() -> Dict[str, Any]:
    return {
        name: {
            "enabled": CFG.providers[name].enabled if name in CFG.providers else True,
            "supports_url": prov.supports_url,
            "supports_domain": prov.supports_domain,
            "supports_ip": prov.supports_ip,
            "supports_hash": prov.supports_hash,
        }
        for name, prov in PROVIDERS.items()
    }


@app.get("/cache/stats")
def cache_stats() -> Dict[str, Any]:
    return CACHE.stats()


@app.post("/cache/clear")
def cache_clear() -> Dict[str, Any]:
    removed = CACHE.clear()
    return {"cleared_entries": removed}


@app.post("/enrich")
def enrich(payload: EnrichExplicitIn) -> Dict[str, Any]:
    bundle = _bundle_from_list(payload.indicators)
    summary = AGGREGATOR.enrich_bundle(bundle, event_type=payload.event_type)
    out = {"summary": summary}
    if payload.include_explanation:
        out["explanation"] = explain(summary)
    return out


@app.post("/enrich_event")
def enrich_event(payload: EnrichEventIn) -> Dict[str, Any]:
    bundle = extract_indicators(
        payload.message,
        reject_private_ips=CFG.reject_private_ips,
    )
    summary = AGGREGATOR.enrich_bundle(
        bundle,
        event_type=payload.event_type,
        message=payload.message,
    )
    out: Dict[str, Any] = {
        "indicators": {
            "urls": bundle.urls,
            "domains": bundle.domains,
            "ipv4s": bundle.ipv4s,
            "ipv6s": bundle.ipv6s,
            "md5s": bundle.md5s,
            "sha1s": bundle.sha1s,
            "sha256s": bundle.sha256s,
        },
        "summary": summary,
    }
    if payload.include_explanation:
        out["explanation"] = explain(summary)
    return out
