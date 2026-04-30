"""Aggregate provider findings for an event into a single summary.

Shape of the summary we hand back (and that ends up on the decision
card):

```
{
  "verdict": "malicious|suspicious|benign|unknown",
  "score": 0.0 .. 1.0,
  "indicator_count": int,
  "findings": [Finding.to_dict(), ...],  # flat list
  "per_indicator": [
     {"kind": "url", "value": "<defanged>", "verdict": "...", "providers": [...]}
  ],
  "mitre": {"tactic": "...", "technique_id": "...", "technique_name": "..."},
  "providers_used": ["virustotal", "urlhaus", ...],
  "providers_errored": ["..."],
  "elapsed_ms": int
}
```

We cap ``findings`` at a small number and drop raw provider response
bodies before returning so nothing surprising ends up in the audit
ledger.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from cache import TTLCache, cache_key
from config import Config
from extractors import IndicatorBundle, IndicatorKind, defang
from providers import (
    Finding,
    MITREProvider,
    OSINTProvider,
    Verdict,
    aggregate_verdict,
)


_VERDICT_RANK = {
    Verdict.MALICIOUS: 4,
    Verdict.SUSPICIOUS: 3,
    Verdict.BENIGN: 2,
    Verdict.UNKNOWN: 1,
    Verdict.ERROR: 0,
}


def _worst(verdicts: List[Verdict]) -> Verdict:
    if not verdicts:
        return Verdict.UNKNOWN
    return max(verdicts, key=lambda v: _VERDICT_RANK.get(v, 0))


def _score_from_findings(findings: List[Finding]) -> float:
    non_error = [f for f in findings if f.verdict != Verdict.ERROR]
    if not non_error:
        return 0.0
    # Weight malicious scores more than suspicious/benign.
    weight = {
        Verdict.MALICIOUS: 1.0,
        Verdict.SUSPICIOUS: 0.6,
        Verdict.BENIGN: 0.0,
        Verdict.UNKNOWN: 0.1,
    }
    total = 0.0
    for f in non_error:
        total += weight.get(f.verdict, 0.0) * float(f.score)
    return max(0.0, min(1.0, total / max(1, len(non_error))))


class Aggregator:
    def __init__(self, *, cfg: Config, providers: Dict[str, OSINTProvider],
                 cache: TTLCache):
        self._cfg = cfg
        self._providers = providers
        self._cache = cache

    # ---- provider dispatch ----

    def _supported(self, provider: OSINTProvider, kind: IndicatorKind) -> bool:
        if kind == IndicatorKind.URL:
            return provider.supports_url
        if kind == IndicatorKind.DOMAIN:
            return provider.supports_domain
        if kind in (IndicatorKind.IPV4, IndicatorKind.IPV6):
            return provider.supports_ip
        if kind in (IndicatorKind.HASH_MD5, IndicatorKind.HASH_SHA1, IndicatorKind.HASH_SHA256):
            return provider.supports_hash
        return False

    def _call_provider(self, provider: OSINTProvider,
                       kind: IndicatorKind, value: str) -> Finding:
        if kind == IndicatorKind.URL:
            return provider.check_url(value)
        if kind == IndicatorKind.DOMAIN:
            return provider.check_domain(value)
        if kind in (IndicatorKind.IPV4, IndicatorKind.IPV6):
            return provider.check_ip(value)
        if kind in (IndicatorKind.HASH_MD5, IndicatorKind.HASH_SHA1, IndicatorKind.HASH_SHA256):
            return provider.check_hash(kind.value, value)
        return Finding(provider.name, Verdict.UNKNOWN, 0.0,
                       f"unsupported kind {kind.value}")

    def _query_one(self, kind: IndicatorKind, value: str, deadline_ts: float) -> Dict[str, Any]:
        per_provider: List[Dict[str, Any]] = []
        findings: List[Finding] = []
        for name, provider in self._providers.items():
            if name == "mitre":
                continue
            if time.time() > deadline_ts:
                break
            if not self._supported(provider, kind):
                continue

            key = cache_key(self._cfg.hmac_secret, name, kind.value, value)
            cached = self._cache.get(key)
            if cached:
                per_provider.append({**cached, "cache_hit": True})
                # Rehydrate into a Finding for aggregation.
                findings.append(Finding(
                    provider=name,
                    verdict=Verdict(cached.get("verdict", "unknown")),
                    score=float(cached.get("score", 0.0)),
                    notes=cached.get("notes", ""),
                    evidence=cached.get("evidence", {}),
                    elapsed_ms=int(cached.get("elapsed_ms", 0)),
                ))
                continue

            finding = self._call_provider(provider, kind, value)
            findings.append(finding)
            snap = finding.to_dict()
            # We only cache non-error results; an error shouldn't
            # suppress the next retry.
            if finding.verdict != Verdict.ERROR:
                self._cache.set(key, snap)
            per_provider.append({**snap, "cache_hit": False})

        verdict = aggregate_verdict(findings)
        return {
            "kind": kind.value,
            "value": defang(value),
            "raw_value_hashed": cache_key(self._cfg.hmac_secret, "indicator", kind.value, value),
            "verdict": verdict.value,
            "providers": per_provider,
        }

    # ---- public entry points ----

    def enrich_bundle(self, bundle: IndicatorBundle, *,
                      event_type: str = "",
                      message: str = "") -> Dict[str, Any]:
        started = time.monotonic()
        deadline_ts = time.time() + float(self._cfg.per_enrichment_deadline)

        per_indicator: List[Dict[str, Any]] = []
        flat_findings: List[Finding] = []

        def _run(kind: IndicatorKind, values: List[str], cap: int):
            for v in values[:cap]:
                if time.time() > deadline_ts:
                    return
                summary = self._query_one(kind, v, deadline_ts)
                per_indicator.append(summary)

        _run(IndicatorKind.URL, bundle.urls, self._cfg.max_urls_per_event)
        _run(IndicatorKind.DOMAIN, bundle.domains, self._cfg.max_domains_per_event)
        _run(IndicatorKind.IPV4, bundle.ipv4s, self._cfg.max_ips_per_event)
        _run(IndicatorKind.IPV6, bundle.ipv6s, self._cfg.max_ips_per_event)
        _run(IndicatorKind.HASH_MD5, bundle.md5s, self._cfg.max_hashes_per_event)
        _run(IndicatorKind.HASH_SHA1, bundle.sha1s, self._cfg.max_hashes_per_event)
        _run(IndicatorKind.HASH_SHA256, bundle.sha256s, self._cfg.max_hashes_per_event)

        # Rebuild flat_findings from per_indicator so we capture both
        # live and cached results.
        for ind in per_indicator:
            for pr in ind.get("providers", []):
                flat_findings.append(Finding(
                    provider=str(pr.get("provider", "")),
                    verdict=Verdict(pr.get("verdict", "unknown")),
                    score=float(pr.get("score", 0.0)),
                    notes=str(pr.get("notes", "")),
                    evidence=dict(pr.get("evidence", {})),
                    elapsed_ms=int(pr.get("elapsed_ms", 0)),
                ))

        verdict = _worst([Verdict(i["verdict"]) for i in per_indicator]) \
            if per_indicator else Verdict.UNKNOWN
        score = _score_from_findings(flat_findings)

        mitre_provider = self._providers.get("mitre")
        mitre_finding: Optional[Finding] = None
        if isinstance(mitre_provider, MITREProvider):
            mitre_finding = mitre_provider.context_for(
                event_type=event_type,
                message=message,
                aggregated_verdict=verdict,
            )

        providers_used = sorted({
            pr.get("provider") for ind in per_indicator for pr in ind.get("providers", [])
            if pr.get("provider")
        })
        providers_errored = sorted({
            pr.get("provider") for ind in per_indicator for pr in ind.get("providers", [])
            if pr.get("verdict") == Verdict.ERROR.value
        })

        elapsed_ms = int((time.monotonic() - started) * 1000)
        out: Dict[str, Any] = {
            "verdict": verdict.value,
            "score": round(float(score), 4),
            "indicator_count": bundle.total(),
            "per_indicator": per_indicator,
            "providers_used": providers_used,
            "providers_errored": providers_errored,
            "elapsed_ms": elapsed_ms,
            "deadline_reached": time.time() > deadline_ts,
        }
        if mitre_finding:
            out["mitre"] = mitre_finding.evidence or {
                "notes": mitre_finding.notes,
            }
        return out
