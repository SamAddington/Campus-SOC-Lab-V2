"""VirusTotal provider.

Uses the v3 API. We read engine counts from ``last_analysis_stats`` and
derive a verdict from the ratio of malicious/suspicious detections to
total engines. No file uploads, ever -- only hash lookups.
"""

from __future__ import annotations

import base64
from typing import Any, Dict

from http_client import OSINTCallError, ScopedHTTP

from .base import Finding, OSINTProvider, Verdict


def _url_to_id(url: str) -> str:
    # VT expects base64url without padding.
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _stats_to_verdict(stats: Dict[str, Any]) -> tuple:
    mal = int(stats.get("malicious", 0) or 0)
    sus = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    total = mal + sus + harmless + undetected
    if total == 0:
        return Verdict.UNKNOWN, 0.0, "VirusTotal returned no engine results"
    score = (mal * 1.0 + sus * 0.5) / max(1, total)
    if mal >= 3 or score >= 0.05:
        return Verdict.MALICIOUS, score, f"{mal}/{total} engines flagged malicious"
    if mal >= 1 or sus >= 2:
        return Verdict.SUSPICIOUS, score, f"{mal}M/{sus}S across {total} engines"
    return Verdict.BENIGN, score, f"0 malicious, {sus} suspicious across {total} engines"


class VirusTotalProvider(OSINTProvider):
    name = "virustotal"
    supports_url = True
    supports_domain = True
    supports_ip = True
    supports_hash = True

    def __init__(self, *, cfg, http: ScopedHTTP):
        self._http = http
        self._api_key = cfg.providers[self.name].api_key

    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self._api_key or ""}

    def _call(self, path: str) -> Finding:
        try:
            resp = self._http.request(self.name, "GET", path,
                                      headers=self._headers())
        except OSINTCallError as exc:
            return Finding(self.name, Verdict.ERROR, 0.0, "", error=str(exc))
        if resp.status_code == 404:
            return Finding(self.name, Verdict.UNKNOWN, 0.0,
                           "indicator not known to VirusTotal",
                           elapsed_ms=resp.elapsed_ms)
        if not resp.ok() or not isinstance(resp.json, dict):
            return Finding(self.name, Verdict.ERROR, 0.0,
                           f"VirusTotal returned status {resp.status_code}",
                           elapsed_ms=resp.elapsed_ms,
                           error=resp.text[:200])
        attributes = (resp.json.get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        verdict, score, notes = _stats_to_verdict(stats)
        return Finding(
            provider=self.name,
            verdict=verdict,
            score=score,
            notes=notes,
            evidence={
                "engine_stats": stats,
                "reputation": attributes.get("reputation"),
                "categories": attributes.get("categories"),
            },
            elapsed_ms=resp.elapsed_ms,
        )

    def check_url(self, url: str) -> Finding:
        return self._call(f"/api/v3/urls/{_url_to_id(url)}")

    def check_domain(self, domain: str) -> Finding:
        return self._call(f"/api/v3/domains/{domain}")

    def check_ip(self, ip: str) -> Finding:
        return self._call(f"/api/v3/ip_addresses/{ip}")

    def check_hash(self, kind: str, value: str) -> Finding:
        return self._call(f"/api/v3/files/{value}")
