"""AbuseIPDB provider.

Scores IPs using ``abuseConfidenceScore`` (0-100). We treat >= 75 as
malicious, 25-74 as suspicious, and < 25 as benign. Thresholds can be
overridden per-deployment by editing the helper below.
"""

from __future__ import annotations

from http_client import OSINTCallError, ScopedHTTP

from .base import Finding, OSINTProvider, Verdict


def _score_to_verdict(score: int) -> tuple:
    if score >= 75:
        return Verdict.MALICIOUS, score / 100.0
    if score >= 25:
        return Verdict.SUSPICIOUS, score / 100.0
    return Verdict.BENIGN, score / 100.0


class AbuseIPDBProvider(OSINTProvider):
    name = "abuseipdb"
    supports_ip = True

    def __init__(self, *, cfg, http: ScopedHTTP):
        self._http = http
        self._api_key = cfg.providers[self.name].api_key

    def check_ip(self, ip: str) -> Finding:
        try:
            resp = self._http.request(
                self.name,
                "GET",
                "/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self._api_key or "", "Accept": "application/json"},
            )
        except OSINTCallError as exc:
            return Finding(self.name, Verdict.ERROR, 0.0, "", error=str(exc))

        if not resp.ok() or not isinstance(resp.json, dict):
            return Finding(self.name, Verdict.ERROR, 0.0,
                           f"AbuseIPDB returned status {resp.status_code}",
                           elapsed_ms=resp.elapsed_ms)

        data = resp.json.get("data") or {}
        score = int(data.get("abuseConfidenceScore", 0) or 0)
        reports = int(data.get("totalReports", 0) or 0)
        verdict, norm = _score_to_verdict(score)
        return Finding(
            provider=self.name,
            verdict=verdict,
            score=norm,
            notes=f"abuse confidence={score}/100 over {reports} reports",
            evidence={
                "abuseConfidenceScore": score,
                "totalReports": reports,
                "countryCode": data.get("countryCode"),
                "usageType": data.get("usageType"),
            },
            elapsed_ms=resp.elapsed_ms,
        )
