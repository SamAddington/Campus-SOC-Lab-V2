"""AlienVault OTX provider.

We use the ``/api/v1/indicators/{section}/{value}/general`` endpoint,
which returns ``pulse_info`` containing the list of threat pulses the
indicator appears in. We treat ``pulse_count >= 1`` as suspicious and
``>= 3`` as malicious (threat intel corroboration).
"""

from __future__ import annotations

from http_client import OSINTCallError, ScopedHTTP

from .base import Finding, OSINTProvider, Verdict


def _pulses_to_verdict(count: int) -> tuple:
    if count >= 3:
        return Verdict.MALICIOUS, min(1.0, count / 10.0)
    if count >= 1:
        return Verdict.SUSPICIOUS, count / 10.0
    return Verdict.BENIGN, 0.0


class OTXProvider(OSINTProvider):
    name = "otx"
    supports_url = True
    supports_domain = True
    supports_ip = True
    supports_hash = True

    _SECTION_BY_KIND = {
        "url": "url",
        "domain": "domain",
        "ipv4": "IPv4",
        "ipv6": "IPv6",
        "md5": "file",
        "sha1": "file",
        "sha256": "file",
    }

    def __init__(self, *, cfg, http: ScopedHTTP):
        self._http = http
        self._api_key = cfg.providers[self.name].api_key

    def _call(self, kind: str, value: str) -> Finding:
        section = self._SECTION_BY_KIND.get(kind)
        if not section:
            return Finding(self.name, Verdict.UNKNOWN, 0.0,
                           f"OTX: unsupported kind {kind}")
        path = f"/api/v1/indicators/{section}/{value}/general"
        try:
            resp = self._http.request(
                self.name, "GET", path,
                headers={"X-OTX-API-KEY": self._api_key or ""},
            )
        except OSINTCallError as exc:
            return Finding(self.name, Verdict.ERROR, 0.0, "", error=str(exc))

        if resp.status_code == 404:
            return Finding(self.name, Verdict.UNKNOWN, 0.0,
                           "OTX: indicator not found",
                           elapsed_ms=resp.elapsed_ms)
        if not resp.ok() or not isinstance(resp.json, dict):
            return Finding(self.name, Verdict.ERROR, 0.0,
                           f"OTX returned status {resp.status_code}",
                           elapsed_ms=resp.elapsed_ms)

        pulse_info = resp.json.get("pulse_info") or {}
        count = int(pulse_info.get("count", 0) or 0)
        verdict, score = _pulses_to_verdict(count)

        # Capture up to 3 pulse names for the reviewer.
        pulses = pulse_info.get("pulses") or []
        pulse_names = [p.get("name", "")[:80] for p in pulses[:3]]

        return Finding(
            provider=self.name,
            verdict=verdict,
            score=score,
            notes=f"{count} OTX pulse(s) reference this indicator",
            evidence={
                "pulse_count": count,
                "pulse_names": pulse_names,
            },
            elapsed_ms=resp.elapsed_ms,
        )

    def check_url(self, url: str) -> Finding:
        return self._call("url", url)

    def check_domain(self, domain: str) -> Finding:
        return self._call("domain", domain)

    def check_ip(self, ip: str) -> Finding:
        kind = "ipv6" if ":" in ip else "ipv4"
        return self._call(kind, ip)

    def check_hash(self, kind: str, value: str) -> Finding:
        return self._call(kind, value)
