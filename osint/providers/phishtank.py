"""Phishtank provider.

The Phishtank checker endpoint accepts a URL and reports whether it is
in the verified phishing database.
"""

from __future__ import annotations

from http_client import OSINTCallError, ScopedHTTP

from .base import Finding, OSINTProvider, Verdict


class PhishtankProvider(OSINTProvider):
    name = "phishtank"
    supports_url = True

    def __init__(self, *, cfg, http: ScopedHTTP):
        self._http = http
        self._app_key = (cfg.providers[self.name].extra or {}).get("app_key") or ""

    def check_url(self, url: str) -> Finding:
        form = {"url": url, "format": "json"}
        if self._app_key:
            form["app_key"] = self._app_key
        try:
            resp = self._http.request(
                self.name, "POST", "/checkurl/", data=form,
                headers={"User-Agent": "wicys-soc-osint/1.0"},
            )
        except OSINTCallError as exc:
            return Finding(self.name, Verdict.ERROR, 0.0, "", error=str(exc))

        if not resp.ok() or not isinstance(resp.json, dict):
            return Finding(self.name, Verdict.ERROR, 0.0,
                           f"Phishtank returned status {resp.status_code}",
                           elapsed_ms=resp.elapsed_ms)

        results = resp.json.get("results") or {}
        in_db = bool(results.get("in_database"))
        verified = bool(results.get("verified"))
        phish_id = results.get("phish_id")

        if in_db and verified:
            return Finding(self.name, Verdict.MALICIOUS, 1.0,
                           f"verified Phishtank entry id={phish_id}",
                           evidence=dict(results),
                           elapsed_ms=resp.elapsed_ms)
        if in_db:
            return Finding(self.name, Verdict.SUSPICIOUS, 0.6,
                           f"Phishtank entry (unverified) id={phish_id}",
                           evidence=dict(results),
                           elapsed_ms=resp.elapsed_ms)
        return Finding(self.name, Verdict.UNKNOWN, 0.0,
                       "not in Phishtank",
                       elapsed_ms=resp.elapsed_ms)
