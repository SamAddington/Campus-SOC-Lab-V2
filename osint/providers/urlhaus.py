"""URLhaus (abuse.ch) provider.

URLhaus is a free, no-key-required feed for known malware-distribution
URLs. We use the JSON API: POST to ``/v1/url/`` or ``/v1/host/`` with a
form-encoded ``url`` or ``host`` parameter.
"""

from __future__ import annotations

from http_client import OSINTCallError, ScopedHTTP

from .base import Finding, OSINTProvider, Verdict


class URLhausProvider(OSINTProvider):
    name = "urlhaus"
    supports_url = True
    supports_domain = True

    def __init__(self, *, cfg, http: ScopedHTTP):
        self._http = http

    def _post(self, path: str, form: dict) -> Finding:
        try:
            resp = self._http.request(self.name, "POST", path, data=form)
        except OSINTCallError as exc:
            return Finding(self.name, Verdict.ERROR, 0.0, "", error=str(exc))
        if not resp.ok() or not isinstance(resp.json, dict):
            return Finding(self.name, Verdict.ERROR, 0.0,
                           f"URLhaus returned status {resp.status_code}",
                           elapsed_ms=resp.elapsed_ms)
        body = resp.json
        query_status = body.get("query_status", "")
        if query_status == "no_results":
            return Finding(self.name, Verdict.UNKNOWN, 0.0,
                           "not listed on URLhaus",
                           elapsed_ms=resp.elapsed_ms)
        if query_status not in ("ok", "found"):
            return Finding(self.name, Verdict.UNKNOWN, 0.0,
                           f"URLhaus status={query_status}",
                           elapsed_ms=resp.elapsed_ms)
        # ``threat`` and ``url_status`` are the primary signals.
        threat = body.get("threat") or body.get("url_info", {}).get("threat")
        url_status = body.get("url_status") or body.get("host_status")
        if threat or url_status in ("online", "active"):
            notes = f"URLhaus lists as threat={threat or 'listed'}"
            if url_status:
                notes += f", status={url_status}"
            return Finding(self.name, Verdict.MALICIOUS, 0.9, notes,
                           evidence={"threat": threat, "url_status": url_status},
                           elapsed_ms=resp.elapsed_ms)
        return Finding(self.name, Verdict.SUSPICIOUS, 0.5,
                       "URLhaus has a record for this indicator",
                       evidence={"query_status": query_status},
                       elapsed_ms=resp.elapsed_ms)

    def check_url(self, url: str) -> Finding:
        return self._post("/v1/url/", {"url": url})

    def check_domain(self, domain: str) -> Finding:
        return self._post("/v1/host/", {"host": domain})
