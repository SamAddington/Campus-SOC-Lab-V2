from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests

log = logging.getLogger("siem_emitters")

_DEFAULT_BULK_PATH = "/_bulk"


def _truthy(v: str) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _safe_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)


def _as_str(x: Any, max_len: int = 4096) -> str:
    s = str(x) if x is not None else ""
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."

def _sleep_backoff(attempt: int) -> None:
    time.sleep(min(8.0, 2 ** attempt))


def _request_with_retries(
    *,
    method: str,
    url: str,
    headers: Dict[str, str],
    data: str,
    timeout_seconds: float,
    retries: int,
    verify: Any,
) -> Tuple[bool, Optional[int], str]:
    last_status: Optional[int] = None
    last_body: str = ""
    for attempt in range(max(0, retries) + 1):
        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                timeout=timeout_seconds,
                verify=verify,
            )
            last_status = resp.status_code
            last_body = _as_str(resp.text, 400)
            if resp.ok:
                return True, resp.status_code, last_body
            if resp.status_code in {408, 429, 500, 502, 503, 504} and attempt < retries:
                _sleep_backoff(attempt)
                continue
            return False, resp.status_code, last_body
        except Exception as e:
            if attempt < retries:
                _sleep_backoff(attempt)
                continue
            return False, None, f"{e.__class__.__name__}: {str(e)[:160]}"
    return False, last_status, last_body


@dataclass(frozen=True)
class _SplunkCfg:
    enabled: bool
    url: str
    token: str
    index: str = ""
    sourcetype: str = "agentic_soc"
    timeout_seconds: float = 10.0
    retries: int = 3
    tls_verify: bool = True
    ca_bundle: str = ""


@dataclass(frozen=True)
class _ElasticCfg:
    enabled: bool
    url: str
    api_key: str = ""
    username: str = ""
    password: str = ""
    index: str = "agentic-soc-events"
    timeout_seconds: float = 10.0
    retries: int = 3
    tls_verify: bool = True
    ca_bundle: str = ""
    bulk_path: str = "/_bulk"


@dataclass(frozen=True)
class _SentinelCfg:
    enabled: bool
    workspace_id: str
    shared_key: str
    log_type: str = "AgenticSocEvent"
    timeout_seconds: float = 10.0
    retries: int = 3
    tls_verify: bool = True
    ca_bundle: str = ""


@dataclass(frozen=True)
class _SyslogCfg:
    enabled: bool
    host: str
    port: int
    proto: str  # udp|tcp
    format: str  # cef|json
    facility: int = 1  # user-level messages
    severity: int = 5  # notice
    app_name: str = "agentic-soc"


def _parse_syslog_dest(dest: str) -> Optional[Tuple[str, int, str]]:
    """Parse syslog destination in forms:
    - udp://host:514
    - tcp://host:514
    - host:514  (defaults udp)
    """
    raw = (dest or "").strip()
    if not raw:
        return None
    proto = "udp"
    hostport = raw
    if "://" in raw:
        proto, hostport = raw.split("://", 1)
        proto = proto.lower().strip()
    if ":" not in hostport:
        return None
    host, port_s = hostport.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError:
        return None
    if proto not in {"udp", "tcp"}:
        return None
    return host.strip(), port, proto


def _cef_escape(s: str) -> str:
    return (s or "").replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n").replace("\r", "\\r")


def _to_cef(event: Dict[str, Any]) -> str:
    # Minimal CEF wrapper. The "extension" is flattened JSON to stay generic.
    name = _cef_escape(_as_str(event.get("source") or event.get("event_type") or "event", 128))
    sev = event.get("severity")
    try:
        sev_num = int(sev) if sev is not None else 3
    except Exception:
        sev_num = 3
    ext = _safe_json(event)
    return f"CEF:0|AgenticSOC|SOC|1.0|ingest|{name}|{sev_num} msg={_cef_escape(ext)}"


class SIEMEmitters:
    """Best-effort emitters for external SIEM/log destinations.

    All emitters are **disabled by default**. When enabled they should receive
    already-anonymized records only (e.g. collector anon_record + derived fields).
    """

    def __init__(self) -> None:
        self._splunk = self._load_splunk()
        self._elastic = self._load_elastic()
        self._sentinel = self._load_sentinel()

        syslog_dest = os.getenv("SIEM_SYSLOG_DEST", "")
        parsed = _parse_syslog_dest(syslog_dest)
        self._syslog = _SyslogCfg(
            enabled=_truthy(os.getenv("SIEM_SYSLOG_ENABLED", "")) and bool(parsed),
            host=(parsed[0] if parsed else ""),
            port=(parsed[1] if parsed else 514),
            proto=(parsed[2] if parsed else "udp"),
            format=(os.getenv("SIEM_SYSLOG_FORMAT", "cef") or "cef").lower(),
            facility=int(os.getenv("SIEM_SYSLOG_FACILITY", "1") or "1"),
            severity=int(os.getenv("SIEM_SYSLOG_SEVERITY", "5") or "5"),
            app_name=os.getenv("SIEM_SYSLOG_APP", "agentic-soc"),
        )

    @staticmethod
    def _load_splunk() -> _SplunkCfg:
        return _SplunkCfg(
            enabled=_truthy(os.getenv("SIEM_SPLUNK_HEC_ENABLED", "")),
            url=(os.getenv("SIEM_SPLUNK_HEC_URL", "") or "").rstrip("/"),
            token=os.getenv("SIEM_SPLUNK_HEC_TOKEN", ""),
            index=os.getenv("SIEM_SPLUNK_HEC_INDEX", ""),
            sourcetype=os.getenv("SIEM_SPLUNK_HEC_SOURCETYPE", "agentic_soc"),
            timeout_seconds=float(os.getenv("SIEM_SPLUNK_HEC_TIMEOUT", "10") or "10"),
            retries=int(os.getenv("SIEM_SPLUNK_HEC_RETRIES", "3") or "3"),
            tls_verify=os.getenv("SIEM_SPLUNK_HEC_TLS_VERIFY", "1") == "1",
            ca_bundle=os.getenv("SIEM_SPLUNK_HEC_CA_BUNDLE", ""),
        )

    @staticmethod
    def _load_elastic() -> _ElasticCfg:
        return _ElasticCfg(
            enabled=_truthy(os.getenv("SIEM_ELASTIC_ENABLED", "")),
            url=(os.getenv("SIEM_ELASTIC_URL", "") or "").rstrip("/"),
            api_key=os.getenv("SIEM_ELASTIC_API_KEY", ""),
            username=os.getenv("SIEM_ELASTIC_USERNAME", ""),
            password=os.getenv("SIEM_ELASTIC_PASSWORD", ""),
            index=os.getenv("SIEM_ELASTIC_INDEX", "agentic-soc-events"),
            timeout_seconds=float(os.getenv("SIEM_ELASTIC_TIMEOUT", "10") or "10"),
            retries=int(os.getenv("SIEM_ELASTIC_RETRIES", "3") or "3"),
            tls_verify=os.getenv("SIEM_ELASTIC_TLS_VERIFY", "1") == "1",
            ca_bundle=os.getenv("SIEM_ELASTIC_CA_BUNDLE", ""),
            bulk_path=os.getenv("SIEM_ELASTIC_BULK_PATH", _DEFAULT_BULK_PATH) or _DEFAULT_BULK_PATH,
        )

    @staticmethod
    def _load_sentinel() -> _SentinelCfg:
        return _SentinelCfg(
            enabled=_truthy(os.getenv("SIEM_SENTINEL_ENABLED", "")),
            workspace_id=os.getenv("SIEM_SENTINEL_WORKSPACE_ID", ""),
            shared_key=os.getenv("SIEM_SENTINEL_SHARED_KEY", ""),
            log_type=os.getenv("SIEM_SENTINEL_LOG_TYPE", "AgenticSocEvent"),
            timeout_seconds=float(os.getenv("SIEM_SENTINEL_TIMEOUT", "10") or "10"),
            retries=int(os.getenv("SIEM_SENTINEL_RETRIES", "3") or "3"),
            tls_verify=os.getenv("SIEM_SENTINEL_TLS_VERIFY", "1") == "1",
            ca_bundle=os.getenv("SIEM_SENTINEL_CA_BUNDLE", ""),
        )

    def status(self) -> Dict[str, Any]:
        return {
            "splunk_hec": {"enabled": self._splunk.enabled, "configured": bool(self._splunk.url and self._splunk.token)},
            "elastic": {"enabled": self._elastic.enabled, "configured": bool(self._elastic.url and (self._elastic.api_key or self._elastic.username))},
            "sentinel": {"enabled": self._sentinel.enabled, "configured": bool(self._sentinel.workspace_id and self._sentinel.shared_key)},
            "syslog": {"enabled": self._syslog.enabled, "configured": bool(self._syslog.host and self._syslog.port)},
        }

    def enabled_destinations(self) -> List[str]:
        out: List[str] = []
        if self._splunk.enabled:
            out.append("splunk_hec")
        if self._elastic.enabled:
            out.append("elastic")
        if self._sentinel.enabled:
            out.append("sentinel")
        if self._syslog.enabled:
            out.append("syslog")
        return out

    def emit(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Emit to all enabled destinations; never raises."""
        out: Dict[str, Any] = {}
        if self._splunk.enabled:
            out["splunk_hec"] = self._emit_splunk(event)
        if self._elastic.enabled:
            out["elastic"] = self._emit_elastic(event)
        if self._sentinel.enabled:
            out["sentinel"] = self._emit_sentinel(event)
        if self._syslog.enabled:
            out["syslog"] = self._emit_syslog(event)
        return out

    def emit_one(self, dest: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Emit to a single destination by name; never raises."""
        try:
            if dest == "splunk_hec":
                return self._emit_splunk(event)
            if dest == "elastic":
                return self._emit_elastic(event)
            if dest == "sentinel":
                return self._emit_sentinel(event)
            if dest == "syslog":
                return self._emit_syslog(event)
            return {"ok": False, "error": "unknown_destination"}
        except Exception as e:
            log.warning("emit_one %s failed: %s", dest, e)
            return {"ok": False, "error": e.__class__.__name__}

    # --- Splunk HEC ---------------------------------------------------------

    def _emit_splunk(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if not (self._splunk.url and self._splunk.token):
            return {"ok": False, "error": "not_configured"}
        url = f"{self._splunk.url}/services/collector/event"
        payload: Dict[str, Any] = {
            "time": time.time(),
            "host": os.getenv("HOSTNAME", "agentic-soc"),
            "sourcetype": self._splunk.sourcetype,
            "event": event,
        }
        if self._splunk.index:
            payload["index"] = self._splunk.index
        headers = {"Authorization": f"Splunk {self._splunk.token}"}
        verify: Any = self._splunk.tls_verify
        if self._splunk.ca_bundle.strip():
            verify = self._splunk.ca_bundle.strip()

        ok, status, body = _request_with_retries(
            method="POST",
            url=url,
            headers=headers,
            data=_safe_json(payload),
            timeout_seconds=self._splunk.timeout_seconds,
            retries=self._splunk.retries,
            verify=verify,
        )
        return {"ok": ok, **({} if ok else {"status": status, "body": body})}

    # --- Elastic/OpenSearch --------------------------------------------------

    def _emit_elastic(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if not self._elastic.url:
            return {"ok": False, "error": "not_configured"}
        headers: Dict[str, str] = {"Content-Type": "application/x-ndjson"}
        if self._elastic.api_key:
            headers["Authorization"] = f"ApiKey {self._elastic.api_key}"
        elif self._elastic.username:
            basic = base64.b64encode(f"{self._elastic.username}:{self._elastic.password}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {basic}"

        # NDJSON bulk with one doc. Avoids extra dependencies.
        index = self._elastic.index or "agentic-soc-events"
        bulk = _safe_json({"index": {"_index": index}}) + "\n" + _safe_json(event) + "\n"
        verify: Any = self._elastic.tls_verify
        if self._elastic.ca_bundle.strip():
            verify = self._elastic.ca_bundle.strip()

        url = f"{self._elastic.url}{self._elastic.bulk_path}"
        ok, status, body_text = _request_with_retries(
            method="POST",
            url=url,
            headers=headers,
            data=bulk,
            timeout_seconds=self._elastic.timeout_seconds,
            retries=self._elastic.retries,
            verify=verify,
        )
        if not ok:
            return {"ok": False, "status": status, "body": body_text}
        # If the response includes JSON, verify that Bulk didn't partially fail.
        try:
            resp_body = json.loads(body_text) if body_text and body_text.strip().startswith("{") else {}
            if isinstance(resp_body, dict) and resp_body.get("errors"):
                return {"ok": False, "error": "bulk_errors"}
        except Exception:
            pass
        return {"ok": True}

    # --- Microsoft Sentinel (Log Analytics Data Collector API) --------------

    def _sentinel_signature(self, date: str, content_len: int, method: str, content_type: str, resource: str) -> str:
        x_headers = f"x-ms-date:{date}"
        string_to_hash = f"{method}\n{content_len}\n{content_type}\n{x_headers}\n{resource}"
        bytes_to_hash = string_to_hash.encode("utf-8")
        decoded_key = base64.b64decode(self._sentinel.shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode("ascii")
        return f"SharedKey {self._sentinel.workspace_id}:{encoded_hash}"

    def _emit_sentinel(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if not (self._sentinel.workspace_id and self._sentinel.shared_key):
            return {"ok": False, "error": "not_configured"}
        body = _safe_json([{**event, "ts": _now_iso()}])
        method = "POST"
        content_type = "application/json"
        resource = "/api/logs"
        date = dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        signature = self._sentinel_signature(date, len(body.encode("utf-8")), method, content_type, resource)
        url = f"https://{self._sentinel.workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
        headers = {
            "Content-Type": content_type,
            "Log-Type": self._sentinel.log_type,
            "x-ms-date": date,
            "Authorization": signature,
        }
        verify: Any = self._sentinel.tls_verify
        if self._sentinel.ca_bundle.strip():
            verify = self._sentinel.ca_bundle.strip()

        ok, status, body_text = _request_with_retries(
            method="POST",
            url=url,
            headers=headers,
            data=body,
            timeout_seconds=self._sentinel.timeout_seconds,
            retries=self._sentinel.retries,
            verify=verify,
        )
        return {"ok": ok, **({} if ok else {"status": status, "body": body_text})}

    # --- Syslog (CEF or JSON) ----------------------------------------------

    def _emit_syslog(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if not (self._syslog.host and self._syslog.port):
            return {"ok": False, "error": "not_configured"}
        msg = _to_cef(event) if self._syslog.format == "cef" else _safe_json(event)
        pri = self._syslog.facility * 8 + self._syslog.severity
        # RFC5424-ish minimal header; keep it permissive.
        line = f"<{pri}>1 {_now_iso()} {socket.gethostname()} {self._syslog.app_name} - - - {msg}"

        try:
            if self._syslog.proto == "tcp":
                with socket.create_connection((self._syslog.host, self._syslog.port), timeout=5) as s:
                    s.sendall(line.encode("utf-8") + b"\n")
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(line.encode("utf-8"), (self._syslog.host, self._syslog.port))
            return {"ok": True}
        except Exception as e:
            log.warning("syslog emit failed: %s", e)
            return {"ok": False, "error": e.__class__.__name__}

