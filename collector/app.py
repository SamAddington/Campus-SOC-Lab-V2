from pathlib import Path
from fastapi import Depends, FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, Annotated
import hashlib
import hmac
import os
import requests
import json
import logging
import sys
sys.path.insert(0, "/app")
from shared.security import require_api_key, require_roles, get_principal
import threading
import time
from shared.siem import SIEMEmitters, DiskSpool, load_spool_config
from datetime import datetime, timezone
from urllib.parse import urljoin

try:
    from shared.schemas import (
        SCHEMA_VERSION,
        AnonRecordV1,
        FeatureVectorV1,
        IngestedEventV1,
    )
except Exception:
    SCHEMA_VERSION = "v1"
    AnonRecordV1 = None
    FeatureVectorV1 = None
    IngestedEventV1 = None

from shared.normalize import normalize_ecs

log = logging.getLogger("collector")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="WiCyS Collector", version="0.2.0")

from shared.hardening import apply_hardening, RateLimitConfig

apply_hardening(app, max_body_bytes=2_000_000, rate_limit=RateLimitConfig(requests=240, per_seconds=60))

# OpenSearch field constants (avoid string drift)
_OS_F_SRC = "anon_record.source"
_OS_F_ET = "anon_record.event_type"
_OS_F_LANG = "anon_record.language"
_OS_F_MSG = "anon_record.message"
_OS_F_UID = "anon_record.user_id_hash"
_OS_F_DOM = "anon_record.email_domain"
_OS_F_RULE = "detector_result.policy_rule_id"

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = Path("/app/data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

INGESTED_PATH = DATA_DIR / "ingested_events.jsonl"

DETECTOR_URL = os.getenv("DETECTOR_URL", "http://detector:8000")
ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8021")
AUDIT_URL = os.getenv("AUDIT_URL", "http://audit:8022")

# Keyed HMAC for anonymization. In dev a default is allowed but a warning is emitted;
# in production HMAC_SECRET MUST be set via env or a mounted secret file.
_DEFAULT_DEV_SECRET = "change-me-dev-only"
HMAC_SECRET = os.getenv("HMAC_SECRET", _DEFAULT_DEV_SECRET)
SOC_API_KEY = os.getenv("SOC_API_KEY", "change-me-dev-api-key")
if HMAC_SECRET == _DEFAULT_DEV_SECRET:
    log.warning(
        "HMAC_SECRET not set; using insecure default. "
        "Set HMAC_SECRET in your environment before any non-workshop use."
    )

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


SIEM = SIEMEmitters()
SPOOL_CFG = load_spool_config()
SPOOL = DiskSpool(SPOOL_CFG)
_SPOOL_STOP = threading.Event()
_SPOOL_THREAD: Optional[threading.Thread] = None

_SPOOL_DEST_ALLOWLIST = {"splunk_hec", "elastic", "sentinel", "syslog"}

# ---------------------------------------------------------------------------
# Optional event store (OpenSearch / Elasticsearch compatible)
# ---------------------------------------------------------------------------
EVENTSTORE_ENABLED = (os.getenv("EVENTSTORE_OPENSEARCH_ENABLED", "0").strip().lower() in ("1", "true", "yes", "on"))
EVENTSTORE_URL = (os.getenv("EVENTSTORE_OPENSEARCH_URL", "") or "").rstrip("/") + "/"
EVENTSTORE_USER = os.getenv("EVENTSTORE_OPENSEARCH_USERNAME", "")
EVENTSTORE_PASS = os.getenv("EVENTSTORE_OPENSEARCH_PASSWORD", "")
EVENTSTORE_INDEX = os.getenv("EVENTSTORE_OPENSEARCH_INDEX", "agentic-soc-events") or "agentic-soc-events"
EVENTSTORE_TLS_VERIFY = os.getenv("EVENTSTORE_OPENSEARCH_TLS_VERIFY", "1") == "1"
ENTITY_INDEX = os.getenv("EVENTSTORE_ENTITY_INDEX", f"{EVENTSTORE_INDEX}-entities") or f"{EVENTSTORE_INDEX}-entities"

SOC_DEFAULT_TENANT = (os.getenv("SOC_DEFAULT_TENANT", "default") or "default").strip()
SOC_TENANT_ISOLATION = os.getenv("SOC_TENANT_ISOLATION", "0").strip().lower() in ("1", "true", "yes", "on")
_ct = (os.getenv("CORRELATION_SOC_TENANT") or "").strip()
CORRELATION_SOC_TENANT = _ct or SOC_DEFAULT_TENANT

_EVENTSTORE_QUEUE: "list[dict]" = []
_EVENTSTORE_LOCK = threading.Lock()
_EVENTSTORE_STOP = threading.Event()
_EVENTSTORE_THREAD: Optional[threading.Thread] = None

# ---------------------------------------------------------------------------
# Correlation scheduler (runs saved searches on a schedule)
# ---------------------------------------------------------------------------
CORRELATION_ENABLED = (os.getenv("CORRELATION_ENABLED", "1").strip().lower() in ("1", "true", "yes", "on"))
CORRELATION_POLL_SECONDS = float(os.getenv("CORRELATION_POLL_SECONDS", "15") or "15")
CORRELATION_MAX_MATCHES = int(os.getenv("CORRELATION_MAX_MATCHES", "200") or "200")

_CORR_STOP = threading.Event()
_CORR_THREAD: Optional[threading.Thread] = None
_CORR_STATE_PATH = DATA_DIR / "correlation_state.json"


def _audit_get(path: str) -> Optional[Dict[str, Any]]:
    try:
        resp = requests.get(
            f"{AUDIT_URL}{path}",
            timeout=8,
            headers={"X-API-Key": SOC_API_KEY},
        )
        return resp.json() if resp.ok else None
    except Exception:
        return None


def _audit_post(path: str, payload: Dict[str, Any]) -> bool:
    try:
        resp = requests.post(
            f"{AUDIT_URL}{path}",
            timeout=8,
            headers={"X-API-Key": SOC_API_KEY},
            json=payload,
        )
        return bool(resp.ok)
    except Exception:
        return False


def _merge_corr_tenant_filt(filt: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(filt)
    if SOC_TENANT_ISOLATION:
        out["soc_tenant"] = CORRELATION_SOC_TENANT
    return out


def _resolve_search_soc_tenant(principal: Dict[str, Any], query_tenant: Optional[str]) -> Optional[str]:
    if not SOC_TENANT_ISOLATION:
        return None
    auth = str(principal.get("auth") or "")
    qt = (query_tenant or "").strip()
    if auth == "jwt":
        jwt_t = str(principal.get("tenant") or "").strip() or SOC_DEFAULT_TENANT
        if qt and qt != jwt_t:
            raise HTTPException(status_code=403, detail="tenant scope mismatch")
        return jwt_t
    return qt or SOC_DEFAULT_TENANT


def _resolve_ingest_soc_tenant(principal: Dict[str, Any], body_tenant: Optional[str]) -> str:
    body_t = (body_tenant or "").strip()
    if not SOC_TENANT_ISOLATION:
        return body_t or SOC_DEFAULT_TENANT
    auth = str(principal.get("auth") or "")
    if auth == "jwt":
        jwt_t = str(principal.get("tenant") or "").strip() or SOC_DEFAULT_TENANT
        if body_t and body_t != jwt_t:
            raise HTTPException(status_code=403, detail="tenant does not match token")
        return jwt_t
    return body_t or SOC_DEFAULT_TENANT


def _entity_doc_id(soc_tenant: str, entity_type: str, entity_key: str) -> str:
    st = (soc_tenant or "").strip()
    if SOC_TENANT_ISOLATION and st:
        return f"{st}:{entity_type}:{entity_key}"
    return f"{entity_type}:{entity_key}"


def _corr_load_state() -> Dict[str, Any]:
    try:
        if _CORR_STATE_PATH.exists():
            return json.loads(_CORR_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {"v": 1, "rules": {}}


def _corr_save_state(state: Dict[str, Any]) -> None:
    try:
        _CORR_STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    except Exception:
        pass


def _corr_due(now: float, rule: Dict[str, Any], st: Dict[str, Any]) -> bool:
    if not rule.get("enabled", True):
        return False
    rule_id = str(rule.get("rule_id") or "")
    sched = int(rule.get("schedule_seconds") or 60)
    if sched < 10:
        sched = 10
    last = float((st.get("rules") or {}).get(rule_id, {}).get("last_run_at") or 0)
    return (now - last) >= sched


def _corr_mark_run(state: Dict[str, Any], rule_id: str, now: float) -> None:
    state.setdefault("rules", {})
    state["rules"].setdefault(rule_id, {})
    state["rules"][rule_id]["last_run_at"] = now


def _corr_recent_alert(state: Dict[str, Any], rule_id: str, now: float, dedup_seconds: int) -> bool:
    last_alert = float((state.get("rules") or {}).get(rule_id, {}).get("last_alert_at") or 0)
    return (now - last_alert) < max(0, int(dedup_seconds or 0))


def _corr_mark_alert(state: Dict[str, Any], rule_id: str, now: float) -> None:
    state.setdefault("rules", {})
    state["rules"].setdefault(rule_id, {})
    state["rules"][rule_id]["last_alert_at"] = now


def _corr_fetch() -> tuple[list[Dict[str, Any]], list[Dict[str, Any]]]:
    rules = (_audit_get("/correlation/rules") or {}).get("items") or []
    searches = (_audit_get("/saved_searches") or {}).get("items") or []
    rules = [r for r in rules if isinstance(r, dict)]
    searches = [s for s in searches if isinstance(s, dict)]
    return rules, searches


def _corr_search_index(searches: list[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    idx: Dict[str, Dict[str, Any]] = {}
    for s in searches:
        sid = str(s.get("search_id") or "")
        if sid:
            idx[sid] = s
    return idx


def _corr_run_rule(now: float, rule: Dict[str, Any], search: Dict[str, Any], state: Dict[str, Any]) -> None:
    rule_id = str(rule.get("rule_id") or "")
    rule_name = str(rule.get("name") or "correlation rule")
    dedup = int(rule.get("dedup_seconds") or 0)
    if dedup and _corr_recent_alert(state, rule_id, now, dedup):
        return

    # Query last schedule window: since last run -> now
    since_ms, until_ms = _corr_window_ms(now=now, rule=rule, state=state, rule_id=rule_id)

    filt = _merge_corr_tenant_filt(
        {
            "since_ms": since_ms,
            "until_ms": until_ms,
            "event_id": "",
            "source": str(search.get("source") or ""),
            "event_type": str(search.get("event_type") or ""),
            "language": str(search.get("language") or ""),
            "q": str(search.get("q") or ""),
        }
    )
    res = _search_opensearch(filt=filt, limit=min(50, CORRELATION_MAX_MATCHES), cursor=0, want_msg=False)
    items = res.get("items") if isinstance(res, dict) else []
    if not isinstance(items, list):
        items = []
    if not items:
        return

    sample_ids = _corr_sample_event_ids(items)
    alert = {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": str(rule.get("severity") or "medium"),
        "summary": f"{rule_name} matched {len(items)} event(s) in the last window.",
        "match_count": len(items),
        "sample_event_ids": sample_ids,
        "query": {"search_id": str(search.get("search_id") or ""), **{k: v for k, v in filt.items() if v}},
    }
    if _audit_post("/correlation/alerts", alert):
        _corr_mark_alert(state, rule_id, now)


def _corr_window_ms(*, now: float, rule: Dict[str, Any], state: Dict[str, Any], rule_id: str) -> tuple[int, int]:
    sched = float(rule.get("schedule_seconds") or 60)
    last = float((state.get("rules") or {}).get(rule_id, {}).get("last_run_at") or (now - sched))
    return int(last * 1000), int(now * 1000)


def _corr_sample_event_ids(items: list[Any], n: int = 10) -> list[str]:
    out: list[str] = []
    for it in items[:n]:
        if isinstance(it, dict):
            eid = it.get("event_id")
            if eid:
                out.append(str(eid))
    return out


def _maybe_start_correlation_thread() -> None:
    global _CORR_THREAD
    if not (CORRELATION_ENABLED and EVENTSTORE_ENABLED and EVENTSTORE_URL):
        return
    _CORR_STOP.clear()

    def _loop() -> None:
        state = _corr_load_state()
        while not _CORR_STOP.is_set():
            now = time.time()
            try:
                _corr_tick(now=now, state=state)
                _corr_save_state(state)
            except Exception as exc:
                log.warning("correlation loop failed: %s", exc)
            _CORR_STOP.wait(max(5.0, CORRELATION_POLL_SECONDS))

    _CORR_THREAD = threading.Thread(target=_loop, name="correlation-scheduler", daemon=True)
    _CORR_THREAD.start()


def _corr_tick(*, now: float, state: Dict[str, Any]) -> None:
    rules, searches = _corr_fetch()
    sidx = _corr_search_index(searches)
    for r in rules:
        rule_id = str(r.get("rule_id") or "")
        if not rule_id:
            continue
        if not _corr_due(now, r, state):
            continue
        _corr_mark_run(state, rule_id, now)
        mode = str(r.get("mode") or "search").strip().lower()
        if mode == "sequence":
            _corr_run_sequence(now=now, rule=r, searches=sidx, state=state)
        else:
            sid = str(r.get("search_id") or "")
            s = sidx.get(sid)
            if s:
                _corr_run_rule(now, r, s, state)


def _corr_run_sequence(*, now: float, rule: Dict[str, Any], searches: Dict[str, Dict[str, Any]], state: Dict[str, Any]) -> None:
    rule_id = str(rule.get("rule_id") or "")
    rule_name = str(rule.get("name") or "sequence correlation rule")
    dedup = int(rule.get("dedup_seconds") or 0)
    if dedup and _corr_recent_alert(state, rule_id, now, dedup):
        return

    within_seconds = int(rule.get("within_seconds") or 600)
    by_field = str(rule.get("by_field") or "anon_record.user_id_hash")
    steps = rule.get("steps") if isinstance(rule.get("steps"), list) else []
    if len(steps) < 2:
        return

    # window: last schedule window, but expand to cover the full sequence window
    since_ms, until_ms = _corr_window_ms(now=now, rule=rule, state=state, rule_id=rule_id)
    since_ms = int(min(since_ms, until_ms - max(1, within_seconds) * 1000))

    step_events: list[dict[str, list[Dict[str, Any]]]] = []
    for st in steps:
        step_events.append(_corr_sequence_step_events(st=st, searches=searches, since_ms=since_ms, until_ms=until_ms))

    matches = _corr_sequence_match(step_events=step_events, by_field=by_field, within_seconds=within_seconds)
    if not matches:
        return

    sample_event_ids = [m.get("event_id") for m in matches[:10] if m.get("event_id")]
    alert = {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": str(rule.get("severity") or "medium"),
        "summary": f"{rule_name} matched {len(matches)} event(s) as a sequence within {within_seconds}s.",
        "match_count": len(matches),
        "sample_event_ids": [str(x) for x in sample_event_ids if x],
        "query": {"mode": "sequence", "within_seconds": within_seconds, "by_field": by_field, "steps": steps},
    }
    if _audit_post("/correlation/alerts", alert):
        _corr_mark_alert(state, rule_id, now)


def _corr_sequence_step_events(
    *, st: Dict[str, Any], searches: Dict[str, Dict[str, Any]], since_ms: int, until_ms: int
) -> dict[str, list[Dict[str, Any]]]:
    # step can reference a saved_search or inline filters
    sid = str(st.get("search_id") or "")
    s = searches.get(sid) if sid else None
    filt = _merge_corr_tenant_filt(
        {
            "since_ms": since_ms,
            "until_ms": until_ms,
            "event_id": "",
            "source": str((st.get("source") or (s or {}).get("source") or "")),
            "event_type": str((st.get("event_type") or (s or {}).get("event_type") or "")),
            "language": str((st.get("language") or (s or {}).get("language") or "")),
            "q": str((st.get("q") or (s or {}).get("q") or "")),
        }
    )
    res = _search_opensearch(filt=filt, limit=min(200, CORRELATION_MAX_MATCHES), cursor=0, want_msg=False)
    items = res.get("items") if isinstance(res, dict) else []
    if not isinstance(items, list):
        items = []
    # group by join key later; return as-is
    return {"items": [it for it in items if isinstance(it, dict)]}


def _corr_sequence_match(
    *, step_events: list[dict[str, list[Dict[str, Any]]]], by_field: str, within_seconds: int
) -> list[Dict[str, Any]]:
    per_step = _corr_sequence_index(step_events=step_events, by_field=by_field)
    keys = _corr_sequence_keys(per_step=per_step)
    if not keys:
        return []

    out: list[Dict[str, Any]] = []
    for k in keys:
        chain = _corr_sequence_pick_chain(per_step=per_step, key=k)
        if not chain or len(chain) < 2:
            continue
        if (_corr_ts_ms(chain[-1]) - _corr_ts_ms(chain[0])) > (within_seconds * 1000):
            continue
        rep = dict(chain[-1])
        rep["_sequence_by"] = k
        rep["_sequence_ids"] = [str(x.get("event_id") or "") for x in chain if x.get("event_id")]
        out.append(rep)
    return out


def _corr_dry_run_search(*, rule: Dict[str, Any], search: Dict[str, Any]) -> Dict[str, Any]:
    now = time.time()
    until_ms = int(now * 1000)
    since_ms = until_ms - 86400 * 1000
    filt = _merge_corr_tenant_filt(
        {
            "since_ms": since_ms,
            "until_ms": until_ms,
            "event_id": "",
            "source": str(search.get("source") or ""),
            "event_type": str(search.get("event_type") or ""),
            "language": str(search.get("language") or ""),
            "q": str(search.get("q") or ""),
        }
    )
    res = _search_opensearch(filt=filt, limit=min(50, CORRELATION_MAX_MATCHES), cursor=0, want_msg=False)
    items = res.get("items") if isinstance(res, dict) else []
    if not isinstance(items, list):
        items = []
    rule_id = str(rule.get("rule_id") or "")
    return {
        "rule_id": rule_id,
        "would_alert": bool(items),
        "match_count": len(items),
        "sample_event_ids": _corr_sample_event_ids(items),
        "window": {"since_ms": since_ms, "until_ms": until_ms},
        "query": {"search_id": str(search.get("search_id") or ""), **{k: v for k, v in filt.items() if v}},
    }


def _corr_dry_run_sequence(*, rule: Dict[str, Any], searches: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    within_seconds = int(rule.get("within_seconds") or 600)
    by_field = str(rule.get("by_field") or "anon_record.user_id_hash")
    steps = rule.get("steps") if isinstance(rule.get("steps"), list) else []
    if len(steps) < 2:
        return {
            "rule_id": str(rule.get("rule_id") or ""),
            "would_alert": False,
            "match_count": 0,
            "sample_event_ids": [],
            "detail": "sequence rule needs at least two steps",
        }
    now = time.time()
    until_ms = int(now * 1000)
    since_ms = until_ms - 86400 * 1000
    since_ms = int(min(since_ms, until_ms - max(1, within_seconds) * 1000))
    step_events: list[dict[str, list[Dict[str, Any]]]] = []
    for st in steps:
        step_events.append(_corr_sequence_step_events(st=st, searches=searches, since_ms=since_ms, until_ms=until_ms))
    matches = _corr_sequence_match(step_events=step_events, by_field=by_field, within_seconds=within_seconds)
    rule_id = str(rule.get("rule_id") or "")
    sample_event_ids = [m.get("event_id") for m in matches[:10] if m.get("event_id")]
    return {
        "rule_id": rule_id,
        "would_alert": bool(matches),
        "match_count": len(matches),
        "sample_event_ids": [str(x) for x in sample_event_ids if x],
        "window": {"since_ms": since_ms, "until_ms": until_ms},
        "query": {"mode": "sequence", "within_seconds": within_seconds, "by_field": by_field, "steps": steps},
    }


def _corr_get_by_path(d: Dict[str, Any], path: str) -> str:
    cur: Any = d
    for part in str(path).split("."):
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(part)
    return str(cur or "")


def _corr_ts_ms(ev: Dict[str, Any]) -> int:
    try:
        return int(datetime.fromisoformat(str(ev.get("ingested_at") or "").replace("Z", "+00:00")).timestamp() * 1000)
    except Exception:
        return 0


def _corr_sequence_index(
    *, step_events: list[dict[str, list[Dict[str, Any]]]], by_field: str
) -> list[Dict[str, list[Dict[str, Any]]]]:
    per_step: list[Dict[str, list[Dict[str, Any]]]] = []
    for step in step_events:
        idx: Dict[str, list[Dict[str, Any]]] = {}
        for ev in step.get("items") or []:
            k = _corr_get_by_path(ev, by_field)
            if not k:
                continue
            idx.setdefault(k, []).append(ev)
        for k in idx.keys():
            idx[k].sort(key=_corr_ts_ms)
        per_step.append(idx)
    return per_step


def _corr_sequence_keys(*, per_step: list[Dict[str, list[Dict[str, Any]]]]) -> set[str]:
    keys: Optional[set[str]] = None
    for idx in per_step:
        ks = set(idx.keys())
        keys = ks if keys is None else (keys & ks)
    return keys or set()


def _corr_sequence_pick_chain(
    *, per_step: list[Dict[str, list[Dict[str, Any]]]], key: str
) -> list[Dict[str, Any]]:
    last_t: Optional[int] = None
    chain: list[Dict[str, Any]] = []
    for idx in per_step:
        evs = idx.get(key) or []
        chosen = None
        for ev in evs:
            t = _corr_ts_ms(ev)
            if last_t is None or t >= last_t:
                chosen = ev
                break
        if not chosen:
            return []
        chain.append(chosen)
        last_t = _corr_ts_ms(chosen)
    return chain


def _eventstore_auth():
    if EVENTSTORE_USER and EVENTSTORE_PASS:
        return (EVENTSTORE_USER, EVENTSTORE_PASS)
    return None


def _eventstore_put_index_template() -> None:
    """Best-effort template to keep fields searchable. Safe to fail."""
    if not EVENTSTORE_ENABLED or not EVENTSTORE_URL:
        return
    tpl = {
        "index_patterns": [f"{EVENTSTORE_INDEX}*"],
        "template": {
            "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
            "mappings": {
                "dynamic": True,
                "properties": {
                    "ingested_at": {"type": "date"},
                    "event_id": {"type": "keyword"},
                    "soc_tenant": {"type": "keyword"},
                    "schema_version": {"type": "keyword"},
                    "anon_record": {"type": "object", "dynamic": True},
                    "ecs": {
                        "type": "object",
                        "dynamic": True,
                        "properties": {
                            "@timestamp": {"type": "date"},
                            "event": {
                                "type": "object",
                                "dynamic": True,
                                "properties": {
                                    "id": {"type": "keyword"},
                                    "dataset": {"type": "keyword"},
                                    "severity": {"type": "integer"},
                                    "risk_score": {"type": "float"},
                                },
                            },
                            "labels": {"type": "object", "dynamic": True},
                            "user": {"type": "object", "dynamic": True},
                            "email": {"type": "object", "dynamic": True},
                            "organization": {"type": "object", "dynamic": True},
                            "rule": {"type": "object", "dynamic": True},
                            "agentic": {"type": "object", "dynamic": True},
                        },
                    },
                },
            },
        },
    }
    try:
        requests.put(
            urljoin(EVENTSTORE_URL, "_index_template/agentic-soc-template"),
            json=tpl,
            timeout=5,
            auth=_eventstore_auth(),
            verify=EVENTSTORE_TLS_VERIFY,
        )
    except Exception:
        pass


def _eventstore_put_entity_index_template() -> None:
    """Best-effort template for entity enrichment index."""
    if not EVENTSTORE_ENABLED or not EVENTSTORE_URL:
        return
    tpl = {
        "index_patterns": [f"{ENTITY_INDEX}*"],
        "template": {
            "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
            "mappings": {
                "dynamic": True,
                "properties": {
                    "entity_id": {"type": "keyword"},
                    "soc_tenant": {"type": "keyword"},
                    "entity_type": {"type": "keyword"},
                    "entity_key": {"type": "keyword"},
                    "display": {"type": "keyword"},
                    "first_seen": {"type": "date"},
                    "last_seen": {"type": "date"},
                    "seen_count": {"type": "long"},
                    "attributes": {"type": "object", "dynamic": True},
                },
            },
        },
    }
    try:
        requests.put(
            urljoin(EVENTSTORE_URL, "_index_template/agentic-soc-entities-template"),
            json=tpl,
            timeout=5,
            auth=_eventstore_auth(),
            verify=EVENTSTORE_TLS_VERIFY,
        )
    except Exception:
        pass


def _entity_upsert(
    entity_type: str,
    entity_key: str,
    *,
    display: str = "",
    attributes: Optional[Dict[str, Any]] = None,
    soc_tenant: str = "",
) -> None:
    """Best-effort entity upsert into the eventstore."""
    if not (EVENTSTORE_ENABLED and EVENTSTORE_URL):
        return
    if not entity_type or not entity_key:
        return
    now = utc_now()
    st = (soc_tenant or "").strip() or SOC_DEFAULT_TENANT
    entity_id = _entity_doc_id(st, entity_type, entity_key)
    script = (
        "ctx._source.seen_count = (ctx._source.seen_count != null ? ctx._source.seen_count : 0) + 1; "
        "ctx._source.last_seen = params.now; "
        "if (ctx._source.first_seen == null) { ctx._source.first_seen = params.now; } "
        "ctx._source.entity_id = params.entity_id; "
        "ctx._source.entity_type = params.entity_type; "
        "ctx._source.entity_key = params.entity_key; "
        "ctx._source.soc_tenant = params.soc_tenant; "
        "if (params.display != null && params.display.length() > 0) { ctx._source.display = params.display; } "
        "if (params.attributes != null) { ctx._source.attributes = params.attributes; }"
    )
    upsert = {
        "entity_id": entity_id,
        "soc_tenant": st,
        "entity_type": entity_type,
        "entity_key": entity_key,
        "display": display or entity_key,
        "first_seen": now,
        "last_seen": now,
        "seen_count": 1,
        "attributes": attributes or {},
    }
    lines = [
        json.dumps({"update": {"_index": ENTITY_INDEX, "_id": entity_id}}),
        json.dumps(
            {
                "scripted_upsert": True,
                "script": {
                    "lang": "painless",
                    "source": script,
                    "params": {
                        "now": now,
                        "entity_id": entity_id,
                        "entity_type": entity_type,
                        "entity_key": entity_key,
                        "soc_tenant": st,
                        "display": display or "",
                        "attributes": attributes or None,
                    },
                },
                "upsert": upsert,
            }
        ),
    ]
    data = "\n".join(lines) + "\n"
    try:
        requests.post(
            urljoin(EVENTSTORE_URL, "_bulk"),
            data=data,
            headers={"Content-Type": "application/x-ndjson"},
            timeout=5,
            auth=_eventstore_auth(),
            verify=EVENTSTORE_TLS_VERIFY,
        )
    except Exception:
        pass


def _enrich_entities(record: Dict[str, Any]) -> None:
    """Extract and upsert entities for pivoting."""
    try:
        st = str(record.get("soc_tenant") or "").strip() or SOC_DEFAULT_TENANT
        ecs = record.get("ecs") if isinstance(record, dict) else None
        agentic = (ecs or {}).get("agentic") if isinstance(ecs, dict) else None
        anon = (agentic or {}).get("anon_record") if isinstance(agentic, dict) else None
        if isinstance(anon, dict):
            uid = str(anon.get("user_id_hash") or "")
            dom = str(anon.get("email_domain") or "")
            if uid:
                _entity_upsert("user", uid, display=uid, attributes={"kind": "anon_user"}, soc_tenant=st)
            if dom:
                _entity_upsert("domain", dom, display=dom, attributes={"kind": "email_domain"}, soc_tenant=st)
    except Exception:
        pass

def _eventstore_enqueue(doc: Dict[str, Any]) -> None:
    if not EVENTSTORE_ENABLED:
        return
    with _EVENTSTORE_LOCK:
        _EVENTSTORE_QUEUE.append(doc)
        # Coarse cap to avoid unbounded memory if store is down.
        if len(_EVENTSTORE_QUEUE) > 20_000:
            _EVENTSTORE_QUEUE[:] = _EVENTSTORE_QUEUE[-20_000:]


def _eventstore_flush_once(max_items: int = 500) -> int:
    if not EVENTSTORE_ENABLED or not EVENTSTORE_URL:
        return 0
    batch: list[dict] = []
    with _EVENTSTORE_LOCK:
        if not _EVENTSTORE_QUEUE:
            return 0
        take = min(max_items, len(_EVENTSTORE_QUEUE))
        batch = _EVENTSTORE_QUEUE[:take]
        del _EVENTSTORE_QUEUE[:take]

    # Bulk API expects NDJSON: action line + doc line.
    lines: list[str] = []
    for doc in batch:
        doc_id = str(doc.get("event_id") or "")
        action = {"index": {"_index": EVENTSTORE_INDEX}}
        if doc_id:
            action["index"]["_id"] = doc_id
        lines.append(json.dumps(action))
        lines.append(json.dumps(doc))
    data = "\n".join(lines) + "\n"

    try:
        resp = requests.post(
            urljoin(EVENTSTORE_URL, "_bulk"),
            data=data,
            headers={"Content-Type": "application/x-ndjson"},
            timeout=5,
            auth=_eventstore_auth(),
            verify=EVENTSTORE_TLS_VERIFY,
        )
        if not resp.ok:
            raise RuntimeError(f"bulk http {resp.status_code}")
        return len(batch)
    except Exception:
        # Put batch back (front) so we try again later.
        with _EVENTSTORE_LOCK:
            _EVENTSTORE_QUEUE[:0] = batch
        return 0


class IngestInput(BaseModel):
    event_id: Optional[str] = None
    user_id: str
    email: str
    source: str
    message: str
    event_type: str
    language: str = "en"
    consent_use_for_distillation: bool = False
    tenant: Optional[str] = None


class ProcessEventRequest(BaseModel):
    event_id: str
    payload: IngestInput
    scenario_id: Optional[str] = None


class CorrelationDryRunIn(BaseModel):
    rule_id: str


def hmac_hash(value: str, length: int = 16) -> str:
    """Keyed HMAC-SHA256 truncated to `length` hex chars.

    Truncated HMAC still resists rainbow-table attacks because the per-deployment
    secret is unknown to attackers, unlike a plain SHA-256 of a known identifier.
    """
    if value is None:
        return ""
    digest = hmac.new(
        HMAC_SECRET.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:length]


def anonymize_record(payload: IngestInput) -> Dict[str, Any]:
    email_domain = ""
    if "@" in payload.email:
        email_domain = payload.email.split("@", 1)[1].lower()

    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": payload.event_id,
        "user_id_hash": hmac_hash(payload.user_id),
        "email_hash": hmac_hash(payload.email),
        "email_domain": email_domain,
        "source": payload.source,
        "event_type": payload.event_type,
        "language": payload.language,
        "message": payload.message,
    }


def extract_features(message: str) -> Dict[str, Any]:
    msg = str(message).lower()

    return {
        "schema_version": SCHEMA_VERSION,
        "contains_link": int(("http" in msg) or ("https" in msg)),
        "contains_password": int(
            ("password" in msg) or ("passphrase" in msg) or ("reset" in msg)
        ),
        "contains_urgent": int(
            ("urgent" in msg) or ("immediately" in msg) or ("expire" in msg)
        ),
        "contains_reward": int(
            ("gift card" in msg) or ("bonus" in msg) or ("reward" in msg)
        ),
        "len_message": len(msg),
    }


def append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def post_json(url: str, payload: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
    resp = requests.post(
        url,
        json=payload,
        timeout=timeout,
        headers={"X-API-Key": SOC_API_KEY},
    )

    try:
        data = resp.json()
    except Exception:
        data = {"detail": resp.text}

    if not resp.ok:
        raise HTTPException(status_code=resp.status_code, detail=data)

    return data


@app.get("/health")
def health():
    return {
        "status": "up",
        "schema_version": SCHEMA_VERSION,
        "hmac_keyed": HMAC_SECRET != _DEFAULT_DEV_SECRET,
        "siem": SIEM.status(),
        "siem_spool": SPOOL.status(),
    }


@app.get(
    "/siem/spool/status",
    responses={400: {"description": "Invalid destination name"}},
)
def siem_spool_status(
    dest: Optional[str] = None,
    _: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))] = None,
) -> Dict[str, Any]:
    siem = SIEM.status()
    spool = SPOOL.status()
    if dest is None:
        return {"siem": siem, "spool": spool}

    dest = str(dest).strip()
    if dest not in _SPOOL_DEST_ALLOWLIST:
        raise HTTPException(status_code=400, detail=f"invalid dest {dest!r}")

    by_dest = spool.get("by_destination") if isinstance(spool, dict) else None
    filtered = (by_dest or {}).get(dest) if isinstance(by_dest, dict) else None
    return {
        "siem": {dest: siem.get(dest, {})} if isinstance(siem, dict) else {},
        "spool": {
            "enabled": spool.get("enabled"),
            "dir": spool.get("dir"),
            "segments_total": spool.get("segments_total"),
            "bytes_total": spool.get("bytes_total"),
            "stats": spool.get("stats"),
            "destination": dest,
            "destination_status": filtered or {"segments": 0, "bytes": 0, "oldest_age_seconds": None},
        },
    }


@app.post(
    "/siem/spool/flush",
    responses={400: {"description": "Invalid destination name"}},
)
def siem_spool_flush(
    dest: Optional[str] = None,
    _: Annotated[Dict[str, Any], Depends(require_roles("admin"))] = None,
) -> Dict[str, Any]:
    if dest is not None:
        dest = str(dest).strip()
        if dest not in _SPOOL_DEST_ALLOWLIST:
            raise HTTPException(status_code=400, detail=f"invalid dest {dest!r}")
    return {"flush": SPOOL.flush_once(emit_one=SIEM.emit_one, dest=dest)}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(_: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))]) -> str:
    """Prometheus text-format metrics (protected by SOC API key)."""
    st = SPOOL.status()
    siem = SIEM.status()
    lines: list[str] = []
    _metrics_collector(lines)
    _metrics_siem(lines, siem)
    _metrics_spool(lines, st)
    lines.append("")
    return "\n".join(lines)


def _metrics_collector(lines: list[str]) -> None:
    lines.append("# HELP wicys_collector_up Collector service up (always 1 for a successful scrape).")
    lines.append("# TYPE wicys_collector_up gauge")
    lines.append("wicys_collector_up 1")


def _metrics_siem(lines: list[str], siem: Dict[str, Any]) -> None:
    lines.append("# HELP wicys_siem_enabled SIEM destination enabled (1/0).")
    lines.append("# TYPE wicys_siem_enabled gauge")
    for dest, info in siem.items():
        if not isinstance(info, dict):
            continue
        enabled = 1 if bool(info.get("enabled")) else 0
        lines.append(f'wicys_siem_enabled{{dest="{dest}"}} {enabled}')

    lines.append("# HELP wicys_siem_configured SIEM destination configured (1/0).")
    lines.append("# TYPE wicys_siem_configured gauge")
    for dest, info in siem.items():
        if not isinstance(info, dict):
            continue
        configured = 1 if bool(info.get("configured")) else 0
        lines.append(f'wicys_siem_configured{{dest="{dest}"}} {configured}')


def _metrics_spool(lines: list[str], st: Dict[str, Any]) -> None:
    lines.append("# HELP wicys_siem_spool_enabled SIEM spool enabled (1/0).")
    lines.append("# TYPE wicys_siem_spool_enabled gauge")
    lines.append(f"wicys_siem_spool_enabled {1 if st.get('enabled') else 0}")

    lines.append("# HELP wicys_siem_spool_segments_total Number of spool segment files.")
    lines.append("# TYPE wicys_siem_spool_segments_total gauge")
    lines.append(f"wicys_siem_spool_segments_total {int(st.get('segments_total') or 0)}")

    lines.append("# HELP wicys_siem_spool_bytes_total Total bytes on disk in spool.")
    lines.append("# TYPE wicys_siem_spool_bytes_total gauge")
    lines.append(f"wicys_siem_spool_bytes_total {int(st.get('bytes_total') or 0)}")

    _metrics_spool_by_dest(lines, st.get("by_destination"))
    _metrics_spool_counters(lines, st.get("stats"))


def _metrics_spool_by_dest(lines: list[str], by_dest: Any) -> None:
    if not isinstance(by_dest, dict):
        return
    lines.append("# HELP wicys_siem_spool_segments Spool segment files by destination.")
    lines.append("# TYPE wicys_siem_spool_segments gauge")
    lines.append("# HELP wicys_siem_spool_bytes Spool bytes by destination.")
    lines.append("# TYPE wicys_siem_spool_bytes gauge")
    lines.append("# HELP wicys_siem_spool_oldest_age_seconds Oldest queued record age by destination.")
    lines.append("# TYPE wicys_siem_spool_oldest_age_seconds gauge")
    for dest, info in by_dest.items():
        if not isinstance(info, dict):
            continue
        segs = int(info.get("segments") or 0)
        b = int(info.get("bytes") or 0)
        age = info.get("oldest_age_seconds")
        lines.append(f'wicys_siem_spool_segments{{dest="{dest}"}} {segs}')
        lines.append(f'wicys_siem_spool_bytes{{dest="{dest}"}} {b}')
        try:
            if age is None:
                continue
            age_f = float(age)
        except Exception:
            continue
        lines.append(f'wicys_siem_spool_oldest_age_seconds{{dest="{dest}"}} {age_f:.3f}')


def _metrics_spool_counters(lines: list[str], stats: Any) -> None:
    if not isinstance(stats, dict):
        return
    lines.append("# HELP wicys_siem_spool_enqueued_total Total records enqueued to spool.")
    lines.append("# TYPE wicys_siem_spool_enqueued_total counter")
    lines.append(f"wicys_siem_spool_enqueued_total {int(stats.get('enqueued') or 0)}")

    lines.append("# HELP wicys_siem_spool_delivered_total Total records delivered from spool.")
    lines.append("# TYPE wicys_siem_spool_delivered_total counter")
    lines.append(f"wicys_siem_spool_delivered_total {int(stats.get('delivered') or 0)}")

    lines.append("# HELP wicys_siem_spool_requeued_total Total records requeued after failed delivery.")
    lines.append("# TYPE wicys_siem_spool_requeued_total counter")
    lines.append(f"wicys_siem_spool_requeued_total {int(stats.get('requeued') or 0)}")

    lines.append("# HELP wicys_siem_spool_dropped_total Total records dropped by reason.")
    lines.append("# TYPE wicys_siem_spool_dropped_total counter")
    lines.append(f'wicys_siem_spool_dropped_total{{reason="max_bytes"}} {int(stats.get("dropped_max_bytes") or 0)}')
    lines.append(f'wicys_siem_spool_dropped_total{{reason="max_files"}} {int(stats.get("dropped_max_files") or 0)}')
    lines.append(f'wicys_siem_spool_dropped_total{{reason="max_attempts"}} {int(stats.get("dropped_max_attempts") or 0)}')


@app.on_event("startup")
def _startup() -> None:
    global _SPOOL_THREAD, _EVENTSTORE_THREAD
    _maybe_start_spool_thread()
    _maybe_start_eventstore_thread()
    _maybe_start_correlation_thread()


def _maybe_start_spool_thread() -> None:
    global _SPOOL_THREAD
    if not SPOOL_CFG.enabled:
        return
    _SPOOL_STOP.clear()

    def _loop() -> None:
        interval = max(1.0, float(SPOOL_CFG.flush_interval_seconds))
        while not _SPOOL_STOP.is_set():
            try:
                SPOOL.flush_once(emit_one=SIEM.emit_one)
            except Exception as exc:
                log.warning("siem spool flush failed: %s", exc)
            _SPOOL_STOP.wait(interval)

    _SPOOL_THREAD = threading.Thread(target=_loop, name="siem-spool-flush", daemon=True)
    _SPOOL_THREAD.start()


def _maybe_start_eventstore_thread() -> None:
    global _EVENTSTORE_THREAD
    if not EVENTSTORE_ENABLED:
        return
    _eventstore_put_index_template()
    _eventstore_put_entity_index_template()
    _EVENTSTORE_STOP.clear()

    def _es_loop() -> None:
        while not _EVENTSTORE_STOP.is_set():
            try:
                _ = _eventstore_flush_once()
            except Exception as exc:
                log.warning("eventstore flush failed: %s", exc)
            _EVENTSTORE_STOP.wait(1.0)

    _EVENTSTORE_THREAD = threading.Thread(target=_es_loop, name="eventstore-flush", daemon=True)
    _EVENTSTORE_THREAD.start()


@app.on_event("shutdown")
def _shutdown() -> None:
    _SPOOL_STOP.set()
    _EVENTSTORE_STOP.set()
    _CORR_STOP.set()
    time.sleep(0.05)


@app.post("/ingest")
def ingest(
    payload: IngestInput,
    principal: Annotated[Dict[str, Any], Depends(get_principal)],
):
    soc_tenant = _resolve_ingest_soc_tenant(principal, payload.tenant)
    anon_record = anonymize_record(payload)
    features = extract_features(payload.message)

    detector_payload = {
        "anon_record": anon_record,
        "features": features,
    }

    detector_result = post_json(f"{DETECTOR_URL}/score", detector_payload)

    record = {
        "schema_version": SCHEMA_VERSION,
        "ingested_at": utc_now(),
        "event_id": payload.event_id,
        "soc_tenant": soc_tenant,
        "anon_record": anon_record,
        "features": features,
        "detector_result": detector_result,
        "consent_use_for_distillation": bool(payload.consent_use_for_distillation),
    }
    record["ecs"] = normalize_ecs(
        event_id=payload.event_id,
        ingested_at_iso=str(record.get("ingested_at") or ""),
        source=str(payload.source or ""),
        event_type=str(payload.event_type or ""),
        language=str(payload.language or ""),
        anon_record=anon_record,
        features=features,
        detector_result=detector_result,
        soc_tenant=soc_tenant,
    )
    append_jsonl(INGESTED_PATH, record)
    _eventstore_enqueue(record)
    _enrich_entities(record)

    _emit_siem_best_effort(anon_record, features, detector_result)

    return {
        "status": "ok",
        "schema_version": SCHEMA_VERSION,
        "anon_record": anon_record,
        "features": features,
        "detector_result": detector_result,
        "human_triage_hint": detector_result.get("explanation", ""),
    }


def _emit_siem_best_effort(anon_record: Dict[str, Any], features: Dict[str, Any], detector_result: Dict[str, Any]) -> None:
    """Emit anonymized SIEM event, optionally spooling failures to disk."""
    siem_event = {
        "kind": "collector_ingest",
        "source": anon_record.get("source"),
        "event_type": anon_record.get("event_type"),
        "language": anon_record.get("language"),
        "email_domain": anon_record.get("email_domain"),
        "user_id_hash": anon_record.get("user_id_hash"),
        "email_hash": anon_record.get("email_hash"),
        "features": features,
        "detector_result": detector_result,
    }
    try:
        results = SIEM.emit(siem_event)
        _spool_failures(results, siem_event)
    except Exception as e:
        log.warning("SIEM emit failed: %s", e)
        _spool_exception(e, siem_event)


def _spool_failures(results: Any, siem_event: Dict[str, Any]) -> None:
    if not SPOOL_CFG.enabled:
        return
    if not isinstance(results, dict):
        return
    for dest, res in results.items():
        if not isinstance(res, dict):
            continue
        if res.get("ok") is True:
            continue
        err = str(res.get("error") or res.get("body") or "emit_failed")
        SPOOL.enqueue(dest=str(dest), event=siem_event, error=err)


def _spool_exception(e: Exception, siem_event: Dict[str, Any]) -> None:
    if not SPOOL_CFG.enabled:
        return
    for dest in SIEM.enabled_destinations():
        SPOOL.enqueue(dest=dest, event=siem_event, error=f"exception:{e.__class__.__name__}")


@app.post("/process_event")
def process_event(req: ProcessEventRequest, _: Annotated[None, Depends(require_api_key)]):
    """Forward a structured event to the orchestrator.

    This lets the collector UI on :8001 display the end-to-end decision
    (detector + policy + LLM) for a single event.
    """
    orchestrator_payload = {
        "event_id": req.event_id,
        "payload": req.payload.model_dump(),
        "scenario_id": req.scenario_id,
    }

    return post_json(
        f"{ORCHESTRATOR_URL}/process_event",
        orchestrator_payload,
    )


@app.get(
    "/search",
    responses={
        403: {"description": "include_message requires analyst/admin role"},
    },
)
def search_events(
    since_ms: Optional[int] = None,
    until_ms: Optional[int] = None,
    event_id: Optional[str] = None,
    event_ids: Optional[str] = None,
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    language: Optional[str] = None,
    user_id_hash: Optional[str] = None,
    email_domain: Optional[str] = None,
    q: Optional[str] = None,
    tenant: Optional[str] = None,
    limit: int = 200,
    cursor: int = 0,
    include_message: int = 0,
    principal: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))] = None,
) -> Dict[str, Any]:
    """Workshop-scale search over persisted ingested events.

    Commercial SIEMs provide a full indexed event store + query language.
    This endpoint is a stepping stone: it enables pivots from dashboards to
    time-bounded raw (anonymized) events without introducing new infra.
    """
    roles = {str(r).strip().lower() for r in (principal or {}).get("roles", [])}
    want_msg = bool(include_message)
    _enforce_message_access(want_msg=want_msg, roles=roles)

    limit_n = max(1, min(int(limit or 200), 1000))
    cursor_n = max(0, int(cursor or 0))

    scope_tenant = _resolve_search_soc_tenant(principal or {}, tenant)
    filt = _search_filter(
        since_ms=since_ms,
        until_ms=until_ms,
        event_id=event_id,
        event_ids=event_ids,
        source=source,
        event_type=event_type,
        language=language,
        user_id_hash=user_id_hash,
        email_domain=email_domain,
        q=q,
        lowercase_q=not (EVENTSTORE_ENABLED and EVENTSTORE_URL),
        soc_tenant=scope_tenant,
    )
    return _search_dispatch(filt=filt, limit=limit_n, cursor=cursor_n, want_msg=want_msg)


@app.get(
    "/entities",
    responses={
        400: {"description": "Entity search requires OpenSearch enabled"},
        500: {"description": "Entity search failed"},
    },
)
def entities(
    q: Optional[str] = None,
    entity_type: Optional[str] = None,
    tenant: Optional[str] = None,
    limit: int = 50,
    cursor: int = 0,
    principal: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))] = None,
) -> Dict[str, Any]:
    scope_tenant = _resolve_search_soc_tenant(principal or {}, tenant)
    return _entities_search(q=q, entity_type=entity_type, limit=limit, cursor=cursor, soc_tenant=scope_tenant)


@app.get(
    "/search/facets",
    responses={
        400: {"description": "Facets require OpenSearch enabled"},
        500: {"description": "Facets query failed"},
    },
)
def search_facets(
    since_ms: Optional[int] = None,
    until_ms: Optional[int] = None,
    event_id: Optional[str] = None,
    event_ids: Optional[str] = None,
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    language: Optional[str] = None,
    user_id_hash: Optional[str] = None,
    email_domain: Optional[str] = None,
    q: Optional[str] = None,
    tenant: Optional[str] = None,
    size: int = 10,
    principal: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))] = None,
) -> Dict[str, Any]:
    if not (EVENTSTORE_ENABLED and EVENTSTORE_URL):
        raise HTTPException(status_code=400, detail="eventstore disabled")
    size_n = max(1, min(int(size or 10), 50))
    scope_tenant = _resolve_search_soc_tenant(principal or {}, tenant)
    filt = _search_filter(
        since_ms=since_ms,
        until_ms=until_ms,
        event_id=event_id,
        event_ids=event_ids,
        source=source,
        event_type=event_type,
        language=language,
        user_id_hash=user_id_hash,
        email_domain=email_domain,
        q=q,
        lowercase_q=False,
        soc_tenant=scope_tenant,
    )
    body = _opensearch_facets_body(filt=filt, size=size_n)
    try:
        resp = requests.post(
            urljoin(EVENTSTORE_URL, f"{EVENTSTORE_INDEX}/_search"),
            json=body,
            timeout=8,
            auth=_eventstore_auth(),
            verify=EVENTSTORE_TLS_VERIFY,
        )
        data = resp.json() if resp.ok else {}
        aggs = (data.get("aggregations") or {}) if isinstance(data, dict) else {}
        return {
            "size": size_n,
            "facets": {
                "source": _agg_buckets(aggs.get("source")),
                "event_type": _agg_buckets(aggs.get("event_type")),
                "email_domain": _agg_buckets(aggs.get("email_domain")),
                "policy_rule_id": _agg_buckets(aggs.get("policy_rule_id")),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"facets failed: {e.__class__.__name__}")


@app.post("/correlation/dry_run")
def correlation_dry_run(
    body: CorrelationDryRunIn,
    _: Annotated[Dict[str, Any], Depends(require_roles("analyst", "admin"))],
) -> Dict[str, Any]:
    """Evaluate a correlation rule against OpenSearch without writing a notable."""
    rid = (body.rule_id or "").strip()
    if not rid:
        raise HTTPException(status_code=400, detail="rule_id required")
    rules, searches = _corr_fetch()
    sidx = _corr_search_index(searches)
    rule = next((r for r in rules if isinstance(r, dict) and str(r.get("rule_id")) == rid), None)
    if not rule:
        raise HTTPException(status_code=404, detail="rule not found")
    mode = str(rule.get("mode") or "search").strip().lower()
    if mode == "sequence":
        return {"dry_run": True, **_corr_dry_run_sequence(rule=rule, searches=sidx)}
    sid = str(rule.get("search_id") or "")
    s = sidx.get(sid)
    if not s:
        raise HTTPException(status_code=400, detail="saved search missing for rule")
    return {"dry_run": True, **_corr_dry_run_search(rule=rule, search=s)}


def _agg_buckets(agg: Any) -> list[Dict[str, Any]]:
    if not isinstance(agg, dict):
        return []
    buckets = agg.get("buckets")
    if not isinstance(buckets, list):
        return []
    out: list[Dict[str, Any]] = []
    for b in buckets:
        if not isinstance(b, dict):
            continue
        k = b.get("key")
        v = b.get("doc_count")
        if k is None:
            continue
        out.append({"key": k, "count": int(v or 0)})
    return out


def _opensearch_facets_body(*, filt: Dict[str, Any], size: int) -> Dict[str, Any]:
    base = _opensearch_query_body(filt=filt, limit=0, cursor=0, want_msg=False)
    base["size"] = 0
    base.pop("sort", None)
    base["aggs"] = {
        "source": {"terms": {"field": _OS_F_SRC, "size": size}},
        "event_type": {"terms": {"field": _OS_F_ET, "size": size}},
        "email_domain": {"terms": {"field": _OS_F_DOM, "size": size}},
        "policy_rule_id": {"terms": {"field": _OS_F_RULE, "size": size}},
    }
    return base


def _entities_search(
    *,
    q: Optional[str],
    entity_type: Optional[str],
    limit: int,
    cursor: int,
    soc_tenant: Optional[str] = None,
) -> Dict[str, Any]:
    if not (EVENTSTORE_ENABLED and EVENTSTORE_URL):
        raise HTTPException(status_code=400, detail="eventstore disabled")

    limit_n = max(1, min(int(limit or 50), 500))
    cursor_n = max(0, int(cursor or 0))
    must = _entity_query_must(q=q, entity_type=entity_type, soc_tenant=soc_tenant)
    body: Dict[str, Any] = {
        "size": limit_n,
        "from": cursor_n,
        "query": {"bool": {"must": must or [{"match_all": {}}]}},
        "sort": [{"last_seen": {"order": "desc"}}],
    }
    data = _entity_opensearch_search(body)
    items, count = _entity_parse_hits(data)
    next_cursor = cursor_n + len(items) if (cursor_n + len(items)) < count else None
    return {"count": count, "items": items, "next_cursor": next_cursor, "source": "opensearch"}


def _entity_query_must(*, q: Optional[str], entity_type: Optional[str], soc_tenant: Optional[str] = None) -> list[Dict[str, Any]]:
    must: list[Dict[str, Any]] = []
    st = str(soc_tenant or "").strip()
    if st:
        must.append({"term": {"soc_tenant": st}})
    if entity_type:
        must.append({"term": {"entity_type": str(entity_type)}})
    if q:
        must.append(
            {
                "multi_match": {
                    "query": str(q),
                    "fields": ["entity_id^3", "entity_key^2", "display^2", "attributes.*"],
                }
            }
        )
    return must


def _entity_opensearch_search(body: Dict[str, Any]) -> Dict[str, Any]:
    resp = requests.post(
        urljoin(EVENTSTORE_URL, f"{ENTITY_INDEX}/_search"),
        json=body,
        timeout=8,
        auth=_eventstore_auth(),
        verify=EVENTSTORE_TLS_VERIFY,
    )
    return resp.json() if resp.ok else {}


def _entity_parse_hits(data: Dict[str, Any]) -> tuple[list[Dict[str, Any]], int]:
    hits = (((data or {}).get("hits") or {}).get("hits") or []) if isinstance(data, dict) else []
    items = [(h.get("_source") or {}) for h in hits if isinstance(h, dict)]
    total_val = ((data.get("hits") or {}).get("total") or {}).get("value") if isinstance(data, dict) else None
    count = int(total_val or len(items))
    return items, count


def _search_dispatch(*, filt: Dict[str, Any], limit: int, cursor: int, want_msg: bool) -> Dict[str, Any]:
    if EVENTSTORE_ENABLED and EVENTSTORE_URL:
        return _search_opensearch(filt=filt, limit=limit, cursor=cursor, want_msg=want_msg)
    rows = _load_ingested_rows()
    if not rows:
        return {"count": 0, "items": [], "next_cursor": None}
    matched_total, out_rows = _collect_matches(rows, filt=filt, limit=limit, cursor=cursor, want_msg=want_msg)
    next_cursor = (cursor + len(out_rows)) if (cursor + len(out_rows)) < matched_total else None
    return {"count": matched_total, "items": out_rows, "next_cursor": next_cursor}


def _search_filter(
    *,
    since_ms: Optional[int],
    until_ms: Optional[int],
    event_id: Optional[str],
    event_ids: Optional[str],
    source: Optional[str],
    event_type: Optional[str],
    language: Optional[str],
    user_id_hash: Optional[str],
    email_domain: Optional[str],
    q: Optional[str],
    lowercase_q: bool,
    soc_tenant: Optional[str] = None,
) -> Dict[str, Any]:
    qv = (q or "").strip()
    out: Dict[str, Any] = {
        "since_ms": since_ms,
        "until_ms": until_ms,
        "event_id": (event_id or "").strip(),
        "event_ids": _parse_event_ids(event_ids),
        "source": (source or "").strip(),
        "event_type": (event_type or "").strip(),
        "language": (language or "").strip(),
        "user_id_hash": (user_id_hash or "").strip(),
        "email_domain": (email_domain or "").strip(),
        "q": qv.lower() if lowercase_q else qv,
    }
    st = (soc_tenant or "").strip()
    if st:
        out["soc_tenant"] = st
    return out


def _parse_event_ids(raw: Optional[str]) -> list[str]:
    if not raw:
        return []
    out: list[str] = []
    for part in str(raw).split(","):
        p = part.strip()
        if p:
            out.append(p)
    return out[:500]


def _search_opensearch(*, filt: Dict[str, Any], limit: int, cursor: int, want_msg: bool) -> Dict[str, Any]:
    body = _opensearch_query_body(filt=filt, limit=limit, cursor=cursor, want_msg=want_msg)

    try:
        resp = requests.post(
            urljoin(EVENTSTORE_URL, f"{EVENTSTORE_INDEX}/_search"),
            json=body,
            timeout=5,
            auth=_eventstore_auth(),
            verify=EVENTSTORE_TLS_VERIFY,
        )
        data = resp.json() if resp.ok else {}
    except Exception:
        # fallback to file-based search if store is unavailable
        rows = _load_ingested_rows()
        filt2 = dict(filt)
        filt2["q"] = str(filt2.get("q") or "").strip().lower()
        matched_total, out_rows = _collect_matches(rows, filt=filt2, limit=limit, cursor=cursor, want_msg=want_msg)
        next_cursor = (cursor + len(out_rows)) if (cursor + len(out_rows)) < matched_total else None
        return {"count": matched_total, "items": out_rows, "next_cursor": next_cursor, "source": "fallback_jsonl"}

    hits = (data.get("hits") or {}).get("hits") or []
    total = (data.get("hits") or {}).get("total") or {}
    try:
        total_n = int(total.get("value") if isinstance(total, dict) else total)
    except Exception:
        total_n = len(hits)
    items = [h.get("_source") for h in hits if isinstance(h, dict) and isinstance(h.get("_source"), dict)]
    next_cursor = (cursor + len(items)) if (cursor + len(items)) < total_n else None
    return {"count": total_n, "items": items, "next_cursor": next_cursor, "source": "opensearch"}


def _opensearch_query_body(*, filt: Dict[str, Any], limit: int, cursor: int, want_msg: bool) -> Dict[str, Any]:
    must: list[Dict[str, Any]] = []
    flt: list[Dict[str, Any]] = []

    src = str(filt.get("source") or "").strip()
    et = str(filt.get("event_type") or "").strip()
    lang = str(filt.get("language") or "").strip()
    ev = str(filt.get("event_id") or "").strip()
    eids = filt.get("event_ids") if isinstance(filt.get("event_ids"), list) else []
    uid = str(filt.get("user_id_hash") or "").strip()
    dom = str(filt.get("email_domain") or "").strip()
    q = str(filt.get("q") or "").strip()
    since_ms = filt.get("since_ms")
    until_ms = filt.get("until_ms")

    flt.extend(_opensearch_filters(ev=ev, eids=eids, src=src, et=et, lang=lang, uid=uid, dom=dom, since_ms=since_ms, until_ms=until_ms))
    soc_scope = str(filt.get("soc_tenant") or "").strip()
    if soc_scope:
        flt.append({"term": {"soc_tenant": soc_scope}})
    must.extend(_opensearch_must(q=q))

    body: Dict[str, Any] = {
        "query": {"bool": {"filter": flt, "must": must}},
        "from": int(cursor),
        "size": int(limit),
        "sort": [{"ingested_at": {"order": "desc"}}],
    }
    if not want_msg:
        body["_source"] = {"excludes": ["anon_record.message"]}
    return body


def _opensearch_filters(
    *,
    ev: str,
    eids: list[str],
    src: str,
    et: str,
    lang: str,
    uid: str,
    dom: str,
    since_ms: Any,
    until_ms: Any,
) -> list[Dict[str, Any]]:
    flt: list[Dict[str, Any]] = []
    if eids:
        flt.append({"terms": {"event_id": eids}})
    elif ev:
        flt.append({"term": {"event_id": ev}})
    if src:
        flt.append({"term": {_OS_F_SRC: src}})
    if et:
        flt.append({"term": {_OS_F_ET: et}})
    if lang:
        flt.append({"term": {_OS_F_LANG: lang}})
    if uid:
        flt.append({"term": {_OS_F_UID: uid}})
    if dom:
        flt.append({"term": {_OS_F_DOM: dom}})
    if since_ms is not None or until_ms is not None:
        flt.append({"range": {"ingested_at": _opensearch_time_range(since_ms=since_ms, until_ms=until_ms)}})
    return flt


def _opensearch_must(*, q: str) -> list[Dict[str, Any]]:
    if not q:
        return []
    return [
        {
            "simple_query_string": {
                "query": q,
                "fields": [_OS_F_MSG, _OS_F_SRC, _OS_F_ET],
                "default_operator": "and",
            }
        }
    ]


def _opensearch_time_range(*, since_ms: Any, until_ms: Any) -> Dict[str, Any]:
    rng: Dict[str, Any] = {"format": "epoch_millis"}
    if since_ms is not None:
        rng["gte"] = int(since_ms)
    if until_ms is not None:
        rng["lte"] = int(until_ms)
    return rng


def _enforce_message_access(*, want_msg: bool, roles: set[str]) -> None:
    if want_msg and not ({"analyst", "admin"} & roles):
        raise HTTPException(status_code=403, detail="include_message requires analyst/admin role")


def _load_ingested_rows() -> list[Dict[str, Any]]:
    if not INGESTED_PATH.exists():
        return []
    out: list[Dict[str, Any]] = []
    with open(INGESTED_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out


def _ingested_ts_ms(rec: Dict[str, Any]) -> Optional[int]:
    t = rec.get("ingested_at")
    if not isinstance(t, str) or not t:
        return None
    try:
        return int(datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp() * 1000)
    except Exception:
        return None


def _matches(rec: Dict[str, Any], filt: Dict[str, Any]) -> bool:
    st = str(filt.get("soc_tenant") or "").strip()
    if st and str(rec.get("soc_tenant") or "") != st:
        return False
    anon = rec.get("anon_record") if isinstance(rec.get("anon_record"), dict) else {}
    if not _matches_fields(anon, filt):
        return False
    if not _matches_time(rec, filt):
        return False
    return _matches_query(anon, filt)


def _matches_fields(anon: Dict[str, Any], filt: Dict[str, Any]) -> bool:
    ev = str(filt.get("event_id") or "").strip()
    eids = filt.get("event_ids") if isinstance(filt.get("event_ids"), list) else []
    src = str(filt.get("source") or "")
    et = str(filt.get("event_type") or "")
    lang = str(filt.get("language") or "")
    uid = str(filt.get("user_id_hash") or "")
    dom = str(filt.get("email_domain") or "")
    aid = str(anon.get("event_id") or "")
    if eids:
        if aid not in [str(x) for x in eids]:
            return False
    elif ev and aid != ev:
        return False
    return (
        _match_term(anon, "source", src)
        and _match_term(anon, "event_type", et)
        and _match_term(anon, "language", lang)
        and _match_term(anon, "user_id_hash", uid)
        and _match_term(anon, "email_domain", dom)
    )


def _match_term(anon: Dict[str, Any], key: str, expected: str) -> bool:
    if not expected:
        return True
    return str(anon.get(key) or "") == expected


def _matches_time(rec: Dict[str, Any], filt: Dict[str, Any]) -> bool:
    ts = _ingested_ts_ms(rec)
    since_ms = filt.get("since_ms")
    until_ms = filt.get("until_ms")
    if since_ms is not None and ts is not None and ts < int(since_ms):
        return False
    if until_ms is not None and ts is not None and ts > int(until_ms):
        return False
    return True


def _matches_query(anon: Dict[str, Any], filt: Dict[str, Any]) -> bool:
    q = str(filt.get("q") or "")
    if q:
        hay = " ".join(
            [
                str(anon.get("message") or ""),
                str(anon.get("source") or ""),
                str(anon.get("event_type") or ""),
            ]
        ).lower()
        return q in hay
    return True


def _strip_message(rec: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(rec)
    if isinstance(out.get("anon_record"), dict):
        out_anon = dict(out["anon_record"])
        out_anon.pop("message", None)
        out["anon_record"] = out_anon
    return out


def _collect_matches(
    rows: list[Dict[str, Any]],
    *,
    filt: Dict[str, Any],
    limit: int,
    cursor: int,
    want_msg: bool,
) -> tuple[int, list[Dict[str, Any]]]:
    matched_total = 0
    skipped = 0
    out_rows: list[Dict[str, Any]] = []
    for rec in reversed(rows):  # newest-first
        if not _matches(rec, filt):
            continue
        matched_total += 1
        if skipped < cursor:
            skipped += 1
            continue
        out_rows.append(dict(rec) if want_msg else _strip_message(rec))
        if len(out_rows) >= limit:
            break
    return matched_total, out_rows


@app.get("/")
def serve_index():
    return FileResponse(STATIC_DIR / "index.html")
