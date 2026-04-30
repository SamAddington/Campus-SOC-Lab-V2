from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, model_validator
from pathlib import Path
from typing import Any, Dict, List, Optional, Annotated
from datetime import datetime, timedelta, timezone
import asyncio
import json
import logging
import os
import uuid

import sys
sys.path.insert(0, "/app")
from shared.security import auth_enabled, record_signature, require_api_key
from shared.security import require_roles

app = FastAPI(title="WiCyS Audit Service")

from shared.hardening import apply_hardening, RateLimitConfig

apply_hardening(app, max_body_bytes=2_000_000, rate_limit=RateLimitConfig(requests=240, per_seconds=60))

_LOG = logging.getLogger("audit")

_CASE_NOT_FOUND = "Case not found"

# ---------------------------------------------------------------------------
# In-memory SSE pub/sub.
# Each subscriber gets its own asyncio.Queue. Publishers call _publish() from
# the same event loop (all endpoints are async), so asyncio.Queue is safe.
# ---------------------------------------------------------------------------
_SUBSCRIBERS: "list[asyncio.Queue[dict]]" = []
_SSE_QUEUE_MAX = 200


def _publish(event_type: str, payload: Dict[str, Any]) -> None:
    envelope = {"event": event_type, "data": payload}
    dead: "list[asyncio.Queue[dict]]" = []
    for q in _SUBSCRIBERS:
        try:
            q.put_nowait(envelope)
        except asyncio.QueueFull:
            # Slow client — drop oldest and push newest so stream stays current.
            try:
                q.get_nowait()
                q.put_nowait(envelope)
            except Exception:
                dead.append(q)
        except Exception:
            dead.append(q)
    for q in dead:
        try:
            _SUBSCRIBERS.remove(q)
        except ValueError:
            pass

LEDGER_DIR = Path("/app/ledger")
LEDGER_DIR.mkdir(parents=True, exist_ok=True)
AUDIT_SIGNING_KEY = os.getenv("AUDIT_SIGNING_KEY", "change-me-dev-audit-signing-key")
AUDIT_RETENTION_DAYS = int(os.getenv("AUDIT_RETENTION_DAYS", "90"))

DECISIONS_PATH = LEDGER_DIR / "decision_cards.jsonl"
OVERRIDES_PATH = LEDGER_DIR / "overrides.jsonl"
POLICY_EVENTS_PATH = LEDGER_DIR / "policy_events.jsonl"
SIM_RUNS_PATH = LEDGER_DIR / "simulation_runs.jsonl"
CASES_PATH = LEDGER_DIR / "cases.jsonl"
CASE_NOTES_PATH = LEDGER_DIR / "case_notes.jsonl"
OPERATOR_ACTIONS_PATH = LEDGER_DIR / "operator_actions.jsonl"
SAVED_SEARCHES_PATH = LEDGER_DIR / "saved_searches.jsonl"
CORRELATION_RULES_PATH = LEDGER_DIR / "correlation_rules.jsonl"
CORRELATION_ALERTS_PATH = LEDGER_DIR / "correlation_alerts.jsonl"


class DecisionCard(BaseModel):
    schema_version: Optional[str] = "v1"
    decision_card_id: str
    event_id: str
    timestamp: str
    source: str
    event_type: str
    language: str
    risk_score_rule: float
    risk_score_fl: Optional[float] = None
    risk_score_final: float
    label: str
    explanation: str
    policy_rule_id: str
    permitted_action: str
    requires_human_review: bool
    final_human_action: Optional[str] = None
    scenario_id: Optional[str] = None
    model_round: Optional[int] = None
    threshold_version: Optional[str] = "default"
    analyst_summary: Optional[str] = None
    helpdesk_explanation: Optional[str] = None
    next_steps: Optional[List[str]] = None
    llm_used: Optional[bool] = None
    llm_reason: Optional[str] = None
    # Phase 1: teacher/student provenance
    llm_tier: Optional[str] = None
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    # Phase 0: consent propagation for downstream distillation
    consent_use_for_distillation: Optional[bool] = False
    # Phase 4: OSINT enrichment provenance
    osint_enabled: Optional[bool] = None
    osint_skipped: Optional[bool] = None
    osint_verdict: Optional[str] = None
    osint_score: Optional[float] = None
    osint_indicator_count: Optional[int] = None
    osint_providers_used: Optional[List[str]] = None
    osint_short_explanation: Optional[str] = None


class OverrideRecord(BaseModel):
    decision_card_id: str
    event_id: str
    reviewer_id: str
    original_action: str
    overridden_action: str
    reason: str
    timestamp: Optional[str] = None


class CaseRecord(BaseModel):
    case_id: Optional[str] = None
    title: str
    description: str = ""
    status: str = "open"  # open|triaged|in_progress|pending_customer|resolved|closed
    severity: str = "medium"  # low|medium|high|critical
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    created_by: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: List[str] = []
    related_decision_cards: List[str] = []
    related_event_ids: List[str] = []
    # SLA / workflow timestamps (ISO)
    sla_response_due_at: Optional[str] = None
    first_acknowledged_at: Optional[str] = None
    resolved_at: Optional[str] = None


class CaseNote(BaseModel):
    case_id: str
    note_id: Optional[str] = None
    author: Optional[str] = None
    body: str
    created_at: Optional[str] = None


class OperatorAction(BaseModel):
    action_id: Optional[str] = None
    actor: str
    action: str
    resource: str = ""
    detail: Dict[str, Any] = {}
    created_at: Optional[str] = None


class SavedSearch(BaseModel):
    search_id: Optional[str] = None
    name: str
    description: str = ""
    # Filter/query parameters (collector /search contract)
    q: str = ""
    source: str = ""
    event_type: str = ""
    language: str = ""
    include_message: bool = False
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    created_by: Optional[str] = None


class CorrelationRule(BaseModel):
    rule_id: Optional[str] = None
    name: str
    description: str = ""
    enabled: bool = True
    severity: str = "medium"  # low|medium|high|critical
    # Reference a saved search (by id) + schedule (simple mode)
    search_id: str = ""
    schedule_seconds: int = 60
    # Simple de-dup window: do not re-alert on same rule within this many seconds
    dedup_seconds: int = 300
    # Sequence mode (EQL-ish): ordered steps within a window, optionally joined by a key.
    mode: str = "search"  # search|sequence
    within_seconds: int = 600
    by_field: str = "anon_record.user_id_hash"
    steps: List[Dict[str, Any]] = Field(default_factory=list)  # [{name, search_id, q, source, event_type, language}]
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    created_by: Optional[str] = None

    @model_validator(mode="after")
    def _validate_mode(self) -> "CorrelationRule":
        mode = str(self.mode or "search").strip().lower()
        if mode == "sequence":
            if not self.steps or len(self.steps) < 2:
                raise ValueError("sequence mode requires at least 2 steps")
            for i, st in enumerate(self.steps):
                if not isinstance(st, dict):
                    raise ValueError(f"steps[{i}] must be an object")
                sid = str(st.get("search_id") or "").strip()
                has_inline = bool(str(st.get("q") or "").strip() or str(st.get("source") or "").strip() or str(st.get("event_type") or "").strip())
                if not sid and not has_inline:
                    raise ValueError(f"steps[{i}] requires search_id or inline q/source/event_type")
        else:
            if not str(self.search_id or "").strip():
                raise ValueError("search mode requires search_id")
        return self


class CorrelationAlert(BaseModel):
    alert_id: Optional[str] = None
    rule_id: str
    rule_name: str
    severity: str = "medium"
    summary: str
    match_count: int = 0
    sample_event_ids: List[str] = []
    created_at: Optional[str] = None
    # Query context that produced the alert (for pivots)
    query: Dict[str, Any] = {}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _case_sla_response_hours(severity: str) -> int:
    sev = (severity or "medium").strip().lower()
    defaults = {"critical": 4, "high": 8, "medium": 24, "low": 72}
    env_key = {
        "critical": "CASE_SLA_RESPONSE_HOURS_CRITICAL",
        "high": "CASE_SLA_RESPONSE_HOURS_HIGH",
        "medium": "CASE_SLA_RESPONSE_HOURS_MEDIUM",
        "low": "CASE_SLA_RESPONSE_HOURS_LOW",
    }.get(sev, "CASE_SLA_RESPONSE_HOURS_MEDIUM")
    return int(os.getenv(env_key, str(defaults.get(sev, 24))))


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _find_latest_by_id(rows: List[Dict[str, Any]], key: str, value: str) -> Optional[Dict[str, Any]]:
    for r in reversed(rows):
        if str(r.get(key) or "") == value:
            return r
    return None


def _append_operator_action(*, principal: Dict[str, Any], action: str, resource: str, detail: Dict[str, Any]) -> None:
    append_jsonl(
        OPERATOR_ACTIONS_PATH,
        {
            "action_id": _new_id("act"),
            "actor": str(principal.get("sub") or "unknown"),
            "action": action,
            "resource": resource,
            "detail": detail,
            "created_at": utc_now(),
        },
    )


def append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    previous_hash = ""
    if path.exists():
        try:
            with open(path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                pos = max(size - 4096, 0)
                f.seek(pos)
                tail = f.read().decode("utf-8", errors="ignore")
                last_line = ""
                for line in tail.splitlines():
                    if line.strip():
                        last_line = line.strip()
                if last_line:
                    last_obj = json.loads(last_line)
                    previous_hash = str(last_obj.get("record_hash", ""))
        except Exception:
            previous_hash = ""

    if not obj.get("timestamp"):
        obj["timestamp"] = utc_now()
    obj["previous_hash"] = previous_hash
    canonical = json.dumps(obj, sort_keys=True)
    obj["record_hash"] = record_signature(AUDIT_SIGNING_KEY, canonical)

    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def _purge_expired(path: Path, retention_days: int) -> int:
    rows = read_jsonl(path)
    if not rows:
        return 0
    now = datetime.now(timezone.utc)
    kept: List[Dict[str, Any]] = []
    removed = 0
    for r in rows:
        ts = r.get("timestamp")
        try:
            dt = datetime.fromisoformat(ts) if isinstance(ts, str) else None
        except Exception:
            dt = None
        if dt is None:
            kept.append(r)
            continue
        age_days = (now - dt).days
        if age_days > retention_days:
            removed += 1
        else:
            kept.append(r)
    if removed:
        with open(path, "w", encoding="utf-8") as f:
            for row in kept:
                f.write(json.dumps(row) + "\n")
    return removed


@app.get("/health")
def health():
    return {"status": "up"}


@app.post("/log_decision")
async def log_decision(card: DecisionCard, _: Annotated[None, Depends(require_api_key)] = None):
    record = card.model_dump()
    append_jsonl(DECISIONS_PATH, record)
    _publish("decision", record)
    return {"status": "logged", "decision_card_id": card.decision_card_id}


@app.post("/log_override")
async def log_override(
    override: OverrideRecord,
    _: Annotated[Dict[str, Any], Depends(require_roles("analyst", "admin"))],
):
    record = override.model_dump()
    if not record.get("timestamp"):
        record["timestamp"] = utc_now()
    append_jsonl(OVERRIDES_PATH, record)
    _publish("override", record)
    return {"status": "logged", "decision_card_id": override.decision_card_id}


# ---------------------------------------------------------------------------
# Server-Sent Events stream. Browsers auto-reconnect, so we keep the handler
# simple: one asyncio.Queue per client, heartbeats every 15s.
# ---------------------------------------------------------------------------


@app.get("/stream")
async def stream(request: Request):
    q: "asyncio.Queue[dict]" = asyncio.Queue(maxsize=_SSE_QUEUE_MAX)
    _SUBSCRIBERS.append(q)

    async def event_source():
        try:
            yield (
                "retry: 3000\n"
                "event: hello\n"
                f"data: {json.dumps({'subscribers': len(_SUBSCRIBERS)})}\n\n"
            )
            while True:
                if await request.is_disconnected():
                    break
                try:
                    envelope = await asyncio.wait_for(q.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
                    continue
                event = envelope.get("event", "message")
                data = envelope.get("data", {})
                yield f"event: {event}\ndata: {json.dumps(data)}\n\n"
        except asyncio.CancelledError:
            raise
        finally:
            try:
                _SUBSCRIBERS.remove(q)
            except ValueError:
                pass

    headers = {
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return StreamingResponse(event_source(), media_type="text/event-stream", headers=headers)


@app.get("/decision_cards")
def decision_cards(limit: int = 20, _: Annotated[None, Depends(require_api_key)] = None):
    rows = read_jsonl(DECISIONS_PATH)
    return {"count": len(rows), "items": rows[-limit:]}


@app.get("/overrides")
def overrides(limit: int = 20, _: Annotated[None, Depends(require_api_key)] = None):
    rows = read_jsonl(OVERRIDES_PATH)
    return {"count": len(rows), "items": rows[-limit:]}


@app.get("/summary")
def summary(_: Annotated[None, Depends(require_api_key)] = None):
    decisions = read_jsonl(DECISIONS_PATH)
    overrides = read_jsonl(OVERRIDES_PATH)

    action_counts: Dict[str, int] = {}
    rule_counts: Dict[str, int] = {}
    scenario_counts: Dict[str, int] = {}
    llm_tier_counts: Dict[str, int] = {}
    llm_provider_counts: Dict[str, int] = {}
    osint_verdict_counts: Dict[str, int] = {}
    osint_enriched = 0

    for d in decisions:
        action = d.get("permitted_action", "unknown")
        rule = d.get("policy_rule_id", "unknown")
        scenario = d.get("scenario_id") or "none"
        # LLM breakdown:
        # - If llm_used is true, provider/tier should be present; otherwise bucket as not_used.
        llm_used = d.get("llm_used")
        if llm_used:
            tier = d.get("llm_tier") or "unspecified"
            provider = d.get("llm_provider") or "unspecified"
        else:
            tier = "not_used"
            provider = "not_used"

        # OSINT breakdown:
        # - If enabled and not skipped -> verdict (or no_verdict)
        # - If disabled -> disabled
        # - If skipped -> skipped
        osint_enabled = d.get("osint_enabled")
        osint_skipped = d.get("osint_skipped")
        if osint_enabled and not osint_skipped:
            verdict_raw = d.get("osint_verdict")
            ind_count = d.get("osint_indicator_count")
            try:
                ind_n = int(ind_count) if ind_count is not None else 0
            except Exception:
                ind_n = 0
            if not verdict_raw:
                osint_verdict = "no_verdict"
            else:
                v = str(verdict_raw).lower()
                # If OSINT ran but extracted zero indicators, "unknown" is misleading.
                osint_verdict = "no_indicators" if (v == "unknown" and ind_n == 0) else v
        elif osint_enabled is False:
            osint_verdict = "disabled"
        elif osint_skipped:
            osint_verdict = "skipped"
        else:
            osint_verdict = "not_used"

        action_counts[action] = action_counts.get(action, 0) + 1
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
        scenario_counts[scenario] = scenario_counts.get(scenario, 0) + 1
        llm_tier_counts[tier] = llm_tier_counts.get(tier, 0) + 1
        llm_provider_counts[provider] = llm_provider_counts.get(provider, 0) + 1
        osint_verdict_counts[osint_verdict] = osint_verdict_counts.get(osint_verdict, 0) + 1
        if osint_enabled and not osint_skipped:
            osint_enriched += 1

    return {
        "total_decisions": len(decisions),
        "total_overrides": len(overrides),
        "action_counts": action_counts,
        "policy_rule_counts": rule_counts,
        "scenario_counts": scenario_counts,
        "llm_tier_counts": llm_tier_counts,
        "llm_provider_counts": llm_provider_counts,
        "osint_verdict_counts": osint_verdict_counts,
        "osint_enriched_count": osint_enriched,
    }


@app.get("/cases")
def list_cases(
    limit: int = 100,
    _: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))] = None,
):
    rows = read_jsonl(CASES_PATH)
    items = rows[-max(1, min(int(limit or 100), 1000)) :]
    return {"count": len(rows), "items": items}


@app.post("/cases")
def create_case(
    case: CaseRecord,
    principal: Annotated[Dict[str, Any], Depends(require_roles("analyst", "admin"))],
):
    rec = case.model_dump()
    rec["case_id"] = rec.get("case_id") or _new_id("case")
    rec["created_at"] = rec.get("created_at") or utc_now()
    rec["updated_at"] = utc_now()
    rec["created_by"] = rec.get("created_by") or str(principal.get("sub") or "unknown")
    if not rec.get("sla_response_due_at"):
        hrs = _case_sla_response_hours(str(rec.get("severity") or "medium"))
        rec["sla_response_due_at"] = (datetime.now(timezone.utc) + timedelta(hours=hrs)).isoformat()
    append_jsonl(CASES_PATH, rec)
    _append_operator_action(
        principal=principal,
        action="case.create",
        resource=rec["case_id"],
        detail={"severity": rec.get("severity"), "status": rec.get("status")},
    )
    _publish("case", rec)
    return {"status": "created", "case_id": rec["case_id"]}


@app.get("/cases/{case_id}")
@app.get("/cases/{case_id}", responses={404: {"description": "Case not found"}})
def get_case(case_id: str, _: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))] = None):
    rows = read_jsonl(CASES_PATH)
    found = _find_latest_by_id(rows, "case_id", case_id)
    if not found:
        raise HTTPException(status_code=404, detail=_CASE_NOT_FOUND)
    notes = [n for n in read_jsonl(CASE_NOTES_PATH) if str(n.get("case_id") or "") == case_id]
    return {"case": found, "notes": notes}


@app.post("/cases/{case_id}/assign", responses={404: {"description": "Case not found"}})
def assign_case(
    case_id: str,
    assigned_to: str,
    principal: Annotated[Dict[str, Any], Depends(require_roles("analyst", "admin"))],
):
    rows = read_jsonl(CASES_PATH)
    cur = _find_latest_by_id(rows, "case_id", case_id)
    if not cur:
        raise HTTPException(status_code=404, detail=_CASE_NOT_FOUND)
    rec = dict(cur)
    rec["assigned_to"] = (assigned_to or "").strip() or None
    rec["updated_at"] = utc_now()
    rec["updated_by"] = str(principal.get("sub") or "unknown")
    if rec.get("assigned_to") and not rec.get("first_acknowledged_at"):
        rec["first_acknowledged_at"] = utc_now()
    append_jsonl(CASES_PATH, rec)
    _append_operator_action(
        principal=principal,
        action="case.assign",
        resource=case_id,
        detail={"assigned_to": rec.get("assigned_to")},
    )
    _publish("case", rec)
    return {"status": "ok", "case_id": case_id, "assigned_to": rec["assigned_to"]}


@app.post(
    "/cases/{case_id}/status",
    responses={400: {"description": "Invalid status"}, 404: {"description": "Case not found"}},
)
def set_case_status(
    case_id: str,
    status: str,
    principal: Annotated[Dict[str, Any], Depends(require_roles("analyst", "admin"))],
):
    next_status = (status or "").strip().lower()
    allowed = {"open", "triaged", "in_progress", "pending_customer", "resolved", "closed"}
    if next_status not in allowed:
        raise HTTPException(status_code=400, detail="invalid status")
    rows = read_jsonl(CASES_PATH)
    cur = _find_latest_by_id(rows, "case_id", case_id)
    if not cur:
        raise HTTPException(status_code=404, detail=_CASE_NOT_FOUND)
    rec = dict(cur)
    rec["status"] = next_status
    rec["updated_at"] = utc_now()
    rec["updated_by"] = str(principal.get("sub") or "unknown")
    if next_status in {"triaged", "in_progress"} and not rec.get("first_acknowledged_at"):
        rec["first_acknowledged_at"] = utc_now()
    if next_status in {"resolved", "closed"}:
        rec["resolved_at"] = utc_now()
    append_jsonl(CASES_PATH, rec)
    _append_operator_action(
        principal=principal,
        action="case.status",
        resource=case_id,
        detail={"status": next_status},
    )
    _publish("case", rec)
    return {"status": "ok", "case_id": case_id, "case_status": next_status}


@app.post("/cases/{case_id}/notes", responses={404: {"description": "Case not found"}})
def add_case_note(
    case_id: str,
    note: CaseNote,
    principal: Annotated[Dict[str, Any], Depends(require_roles("analyst", "admin"))],
):
    # Ensure case exists
    rows = read_jsonl(CASES_PATH)
    if not _find_latest_by_id(rows, "case_id", case_id):
        raise HTTPException(status_code=404, detail=_CASE_NOT_FOUND)
    rec = note.model_dump()
    rec["case_id"] = case_id
    rec["note_id"] = rec.get("note_id") or _new_id("note")
    rec["author"] = rec.get("author") or str(principal.get("sub") or "unknown")
    rec["created_at"] = rec.get("created_at") or utc_now()
    append_jsonl(CASE_NOTES_PATH, rec)
    _append_operator_action(
        principal=principal,
        action="case.note",
        resource=case_id,
        detail={"note_id": rec.get("note_id")},
    )
    _publish("case_note", rec)
    return {"status": "ok", "case_id": case_id, "note_id": rec["note_id"]}


@app.get("/saved_searches")
def saved_searches(limit: int = 200, _: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))] = None):
    rows = read_jsonl(SAVED_SEARCHES_PATH)
    items = rows[-max(1, min(int(limit or 200), 2000)) :]
    return {"count": len(rows), "items": items}


@app.post("/saved_searches")
def saved_search_create(
    s: SavedSearch,
    principal: Annotated[Dict[str, Any], Depends(require_roles("analyst", "admin"))],
):
    rec = s.model_dump()
    rec["search_id"] = rec.get("search_id") or _new_id("search")
    rec["created_at"] = rec.get("created_at") or utc_now()
    rec["updated_at"] = utc_now()
    rec["created_by"] = rec.get("created_by") or str(principal.get("sub") or "unknown")
    append_jsonl(SAVED_SEARCHES_PATH, rec)
    _append_operator_action(principal=principal, action="saved_search.create", resource=rec["search_id"], detail={"name": rec.get("name")})
    _publish("saved_search", rec)
    return {"status": "created", "search_id": rec["search_id"]}


@app.post("/correlation/rules")
def correlation_rule_create(
    r: CorrelationRule,
    principal: Annotated[Dict[str, Any], Depends(require_roles("analyst", "admin"))],
):
    rec = r.model_dump()
    rec["rule_id"] = rec.get("rule_id") or _new_id("rule")
    rec["created_at"] = rec.get("created_at") or utc_now()
    rec["updated_at"] = utc_now()
    rec["created_by"] = rec.get("created_by") or str(principal.get("sub") or "unknown")
    append_jsonl(CORRELATION_RULES_PATH, rec)
    _append_operator_action(principal=principal, action="correlation_rule.create", resource=rec["rule_id"], detail={"name": rec.get("name")})
    _publish("correlation_rule", rec)
    return {"status": "created", "rule_id": rec["rule_id"]}


@app.get("/correlation/rules")
def correlation_rules(limit: int = 500, _: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))] = None):
    rows = read_jsonl(CORRELATION_RULES_PATH)
    items = rows[-max(1, min(int(limit or 500), 5000)) :]
    return {"count": len(rows), "items": items}


@app.post("/correlation/alerts")
def correlation_alert_create(
    a: CorrelationAlert,
    principal: Annotated[Dict[str, Any], Depends(require_roles("admin"))],
):
    rec = a.model_dump()
    rec["alert_id"] = rec.get("alert_id") or _new_id("alert")
    rec["created_at"] = rec.get("created_at") or utc_now()
    append_jsonl(CORRELATION_ALERTS_PATH, rec)
    _append_operator_action(
        principal=principal,
        action="correlation_alert.create",
        resource=rec["alert_id"],
        detail={"rule_id": rec.get("rule_id"), "severity": rec.get("severity"), "match_count": rec.get("match_count")},
    )
    _publish("correlation_alert", rec)
    return {"status": "created", "alert_id": rec["alert_id"]}


@app.get("/correlation/alerts")
def correlation_alerts(limit: int = 200, _: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))] = None):
    rows = read_jsonl(CORRELATION_ALERTS_PATH)
    items = rows[-max(1, min(int(limit or 200), 2000)) :]
    return {"count": len(rows), "items": items}


@app.post("/log_operator_action")
def log_operator_action(
    act: OperatorAction,
    principal: Annotated[Dict[str, Any], Depends(require_roles("analyst", "admin"))],
):
    rec = act.model_dump()
    rec["action_id"] = rec.get("action_id") or _new_id("act")
    rec["created_at"] = rec.get("created_at") or utc_now()
    # Force actor from principal (don't trust client-supplied).
    rec["actor"] = str(principal.get("sub") or "unknown")
    append_jsonl(OPERATOR_ACTIONS_PATH, rec)
    return {"status": "ok", "action_id": rec["action_id"]}
    
class SimulationRun(BaseModel):
    scenario_id: str
    description: str = ""
    target_url: str
    pace_ms: int
    total_events: int
    success_count: int
    error_count: int
    started_at: str
    ended_at: str


@app.post("/log_simulation_run")
def log_simulation_run(run: SimulationRun, _: Annotated[None, Depends(require_api_key)] = None):
    append_jsonl(SIM_RUNS_PATH, run.model_dump())
    return {"status": "logged", "scenario_id": run.scenario_id}


@app.post("/retention/purge")
def purge_retention(_: Annotated[Dict[str, Any], Depends(require_roles("admin"))]):
    removed = {
        "decision_cards": _purge_expired(DECISIONS_PATH, AUDIT_RETENTION_DAYS),
        "overrides": _purge_expired(OVERRIDES_PATH, AUDIT_RETENTION_DAYS),
        "simulation_runs": _purge_expired(SIM_RUNS_PATH, AUDIT_RETENTION_DAYS),
    }
    return {"status": "ok", "retention_days": AUDIT_RETENTION_DAYS, "removed": removed}


@app.get("/integrity/verify")
def verify_integrity(_: Annotated[None, Depends(require_api_key)] = None):
    def _verify(path: Path) -> Dict[str, Any]:
        rows = read_jsonl(path)
        prev = ""
        checked = 0
        for row in rows:
            row_copy = dict(row)
            expected = row_copy.pop("record_hash", "")
            canonical = json.dumps(row_copy, sort_keys=True)
            calc = record_signature(AUDIT_SIGNING_KEY, canonical)
            if row_copy.get("previous_hash", "") != prev or expected != calc:
                return {"ok": False, "checked": checked, "path": str(path)}
            prev = expected
            checked += 1
        return {"ok": True, "checked": checked, "path": str(path)}

    return {
        "auth_enabled": auth_enabled(),
        "decision_cards": _verify(DECISIONS_PATH),
        "overrides": _verify(OVERRIDES_PATH),
        "simulation_runs": _verify(SIM_RUNS_PATH),
    }