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
import requests

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
LLM_ASSISTANT_URL = os.getenv("LLM_ASSISTANT_URL", "http://llm_assistant:8024").rstrip("/")
TRAINING_LLM_GRADING_ENABLED = os.getenv("TRAINING_LLM_GRADING_ENABLED", "1").strip().lower() in ("1", "true", "yes", "on")

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
TRAINING_RUNS_PATH = LEDGER_DIR / "training_runs.jsonl"
TRAINING_ACTIONS_PATH = LEDGER_DIR / "training_actions.jsonl"


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


class TrainingChallenge(BaseModel):
    challenge_id: str
    name: str
    difficulty: str = "beginner"  # beginner|intermediate|advanced
    category: str = "phishing"    # phishing|ddos|malware|insider|other
    description: str = ""
    briefing: str = ""
    objectives: List[Dict[str, Any]] = Field(default_factory=list)  # [{id,title,required}]
    rubric: Dict[str, Any] = Field(default_factory=dict)            # weights, pass score, gates, etc.


class TrainingRun(BaseModel):
    run_id: str
    challenge_id: str
    trainee_id: str = ""
    status: str = "in_progress"  # in_progress|completed|abandoned
    started_at: str
    completed_at: Optional[str] = None
    score: Optional[float] = None
    passed: Optional[bool] = None
    report: Dict[str, Any] = Field(default_factory=dict)


class TrainingAction(BaseModel):
    action_id: str
    run_id: str
    trainee_id: str = ""
    action_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: str


class TrainingStartRequest(BaseModel):
    challenge_id: str


class TrainingActionRequest(BaseModel):
    run_id: str
    action_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)


class TrainingCompleteRequest(BaseModel):
    run_id: str


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


def _training_challenges() -> List[TrainingChallenge]:
    """MVP challenge catalog (code-defined)."""
    late_night = TrainingChallenge(
        challenge_id="late-night-phishing",
        name="Late-night phishing campaign",
        difficulty="beginner",
        category="phishing",
        description="Investigate a burst of suspicious emails after hours; scope the campaign and choose safe response steps.",
        briefing=(
            "### Situation\n"
            "It’s **01:42 local time**. The helpdesk and after-hours hotline report a burst of **password reset / account verification** emails. "
            "Multiple users say they received similar messages within minutes.\n\n"
            "### Your role\n"
            "You are the **on-call SOC analyst**. Your job is to determine whether this is a coordinated phishing campaign, scope impact, "
            "and document safe response steps.\n\n"
            "### Constraints (training guardrails)\n"
            "- Treat this as a **training lab**: you do not have production authority.\n"
            "- Avoid disruptive actions without evidence.\n"
            "- Write notes as if another analyst will take over at shift change.\n\n"
            "### What you should produce\n"
            "1) A case with a short summary and severity.\n"
            "2) At least **two concrete indicators** (URL/domain/sender/subject theme/user reports).\n"
            "3) A short scope statement (who/what/when/how) + next pivots.\n"
            "4) A response plan (user comms, containment options, monitoring).\n\n"
            "### Hints\n"
            "- Look for shared subject lines, sender patterns, and link themes.\n"
            "- Separate what you *know* from what you *suspect*.\n"
        ),
        objectives=[
            {"id": "open_case", "title": "Open an investigation case with severity + short summary.", "required": True},
            {"id": "document_indicators", "title": "Document at least 2 indicators (e.g., subject theme, sender pattern, URL/domain, user reports).", "required": True},
            {"id": "scope_campaign", "title": "Describe scope (who/what/when) and recommend next pivots.", "required": True},
            {"id": "response_steps", "title": "Provide safe response steps (user comms, containment, monitoring).", "required": True},
        ],
        rubric={
            "pass_score": 0.70,
            "weights": {
                "open_case": 0.25,
                "document_indicators": 0.25,
                "scope_campaign": 0.25,
                "response_steps": 0.25,
            },
        },
    )
    ddos = TrainingChallenge(
        challenge_id="full-scale-ddos",
        name="Full-scale DDoS attack",
        difficulty="intermediate",
        category="ddos",
        description="Investigate a large traffic spike and propose a safe mitigation plan without unsafe automated enforcement.",
        briefing=(
            "### Situation\n"
            "It’s **02:17 local time**. Operators report intermittent timeouts for public-facing services. "
            "Network telemetry indicates a sharp, sustained increase in inbound traffic volume. "
            "You suspect a **volumetric DDoS** or coordinated abuse.\n\n"
            "### Your role\n"
            "You are the **SOC analyst coordinating with network operations**. Your goal is to:\n"
            "1) confirm whether the pattern is consistent with DDoS, 2) document scope/impact, and 3) recommend safe mitigations.\n\n"
            "### Constraints (training guardrails)\n"
            "- This lab uses **aggregate-only telemetry** (no raw IPs/payloads).\n"
            "- Guardrail: **do not recommend blanket automated enforcement** (e.g., “block all IPs”) based only on aggregate anomaly signals.\n"
            "- Prefer staged mitigations: rate limiting, upstream/provider coordination, WAF/CDN protections, and comms.\n\n"
            "### What you should produce\n"
            "1) A high/critical case summary.\n"
            "2) At least two observations: impacted service(s), timeframe, traffic pattern, symptoms.\n"
            "3) A scope statement: what is degraded, where, when.\n"
            "4) A mitigation plan including upstream/provider actions + customer comms.\n\n"
            "### Hints\n"
            "- Avoid overconfident attribution.\n"
            "- Emphasize safe mitigations and coordination steps.\n"
        ),
        objectives=[
            {"id": "open_case", "title": "Open an investigation case (high/critical) with short incident summary.", "required": True},
            {"id": "document_indicators", "title": "Document at least 2 indicators/observations (target service, timeframe, traffic pattern, affected users).", "required": True},
            {"id": "scope_campaign", "title": "Describe scope and impact (what is degraded, where, when).", "required": True},
            {"id": "response_steps", "title": "Provide mitigation steps and comms plan (include upstream/provider actions).", "required": True},
            {"id": "guardrails_no_auto_enforcement", "title": "Avoid unsafe automated enforcement recommendations (no blanket IP blocks from aggregate-only signals).", "required": True},
        ],
        rubric={
            "pass_score": 0.75,
            "weights": {
                "open_case": 0.20,
                "document_indicators": 0.20,
                "scope_campaign": 0.20,
                "response_steps": 0.30,
                "guardrails_no_auto_enforcement": 0.10,
            },
            "guardrails": {
                "forbidden_phrases": [
                    "auto-block",
                    "automatically block",
                    "block all",
                    "blackhole all",
                    "drop all traffic",
                    "block every ip",
                    "block all ips",
                ]
            },
        },
    )
    acct_compromise = TrainingChallenge(
        challenge_id="account-compromise-o365-google",
        name="Account compromise (O365/Google)",
        difficulty="beginner",
        category="iam",
        description="Investigate suspicious sign-ins and determine whether an account is compromised (impossible travel, risky locations, MFA prompts).",
        briefing=(
            "### Situation\n"
            "It’s **08:05**. The helpdesk reports a surge of \"I got an MFA prompt I didn’t request\" calls. "
            "Your IdP dashboard shows several recent sign-ins for the same user from **two distant geolocations** within minutes.\n\n"
            "### Your role\n"
            "You are the SOC analyst. Your job is to quickly triage the suspected account compromise, document evidence, and recommend safe containment steps.\n\n"
            "### What you should produce\n"
            "1) Case with severity and a one-paragraph summary.\n"
            "2) Indicators: sign-in timestamps, locations/IP ranges (as available), device/user-agent changes, MFA anomalies.\n"
            "3) Scope: affected accounts, apps accessed, any risky actions (mailbox rules, OAuth grants).\n"
            "4) Response plan: credential reset, session revocation, MFA rebind, risky sign-in policy review, comms.\n\n"
            "### Example artifacts (training)\n"
            "- A sign-in timeline showing **impossible travel** and new device.\n"
            "- A badge/flag for \"Impossible travel\" or \"Atypical location\".\n"
        ),
        objectives=[
            {"id": "open_case", "title": "Open an investigation case with severity + short summary.", "required": True},
            {"id": "document_indicators", "title": "Document indicators (sign-in timeline, location/device change, MFA prompt reports).", "required": True},
            {"id": "scope_campaign", "title": "Scope the incident (accounts/apps/sessions) and propose next pivots.", "required": True},
            {"id": "response_steps", "title": "Provide containment and recovery steps (revoke sessions, reset creds, MFA posture).", "required": True},
        ],
        rubric={
            "pass_score": 0.75,
            "weights": {"open_case": 0.25, "document_indicators": 0.25, "scope_campaign": 0.25, "response_steps": 0.25},
        },
    )

    bec = TrainingChallenge(
        challenge_id="bec-mailbox-rules",
        name="Business Email Compromise (BEC)",
        difficulty="intermediate",
        category="phishing",
        description="Triage suspected mailbox compromise and malicious forwarding/rules; recommend safe steps and evidence preservation.",
        briefing=(
            "### Situation\n"
            "Finance reports an \"urgent vendor update\" email thread that looks legitimate — but the bank account details changed. "
            "Separately, mail admins see unusual **inbox rules** and **forwarding** configured on an executive mailbox.\n\n"
            "### Your role\n"
            "You are the SOC analyst coordinating with email admins and finance. "
            "Your goal is to determine whether this is BEC, preserve evidence, and stop further fraud.\n\n"
            "### What you should produce\n"
            "1) Case summary (what happened, who reported it, immediate risk).\n"
            "2) Indicators: suspicious reply-to, forwarding target, new mailbox rules, OAuth grants, IP/device anomalies.\n"
            "3) Scope: other mailboxes affected, similar rules, impacted vendor threads.\n"
            "4) Response plan: disable forwarding/rules, reset creds, revoke sessions, finance fraud playbook, notify stakeholders.\n\n"
            "### Example artifacts (training)\n"
            "- A \"rule chain\" panel showing how mail was forwarded or hidden.\n"
        ),
        objectives=[
            {"id": "open_case", "title": "Open an investigation case with severity + short summary.", "required": True},
            {"id": "document_indicators", "title": "Document mailbox rule/forwarding indicators and suspicious email headers/themes.", "required": True},
            {"id": "scope_campaign", "title": "Scope affected mailboxes and threads; propose pivots (rules search, OAuth grants).", "required": True},
            {"id": "response_steps", "title": "Provide containment steps + finance coordination and evidence preservation.", "required": True},
        ],
        rubric={
            "pass_score": 0.78,
            "weights": {"open_case": 0.22, "document_indicators": 0.28, "scope_campaign": 0.25, "response_steps": 0.25},
        },
    )

    ransomware = TrainingChallenge(
        challenge_id="ransomware-outbreak",
        name="Ransomware outbreak",
        difficulty="advanced",
        category="malware",
        description="Investigate a fast-moving ransomware outbreak; scope blast radius and propose containment and recovery steps.",
        briefing=(
            "### Situation\n"
            "Users report files renamed with a new extension and ransom notes on shared drives. "
            "EDR alerts show multiple hosts spawning encryption-like activity.\n\n"
            "### Your role\n"
            "You are the SOC analyst on an incident bridge. Your goal is to rapidly assess impact, contain spread safely, "
            "and document an initial recovery plan.\n\n"
            "### What you should produce\n"
            "1) Critical-severity case summary.\n"
            "2) Indicators: affected hostnames, file extension, ransom note name, suspicious parent process, lateral movement hints.\n"
            "3) Scope: blast radius (which hosts and shares), time of first impact, likely initial access vector.\n"
            "4) Response plan: isolate hosts, disable compromised accounts, preserve evidence, backups, comms.\n\n"
            "### Example artifacts (training)\n"
            "- A blast-radius host grid.\n"
            "- An \"encryption progress\" meter.\n"
        ),
        objectives=[
            {"id": "open_case", "title": "Open an investigation case (critical) with short incident summary.", "required": True},
            {"id": "document_indicators", "title": "Document indicators (extension, ransom note, suspicious process, impacted hosts/shares).", "required": True},
            {"id": "scope_campaign", "title": "Scope blast radius and propose next pivots (patient zero, lateral spread).", "required": True},
            {"id": "response_steps", "title": "Provide containment and recovery steps (isolation, backups, comms).", "required": True},
        ],
        rubric={
            "pass_score": 0.80,
            "weights": {"open_case": 0.20, "document_indicators": 0.30, "scope_campaign": 0.25, "response_steps": 0.25},
        },
    )

    endpoint_malware = TrainingChallenge(
        challenge_id="endpoint-malware-infostealer",
        name="Malware on endpoint (trojan/infostealer)",
        difficulty="intermediate",
        category="malware",
        description="Triage suspicious endpoint behavior; document process tree and likely C2 beacons; propose safe containment.",
        briefing=(
            "### Situation\n"
            "EDR flags a user workstation for suspicious child processes and repeated outbound connections to a rare domain. "
            "The user reports a \"new PDF viewer\" install.\n\n"
            "### Your role\n"
            "You are the SOC analyst. Your goal is to determine whether this is malware (trojan/infostealer), "
            "document evidence, and recommend safe containment steps.\n\n"
            "### What you should produce\n"
            "1) Case summary with severity.\n"
            "2) Indicators: process tree (parent/child), file path, hash (if present), outbound domain, periodic beacons.\n"
            "3) Scope: other affected endpoints, user accounts, possible credential exposure.\n"
            "4) Response plan: isolate endpoint, collect triage package, reset creds if needed, hunt across fleet.\n\n"
            "### Example artifacts (training)\n"
            "- A process tree panel.\n"
            "- A C2 beacon ticker (connections every N seconds).\n"
        ),
        objectives=[
            {"id": "open_case", "title": "Open an investigation case with severity + short summary.", "required": True},
            {"id": "document_indicators", "title": "Document indicators (process tree, domain/C2 pattern, file path/hash).", "required": True},
            {"id": "scope_campaign", "title": "Scope affected endpoints/accounts; propose hunt pivots.", "required": True},
            {"id": "response_steps", "title": "Provide containment and triage steps (isolate, collect evidence, reset creds).", "required": True},
        ],
        rubric={
            "pass_score": 0.77,
            "weights": {"open_case": 0.22, "document_indicators": 0.28, "scope_campaign": 0.25, "response_steps": 0.25},
        },
    )

    cred_stuffing = TrainingChallenge(
        challenge_id="credential-stuffing-bruteforce",
        name="Credential stuffing / brute force",
        difficulty="beginner",
        category="iam",
        description="Investigate repeated auth failures and lockouts; identify targeted accounts and recommend safe mitigations.",
        briefing=(
            "### Situation\n"
            "Authentication logs show a sharp increase in failed logins against student and staff accounts. "
            "Several accounts are now locked out. Traffic appears automated.\n\n"
            "### Your role\n"
            "You are the SOC analyst coordinating with IAM. Your goal is to determine whether this is credential stuffing/brute force, "
            "scope impacted accounts/apps, and recommend safe mitigations.\n\n"
            "### What you should produce\n"
            "1) Case summary and severity.\n"
            "2) Indicators: failure rate, lockouts, top targeted usernames, source patterns (as available).\n"
            "3) Scope: which apps/tenants are targeted; whether any successful logins occurred.\n"
            "4) Response plan: tighten rate limits, MFA enforcement, password reset guidance, user comms.\n\n"
            "### Example artifacts (training)\n"
            "- An auth heatmap (failures by minute and app).\n"
            "- A lockout counter.\n"
        ),
        objectives=[
            {"id": "open_case", "title": "Open an investigation case with severity + short summary.", "required": True},
            {"id": "document_indicators", "title": "Document indicators (failure spike, lockouts, targeted accounts/apps).", "required": True},
            {"id": "scope_campaign", "title": "Scope impacted apps/accounts and confirm any successful compromises.", "required": True},
            {"id": "response_steps", "title": "Provide mitigations (rate limits, MFA, password reset + comms).", "required": True},
        ],
        rubric={
            "pass_score": 0.75,
            "weights": {"open_case": 0.25, "document_indicators": 0.25, "scope_campaign": 0.25, "response_steps": 0.25},
        },
    )

    web_app = TrainingChallenge(
        challenge_id="web-app-attack",
        name="Web app attack (SQLi/XSS/credential leak)",
        difficulty="intermediate",
        category="web",
        description="Investigate suspicious WAF / app logs, identify affected endpoints, and propose mitigations and monitoring.",
        briefing=(
            "### Situation\n"
            "The WAF shows a spike in blocked requests with payload-like patterns. "
            "The application team reports elevated 500s on a login endpoint.\n\n"
            "### Your role\n"
            "You are the SOC analyst coordinating with the app team. Your goal is to determine whether this is an active web attack "
            "(SQLi/XSS/credential stuffing) and document impact.\n\n"
            "### What you should produce\n"
            "1) Case summary and severity.\n"
            "2) Indicators: affected endpoint(s), WAF rule IDs/categories, error spike timeframe.\n"
            "3) Scope: which apps/hosts are impacted; whether any suspicious successes occurred.\n"
            "4) Response plan: tighten rules, patch/mitigate, add monitoring, coordinate comms.\n\n"
            "### Example artifacts (training)\n"
            "- WAF/event spike visualization.\n"
            "- Affected endpoint list.\n"
        ),
        objectives=[
            {"id": "open_case", "title": "Open an investigation case with severity + short summary.", "required": True},
            {"id": "document_indicators", "title": "Document indicators (WAF spike, endpoint(s), error timeframe).", "required": True},
            {"id": "scope_campaign", "title": "Scope impacted apps/hosts and propose pivots (logs, auth, DB).", "required": True},
            {"id": "response_steps", "title": "Provide mitigations and monitoring steps with app-team coordination.", "required": True},
        ],
        rubric={
            "pass_score": 0.77,
            "weights": {"open_case": 0.22, "document_indicators": 0.28, "scope_campaign": 0.25, "response_steps": 0.25},
        },
    )

    vuln_exploit = TrainingChallenge(
        challenge_id="vulnerability-exploitation",
        name="Vulnerability exploitation (critical CVE on edge)",
        difficulty="intermediate",
        category="vuln",
        description="Investigate suspected exploitation of a critical CVE; assess patch gap and propose containment and patch plan.",
        briefing=(
            "### Situation\n"
            "Threat intel reports active exploitation of a critical CVE affecting a common edge device/app. "
            "Your telemetry shows suspicious requests consistent with exploit attempts.\n\n"
            "### Your role\n"
            "You are the SOC analyst coordinating with infra. Your goal is to assess exposure (patch gap), "
            "determine whether exploitation occurred, and recommend staged mitigations.\n\n"
            "### What you should produce\n"
            "1) Case summary and severity.\n"
            "2) Indicators: exploit attempt patterns, targeted asset(s), suspicious responses.\n"
            "3) Scope: which systems are vulnerable/unpatched; timeframe; any evidence of post-exploit activity.\n"
            "4) Response plan: mitigations, patch sequencing, monitoring/hunt, comms.\n\n"
            "### Example artifacts (training)\n"
            "- Patch gap meter (patched vs unpatched).\n"
            "- Exploitation chain steps panel.\n"
        ),
        objectives=[
            {"id": "open_case", "title": "Open an investigation case with severity + short summary.", "required": True},
            {"id": "document_indicators", "title": "Document indicators (attempt patterns, vulnerable assets, timeframe).", "required": True},
            {"id": "scope_campaign", "title": "Scope patch gap and impacted systems; propose hunt pivots.", "required": True},
            {"id": "response_steps", "title": "Provide mitigations + patch plan + monitoring steps.", "required": True},
        ],
        rubric={
            "pass_score": 0.77,
            "weights": {"open_case": 0.22, "document_indicators": 0.28, "scope_campaign": 0.25, "response_steps": 0.25},
        },
    )

    exfil = TrainingChallenge(
        challenge_id="data-exfiltration",
        name="Data exfiltration",
        difficulty="advanced",
        category="exfil",
        description="Investigate suspicious outbound data transfer; identify likely destinations and propose containment and evidence steps.",
        briefing=(
            "### Situation\n"
            "Network monitoring detects a sustained spike in outbound data volume from a file server to rare external domains. "
            "The pattern suggests possible data exfiltration.\n\n"
            "### Your role\n"
            "You are the SOC analyst. Your goal is to assess whether the traffic is legitimate, "
            "document likely destinations and impacted datasets, and recommend containment.\n\n"
            "### What you should produce\n"
            "1) Case summary and severity.\n"
            "2) Indicators: bytes-out spike, destination domains/IPs (as available), source hosts/accounts.\n"
            "3) Scope: what data may be affected; timeframe; whether other hosts show similar patterns.\n"
            "4) Response plan: contain (egress controls), preserve evidence, notify stakeholders, hunt.\n\n"
            "### Example artifacts (training)\n"
            "- Exfil gauge (bytes out).\n"
            "- Destination domain list.\n"
        ),
        objectives=[
            {"id": "open_case", "title": "Open an investigation case with severity + short summary.", "required": True},
            {"id": "document_indicators", "title": "Document indicators (bytes-out spike, destinations, sources).", "required": True},
            {"id": "scope_campaign", "title": "Scope impacted systems/data and propose pivots (DLP, auth, endpoint).", "required": True},
            {"id": "response_steps", "title": "Provide containment + evidence preservation + notification steps.", "required": True},
        ],
        rubric={
            "pass_score": 0.80,
            "weights": {"open_case": 0.20, "document_indicators": 0.30, "scope_campaign": 0.25, "response_steps": 0.25},
        },
    )

    insider = TrainingChallenge(
        challenge_id="insider-misuse",
        name="Insider misuse / improper access",
        difficulty="intermediate",
        category="insider",
        description="Investigate unusual access patterns to sensitive resources; document evidence and propose a safe response with HR/legal coordination.",
        briefing=(
            "### Situation\n"
            "A department reports unusual access to a sensitive shared folder outside normal hours. "
            "Audit logs show a user accessing resources they don’t normally touch.\n\n"
            "### Your role\n"
            "You are the SOC analyst. Your goal is to document observable facts, minimize disruption, "
            "and recommend a response that respects privacy, HR/legal coordination, and evidence handling.\n\n"
            "### What you should produce\n"
            "1) Case summary and severity.\n"
            "2) Indicators: access timestamps, resources touched, deviation from baseline.\n"
            "3) Scope: other accounts/resources involved; whether this is misconfiguration vs misuse.\n"
            "4) Response plan: access review, least-privilege, monitoring, HR/legal engagement, comms.\n\n"
            "### Example artifacts (training)\n"
            "- Access graph (user → resource edges).\n"
            "- An anomaly trend line.\n"
        ),
        objectives=[
            {"id": "open_case", "title": "Open an investigation case with severity + short summary.", "required": True},
            {"id": "document_indicators", "title": "Document indicators (resources accessed, off-hours, baseline deviation).", "required": True},
            {"id": "scope_campaign", "title": "Scope accounts/resources; consider misconfig vs misuse; propose pivots.", "required": True},
            {"id": "response_steps", "title": "Provide a safe response plan including HR/legal and evidence handling.", "required": True},
        ],
        rubric={
            "pass_score": 0.77,
            "weights": {"open_case": 0.22, "document_indicators": 0.28, "scope_campaign": 0.25, "response_steps": 0.25},
        },
    )

    return [
        late_night,
        acct_compromise,
        bec,
        ransomware,
        endpoint_malware,
        cred_stuffing,
        ddos,
        web_app,
        vuln_exploit,
        exfil,
        insider,
    ]


def _training_challenge_by_id(challenge_id: str) -> Optional[TrainingChallenge]:
    cid = str(challenge_id or "").strip()
    for c in _training_challenges():
        if c.challenge_id == cid:
            return c
    return None


def _training_latest_run(run_id: str) -> Optional[Dict[str, Any]]:
    return _find_latest_by_id(read_jsonl(TRAINING_RUNS_PATH), "run_id", str(run_id or ""))


def _training_actions_for(run_id: str) -> List[Dict[str, Any]]:
    rid = str(run_id or "")
    return [a for a in read_jsonl(TRAINING_ACTIONS_PATH) if str(a.get("run_id") or "") == rid]


def _training_score(*, challenge: TrainingChallenge, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic MVP scorer. Keeps evaluation explainable."""
    weights = (challenge.rubric or {}).get("weights") if isinstance(challenge.rubric, dict) else None
    weights = weights if isinstance(weights, dict) else {}
    pass_score = float((challenge.rubric or {}).get("pass_score") or 0.7) if isinstance(challenge.rubric, dict) else 0.7

    flags = {obj.get("id"): False for obj in (challenge.objectives or []) if isinstance(obj, dict) and obj.get("id")}
    notes_text: List[str] = []
    response_text: List[str] = []
    for a in actions:
        at = str(a.get("action_type") or "")
        payload = a.get("payload") if isinstance(a.get("payload"), dict) else {}
        if at == "case_create":
            flags["open_case"] = True
        if at in ("case_note", "campaign_note"):
            body = str(payload.get("body") or "")
            if body:
                notes_text.append(body.lower())
        if at == "campaign_scope":
            flags["scope_campaign"] = True
        if at == "response_plan":
            flags["response_steps"] = True
            body2 = str(payload.get("body") or "")
            if body2:
                response_text.append(body2.lower())

    combined = " ".join(notes_text)
    # Minimal heuristic: indicators = look for common indicator-like words.
    indicator_hits = 0
    for kw in ("http", "domain", "sender", "from:", "link", "url", "subject", "spoof", "login", "reset"):
        if kw in combined:
            indicator_hits += 1
    if indicator_hits >= 2:
        flags["document_indicators"] = True

    # Challenge-specific guardrail: no unsafe automated enforcement for DDoS.
    forbidden = []
    if isinstance(challenge.rubric, dict):
        gr = challenge.rubric.get("guardrails")
        if isinstance(gr, dict) and isinstance(gr.get("forbidden_phrases"), list):
            forbidden = [str(x).lower() for x in gr.get("forbidden_phrases") if str(x).strip()]
    resp_combined = " ".join(response_text)
    if "guardrails_no_auto_enforcement" in flags:
        flags["guardrails_no_auto_enforcement"] = True
        hits = [p for p in forbidden if p and p in resp_combined]
        if hits:
            flags["guardrails_no_auto_enforcement"] = False

    # Weighted score: objectives achieved.
    total = 0.0
    by_obj: Dict[str, Any] = {}
    for obj_id, ok in flags.items():
        w = float(weights.get(obj_id) or 0.0)
        total += (w if ok else 0.0)
        by_obj[obj_id] = {"ok": bool(ok), "weight": w}
    # Normalize if weights don’t sum to 1.
    wsum = sum(float(v.get("weight") or 0.0) for v in by_obj.values()) or 1.0
    score = max(0.0, min(1.0, total / wsum))
    passed = score >= pass_score

    return {
        "score": score,
        "passed": passed,
        "by_objective": by_obj,
        "pass_score": pass_score,
        "notes": {
            "indicator_hits": indicator_hits,
            "guardrails": {
                "forbidden_phrases": forbidden,
            },
            "explainability": "MVP scoring is deterministic and objective-based; narrative coaching can be added later.",
        },
    }


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


# ---------------------------------------------------------------------------
# Training / interactive simulator tutor (MVP)
# ---------------------------------------------------------------------------


@app.get("/training/challenges")
def training_challenges(_: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))]) -> Dict[str, Any]:
    items = [c.model_dump() for c in _training_challenges()]
    return {"count": len(items), "items": items}


@app.get("/training/challenges/{challenge_id}")
def training_challenge_detail(
    challenge_id: str,
    _: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))],
) -> Dict[str, Any]:
    c = _training_challenge_by_id(challenge_id)
    if not c:
        raise HTTPException(status_code=404, detail="challenge not found")
    return {"challenge": c.model_dump()}


@app.post("/training/runs")
def training_run_start(
    req: TrainingStartRequest,
    principal: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))],
) -> Dict[str, Any]:
    c = _training_challenge_by_id(req.challenge_id)
    if not c:
        raise HTTPException(status_code=404, detail="challenge not found")

    run = TrainingRun(
        run_id=_new_id("trn"),
        challenge_id=c.challenge_id,
        trainee_id=str(principal.get("sub") or ""),
        status="in_progress",
        started_at=utc_now(),
    )
    append_jsonl(TRAINING_RUNS_PATH, run.model_dump())
    _append_operator_action(
        principal=principal,
        action="training_run_start",
        resource=f"training:{run.run_id}",
        detail={"challenge_id": c.challenge_id},
    )
    return {"status": "started", "run": run.model_dump(), "challenge": c.model_dump()}


@app.post("/training/actions")
def training_action_log(
    req: TrainingActionRequest,
    principal: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))],
) -> Dict[str, Any]:
    run = _training_latest_run(req.run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    if str(run.get("status") or "") != "in_progress":
        raise HTTPException(status_code=400, detail="run is not active")

    act = TrainingAction(
        action_id=_new_id("ta"),
        run_id=str(req.run_id),
        trainee_id=str(principal.get("sub") or ""),
        action_type=str(req.action_type or "").strip(),
        payload=req.payload if isinstance(req.payload, dict) else {},
        created_at=utc_now(),
    )
    append_jsonl(TRAINING_ACTIONS_PATH, act.model_dump())
    _append_operator_action(
        principal=principal,
        action="training_action",
        resource=f"training:{req.run_id}",
        detail={"action_type": act.action_type},
    )
    return {"status": "logged", "action": act.model_dump()}


@app.post("/training/complete")
def training_run_complete(
    req: TrainingCompleteRequest,
    principal: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))],
) -> Dict[str, Any]:
    run = _training_latest_run(req.run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    if str(run.get("status") or "") != "in_progress":
        raise HTTPException(status_code=400, detail="run is not active")
    c = _training_challenge_by_id(str(run.get("challenge_id") or ""))
    if not c:
        raise HTTPException(status_code=500, detail="challenge definition missing")
    actions = _training_actions_for(req.run_id)

    score = _training_score(challenge=c, actions=actions)
    llm_grade: Optional[Dict[str, Any]] = None
    if TRAINING_LLM_GRADING_ENABLED:
        try:
            resp = requests.post(
                f"{LLM_ASSISTANT_URL}/grade_training",
                timeout=60,
                json={
                    "challenge": c.model_dump(),
                    "run": {"run_id": req.run_id, "started_at": run.get("started_at"), "trainee_id": run.get("trainee_id")},
                    "actions": actions,
                },
            )
            llm_grade = resp.json() if resp.ok else {"error": f"http_{resp.status_code}", "detail": resp.text}
        except Exception as e:
            llm_grade = {"error": e.__class__.__name__}
    completed = TrainingRun(
        run_id=str(run.get("run_id") or ""),
        challenge_id=c.challenge_id,
        trainee_id=str(run.get("trainee_id") or ""),
        status="completed",
        started_at=str(run.get("started_at") or utc_now()),
        completed_at=utc_now(),
        score=float(score.get("score") or 0.0),
        passed=bool(score.get("passed")),
        report={
            "challenge": c.model_dump(),
            "metrics": score,
            "llm_grade": llm_grade or {"enabled": False},
            "action_count": len(actions),
            "recommendations": [
                "Write a one-paragraph campaign summary (who/what/when/how).",
                "Record at least two concrete indicators (URL/domain/sender/subject theme).",
                "Propose containment + comms steps (user notification, mailbox rules, monitoring).",
            ],
        },
    )
    # If LLM grading returned a structured grade, let it determine pass/fail + letter grade.
    if isinstance(llm_grade, dict) and isinstance(llm_grade.get("grade"), dict):
        g = llm_grade.get("grade")
        if isinstance(g, dict):
            if isinstance(g.get("passed"), bool):
                completed.passed = bool(g.get("passed"))
            if isinstance(g.get("score_pct"), (int, float)):
                completed.score = float(g.get("score_pct")) / 100.0
            # Surface the grade in the report for the console to display.
            if isinstance(completed.report, dict):
                completed.report["grade"] = {
                    "letter": g.get("letter_grade"),
                    "passed": g.get("passed"),
                    "score_pct": g.get("score_pct"),
                    "feedback": g.get("feedback"),
                }
    append_jsonl(TRAINING_RUNS_PATH, completed.model_dump())
    _append_operator_action(
        principal=principal,
        action="training_run_complete",
        resource=f"training:{req.run_id}",
        detail={"score": completed.score, "passed": completed.passed},
    )
    return {"status": "completed", "run": completed.model_dump()}


@app.get("/training/runs/{run_id}")
def training_run_get(
    run_id: str,
    _: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))],
) -> Dict[str, Any]:
    run = _training_latest_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    actions = _training_actions_for(run_id)
    return {"run": run, "actions": actions}


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