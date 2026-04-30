from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from typing import Any, Dict, Optional, Annotated
import os
import requests
from datetime import datetime, timezone
import sys
sys.path.insert(0, "/app")
from shared.security import require_api_key, require_roles
from urllib.parse import urlparse

SCHEMA_VERSION = "v1"

app = FastAPI(title="WiCyS Orchestrator", version="0.2.0")

from shared.hardening import apply_hardening, RateLimitConfig

apply_hardening(app, max_body_bytes=2_000_000, rate_limit=RateLimitConfig(requests=240, per_seconds=60))

COLLECTOR_URL = os.getenv("COLLECTOR_URL", "http://collector:8001")
DETECTOR_URL = os.getenv("DETECTOR_URL", "http://detector:8000")
POLICY_URL = os.getenv("POLICY_URL", "http://policy_engine:8020")
AUDIT_URL = os.getenv("AUDIT_URL", "http://audit:8022")

LLM_ASSISTANT_URL = os.getenv("LLM_ASSISTANT_URL", "http://llm_assistant:8024")

# ---------------------------------------------------------------------------
# OSINT enrichment is opt-in. It is triggered for:
#   - email_gateway events (high indicator density), and
#   - any other event whose rule-based score is >= OSINT_MIN_RULE_SCORE.
# Traffic-anomaly events skip enrichment because their synthesized
# message contains no user-supplied indicators by design.
# ---------------------------------------------------------------------------
OSINT_URL = os.getenv("OSINT_URL", "http://osint:8028")
SOC_API_KEY = os.getenv("SOC_API_KEY", "change-me-dev-api-key")
OSINT_ENABLED = (os.getenv("ENABLE_OSINT_ENRICHMENT", "1").strip().lower()
                 in ("1", "true", "yes", "on"))
OSINT_TIMEOUT = int(os.getenv("OSINT_TIMEOUT_SECONDS", "30"))
try:
    OSINT_MIN_RULE_SCORE = float(os.getenv("OSINT_MIN_RULE_SCORE", "0.40"))
except ValueError:
    OSINT_MIN_RULE_SCORE = 0.40
_OSINT_SKIP_SOURCES = {"traffic_anomaly"}

# ---------------------------------------------------------------------------
# SOAR (small, approval-gated playbooks)
# ---------------------------------------------------------------------------
SOAR_ENABLED = (os.getenv("SOAR_ENABLED", "0").strip().lower() in ("1", "true", "yes", "on"))
SOAR_REQUIRE_APPROVAL = (os.getenv("SOAR_REQUIRE_APPROVAL", "1").strip().lower() in ("1", "true", "yes", "on"))
SOAR_WEBHOOK_ALLOWLIST = [x.strip() for x in (os.getenv("SOAR_WEBHOOK_ALLOWLIST", "") or "").split(",") if x.strip()]


def _webhook_allowed(url: str) -> bool:
    if not SOAR_WEBHOOK_ALLOWLIST:
        return False
    try:
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}".lower()
    except Exception:
        return False
    allowed = {a.lower().rstrip("/") for a in SOAR_WEBHOOK_ALLOWLIST}
    return base.rstrip("/") in allowed


class SoarRunRequest(BaseModel):
    name: str
    approved: bool = False
    inputs: Dict[str, Any] = {}


@app.get("/soar/playbooks")
def list_playbooks(_: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))]):
    return {
        "enabled": SOAR_ENABLED,
        "require_approval": SOAR_REQUIRE_APPROVAL,
        "playbooks": [
            {
                "name": "create_case",
                "description": "Create an investigation case in the audit service.",
                "requires_approval": SOAR_REQUIRE_APPROVAL,
            },
            {
                "name": "webhook_notify",
                "description": "POST a JSON payload to an allowlisted webhook URL.",
                "requires_approval": SOAR_REQUIRE_APPROVAL,
            },
        ],
    }


def _run_create_case(inputs: Dict[str, Any]) -> Dict[str, Any]:
    title = str(inputs.get("title") or "SOC investigation").strip()
    description = str(inputs.get("description") or "").strip()
    severity = str(inputs.get("severity") or "medium").strip()
    assigned_to = str(inputs.get("assigned_to") or "").strip() or None
    related = inputs.get("related_decision_cards") or []
    if not isinstance(related, list):
        related = []
    body = {
        "title": title,
        "description": description,
        "severity": severity,
        "assigned_to": assigned_to,
        "related_decision_cards": related,
        "status": "open",
    }
    return post_json(f"{AUDIT_URL}/cases", body)


def _run_webhook_notify(inputs: Dict[str, Any]) -> Dict[str, Any]:
    url = str(inputs.get("url") or "").strip()
    payload = inputs.get("payload") or {}
    if not url or not _webhook_allowed(url):
        raise HTTPException(status_code=400, detail="webhook url not allowlisted")
    try:
        resp = requests.post(url, json=payload, timeout=10)
        return {"http_status": resp.status_code}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"webhook failed: {e.__class__.__name__}")


@app.post("/soar/playbooks/run")
@app.post(
    "/soar/playbooks/run",
    responses={
        400: {"description": "SOAR disabled / unknown playbook / invalid inputs"},
        502: {"description": "Webhook destination failure"},
    },
)
def run_playbook(
    req: SoarRunRequest,
    _: Annotated[Dict[str, Any], Depends(require_roles("admin"))],
):
    if not SOAR_ENABLED:
        raise HTTPException(status_code=400, detail="SOAR disabled")
    if SOAR_REQUIRE_APPROVAL and not bool(req.approved):
        return {"status": "requires_approval", "playbook": req.name}

    name = (req.name or "").strip()
    inputs = req.inputs or {}

    if name == "create_case":
        out = _run_create_case(inputs)
        try:
            post_json(
                f"{AUDIT_URL}/log_operator_action",
                {
                    "action": "soar.run",
                    "resource": "create_case",
                    "detail": {"result_case_id": out.get("case_id")},
                },
                timeout=5,
            )
        except Exception:
            pass
        return {"status": "ok", "playbook": name, "result": out}

    if name == "webhook_notify":
        out = _run_webhook_notify(inputs)
        try:
            post_json(
                f"{AUDIT_URL}/log_operator_action",
                {
                    "action": "soar.run",
                    "resource": "webhook_notify",
                    "detail": {"http_status": out.get("http_status")},
                },
                timeout=5,
            )
        except Exception:
            pass
        return {"status": "ok", "playbook": name, "result": out}

    raise HTTPException(status_code=400, detail="unknown playbook")

class EventPayload(BaseModel):
    user_id: str
    email: str
    source: str
    message: str
    event_type: str
    language: str = "en"
    consent_use_for_distillation: bool = False


class ProcessEventRequest(BaseModel):
    event_id: str
    payload: EventPayload
    scenario_id: Optional[str] = None


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


def _osint_should_enrich(source: str, risk_score_rule: float) -> bool:
    if not OSINT_ENABLED:
        return False
    if source in _OSINT_SKIP_SOURCES:
        return False
    if source == "email_gateway":
        return True
    try:
        return float(risk_score_rule) >= OSINT_MIN_RULE_SCORE
    except (TypeError, ValueError):
        return False


def get_osint_enrichment(
    payload_dict: Dict[str, Any],
    detector_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Call the OSINT service for this event.

    Never raises: any failure degrades to a well-formed empty summary
    so the rest of the pipeline continues unaffected.
    """
    source = payload_dict.get("source", "")
    rule_score = detector_result.get("risk_score_rule",
                                     detector_result.get("risk_score", 0.0))
    if not _osint_should_enrich(source, rule_score):
        return {
            "enabled": False,
            "skipped": True,
            "reason": "osint_enrichment not applicable for this event",
            "summary": {
                "verdict": "unknown",
                "score": 0.0,
                "indicator_count": 0,
            },
        }
    body = {
        "message": payload_dict.get("message", ""),
        "event_type": payload_dict.get("event_type", ""),
        "language": payload_dict.get("language", "en"),
        "source": source,
        "include_explanation": True,
    }
    try:
        resp = requests.post(f"{OSINT_URL}/enrich_event",
                             json=body, timeout=OSINT_TIMEOUT)
        if not resp.ok:
            return {
                "enabled": True,
                "skipped": False,
                "reason": f"osint returned http {resp.status_code}",
                "summary": {"verdict": "unknown", "score": 0.0, "indicator_count": 0},
            }
        data = resp.json() or {}
        return {
            "enabled": True,
            "skipped": False,
            "reason": "ok",
            "indicators": data.get("indicators", {}),
            "summary": data.get("summary", {}),
            "explanation": data.get("explanation", {}),
        }
    except Exception as exc:
        return {
            "enabled": True,
            "skipped": False,
            "reason": f"osint unavailable: {str(exc)[:200]}",
            "summary": {"verdict": "unknown", "score": 0.0, "indicator_count": 0},
        }


def get_llm_assist(
    event_id: str,
    payload_dict: Dict[str, Any],
    detector_result: Dict[str, Any],
    policy_result: Dict[str, Any],
    features: Dict[str, Any],
    scenario_id: Optional[str] = None,
    osint_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    # Enrich the features map the LLM sees with OSINT context so the
    # student / teacher can reference it in the explanation. The raw
    # indicator values are never forwarded -- only aggregated verdict
    # and scoreband.
    osint_features: Dict[str, Any] = {}
    if osint_result and osint_result.get("enabled") and not osint_result.get("skipped"):
        summary = osint_result.get("summary") or {}
        osint_features = {
            "osint_verdict": summary.get("verdict", "unknown"),
            "osint_score": summary.get("score", 0.0),
            "osint_indicator_count": summary.get("indicator_count", 0),
            "osint_short_explanation": (
                (osint_result.get("explanation") or {}).get("short_explanation", "")
            ),
        }

    req_body = {
        "event_id": event_id,
        "source": payload_dict["source"],
        "event_type": payload_dict["event_type"],
        "language": payload_dict.get("language", "en"),
        "risk_score_rule": detector_result.get("risk_score_rule", detector_result.get("risk_score", 0.0)),
        "risk_score_fl": (detector_result.get("federated_result", {}) or {}).get("risk_score_fl"),
        "risk_score_final": detector_result.get("risk_score_final", detector_result.get("risk_score", 0.0)),
        "label": detector_result.get("label", "unknown"),
        "action": detector_result.get("action", "queue_for_review"),
        "explanation": detector_result.get("explanation", ""),
        "policy_rule_id": policy_result.get("policy_rule_id", "UNKNOWN"),
        "policy_reason": policy_result.get("policy_reason", ""),
        "requires_human_review": bool(policy_result.get("requires_human_review", True)),
        "features": {**features, **osint_features},
        "scenario_id": scenario_id,
    }

    try:
        return post_json(f"{LLM_ASSISTANT_URL}/assist", req_body)
    except Exception:
        return {
            "analyst_summary": "LLM assistant unavailable. Use detector explanation and policy result directly.",
            "helpdesk_explanation": "This event was flagged for review. Please follow the helpdesk triage runbook.",
            "next_steps": [
                "Review the detector explanation.",
                "Check the applicable policy rule.",
                "Escalate or queue based on the bounded triage workflow."
            ],
            "llm_used": False,
            "llm_reason": "LLM assistant unavailable."
        }


@app.get("/health")
def health():
    return {"status": "up"}

@app.post("/process_event")
def process_event(req: ProcessEventRequest, _: None = Depends(require_api_key)):
    payload_dict = req.payload.model_dump()

    # Step 1: send to collector / ingest
    collector_resp = post_json(f"{COLLECTOR_URL}/ingest", payload_dict)

    detector_result = collector_resp.get("detector_result", {})
    if not detector_result:
        raise HTTPException(status_code=500, detail="Detector result missing from collector response.")

    features = collector_resp.get("features", {})

    # Step 2a: OSINT enrichment (best-effort, before policy so rules can
    # match on osint_verdict). Degrades cleanly on any failure.
    osint_result = get_osint_enrichment(payload_dict, detector_result)
    osint_summary = osint_result.get("summary") or {}
    features_with_osint: Dict[str, Any] = {
        **features,
        "osint_verdict": osint_summary.get("verdict", "unknown"),
        "osint_score": osint_summary.get("score", 0.0),
        "osint_indicator_count": osint_summary.get("indicator_count", 0),
    }

    # Step 2b: evaluate policy
    policy_input = {
        "event_id": req.event_id,
        "source": payload_dict["source"],
        "event_type": payload_dict["event_type"],
        "language": payload_dict["language"],
        "risk_score_rule": detector_result.get("risk_score_rule", detector_result.get("risk_score", 0.0)),
        "risk_score_fl": (detector_result.get("federated_result", {}) or {}).get("risk_score_fl"),
        "risk_score_final": detector_result.get("risk_score_final", detector_result.get("risk_score", 0.0)),
        "label": detector_result.get("label", "unknown"),
        "features": features_with_osint,
    }

    policy_result = post_json(f"{POLICY_URL}/evaluate", policy_input)

    # Step 3: bounded LLM assist
    llm_result = get_llm_assist(
        event_id=req.event_id,
        payload_dict=payload_dict,
        detector_result=detector_result,
        policy_result=policy_result,
        features=features_with_osint,
        scenario_id=req.scenario_id,
        osint_result=osint_result,
    )

    # Step 4: build decision card
    decision_card = {
        "schema_version": SCHEMA_VERSION,
        "decision_card_id": f"dc-{req.event_id}",
        "event_id": req.event_id,
        "timestamp": utc_now(),
        "source": payload_dict["source"],
        "event_type": payload_dict["event_type"],
        "language": payload_dict["language"],
        "risk_score_rule": policy_input["risk_score_rule"],
        "risk_score_fl": policy_input["risk_score_fl"],
        "risk_score_final": policy_input["risk_score_final"],
        "label": policy_input["label"],
        "explanation": detector_result.get("explanation", ""),
        "policy_rule_id": policy_result["policy_rule_id"],
        "permitted_action": policy_result["permitted_action"],
        "requires_human_review": policy_result["requires_human_review"],
        "final_human_action": None,
        "scenario_id": req.scenario_id,
        "model_round": (detector_result.get("federated_result", {}) or {}).get("model_round"),
        "threshold_version": detector_result.get("threshold_version", "default"),
        "analyst_summary": llm_result.get("analyst_summary"),
        "helpdesk_explanation": llm_result.get("helpdesk_explanation"),
        "next_steps": llm_result.get("next_steps", []),
        "llm_used": llm_result.get("llm_used", False),
        "llm_reason": llm_result.get("llm_reason", "unknown"),
        # Phase 1: teacher/student provenance
        "llm_tier": llm_result.get("llm_tier"),
        "llm_provider": llm_result.get("llm_provider"),
        "llm_model": llm_result.get("llm_model"),
        # Phase 0: consent propagation
        "consent_use_for_distillation": bool(payload_dict.get("consent_use_for_distillation", False)),
        # Phase 4: OSINT enrichment provenance
        "osint_enabled": bool(osint_result.get("enabled", False)),
        "osint_skipped": bool(osint_result.get("skipped", False)),
        "osint_verdict": osint_summary.get("verdict", "unknown"),
        "osint_score": osint_summary.get("score", 0.0),
        "osint_indicator_count": osint_summary.get("indicator_count", 0),
        "osint_providers_used": osint_summary.get("providers_used", []),
        "osint_short_explanation": (
            (osint_result.get("explanation") or {}).get("short_explanation", "")
        ),
    }

    # Step 5: audit log
    audit_resp = post_json(f"{AUDIT_URL}/log_decision", decision_card)

    return {
        "status": "processed",
        "event_id": req.event_id,
        "detector_result": detector_result,
        "policy_result": policy_result,
        "llm_result": llm_result,
        "osint_result": osint_result,
        "decision_card_id": decision_card["decision_card_id"],
        "audit_status": audit_resp.get("status", "logged"),
    }