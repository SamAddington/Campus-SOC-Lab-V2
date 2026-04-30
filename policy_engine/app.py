import os
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
from typing import Any, Dict, List, Optional, Annotated
import yaml
import sys
sys.path.insert(0, "/app")
from shared.security import require_api_key, require_roles
from shared.hardening import RateLimitConfig, apply_hardening

app = FastAPI(title="WiCyS Policy Engine")
apply_hardening(app, max_body_bytes=2_000_000, rate_limit=RateLimitConfig(requests=240, per_seconds=60))

RULES_PATH = Path("/app/rules.yaml")
AUDIT_URL = (os.getenv("AUDIT_URL", "http://audit:8022") or "").rstrip("/")
SOC_API_KEY = os.getenv("SOC_API_KEY", "change-me-dev-api-key")


class PolicyInput(BaseModel):
    event_id: str
    source: str
    event_type: str
    language: str
    risk_score_rule: float
    risk_score_fl: Optional[float] = None
    risk_score_final: float
    label: str
    features: Dict[str, Any] = {}


def load_rules() -> Dict[str, Any]:
    if not RULES_PATH.exists():
        raise FileNotFoundError(f"Policy rules file not found: {RULES_PATH}")
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    data.setdefault("version", 1)
    data.setdefault("rules", [])
    return data


def matches_rule(rule_when: Dict[str, Any], item: PolicyInput) -> bool:
    if "source" in rule_when and rule_when["source"] != item.source:
        return False

    if "event_type" in rule_when and rule_when["event_type"] != item.event_type:
        return False

    if "language" in rule_when and rule_when["language"] != item.language:
        return False

    if "label" in rule_when and rule_when["label"] != item.label:
        return False

    if "min_final_score" in rule_when and item.risk_score_final < float(rule_when["min_final_score"]):
        return False

    if "max_final_score" in rule_when and item.risk_score_final > float(rule_when["max_final_score"]):
        return False

    if "min_rule_score" in rule_when and item.risk_score_rule < float(rule_when["min_rule_score"]):
        return False

    if "max_rule_score" in rule_when and item.risk_score_rule > float(rule_when["max_rule_score"]):
        return False

    if "min_fl_score" in rule_when:
        fl = item.risk_score_fl if item.risk_score_fl is not None else -1.0
        if fl < float(rule_when["min_fl_score"]):
            return False

    feature_requirements = rule_when.get("feature_flags", {})
    for key, expected in feature_requirements.items():
        actual = item.features.get(key)
        if actual != expected:
            return False

    return True


def _validate_rules_doc(doc: Dict[str, Any]) -> None:
    if not isinstance(doc, dict):
        raise ValueError("rules doc must be a YAML mapping")
    v = doc.get("version")
    if v is not None:
        try:
            _ = int(v)
        except Exception as e:
            raise ValueError(f"version must be int: {e}") from e
    rules = doc.get("rules")
    if rules is None:
        raise ValueError("missing top-level 'rules' list")
    if not isinstance(rules, list):
        raise ValueError("'rules' must be a list")
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            raise ValueError(f"rules[{i}] must be a mapping")
        if not r.get("id"):
            raise ValueError(f"rules[{i}] missing id")
        if r.get("action") not in {"allow", "queue_for_review", "escalate"}:
            raise ValueError(f"rules[{i}] invalid action")
        when = r.get("when")
        if when is None or not isinstance(when, dict):
            raise ValueError(f"rules[{i}] missing/invalid when")


def _audit_operator_action(action: str, resource: str, detail: Dict[str, Any]) -> None:
    if not AUDIT_URL:
        return
    try:
        import requests

        requests.post(
            f"{AUDIT_URL}/log_operator_action",
            json={"action": action, "resource": resource, "detail": detail},
            timeout=5,
            headers={"X-API-Key": SOC_API_KEY},
        )
    except Exception:
        pass


@app.get("/health")
def health():
    return {"status": "up"}


@app.get("/rules")
def rules(_: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))]):
    return load_rules()


class RulesUpdate(BaseModel):
    yaml_text: str


@app.get(
    "/rules/raw",
    responses={
        500: {"description": "Failed to read rules file"},
    },
)
def rules_raw(_: Annotated[Dict[str, Any], Depends(require_roles("viewer", "analyst", "admin"))]):
    try:
        return {"path": str(RULES_PATH), "yaml_text": RULES_PATH.read_text(encoding="utf-8")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to read rules: {e.__class__.__name__}")


@app.post(
    "/rules/update",
    responses={
        400: {"description": "Invalid YAML or schema"},
        500: {"description": "Failed to write rules file"},
    },
)
def rules_update(
    body: RulesUpdate,
    principal: Annotated[Dict[str, Any], Depends(require_roles("admin"))],
):
    raw = (body.yaml_text or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="empty yaml_text")
    try:
        doc = yaml.safe_load(raw) or {}
        _validate_rules_doc(doc)
        # bump version
        try:
            doc["version"] = int(doc.get("version") or 0) + 1
        except Exception:
            doc["version"] = 1
        canonical = yaml.safe_dump(doc, sort_keys=False)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"invalid yaml: {e.__class__.__name__}")

    try:
        RULES_PATH.write_text(canonical, encoding="utf-8")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to write rules: {e.__class__.__name__}")

    _audit_operator_action(
        "policy.rules.update",
        "rules.yaml",
        {
            "actor": str(principal.get("sub") or "unknown"),
            "new_version": doc.get("version"),
            "rules_count": len(doc.get("rules") or []),
        },
    )
    return {"status": "ok", "version": doc.get("version"), "rules_count": len(doc.get("rules") or [])}


@app.post("/evaluate")
def evaluate(
    inp: PolicyInput,
    _: Annotated[None, Depends(require_api_key)] = None,
):
    rules_doc = load_rules()
    rules_list: List[Dict[str, Any]] = rules_doc.get("rules", [])

    for rule in rules_list:
        rule_when = rule.get("when", {})
        if matches_rule(rule_when, inp):
            return {
                "permitted_action": rule["action"],
                "requires_human_review": bool(rule.get("requires_human_review", True)),
                "policy_rule_id": rule["id"],
                "policy_reason": rule.get("reason", "Matched configured policy rule."),
                "policy_version": rules_doc.get("version", 1),
            }

    # safe default if nothing matches
    return {
        "permitted_action": "queue_for_review",
        "requires_human_review": True,
        "policy_rule_id": "DEFAULT-REVIEW",
        "policy_reason": "No explicit rule matched. Defaulting to human review.",
        "policy_version": rules_doc.get("version", 1),
    }