from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _ts_ms_now() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _parse_ts_ms(iso: str) -> int:
    try:
        return int(datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp() * 1000)
    except Exception:
        return _ts_ms_now()


def _float_or(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def _float_opt(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(v)
    except Exception:
        return None


def normalize_ecs(
    *,
    event_id: Optional[str],
    ingested_at_iso: str,
    source: str,
    event_type: str,
    language: str,
    anon_record: Dict[str, Any],
    features: Dict[str, Any],
    detector_result: Dict[str, Any],
    soc_tenant: str = "",
) -> Dict[str, Any]:
    """
    Produce a small ECS-ish envelope that is stable for search/pivots.

    - We keep raw/anonymized content under `agentic.*` to avoid collisions.
    - We expose a few high-value fields under common ECS names for SIEM-like UX.
    """
    ts_ms = _parse_ts_ms(ingested_at_iso)
    final_score = _float_or(detector_result.get("risk_score_final") or detector_result.get("risk_score") or 0.0)
    rule_score = _float_or(detector_result.get("risk_score_rule") or detector_result.get("rule_score") or 0.0)
    fl_score_f = _float_opt(detector_result.get("risk_score_fl"))

    email_domain = str(anon_record.get("email_domain") or "")
    # Stable, privacy-preserving “entity” keys
    user_id_hash = str(anon_record.get("user_id_hash") or "")
    email_hash = str(anon_record.get("email_hash") or "")

    return {
        "@timestamp": ingested_at_iso,
        "event": {
            "id": str(event_id or ""),
            "kind": "event",
            "category": ["security"],
            "type": [str(event_type or "")],
            "dataset": f"agentic_soc.{str(source or '')}",
            "severity": int(round(min(100.0, max(0.0, final_score * 100.0)))),
            "risk_score": final_score * 100.0,
        },
        "labels": {
            "language": str(language or ""),
            "source": str(source or ""),
            **({"soc_tenant": str(soc_tenant).strip()} if str(soc_tenant or "").strip() else {}),
        },
        "rule": {
            "name": str(detector_result.get("policy_rule_id") or detector_result.get("rule_id") or ""),
        },
        "user": {
            "id": user_id_hash,
        },
        "email": {
            "from": {"address": email_hash},
        },
        "organization": {
            "name": email_domain,
        },
        "agentic": {
            "ts_ms": ts_ms,
            "source": str(source or ""),
            "event_type": str(event_type or ""),
            "language": str(language or ""),
            "scores": {
                "final": final_score,
                "rule": rule_score,
                "fl": fl_score_f,
            },
            "anon_record": anon_record,
            "features": features,
            "detector_result": detector_result,
        },
    }

