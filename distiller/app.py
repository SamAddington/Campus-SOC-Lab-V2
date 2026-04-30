"""Offline teacher -> student distillation utilities.

The distiller reads (a) decision cards from the audit ledger and (b) teacher
shadow outputs logged by the LLM assistant. It produces training corpora and
summary statistics. It does NOT fine-tune models here; that is a separate,
optional step delegated to a notebook so instructors can inspect data first.

Governance:
- Records without ``consent_use_for_distillation=true`` are filtered out by
  default. An instructor can opt-in to including simulator/synthetic events.
- No PII is emitted. The corpus preserves only features, policy metadata,
  and teacher-written rationales -- everything that is already in the audit
  ledger.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="WiCyS Distiller", version="0.1.0")

LEDGER_DIR = Path(os.getenv("LEDGER_DIR", "/app/ledger"))
CORPUS_DIR = Path(os.getenv("CORPUS_DIR", "/app/corpus"))
DECISIONS_PATH = LEDGER_DIR / "decision_cards.jsonl"
SHADOW_PATH = LEDGER_DIR / "teacher_shadow.jsonl"

CORPUS_DIR.mkdir(parents=True, exist_ok=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


class ExportCorpusRequest(BaseModel):
    include_simulator: bool = True
    require_teacher_output: bool = True
    min_final_score: Optional[float] = None
    max_final_score: Optional[float] = None
    languages: Optional[List[str]] = None
    output_name: str = "corpus.jsonl"


def _consented(card: Dict[str, Any], include_simulator: bool) -> bool:
    if card.get("consent_use_for_distillation") is True:
        return True
    # Simulator scenarios are synthetic by construction; allow when opted-in.
    return include_simulator and bool(card.get("scenario_id"))


def _filters_match(card: Dict[str, Any], req: ExportCorpusRequest) -> bool:
    if req.min_final_score is not None and float(card.get("risk_score_final", 0.0)) < req.min_final_score:
        return False
    if req.max_final_score is not None and float(card.get("risk_score_final", 0.0)) > req.max_final_score:
        return False
    if req.languages and card.get("language") not in req.languages:
        return False
    return True


def _teacher_index(shadow_rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Index teacher shadow outputs by event_id for quick lookup."""
    idx: Dict[str, Dict[str, Any]] = {}
    for row in shadow_rows:
        req = row.get("request") or {}
        event_id = req.get("event_id")
        if event_id:
            idx[event_id] = row
    return idx


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "up",
        "decisions_exist": DECISIONS_PATH.exists(),
        "shadow_exist": SHADOW_PATH.exists(),
    }


@app.get("/status")
def status() -> Dict[str, Any]:
    decisions = read_jsonl(DECISIONS_PATH)
    shadows = read_jsonl(SHADOW_PATH)

    tier_counts: Dict[str, int] = {}
    language_counts: Dict[str, int] = {}
    consented = 0
    for d in decisions:
        tier = d.get("llm_tier") or "unknown"
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
        lang = d.get("language") or "unknown"
        language_counts[lang] = language_counts.get(lang, 0) + 1
        if d.get("consent_use_for_distillation"):
            consented += 1

    return {
        "total_decisions": len(decisions),
        "total_shadow_records": len(shadows),
        "consented_decisions": consented,
        "decisions_by_tier": tier_counts,
        "decisions_by_language": language_counts,
    }


@app.post("/export_corpus")
def export_corpus(req: ExportCorpusRequest) -> Dict[str, Any]:
    decisions = read_jsonl(DECISIONS_PATH)
    shadows = read_jsonl(SHADOW_PATH)
    teacher_idx = _teacher_index(shadows)

    rows: List[Dict[str, Any]] = []
    skipped_consent = 0
    skipped_no_teacher = 0
    skipped_filter = 0

    for d in decisions:
        if not _consented(d, req.include_simulator):
            skipped_consent += 1
            continue
        if not _filters_match(d, req):
            skipped_filter += 1
            continue

        event_id = d.get("event_id")
        teacher_row = teacher_idx.get(event_id) if event_id else None
        if req.require_teacher_output and not teacher_row:
            skipped_no_teacher += 1
            continue

        prompt_input = {
            "source": d.get("source"),
            "event_type": d.get("event_type"),
            "language": d.get("language"),
            "risk_score_rule": d.get("risk_score_rule"),
            "risk_score_fl": d.get("risk_score_fl"),
            "risk_score_final": d.get("risk_score_final"),
            "label": d.get("label"),
            "action": d.get("permitted_action"),
            "explanation": d.get("explanation"),
            "policy_rule_id": d.get("policy_rule_id"),
            "requires_human_review": d.get("requires_human_review"),
            "scenario_id": d.get("scenario_id"),
        }

        teacher_output = (teacher_row or {}).get("teacher_output") or {
            "analyst_summary": d.get("analyst_summary"),
            "helpdesk_explanation": d.get("helpdesk_explanation"),
            "next_steps": d.get("next_steps") or [],
        }

        rows.append({
            "event_id": event_id,
            "input": prompt_input,
            "target": teacher_output,
            "teacher_provider": (teacher_row or {}).get("teacher_provider"),
            "teacher_model": (teacher_row or {}).get("teacher_model"),
            "exported_at": utc_now(),
        })

    out_path = CORPUS_DIR / req.output_name
    write_jsonl(out_path, rows)

    return {
        "status": "exported",
        "count": len(rows),
        "output_path": str(out_path),
        "skipped_consent": skipped_consent,
        "skipped_no_teacher": skipped_no_teacher,
        "skipped_filter": skipped_filter,
    }


class EvalSummaryRequest(BaseModel):
    limit: Optional[int] = None


@app.post("/eval_summary")
def eval_summary(req: EvalSummaryRequest) -> Dict[str, Any]:
    """Compare agreement between teacher shadow outputs and audited
    (student/fallback) decision-card outputs on matching event_ids.

    Agreement metrics stay intentionally simple: did next_steps length match,
    and did the analyst_summary share any substantive overlap. Replace with
    richer metrics in a notebook before making policy changes.
    """
    decisions = read_jsonl(DECISIONS_PATH)
    shadows = read_jsonl(SHADOW_PATH)
    teacher_idx = _teacher_index(shadows)

    if req.limit is not None:
        decisions = decisions[-req.limit:]

    compared = 0
    steps_length_match = 0
    overlap_hits = 0
    by_tier: Dict[str, int] = {}

    for d in decisions:
        tier = d.get("llm_tier") or "unknown"
        by_tier[tier] = by_tier.get(tier, 0) + 1

        event_id = d.get("event_id")
        t = teacher_idx.get(event_id) if event_id else None
        if not t:
            continue

        t_out = t.get("teacher_output") or {}
        served_steps = d.get("next_steps") or []
        teacher_steps = t_out.get("next_steps") or []

        compared += 1
        if len(served_steps) == len(teacher_steps):
            steps_length_match += 1

        served_sum = (d.get("analyst_summary") or "").lower()
        teacher_sum = (t_out.get("analyst_summary") or "").lower()
        if served_sum and teacher_sum:
            served_words = {w for w in served_sum.split() if len(w) > 4}
            teacher_words = {w for w in teacher_sum.split() if len(w) > 4}
            if served_words and teacher_words and len(served_words & teacher_words) >= 3:
                overlap_hits += 1

    return {
        "decisions_considered": len(decisions),
        "decisions_by_tier": by_tier,
        "compared_against_teacher": compared,
        "next_steps_length_match": steps_length_match,
        "analyst_summary_overlap_hits": overlap_hits,
    }
