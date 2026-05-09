"""FastAPI wrapper around the teacher/student LLM router.

Keeps the historical public contract (``POST /assist`` returning
``{analyst_summary, helpdesk_explanation, next_steps, llm_used, llm_reason}``)
while adding the new ``llm_tier`` / ``llm_provider`` / ``llm_model`` fields
so the orchestrator and audit ledger can capture provenance.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

sys.path.insert(0, "/app")
from shared.schemas import LLMAssistRequestV1

from teacher_student import (
    grade_training,
    provider_status,
    reset_runtime_config,
    route,
    runtime_config_status,
    safe_fallback,
    update_runtime_config,
)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("llm_assistant")

app = FastAPI(title="WiCyS LLM Assistant", version="0.2.0")


class TrainingGradeRequest(BaseModel):
    challenge: Dict[str, Any]
    run: Dict[str, Any] = Field(default_factory=dict)
    actions: List[Dict[str, Any]] = Field(default_factory=list)


class TrainingGradeFeedback(BaseModel):
    strengths: List[str] = Field(default_factory=list)
    improvements: List[str] = Field(default_factory=list)
    step_by_step: List[str] = Field(default_factory=list)


class TrainingGrade(BaseModel):
    passed: bool
    letter_grade: str  # A|B|C|D|F
    score_pct: float = Field(ge=0.0, le=100.0)
    feedback: TrainingGradeFeedback


class TrainingGradeResponse(BaseModel):
    grade: TrainingGrade
    llm_used: bool
    llm_reason: str
    llm_tier: str = "fallback"
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None


class LLMRuntimeConfigRequest(BaseModel):
    teacher_provider: Optional[str] = None
    teacher_model: Optional[str] = None
    student_provider: Optional[str] = None
    student_model: Optional[str] = None
    ollama_base_url: Optional[str] = None
    llm_default_mode: Optional[str] = None
    llm_human_review_mode: Optional[str] = None


@app.get("/health")
def health() -> Dict[str, Any]:
    status = provider_status()
    return {"status": "up", **status}


@app.get("/providers")
def providers() -> Dict[str, Any]:
    return provider_status()


@app.get("/config")
def config() -> Dict[str, Any]:
    return runtime_config_status()


@app.post("/config")
def update_config(req: LLMRuntimeConfigRequest) -> Dict[str, Any]:
    return update_runtime_config(req.model_dump(exclude_unset=True))


@app.post("/config/reset")
def reset_config() -> Dict[str, Any]:
    return reset_runtime_config()


@app.post("/assist")
def assist(req: LLMAssistRequestV1) -> Dict[str, Any]:
    try:
        resp = route(req)
    except Exception as e:
        log.exception("Unexpected router error: %s", e)
        resp = safe_fallback(req, f"router_error: {e.__class__.__name__}")
    return resp.model_dump(mode="json")


@app.post("/grade_training")
def grade_training_endpoint(req: TrainingGradeRequest) -> Dict[str, Any]:
    """Grade a training run (pass/fail + letter grade + feedback)."""
    try:
        out = grade_training(req.challenge, req.run, req.actions)
        # Validate and normalize the returned structure.
        return TrainingGradeResponse(**out).model_dump(mode="json")
    except Exception as e:
        log.exception("Training grading failed: %s", e)
        # Safe fallback: never 500.
        fb = TrainingGradeResponse(
            grade=TrainingGrade(
                passed=False,
                letter_grade="F",
                score_pct=0.0,
                feedback=TrainingGradeFeedback(
                    strengths=[],
                    improvements=["Grading service unavailable. Retry later or enable a provider."],
                    step_by_step=["Record a case, indicators, scope, and response plan, then complete the run again."],
                ),
            ),
            llm_used=False,
            llm_reason=f"fallback: {e.__class__.__name__}",
            llm_tier="fallback",
        )
        return fb.model_dump(mode="json")
