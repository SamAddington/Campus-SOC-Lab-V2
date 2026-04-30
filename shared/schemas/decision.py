from pydantic import BaseModel, Field
from typing import List, Optional

from .base import SCHEMA_VERSION


class DecisionCardV1(BaseModel):
    """The canonical audit record.

    Every triage decision in the stack -- whether produced live by the
    orchestrator or replayed by the simulator -- appends one of these to
    ``audit/ledger/decision_cards.jsonl``.
    """

    schema_version: str = Field(default=SCHEMA_VERSION)
    decision_card_id: str
    event_id: str
    timestamp: str
    source: str
    event_type: str
    language: str

    # Risk breakdown
    risk_score_rule: float
    risk_score_fl: Optional[float] = None
    risk_score_final: float
    label: str
    explanation: str

    # Policy decision
    policy_rule_id: str
    permitted_action: str
    requires_human_review: bool
    final_human_action: Optional[str] = None

    # Context
    scenario_id: Optional[str] = None
    model_round: Optional[int] = None
    threshold_version: Optional[str] = "default"

    # LLM assist outputs
    analyst_summary: Optional[str] = None
    helpdesk_explanation: Optional[str] = None
    next_steps: Optional[List[str]] = None
    llm_used: Optional[bool] = None
    llm_reason: Optional[str] = None

    # NEW in Phase 1: teacher/student routing provenance
    llm_tier: Optional[str] = None      # "teacher" | "student" | "fallback"
    llm_provider: Optional[str] = None  # "ollama" | "openai" | "anthropic" | ...
    llm_model: Optional[str] = None

    # NEW in Phase 1: consent propagation for offline distillation
    consent_use_for_distillation: bool = False
