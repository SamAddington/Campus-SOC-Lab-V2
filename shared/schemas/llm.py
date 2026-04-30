from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from enum import Enum

from .base import SCHEMA_VERSION


class LLMTier(str, Enum):
    TEACHER = "teacher"
    STUDENT = "student"
    FALLBACK = "fallback"


class LLMMode(str, Enum):
    """How the teacher/student router should behave for a given request.

    - ``student_only``: only the small on-device model runs. Default for realtime.
    - ``teacher_only``: only the teacher runs. Used offline for curating
      distillation targets. Not for realtime.
    - ``teacher_shadow``: student serves the user; teacher is invoked in the
      background (best-effort) to capture a higher-quality target. The
      user-facing response always comes from the student so latency stays flat.
    - ``teacher_then_student_refine``: teacher drafts, student rewrites. Only
      enabled when ``requires_human_review`` is true.
    """

    STUDENT_ONLY = "student_only"
    TEACHER_ONLY = "teacher_only"
    TEACHER_SHADOW = "teacher_shadow"
    TEACHER_THEN_STUDENT_REFINE = "teacher_then_student_refine"


class LLMAssistRequestV1(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    event_id: str
    source: str
    event_type: str
    language: str = "en"

    risk_score_rule: float
    risk_score_fl: Optional[float] = None
    risk_score_final: float

    label: str
    action: str
    explanation: str

    policy_rule_id: str
    policy_reason: str
    requires_human_review: bool = True

    features: Dict[str, Any] = Field(default_factory=dict)
    scenario_id: Optional[str] = None

    # Optional override: if unset the server picks a default based on
    # ``requires_human_review`` and the server's environment configuration.
    mode: Optional[LLMMode] = None


class LLMAssistResponseV1(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    analyst_summary: str
    helpdesk_explanation: str
    next_steps: List[str]
    llm_used: bool
    llm_reason: str
    llm_tier: LLMTier = LLMTier.FALLBACK
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
