"""Teacher / student routing for the bounded LLM assistant.

Design goals:
- Deterministic, auditable choice of tier for every request.
- The student tier (small, local) always serves realtime traffic so latency
  and privacy are not blocked on an external API.
- The teacher tier (large, optionally hosted) is used only for (a) offline
  distillation corpora and (b) "shadow" runs that capture higher-quality
  targets without blocking the user.
- Every response is validated against the same JSON schema, regardless of
  which tier produced it. Schema validation lives here, not in the providers.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

sys.path.insert(0, "/app")
from shared.schemas import LLMAssistRequestV1, LLMAssistResponseV1, LLMMode, LLMTier

from providers import LLMProvider, LLMProviderError, build_provider

log = logging.getLogger("teacher_student")


# ---------- Config ---------- #

def _read_env_mode(name: str, default: LLMMode) -> LLMMode:
    raw = (os.getenv(name, "") or "").strip().lower()
    if not raw:
        return default
    try:
        return LLMMode(raw)
    except ValueError:
        log.warning("Unknown %s=%r, falling back to %s", name, raw, default.value)
        return default


TEACHER_PROVIDER = os.getenv("TEACHER_PROVIDER", "none")
TEACHER_MODEL = os.getenv("TEACHER_MODEL", "")
STUDENT_PROVIDER = os.getenv("STUDENT_PROVIDER", "ollama")
STUDENT_MODEL = os.getenv("STUDENT_MODEL", os.getenv("OLLAMA_MODEL", "llama3.2"))

DEFAULT_MODE = _read_env_mode("LLM_DEFAULT_MODE", LLMMode.STUDENT_ONLY)
HUMAN_REVIEW_MODE = _read_env_mode("LLM_HUMAN_REVIEW_MODE", LLMMode.TEACHER_SHADOW)

# Where to persist teacher shadow outputs for later distillation training.
# The file lives on the ledger volume so it is already under audit control.
SHADOW_LOG_PATH = Path(os.getenv("LLM_SHADOW_LOG", "/app/ledger/teacher_shadow.jsonl"))


# ---------- Provider construction ---------- #

def _safe_build(provider_name: str, model: str) -> LLMProvider:
    try:
        return build_provider(provider_name, model)
    except Exception as e:
        log.warning("Could not build provider %r (%s); using null.", provider_name, e)
        return build_provider("none", model)


_TEACHER = _safe_build(TEACHER_PROVIDER, TEACHER_MODEL)
_STUDENT = _safe_build(STUDENT_PROVIDER, STUDENT_MODEL)


def provider_status() -> Dict[str, Any]:
    return {
        "teacher": _TEACHER.describe(),
        "student": _STUDENT.describe(),
        "default_mode": DEFAULT_MODE.value,
        "human_review_mode": HUMAN_REVIEW_MODE.value,
    }


# ---------- Prompt construction ---------- #

_SCHEMA_INSTRUCTION = """Return valid JSON only with this schema:
{
  "analyst_summary": "string",
  "helpdesk_explanation": "string",
  "next_steps": ["string", "string", "string"]
}

Rules:
- Keep analyst_summary to 2-4 sentences.
- Keep helpdesk_explanation plain-language and non-technical.
- next_steps must contain exactly 3 short actionable items.
- Do not invent facts not present in the input.
- Do not contradict the final action.
- Mention human review when requires_human_review is true.
"""


def build_prompt(req: LLMAssistRequestV1) -> str:
    return f"""You are a bounded cybersecurity triage assistant for a teaching SOC environment.

Your job is to help a human analyst understand the triage result.
You MUST NOT change the action, risk score, or policy decision.
You MUST NOT recommend destructive or autonomous actions.
You MUST stay consistent with the provided detector and policy results.

{_SCHEMA_INSTRUCTION}

Input:
event_id: {req.event_id}
source: {req.source}
event_type: {req.event_type}
language: {req.language}
risk_score_rule: {req.risk_score_rule}
risk_score_fl: {req.risk_score_fl}
risk_score_final: {req.risk_score_final}
label: {req.label}
action: {req.action}
explanation: {req.explanation}
policy_rule_id: {req.policy_rule_id}
policy_reason: {req.policy_reason}
requires_human_review: {req.requires_human_review}
features: {req.features}
scenario_id: {req.scenario_id}
""".strip()


# ---------- Schema validation ---------- #

def _parse_and_validate(raw: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except Exception as e:
        raise LLMProviderError(f"Output was not valid JSON: {raw[:300]}") from e

    analyst_summary = parsed.get("analyst_summary")
    helpdesk_explanation = parsed.get("helpdesk_explanation")
    next_steps = parsed.get("next_steps")

    if (
        not isinstance(analyst_summary, str)
        or not analyst_summary.strip()
        or not isinstance(helpdesk_explanation, str)
        or not helpdesk_explanation.strip()
        or not isinstance(next_steps, list)
        or len(next_steps) != 3
        or not all(isinstance(s, str) and s.strip() for s in next_steps)
    ):
        raise LLMProviderError(
            f"Output did not match required schema: {raw[:300]}"
        )

    return {
        "analyst_summary": analyst_summary.strip(),
        "helpdesk_explanation": helpdesk_explanation.strip(),
        "next_steps": [s.strip() for s in next_steps],
    }


def _invoke(provider: LLMProvider, prompt: str) -> Dict[str, Any]:
    raw = provider.generate_json(prompt)
    return _parse_and_validate(raw)


# ---------- Training grading (MVP) ---------- #


def _parse_and_validate_training_grade(raw: str) -> Dict[str, Any]:
    """Validate a strict JSON grading response."""
    try:
        parsed = json.loads(raw)
    except Exception as e:
        raise LLMProviderError(f"Output was not valid JSON: {raw[:300]}") from e

    passed = parsed.get("passed")
    letter = parsed.get("letter_grade")
    score_pct = parsed.get("score_pct")
    feedback = parsed.get("feedback")

    if not isinstance(passed, bool):
        raise LLMProviderError(f"Missing/invalid passed: {raw[:200]}")
    if not isinstance(letter, str) or letter.strip().upper() not in {"A", "B", "C", "D", "F"}:
        raise LLMProviderError(f"Missing/invalid letter_grade: {raw[:200]}")
    try:
        score_f = float(score_pct)
    except Exception as e:
        raise LLMProviderError(f"Missing/invalid score_pct: {raw[:200]}") from e
    score_f = max(0.0, min(100.0, score_f))
    if not isinstance(feedback, dict):
        raise LLMProviderError(f"Missing/invalid feedback: {raw[:200]}")

    strengths = feedback.get("strengths") or []
    improvements = feedback.get("improvements") or []
    steps = feedback.get("step_by_step") or []
    if not (isinstance(strengths, list) and isinstance(improvements, list) and isinstance(steps, list)):
        raise LLMProviderError(f"Invalid feedback lists: {raw[:200]}")

    strengths = [str(s).strip() for s in strengths if str(s).strip()][:8]
    improvements = [str(s).strip() for s in improvements if str(s).strip()][:8]
    steps = [str(s).strip() for s in steps if str(s).strip()][:10]

    return {
        "passed": bool(passed),
        "letter_grade": letter.strip().upper(),
        "score_pct": score_f,
        "feedback": {"strengths": strengths, "improvements": improvements, "step_by_step": steps},
    }


def _invoke_training_grade(provider: LLMProvider, prompt: str) -> Dict[str, Any]:
    raw = provider.generate_json(prompt)
    return _parse_and_validate_training_grade(raw)


def _build_training_grade_prompt(challenge: Dict[str, Any], run: Dict[str, Any], actions: list[Dict[str, Any]]) -> str:
    return f"""You are grading a SOC analyst training exercise.

Return ONLY valid JSON with EXACT keys:
{{
  "passed": true|false,
  "letter_grade": "A"|"B"|"C"|"D"|"F",
  "score_pct": 0-100,
  "feedback": {{
    "strengths": [string, ...],
    "improvements": [string, ...],
    "step_by_step": [string, ...]
  }}
}}

Grading guidance:
- Be strict but fair.
- Use the challenge objectives and rubric to justify the grade.
- If the challenge guardrails prohibit unsafe automated enforcement and the trainee recommends it, they should not pass.

Challenge:
{json.dumps(challenge, indent=2)}

Run:
{json.dumps(run, indent=2)}

Actions (chronological):
{json.dumps(actions, indent=2)}
""".strip()


def grade_training(challenge: Dict[str, Any], run: Dict[str, Any], actions: list[Dict[str, Any]]) -> Dict[str, Any]:
    """Grade a training run using the teacher/student providers.

    Returns a dict shaped for llm_assistant/app.py TrainingGradeResponse.
    """
    prompt = _build_training_grade_prompt(challenge, run, actions)

    if _TEACHER.enabled:
        try:
            g = _invoke_training_grade(_TEACHER, prompt)
            return {
                "grade": g,
                "llm_used": True,
                "llm_reason": f"Graded by teacher {_TEACHER.name}:{_TEACHER.model}.",
                "llm_tier": "teacher",
                "llm_provider": _TEACHER.name,
                "llm_model": _TEACHER.model,
            }
        except LLMProviderError as e:
            log.info("Teacher grading failed: %s", e)

    if _STUDENT.enabled:
        try:
            g = _invoke_training_grade(_STUDENT, prompt)
            return {
                "grade": g,
                "llm_used": True,
                "llm_reason": f"Graded by student {_STUDENT.name}:{_STUDENT.model}.",
                "llm_tier": "student",
                "llm_provider": _STUDENT.name,
                "llm_model": _STUDENT.model,
            }
        except LLMProviderError as e:
            log.info("Student grading failed: %s", e)

    return {
        "grade": {
            "passed": False,
            "letter_grade": "F",
            "score_pct": 0.0,
            "feedback": {
                "strengths": [],
                "improvements": ["No LLM provider configured for grading."],
                "step_by_step": ["Enable a student or teacher provider, then re-run grading."],
            },
        },
        "llm_used": False,
        "llm_reason": "fallback: no providers enabled",
        "llm_tier": "fallback",
    }


# ---------- Fallback ---------- #

def safe_fallback(req: LLMAssistRequestV1, reason: str) -> LLMAssistResponseV1:
    analyst_summary = (
        f"This event was labeled {req.label} with final action '{req.action}'. "
        f"The detector explanation indicates: {req.explanation} "
        f"Policy rule {req.policy_rule_id} supports this decision."
    )
    helpdesk_explanation = (
        "This message was flagged because it appears similar to a suspicious "
        "security-related message. Please avoid clicking links or entering "
        "credentials until the sender and message are verified."
    )
    next_steps = [
        "Verify the sender and domain against known trusted systems.",
        "Inspect any links or account-verification claims before taking action.",
        "Follow the documented triage runbook and escalate if required.",
    ]
    return LLMAssistResponseV1(
        analyst_summary=analyst_summary,
        helpdesk_explanation=helpdesk_explanation,
        next_steps=next_steps,
        llm_used=False,
        llm_reason=f"Fallback used: {reason}",
        llm_tier=LLMTier.FALLBACK,
        llm_provider=None,
        llm_model=None,
    )


# ---------- Shadow logging ---------- #

_shadow_lock = threading.Lock()


def _log_shadow(req: LLMAssistRequestV1, teacher_output: Dict[str, Any]) -> None:
    """Append a teacher output alongside the request to the shadow log.

    Only triggered when operating mode is TEACHER_SHADOW. The shadow log is
    the canonical distillation corpus source and is written under the audit
    ledger volume.
    """
    try:
        SHADOW_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "request": req.model_dump(mode="json"),
            "teacher_output": teacher_output,
            "teacher_provider": _TEACHER.name,
            "teacher_model": _TEACHER.model,
        }
        with _shadow_lock, open(SHADOW_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        log.warning("Shadow log write failed: %s", e)


def _shadow_fire_and_forget(req: LLMAssistRequestV1, prompt: str) -> None:
    if not _TEACHER.enabled:
        return

    def _run():
        try:
            out = _invoke(_TEACHER, prompt)
            _log_shadow(req, out)
        except LLMProviderError as e:
            log.info("Teacher shadow skipped: %s", e)
        except Exception as e:
            log.warning("Teacher shadow failed: %s", e)

    threading.Thread(target=_run, name="teacher-shadow", daemon=True).start()


# ---------- Core router ---------- #

def _select_mode(req: LLMAssistRequestV1) -> LLMMode:
    if req.mode is not None:
        return req.mode
    if req.requires_human_review:
        return HUMAN_REVIEW_MODE
    return DEFAULT_MODE


def _response_from(
    parsed: Dict[str, Any],
    tier: LLMTier,
    provider: LLMProvider,
    reason: str,
) -> LLMAssistResponseV1:
    return LLMAssistResponseV1(
        analyst_summary=parsed["analyst_summary"],
        helpdesk_explanation=parsed["helpdesk_explanation"],
        next_steps=parsed["next_steps"],
        llm_used=True,
        llm_reason=reason,
        llm_tier=tier,
        llm_provider=provider.name,
        llm_model=provider.model,
    )


def _try_student(prompt: str) -> Optional[LLMAssistResponseV1]:
    if not _STUDENT.enabled:
        return None
    try:
        parsed = _invoke(_STUDENT, prompt)
    except LLMProviderError as e:
        log.info("Student failed: %s", e)
        return None
    return _response_from(
        parsed,
        tier=LLMTier.STUDENT,
        provider=_STUDENT,
        reason=f"Generated by student {_STUDENT.name}:{_STUDENT.model}.",
    )


def _try_teacher(prompt: str) -> Tuple[Optional[LLMAssistResponseV1], Optional[Dict[str, Any]]]:
    if not _TEACHER.enabled:
        return None, None
    try:
        parsed = _invoke(_TEACHER, prompt)
    except LLMProviderError as e:
        log.info("Teacher failed: %s", e)
        return None, None
    resp = _response_from(
        parsed,
        tier=LLMTier.TEACHER,
        provider=_TEACHER,
        reason=f"Generated by teacher {_TEACHER.name}:{_TEACHER.model}.",
    )
    return resp, parsed


def route(req: LLMAssistRequestV1) -> LLMAssistResponseV1:
    mode = _select_mode(req)
    prompt = build_prompt(req)

    if mode == LLMMode.TEACHER_ONLY:
        resp, _ = _try_teacher(prompt)
        if resp is not None:
            return resp
        # Teacher unavailable -> try student so triage is never blocked.
        student_resp = _try_student(prompt)
        if student_resp is not None:
            return student_resp
        return safe_fallback(req, "teacher_only mode but teacher+student both unavailable")

    if mode == LLMMode.STUDENT_ONLY:
        student_resp = _try_student(prompt)
        if student_resp is not None:
            return student_resp
        return safe_fallback(req, "student unavailable")

    if mode == LLMMode.TEACHER_SHADOW:
        # Student responds to the user; teacher runs in background.
        _shadow_fire_and_forget(req, prompt)
        student_resp = _try_student(prompt)
        if student_resp is not None:
            return student_resp
        # Student unavailable: we may wait briefly on teacher so the user
        # still gets a response, but only because the shadow path already
        # started the teacher call.
        teacher_resp, _ = _try_teacher(prompt)
        if teacher_resp is not None:
            return teacher_resp
        return safe_fallback(req, "shadow mode but both tiers unavailable")

    if mode == LLMMode.TEACHER_THEN_STUDENT_REFINE:
        teacher_resp, teacher_parsed = _try_teacher(prompt)
        if teacher_resp is None:
            student_resp = _try_student(prompt)
            if student_resp is not None:
                return student_resp
            return safe_fallback(req, "refine mode but teacher+student both unavailable")

        # Ask student to rewrite plain-language pieces while preserving
        # structure. If the refine call fails, return the teacher output.
        refine_prompt = (
            prompt
            + "\n\nPrior draft (rewrite it for clarity; keep the same facts and next_steps):\n"
            + json.dumps(teacher_parsed)
        )
        try:
            refined = _invoke(_STUDENT, refine_prompt) if _STUDENT.enabled else None
        except LLMProviderError:
            refined = None

        if refined is None:
            return teacher_resp

        # Student must not invent new facts; keep teacher's next_steps as-is.
        refined["next_steps"] = teacher_parsed["next_steps"]
        return _response_from(
            refined,
            tier=LLMTier.STUDENT,
            provider=_STUDENT,
            reason=(
                f"Teacher {_TEACHER.name}:{_TEACHER.model} drafted; "
                f"student {_STUDENT.name}:{_STUDENT.model} refined."
            ),
        )

    return safe_fallback(req, f"unknown mode {mode}")
