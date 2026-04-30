"""FastAPI wrapper around the teacher/student LLM router.

Keeps the historical public contract (``POST /assist`` returning
``{analyst_summary, helpdesk_explanation, next_steps, llm_used, llm_reason}``)
while adding the new ``llm_tier`` / ``llm_provider`` / ``llm_model`` fields
so the orchestrator and audit ledger can capture provenance.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Dict

from fastapi import FastAPI

sys.path.insert(0, "/app")
from shared.schemas import LLMAssistRequestV1

from teacher_student import provider_status, route, safe_fallback

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("llm_assistant")

app = FastAPI(title="WiCyS LLM Assistant", version="0.2.0")


@app.get("/health")
def health() -> Dict[str, Any]:
    status = provider_status()
    return {"status": "up", **status}


@app.get("/providers")
def providers() -> Dict[str, Any]:
    return provider_status()


@app.post("/assist")
def assist(req: LLMAssistRequestV1) -> Dict[str, Any]:
    try:
        resp = route(req)
    except Exception as e:
        log.exception("Unexpected router error: %s", e)
        resp = safe_fallback(req, f"router_error: {e.__class__.__name__}")
    return resp.model_dump(mode="json")
