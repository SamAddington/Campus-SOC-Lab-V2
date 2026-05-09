# Teacher / Student LLM Assistant

The `llm_assistant` service is a bounded wrapper that routes between a large
**teacher** model and a small on-device **student** model, then validates
every response against a strict JSON schema before returning it to the
orchestrator.

## Provider matrix

| Provider slug | Backend | Credentials env |
|---|---|---|
| `none` | Disabled | _none_ |
| `ollama` | Local Ollama daemon | `OLLAMA_BASE_URL` |
| `openai` | OpenAI-compatible chat-completions (api.openai.com, Groq, OpenRouter, LM Studio, ...) | `OPENAI_API_KEY`, `OPENAI_BASE_URL` |
| `anthropic` | Anthropic Messages API | `ANTHROPIC_API_KEY` |

The teacher and the student are configured independently with
`TEACHER_PROVIDER` / `TEACHER_MODEL` and `STUDENT_PROVIDER` / `STUDENT_MODEL`.
The console Settings page can also save runtime overrides, including
`OLLAMA_BASE_URL`, to `LLM_RUNTIME_CONFIG_PATH` and reload the LLM assistant
providers without Docker socket access.

For host Ollama, use `OLLAMA_BASE_URL=http://host.docker.internal:11434`.
For Docker Ollama, start the optional service and pull the model:

```powershell
docker compose up -d ollama
docker compose exec ollama ollama pull llama3.2:1b
```

Then set the runtime Ollama base URL to `http://ollama:11434`. The optional
service maps host port `${OLLAMA_HOST_PORT:-11435}` to container port `11434`
so it can coexist with a host Ollama already using `11434`.

## Routing modes

Set `LLM_DEFAULT_MODE` and `LLM_HUMAN_REVIEW_MODE` in the environment.

| Mode | Behavior |
|---|---|
| `student_only` | Only the student runs. Default for realtime. Lowest latency, fully offline if student is `ollama`. |
| `teacher_only` | Only the teacher runs. For offline curation of distillation targets. |
| `teacher_shadow` | Student serves the user; teacher runs in a background thread and writes to `teacher_shadow.jsonl`. User latency unchanged. |
| `teacher_then_student_refine` | Teacher drafts, student rewrites for clarity without inventing new facts. |

`LLM_HUMAN_REVIEW_MODE` applies when the policy engine flags an event with
`requires_human_review=true`; `LLM_DEFAULT_MODE` applies otherwise.

## Schema contract

Every tier must return, after post-filtering, the `LLMAssistResponseV1`
shape:

```json
{
  "analyst_summary": "string",
  "helpdesk_explanation": "string",
  "next_steps": ["string", "string", "string"],
  "llm_used": true,
  "llm_reason": "string",
  "llm_tier": "student | teacher | fallback",
  "llm_provider": "ollama | openai | anthropic | null",
  "llm_model": "string | null"
}
```

If a provider misbehaves (non-JSON, wrong schema, transport error), the
router falls back to the deterministic template in `safe_fallback`. Fallback
responses always carry `llm_used=false` and `llm_tier=fallback`.

## Distillation loop

1. Run traffic with `LLM_DEFAULT_MODE=teacher_shadow` (or configured per
   event). Teacher outputs accumulate in `audit/ledger/teacher_shadow.jsonl`.
2. Call `POST http://localhost:8026/export_corpus` on the distiller. Set
   `include_simulator=true` to include synthetic scenarios, and
   `require_teacher_output=true` to keep only pairs with a teacher label.
3. Open notebook `05_teacher_student_eval.ipynb` to compare served vs
   teacher outputs, broken down by language.
4. If agreement metrics pass thresholds documented in the notebook, a human
   reviewer approves promotion by writing an entry in
   `docs/threshold_changes.md`.
5. Model training itself is intentionally outside this service; use the
   exported corpus with your toolchain of choice (Unsloth, PEFT, HF TRL,
   ...). Import the resulting model back into Ollama and set `STUDENT_MODEL`
   accordingly.

## What the assistant will NOT do

- Change the detector's risk score, the policy action, or the human-review
  flag. The assistant is strictly an explainer.
- Recommend autonomous or destructive actions.
- Return content that fails JSON-schema validation. Failures are silently
  converted to a bounded fallback and marked in the audit ledger.
