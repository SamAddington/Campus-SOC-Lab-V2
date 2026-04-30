# Privacy Model (Phase 0)

This document describes the privacy commitments implemented in the current
stack. It is kept short on purpose: each commitment should be testable from
the running system.

## 1. Keyed anonymization (HMAC)

- All `user_id` and `email` values are hashed with **HMAC-SHA256** using a
  per-deployment secret (`HMAC_SECRET`), truncated to 16 hex chars.
- The secret lives only in the collector (and any future integration)
  container's environment. It is never logged, returned in a response,
  or written to the audit ledger.
- Truncation is safe because an attacker without the secret cannot
  precompute a rainbow table for `hmac(secret, email)` across the input
  space; truncation only matters once the secret is known.

**Test:** start the stack with `HMAC_SECRET=change-me-dev-only` and confirm
`GET /health` on the collector returns `"hmac_keyed": false`. Set a real
secret in `.env` and re-check: it must flip to `true`.

## 2. Raw-identifier exclusion

- `AnonRecordV1` does not contain `user_id` or `email` fields. Only the
  hash and the email domain leave the collector.
- `data/ingested_events.jsonl` is derived from `AnonRecordV1` and inherits
  the same exclusion. It is safe to share with instructors.

## 3. Bounded LLM outputs

- The LLM assistant post-filters every provider response against the
  `LLMAssistResponseV1` schema. Non-conforming outputs fall back to a
  bounded deterministic response.
- `llm_tier` / `llm_provider` / `llm_model` are stamped into every
  decision card so external-API usage is always auditable.

## 4. Consent-gated distillation

- Decision cards carry a `consent_use_for_distillation` boolean that
  propagates from ingest.
- The distiller filters out any record where this is false, unless the
  record came from a simulator scenario (which is synthetic by
  construction) **and** the operator opts in via `include_simulator=true`.

## 5. Roadmap

Not yet implemented; planned for later phases:

- Differential-privacy noise on federated client updates (`Laplace(ε)`).
- Egress allowlist / redaction via a `privacy_gateway` sidecar.
- k-anonymity check in the collector before an event can influence
  federated training.
