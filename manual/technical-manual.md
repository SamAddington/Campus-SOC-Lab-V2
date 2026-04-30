# Technical manual — Agentic SOC stack

This document describes **architecture**, **services**, **data contracts**, and **operational interfaces** for engineers and operators maintaining the repository.

For a narrative overview, see the root `README.md`. For governance and privacy depth, see `docs/privacy_model.md`, `governance_checklist.md`, and `docs/osint.md`.

---

## 1. System architecture

### 1.1 Logical pipeline

```text
simulator ──▶ collector ──▶ detector ──▶ orchestrator ──▶ audit ──▶ console (SSE)
                                 ▲       policy_engine ─┘    │
                                 │       osint ──────────────┤
                                 │       llm_assistant ──────┤
                aggregator ◀─────┘       (federated signal)  │
                                                              ▼
                                                    /log_override (reviewer)
```

- **Ingest path**: Events enter via `collector` `/ingest` (or orchestrator-driven `process_event` which reuses collector semantics), are HMAC-anonymized, featurized, optionally indexed to OpenSearch, then scored.
- **Decision path**: `orchestrator` `/process_event` sequences detector → OSINT (conditional) → policy → LLM (bounded) → audit persist.
- **Real-time UI**: `audit` exposes Server-Sent Events (`/stream`); the console subscribes via nginx (`/api/audit/stream`) with buffering disabled.

### 1.2 Service matrix (ports)

| Port | Service | Runtime | Primary responsibilities |
|-----:|---------|---------|---------------------------|
| 8080 | Console | nginx + static SPA | Operator UI; proxies `/api/*` to backends |
| 8001 | collector | FastAPI | Ingest, HMAC, features, optional OpenSearch/SIEM spool, correlation scheduler |
| 8000 | detector | FastAPI | Rule + optional ML + optional federated boost → scores |
| 8021 | orchestrator | FastAPI | MAO: assemble decision card, call agents |
| 8020 | policy_engine | FastAPI | YAML rules → action + human review flag |
| 8022 | audit | FastAPI | Append-only JSONL ledger, hash chain, SSE |
| 8028 | osint | FastAPI | Indicator extraction, provider calls, cache |
| 8024 | llm_assistant | FastAPI | Teacher/student router; schema-validated responses |
| 8010 | aggregator | FastAPI | FedAvg-style global logistic model |
| 8011–8013 | client_* | FastAPI | Local training + submit updates |
| 8023 | simulator | FastAPI | Scripted scenarios through pipeline |
| 8027 | traffic_ingestor | FastAPI | Flow adapters, windowed detectors, anomaly → collector |
| 8025 | integrations | FastAPI | LMS/network connectors → collector |
| 8026 | distiller | FastAPI | Corpus export / eval summaries |
| 8888 | notebooks | JupyterLab | Teaching and threshold-equity workflows |

Compose wiring: `docker-compose.yml`. Environment template: `.env.example`.

---

## 2. Shared contracts

### 2.1 Python shared package

Path: `shared/` (mounted or copied per service Dockerfile).

- **`shared/schemas/`** — Pydantic models for decision cards, detector output, LLM responses, ingest shapes.
- **`shared/security.py`** — API key and optional JWT/OIDC verification; role dependencies for FastAPI.
- **`shared/normalize.py`** — ECS-oriented normalization for indexed events.
- **`shared/siem/`** — Optional SIEM emitters and durable spool.
- **`shared/hardening.py`** — Rate limits and body size limits (where applied).

### 2.2 Audit ledger files

Typical volume mount: `audit/ledger/` (see compose).

- `decision_cards.jsonl`, `overrides.jsonl`, `policy_events.jsonl`, `simulation_runs.jsonl`, optional `teacher_shadow.jsonl`.
- Records carry `previous_hash` / `record_hash` for tamper evidence (`AUDIT_SIGNING_KEY`).

### 2.3 Policy rules

- Single source: `policy_engine/rules.yaml`.
- Evaluated **in order**; first match wins. Every match surfaces as `policy_rule_id` and rationale on the decision card.

---

## 3. Key HTTP APIs (direct access)

> In production UI, prefer paths under **`/api/<service>/...`** from the console origin.

| Service | Example endpoints | Auth |
|---------|-------------------|------|
| collector | `POST /ingest`, `GET /search`, `GET /health`, `POST /correlation/dry_run` | `X-API-Key` and/or `Authorization: Bearer` |
| orchestrator | `POST /process_event` | `X-API-Key` |
| audit | `GET /decision_cards`, `GET /stream`, integrity/retention routes | `X-API-Key` |
| detector | `POST /score` | Internal / key per deployment |
| policy | `POST /evaluate` | Service-to-service |
| osint | enrichment entrypoints | As configured |
| llm_assistant | `GET /providers`, `POST /assist` | As configured |

Refer to each service’s `app.py` for the authoritative route list and request bodies.

---

## 4. Data stores and indices

- **Local JSONL**: `data/ingested_events.jsonl` (collector append path; workshop scale).
- **OpenSearch** (optional): `EVENTSTORE_OPENSEARCH_*` env vars; index templates created by collector on startup when enabled.
- **Entity index**: companion index for pivot entities when event store is on.
- **Federated state**: `federated/shared/global_model.json`, `round_state.json`, `updates.json` on shared volume.

---

## 5. Build and deploy

```bash
cp .env.example .env   # set HMAC_SECRET, SOC_API_KEY, AUDIT_SIGNING_KEY at minimum
docker compose build
docker compose up -d
```

- **Console**: multi-stage Node build → nginx static hosting; build args may inject Vite `VITE_*` OIDC settings.
- **Python services**: per-service `Dockerfile` + `requirements.txt`; compose sets service URLs via internal DNS.

---

## 6. Observability

- Collector **`GET /metrics`** (Prometheus text) for SIEM/spool counters when enabled.
- **Services** page in console: health checks per backend.

---

## 7. Security notes (technical)

- Rotate **`HMAC_SECRET`**, **`SOC_API_KEY`**, **`AUDIT_SIGNING_KEY`** for any non-workshop use.
- JWT/OIDC: configure `SOC_OIDC_JWKS_URL`, issuer, audience; roles from token claims. Optional tenant isolation: `SOC_TENANT_ISOLATION`, `SOC_DEFAULT_TENANT`, `CORRELATION_SOC_TENANT` (collector).
- OSINT and integrations use **`scopes.yaml`** allowlists — widening paths is a governance change.

---

## 8. Further reading

| Topic | Document |
|-------|----------|
| Traffic adapters | `docs/traffic_anomaly.md` |
| Integrations | `docs/integrations/README.md` |
| OSINT | `docs/osint.md` |
| LLM tiers | `docs/llm_teacher_student.md` |
| Privacy | `docs/privacy_model.md` |
| Overrides | `docs/overrides_log.md` |

---

*Document version: aligned with repository layout and root README. Update when services or ports change.*
