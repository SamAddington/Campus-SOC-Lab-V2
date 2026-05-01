# Agentic SOC — FL · PE · MAO · AL · SIM · LLM

**An interpretable, research-grade, multi-agent Security Operations Center (SOC) framework for resource-constrained environments.**

> Agentic AI for Resource-Constrained Campus SOCs: Hands-On, Interpretable Defense

This repository is a **research prototype** that combines the core pillars of a modern, explainable SOC into a single containerized stack:

| Acronym | Pillar                                   | Services                                                      |
|---------|------------------------------------------|---------------------------------------------------------------|
| **SOC** | Security Operations Center pipeline      | `collector`, `detector`, `audit`, `console`                   |
| **FL**  | **Federated Learning**                   | `aggregator`, `client_a`, `client_b`, `client_c`              |
| **PE**  | **Policy Engine** (deterministic rules)  | `policy_engine` + `rules.yaml`                                |
| **MAO** | **Multi-Agent Orchestration**            | `orchestrator` (fan-out to detector, policy, OSINT, LLM, FL)  |
| **AL**  | **Audit Ledger** (append-only + SSE)     | `audit` (`/log_decision`, `/log_override`, `/stream`)         |
| **SIM** | **Simulation** (scripted attack/benign)  | `simulator`, `traffic_ingestor`                               |
| **LLM** | **Teacher / Student LLM Assistant**      | `llm_assistant`, `distiller`                                  |

The stack is designed to run on a standard laptop (Docker Desktop, ~4 GB RAM), use **anonymized or synthetic logs only**, and foreground **interpretability**, **privacy**, **fairness**, and **human-in-the-loop defense**.

---

## Author

**Samuel Addington**
*AI-driven Cybersecurity Researcher · Computer Science Professor*

This project is maintained as part of an ongoing research program on agentic, privacy-preserving, and pedagogically transparent AI for cyber defense in under-resourced institutions.

> **Research-only notice.** This software is provided **strictly for research, teaching, and experimentation**. It is **not** intended, certified, or supported for production security operations. Do not connect it to production identity, LMS, email, or network systems. Always use synthetic or properly anonymized data and follow your institution's policies and applicable regulations (FERPA, GDPR, etc.) before any field use.

---

## Design principles

* **Interpretability first.** Rule-based features plus a tiny second-opinion ML model. Every decision carries a human-readable rationale.
* **Privacy by construction.** HMAC-keyed anonymization at ingest; aggressive data reduction; no raw payloads or identifiers propagate past the collector.
* **Fairness and language equity.** Per-group metrics and threshold-tuning notebooks; explicit governance checklist.
* **Human-in-the-loop.** Three bounded actions — `allow`, `queue_for_review`, `escalate` — plus reviewer overrides persisted to the audit ledger.
* **Agentic but bounded.** The LLM assistant is an **explainer**, not an actor; it cannot change scores, policies, or human-review flags.
* **Teacher / student distillation loop.** Large teacher model captures high-quality rationales offline; small on-device student serves real-time triage; a distiller produces training corpora under consent and governance constraints.
* **Federated, not centralized.** Clients train locally and share only model updates with the aggregator; raw data never leaves the client.
* **SIEM-style unified UX.** One dark-themed console fronts every service with live SSE updates.

---

## Security, privacy, and AI compliance posture (practical)

This stack is designed to support **Zero Trust-style operation**, **NIST CSF 2.0-aligned governance**, **privacy by design**, and **auditability** in a workshop/research setting. Key operator-facing controls:

- **API access control (Zero Trust baseline)**: sensitive endpoints require `X-API-Key` (`SOC_API_KEY`). Configure the same key in the console under **Settings → API access** (stored as `localStorage.soc_api_key`).
- **AI is bounded + auditable**: the LLM assistant is an *explainer* only (cannot change scores/actions). Each decision card records `llm_tier`, `llm_provider`, and `llm_model` so any external AI usage is auditable.
- **Privacy by design**: identifiers are HMAC-pseudonymized at ingest (`HMAC_SECRET`). See `docs/privacy_model.md`.
- **OSINT minimization**: only extracted indicators are queried; private/reserved IPs are rejected; outbound endpoints are allowlisted (`osint/scopes.yaml`). See `docs/osint.md`.
- **Audit integrity + retention**: ledger records are hash-chained (`previous_hash`, `record_hash`) using `AUDIT_SIGNING_KEY`; retention is controlled by `AUDIT_RETENTION_DAYS` and can be enforced via `POST /retention/purge`.

Important: enabling a hosted LLM teacher (`TEACHER_PROVIDER=openai|anthropic`) sends prompts/outputs to that vendor. Keep `TEACHER_PROVIDER=none` for fully local operation.

## Settings page coverage

The console's **Settings** page stores operator preferences in browser `localStorage`. It now includes sections for:

- **LLM providers (local notes)**: teacher/student provider/model and routing modes. Backend is still configured via env vars.
- **Threat intel & OSINT keys (local reference)**: NVD, MalwareBazaar, Tavily (intended for future integrations). Prefer env/secret stores in real deployments.
- **Deployment profile**: how you intend to run orchestration at runtime and whether local LLM inference is GPU-accelerated.
- **Neurosymbolic guardrails (posture)**: strictness / hosted-teacher allowance as operator guidance.

These settings are primarily to keep the *operational intent* explicit and auditable; they do not automatically reconfigure running containers.

## Core functionality

### 1. SOC operations pipeline

A complete, end-to-end campus-SOC pipeline composed of small FastAPI services:

```text
simulator ──▶ collector ──▶ detector ──▶ orchestrator ──▶ audit ──▶ console (SSE)
                                 ▲       policy_engine ─┘    │
                                 │       osint ──────────────┤
                                 │       llm_assistant ──────┤
                aggregator ◀─────┘                            ▼
                                                    /log_override (reviewer)
```

* **`collector`** — Ingests LMS / email / traffic events, performs HMAC anonymization, extracts features (`contains_link`, `contains_password`, `contains_urgent`, `contains_reward`, `len_message`, …), and appends to `data/ingested_events.jsonl`. Optional **SIEM egress** can forward anonymized records to Splunk HEC, Elastic/OpenSearch, Sentinel, or Syslog (QRadar/ArcSight) when enabled via env vars.
* **`detector`** — Rule-based risk scoring with an **optional tiny logistic ML second opinion** (`USE_ML=1`) and an **optional federated global model** (`USE_FEDERATED=1`). Produces `risk_score_rule`, `risk_score_final`, `label`, and `action`.
* **`policy_engine`** — Deterministic YAML-defined rules (`policy_engine/rules.yaml`) that map `(source, event_type, score bands, OSINT verdict, …)` → `{allow, queue_for_review, escalate}` with a `requires_human_review` flag.
* **`audit`** — Append-only ledger of decision cards, overrides, policy events, and simulation runs with a tamper-evident hash chain (`previous_hash`, `record_hash`). Exposes a **Server-Sent Events** stream (`GET /stream`) that the console consumes in real time.

### 2. Multi-Agent Orchestration (MAO)

The **`orchestrator`** is the agentic conductor of the pipeline. On each `POST /process_event` it:

1. Calls the **collector** (ingest + anonymize + featurize).
2. Conditionally calls the **OSINT** agent for enrichment (skips traffic anomalies by design; fires on high-risk-score or email events).
3. Calls the **policy engine** with detector + OSINT features.
4. Calls the **LLM assistant** in the mode selected by policy (`requires_human_review` → `LLM_HUMAN_REVIEW_MODE`; else `LLM_DEFAULT_MODE`).
5. Assembles a complete `DecisionCard` (schema `v1`) with full provenance — detector scores, policy rule ID, OSINT verdict/indicator count/providers, LLM tier/provider/model, FL round, threshold version, consent flags — and logs it to **audit**.

Each downstream agent can fail independently without blocking the pipeline: OSINT returns a typed "skipped" result; the LLM falls back to a deterministic safe template; the federated model degrades to rule-only scoring.

### 3. Federated Learning (FL)

Weighted-FedAvg logistic regression over the shared interpretable feature set:

* **`aggregator`** (port 8010) — Holds round state, collects per-client updates (`coef`, `intercept`, `sample_count`, `feature_order`), computes sample-weighted global model, writes `federated/shared/global_model.json`.
* **`client_a` / `client_b` / `client_c`** (ports 8011–8013) — Train locally on their own `data/` partition and `POST /submit_update` to the aggregator. Raw data never leaves the client.
* **Governance-friendly combination.** In the detector, the federated score may **only raise** the final risk score, never lower it — an explicit conservative design choice for teaching environments.
* Notebook `04_federated_learning_review.ipynb` walks through rounds, participation, and drift.

### 4. Policy Engine (PE)

A small, auditable YAML rules file (`policy_engine/rules.yaml`) covering:

* OSINT-verdict escalations (`OSINT-MALICIOUS-001`, `OSINT-SUSPICIOUS-001`).
* Source-specific bands (`EMAIL-HIGH-001`, `LMS-MED-001`).
* Traffic-anomaly tiers (`TRAFFIC-ANOMALY-{HIGH,MED,LOW}-001`) — **no automated enforcement** is permitted on traffic-derived signals.
* Low-risk pass-through (`LOW-RISK-001`).

Rules are evaluated in order; the first match wins. Every match records a `policy_rule_id` and human-readable `policy_reason` in the decision card.

### 5. Audit Ledger (AL) with real-time streaming

* Append-only JSONL ledger on a Docker volume: `decision_cards.jsonl`, `overrides.jsonl`, `policy_events.jsonl`, `simulation_runs.jsonl`, `teacher_shadow.jsonl`.
* Hash-chained records signed with `AUDIT_SIGNING_KEY`; integrity can be checked through `GET /integrity/verify`.
* Retention controls via `AUDIT_RETENTION_DAYS` and `POST /retention/purge`.
* **SSE pub/sub** (`GET /api/audit/stream`): `log_decision` and `log_override` calls publish typed JSON envelopes to every subscriber, with heartbeats so idle connections don't time out.
* The console's Dashboard and Alerts pages update **without polling** and show a live/offline health indicator.
* An `nginx` unbuffered location block preserves streaming through the reverse proxy.

### 6. Simulation (SIM)

Two complementary simulators:

* **`simulator`** — Scripted JSON scenarios under `simulator/scenarios/` fan out through the full pipeline. Included scenarios:
  * `phishing_burst`, `password_reset_lure_wave`, `reward_bait_wave`
  * `lms_account_takeover`, `late_night_burst`, `override_training_case`
  * `multilingual_campaign`, `benign_multilingual_reminders`
  * `advising_and_financial_aid_mix`, `mixed_benign_noise`, `cross_campus_drift_case`
* **`traffic_ingestor`** — Rolling-window flow telemetry with pluggable anomaly detectors (EWMA z-score, rate-burst, optional Isolation Forest) plus a **synthetic traffic generator** (start / stop / burst). Outputs aggregate anomalies only — never raw IPs or payloads.

### 7. Teacher / Student LLM Assistant

`llm_assistant` is a **bounded explainer** that routes each request between two tiers and validates every response against a strict `LLMAssistResponseV1` JSON schema.

**Tiers and providers**

| Tier     | Role                           | Providers supported                                                 |
|----------|--------------------------------|---------------------------------------------------------------------|
| Student  | Small, on-device, real time    | `ollama` (default), `openai`-compatible, `anthropic`, `none`        |
| Teacher  | Larger, offline / shadow       | `openai`-compatible, `anthropic`, `ollama`, `none`                  |

**Routing modes** (`LLM_DEFAULT_MODE`, `LLM_HUMAN_REVIEW_MODE`)

| Mode                              | Behavior                                                                                    |
|-----------------------------------|---------------------------------------------------------------------------------------------|
| `student_only`                    | Student only (default real-time). Fully offline if student is `ollama`.                    |
| `teacher_only`                    | Teacher only. Offline curation of distillation targets.                                     |
| `teacher_shadow`                  | Student serves the user; teacher runs in a background thread → `teacher_shadow.jsonl`.      |
| `teacher_then_student_refine`     | Teacher drafts, student rewrites for clarity without inventing new facts.                   |

If all providers are disabled or misbehave, the router falls back to a deterministic template with `llm_used=false`, `llm_tier=fallback`.

**Invariants**

The LLM **never** changes the detector score, the policy action, or the human-review flag. Every decision card carries full provenance: `llm_tier`, `llm_provider`, `llm_model`, `llm_reason`.

### 8. Knowledge distillation loop

The **`distiller`** service (port 8026) closes the teacher → student loop:

1. Run traffic in `teacher_shadow` mode — teacher outputs accumulate in the audit ledger.
2. `POST /export_corpus` with consent filters (`include_simulator`, `require_teacher_output`, score/language filters).
3. Notebook `05_teacher_student_eval.ipynb` compares teacher vs served outputs (agreement on `next_steps` length, substantive summary overlap, tier breakdown).
4. A human reviewer approves promotion by documenting the decision in `docs/threshold_changes.md`.
5. Model training itself is **outside** the service (Unsloth / PEFT / HF TRL / …); the resulting student is re-imported into Ollama and `STUDENT_MODEL` updated.

Consent is enforced: records without `consent_use_for_distillation=true` are excluded by default (simulator scenarios can be opted in explicitly).

### 9. OSINT enrichment

`osint` extracts indicators (domains, IPs, URLs, hashes, …) from messages and aggregates verdicts across pluggable providers with a TTL cache, per-provider rate limiting, and scoped HTTP egress (`scopes.yaml`). Outputs a verdict (`malicious / suspicious / benign / unknown`), a confidence score, indicator count, providers used, and a short natural-language explanation — all carried on the decision card.

### 10. Integrations & connectors

`integrations` is a connector service with per-provider allowlists, rate limits, redacted config dumps, and on-disk state. It forwards **anonymized summaries** to the collector via the `/ingest` contract.

Included connectors (all opt-in; disabled without credentials):

* **LMS**: Canvas, Blackboard, Moodle, Brightspace
* **Cisco / network & identity**: Meraki, Duo, Umbrella, ISE, Firepower (FMC audit)
* **Device polling**: SNMP, NETCONF, RESTCONF snapshot, SSH polling (requires explicit `DEVICE_ALLOWLIST`)

By default the workshop runs without live integrations. See `docs/integrations/README.md` and `.env.example`.

### 11. Unified SOC Console (port 8080)

A Vite + React + TypeScript + Tailwind SPA that replaces per-service HTML pages:

* **Dashboard** — KPI tiles (decisions, escalations, auto-blocks, manual reviews) with SSE live updates, stacked-bar action mix over `1h / 6h / 24h / 7d`, recent-alerts table.
* **Alerts** — Live queue with severity / action / text filters, override badges; detail view with **7 tabs**: Summary · Detector · Policy · OSINT · LLM · Federated · History; **Override action** dialog POSTs to `/log_override`.
* **LLM** — Provider cards (teacher/student live status), routing over time (stacked bar), top providers / models / reasons, and a **Playground** that calls `/assist` on demand (not audited).
* **Federated ML** — Round status, per-client participation, current global model (coefficients + feature order + update time).
* **Traffic** — Window configuration, anomaly counts, synthetic-generator controls, traffic-volume area chart, recent-anomalies table.
* **Simulator** — Pick and run a scenario; results stream into Alerts live.
* **Training** — Interactive analyst tutoring labs: phishing email popup + DDoS network map animation, action logging, and LLM letter-grade AAR.
* **Services** — Per-backend health dashboard with latency and errors.
* **Compliance Hub** — Framework-aligned view of Zero Trust controls, AI guardrails, and audit integrity signals.
* **Audit** — Integrity verification, retention operations, and evidence exports (JSON/Markdown/PDF via print-to-PDF).
* **Settings** — Rebrand the program, set analyst name/ID, tenant, environment (all stored in `localStorage`).
* **Help** — Full in-app reference: per-page features, glossary, severity scale, ASCII data-flow diagram.

---

## Services and ports

All services run in Docker Compose on a single shared network.

| Port | Service             | Purpose                                                                              |
|-----:|---------------------|--------------------------------------------------------------------------------------|
| 8080 | **SOC Console**     | Unified React/Tailwind operator UI (main entry point)                                |
| 8888 | JupyterLab          | Research notebooks (token: `wicys2026`)                                              |
| 8000 | detector            | Rule-based + tiny-ML + optional FL scoring (`/score`)                                |
| 8001 | collector           | Event ingestion, HMAC anonymization, feature extraction (`/ingest`)                  |
| 8010 | aggregator          | Federated-learning aggregator (`/submit_update`, `/aggregate`, `/global_model`)      |
| 8011 | client_a            | Federated client A                                                                   |
| 8012 | client_b            | Federated client B                                                                   |
| 8013 | client_c            | Federated client C                                                                   |
| 8020 | policy_engine       | Deterministic `allow / queue_for_review / escalate` rules                            |
| 8021 | orchestrator        | Multi-agent decision assembler (`/process_event`)                                    |
| 8022 | audit               | Append-only ledger + SSE `/stream`                                                   |
| 8023 | simulator           | Scripted scenarios that fan out through the full pipeline                            |
| 8024 | llm_assistant       | Teacher / student LLM router (`/providers`, `/assist`)                               |
| 8025 | integrations        | External LMS / email connector stubs                                                 |
| 8026 | distiller           | Offline teacher → student distillation helper (`/export_corpus`, `/eval_summary`)    |
| 8027 | traffic_ingestor    | Rolling-window flow telemetry + anomaly detection + synthetic generator              |
| 8028 | osint               | OSINT enrichment service                                                             |

> You rarely hit these ports directly. The console proxies each one behind `/api/<service>/…` via nginx (container) or Vite (dev mode).

---

## Repository structure

```text
console/                     # Vite + React + Tailwind SOC Console (port 8080)
  src/
    pages/                   # Dashboard, Alerts, AlertDetail, Traffic, LLM,
                             # Federated, Simulator, Services, Settings, Help
    components/              # Shell, Card, Badge, Tabs, Modal, ScoreBar, JsonView
    lib/
      api.ts                 # Typed API client (audit, orch, LLM, traffic, federated, …)
      sse.ts                 # Typed EventSource wrapper with auto-reconnect
      settings.tsx           # Browser-persisted analyst / program settings
  Dockerfile                 # Multi-stage build → nginx static site
  nginx.conf                 # SPA + /api/<service>/ proxies + unbuffered SSE route
  vite.config.ts             # Dev server with matching proxy rules

collector/                   # FastAPI: log ingestion + anonymization + feature extraction
detector/                    # FastAPI: rule + tiny-ML + federated scoring
policy_engine/               # FastAPI: deterministic YAML rules
  rules.yaml
orchestrator/                # FastAPI: multi-agent decision assembler
audit/                       # FastAPI: append-only ledger + SSE /stream
osint/                       # FastAPI: OSINT enrichment
  aggregator.py, providers/, extractors/, cache.py, rate_limiter.py
llm_assistant/               # FastAPI: teacher / student router
  providers/                 # ollama / openai-like / anthropic / none
  teacher_student.py
distiller/                   # FastAPI: offline distillation helper
federated/
  aggregator/                # FedAvg server
  client_a/, client_b/, client_c/  # Federated clients
  shared/                    # Global model + round state (shared volume)
simulator/                   # FastAPI: scripted scenarios
  scenarios/                 # 11 JSON scenarios (benign, phishing, multilingual, …)
traffic_ingestor/            # FastAPI: flow telemetry + anomaly detection
  detectors/, features/, adapters/, emitter.py, config.py
integrations/                # FastAPI: LMS / email connector scaffolding
  adapters/, providers/, state/
shared/schemas/              # Pydantic v1 models shared across services
  decision.py, llm.py, detector.py, ingest.py, features.py, anon.py

notebooks/                   # JupyterLab notebooks
  01_intro_pipeline.ipynb
  02_feature_extraction.ipynb
  03_threshold_tuning_equity.ipynb
  04_federated_learning_review.ipynb
  05_teacher_student_eval.ipynb

data/                        # Seed datasets + generated ledger files
  seed_lms_events.csv
  seed_email_events.csv
  ingested_events.jsonl      # (created at runtime)
  ledger/                    # Audit ledger volume mount

manual/                      # Operator manuals (technical, training, technology whitepaper)
  README.md
  technical-manual.md
  training-manual-new-users.md
  whitepaper-technologies.md

labs/                        # Student labs / assignments (how to complete Training challenges)
  README.md
  soc-training-labs.md

docs/
  llm_teacher_student.md
  traffic_anomaly.md
  osint.md
  privacy_model.md
  runbooks/helpdesk_triage.md
  threshold_changes.md
  overrides_log.md
  integrations/README.md
governance_checklist.md
docker-compose.yml
.env.example
LICENSE
README.md
```

---

## Quick start

### Prerequisites

* Docker Desktop (or any Docker engine) with Compose v2
* Git
* A laptop with at least 4 GB of RAM free

### Clone and run

```bash
git clone https://github.com/SamAddington/Agentic-SOC-FL-PE-MAO-AL-SIM-LLM
cd Agentic-SOC-FL-PE-MAO-AL-SIM-LLM

cp .env.example .env          # edit provider keys / flags as desired
docker compose build
docker compose up -d
```

Then open **`http://localhost:8080`** — the SOC Console is your main UI. Everything else is an API behind it.

For notebooks, go to `http://localhost:8888` with token `wicys2026` (configurable in `docker-compose.yml`).

### Generating data

The fastest path: open the console → **Simulator** → pick a scenario → **Run**. New decisions stream into **Alerts** live.

Or POST directly to the collector (include your configured `SOC_API_KEY`):

```bash
curl -X POST http://localhost:8001/ingest \
  -H "X-API-Key: $SOC_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "user_id": "student123",
        "email": "student123@example.edu",
        "source": "email_gateway",
        "message": "URGENT: Your campus password will expire today. Click this link to keep your account active and receive a gift card.",
        "event_type": "suspicious_email",
        "language": "en"
      }'
```

All ingested events append to `data/ingested_events.jsonl`, used by the fairness and threshold-tuning notebook.

---

## Configuration (selected environment variables)

Defined in `docker-compose.yml` / `.env.example`:

| Variable                        | Service            | Default                          | Purpose                                                    |
|---------------------------------|--------------------|----------------------------------|------------------------------------------------------------|
| `USE_ML`                        | detector           | `0`                              | Enable tiny-ML second opinion                              |
| `USE_FEDERATED`                 | detector           | `0`                              | Consume FL global model                                     |
| `ENABLE_OSINT_ENRICHMENT`       | orchestrator       | `1`                              | Toggle OSINT enrichment                                     |
| `OSINT_MIN_RULE_SCORE`          | orchestrator       | `0.40`                           | Score threshold above which non-email events enrich         |
| `SOC_API_KEY`                   | collector/orchestrator/policy/audit/integrations | `change-me-dev-api-key` | Shared API key required for sensitive API calls |
| `AUDIT_SIGNING_KEY`             | audit              | `change-me-dev-audit-signing-key` | HMAC key for tamper-evident ledger hash chaining |
| `AUDIT_RETENTION_DAYS`          | audit              | `90`                             | Automatic retention horizon for ledger cleanup              |
| `TEACHER_PROVIDER`/`TEACHER_MODEL` | llm_assistant   | `none` / ``                      | Teacher LLM config                                          |
| `STUDENT_PROVIDER`/`STUDENT_MODEL` | llm_assistant   | `ollama` / `llama3.2`            | Student LLM config                                          |
| `LLM_DEFAULT_MODE`              | llm_assistant      | `student_only`                   | Routing mode for normal traffic                             |
| `LLM_HUMAN_REVIEW_MODE`         | llm_assistant      | `teacher_shadow`                 | Routing mode when `requires_human_review=true`              |
| `LLM_SHADOW_LOG`                | llm_assistant      | `/app/ledger/teacher_shadow.jsonl` | Shadow output path                                        |

See `.env.example` for the full list and provider-specific keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OLLAMA_BASE_URL`, `OSINT_HMAC_KEY`, …).

### Server log collectors (host-side shippers)

This repo includes lightweight **host-side shippers** that forward log lines into the normal collector `/ingest` path (so the same anonymization/features/policy pipeline applies):

* `tools/shippers/windows_eventlog_shipper.ps1` — polls Windows Event Logs via `Get-WinEvent`
* `tools/shippers/journald_shipper.sh` — streams `journalctl -f -o json`
* `tools/shippers/file_tail_shipper.py` — tails any text file and forwards lines

These are intentionally minimal and are meant for **lab/workshop** usage; for production, prefer your institution’s approved log forwarders and policies.

### SIEM egress durability (spooling/queueing)

If you enable SIEM egress (Splunk/Sentinel/Elastic/Syslog), you can also enable a
durable on-disk spool in the collector so outages do not drop events:

- Set `SIEM_SPOOL_ENABLED=1` (defaults to off)
- Spool directory defaults to `SIEM_SPOOL_DIR=/app/data/siem_spool` (on the mounted `./data` volume)

The collector will enqueue per-destination failures and flush them in the background.

You can inspect queue health and counters via:

- `GET /siem/spool/status` (requires `X-API-Key`)
- `GET /siem/spool/status?dest=elastic` for a destination-filtered view (requires `X-API-Key`)
- `POST /siem/spool/flush` to force one flush batch (requires `X-API-Key`)
- `POST /siem/spool/flush?dest=elastic` to flush a single destination queue (requires `X-API-Key`)
- `GET /metrics` for Prometheus-format spool + SIEM metrics (requires `X-API-Key`)

### Console auth note

The console now sends API credentials from browser storage key `soc_api_key` as header `X-API-Key`.
Set this value in **Settings → API access** after startup so protected endpoints (ingest, process, override, audit reads, simulator runs) succeed.

---

## Governance, privacy, and fairness

### Governance checklist

`governance_checklist.md` documents testable commitments across:

* Data reduction and anonymization
* Transparency and interpretability
* Fairness and language-equity checks
* Human-in-the-loop triage
* Safe operation for resource-limited environments
* Documentation and reproducibility

### Privacy model

See `docs/privacy_model.md`. The collector applies HMAC-keyed anonymization and aggressive data reduction; raw message bodies are **not** forwarded to downstream agents, and the traffic ingestor surfaces only aggregate anomaly features (no raw IPs or payloads).

### Helpdesk triage runbook

`docs/runbooks/helpdesk_triage.md` covers how to handle `allow` / `queue_for_review` / `escalate`, when and how to override (the console's Override dialog logs these), and how to communicate with end users.

### Fairness and threshold tuning

`notebooks/03_threshold_tuning_equity.ipynb` loads `data/ingested_events.jsonl`, computes metrics by language and domain, plots risk-score distributions per group, and sweeps thresholds to surface escalation-rate gaps. Decisions are recorded in `docs/threshold_changes.md`.

### Audit and overrides

Every decision, override, policy event, and simulation run is appended to the audit ledger. Overrides are additionally summarized in `docs/overrides_log.md`.

---

## Research notes

This framework is intentionally small enough to read end-to-end in one sitting. It is designed to support empirical studies of:

* **Agentic orchestration** trade-offs between best-effort, independent agents vs. strict sequential composition.
* **Teacher / student distillation** under consent, where the teacher is a hosted frontier model and the student is a small local model served offline.
* **Federated learning** on highly interpretable, low-dimensional feature spaces where local data heterogeneity is the norm (per-campus phishing cultures, multilingual cohorts).
* **Fairness in bounded SOC decisions**, especially across languages and communication domains common to low-resource institutions.
* **Human-in-the-loop override dynamics**, auditable via the ledger and visible in the console's History tab.

Reproducibility: all code and seed data are in this repository; all long-running state (ledger, federated shared model) is captured on named volumes in `docker-compose.yml`.

---

## Adaptation for local contexts

You can adapt this stack for:

* Community colleges and regional universities
* Cybersecurity workforce programs
* Student cyber clubs and competitions
* Courses in networking, security, data science, or applied ML

Common adaptations:

* Replace `seed_*` CSVs with your own **anonymized** exports.
* Add rules or features in `collector/app.py` and `detector/app.py`.
* Extend notebooks with additional fairness metrics.
* Plug real provider keys into `llm_assistant` (teacher or student) to move beyond fallback responses.
* Rename the program and add your analysts in **Settings** so the UI feels like yours.

Always ensure that no direct identifiers appear in logs or notebooks, and that local policies and regulations are followed for data handling.

---

## Troubleshooting

**Dashboard or Alerts are empty.** Check the **Services** page: if `audit`, `orchestrator`, or `detector` are red, the pipeline isn't producing decisions. Run a scenario from the **Simulator** page.

**LLM tab always shows `fallback`.** No provider is configured. Open the **LLM Assistant** page — if both provider cards say `disabled`, add an API key (or a local Ollama model) in `.env` / `docker-compose.yml` for `llm_assistant` and restart that service.

**SSE isn't live.** Check the green/amber dot in the Dashboard header. If amber, `audit` is likely down or the unbuffered nginx location isn't in play — rebuild the console container:

```bash
docker compose build console && docker compose up -d console
```

**`http://localhost:8001` seems to disappear.** Expected — the legacy collector dashboard now redirects to the SOC Console on `:8080`. The collector API endpoints on `:8001` (`/health`, `/ingest`) are still live.

**I get `401`/`403` errors from the console.** Ensure:
- `SOC_API_KEY` is set in `.env` / `docker-compose.yml` for protected services.
- The same value is saved in the console under **Settings → API access** (`localStorage.soc_api_key`).

---

## Citation

If you use this framework in academic work, please cite:

```bibtex
@software{addington_agentic_soc_2026,
  author  = {Addington, Samuel},
  title   = {Agentic SOC: Federated, Policy-Driven, Multi-Agent,
             Audited, Simulated, LLM-Assisted Defense for
             Resource-Constrained Campus SOCs},
  year    = {2026},
  note    = {Research prototype. AI-driven Cybersecurity Research,
             Computer Science.}
}
```

---

## License

Released under the **MIT License** — see `LICENSE`.

Copyright &copy; 2026 **Samuel Addington**.

> Reminder: this is a **research prototype**. It is provided "as is", without warranty of any kind, for research, teaching, and experimentation only.
