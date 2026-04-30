# Whitepaper — technologies in the Agentic SOC software

**Audience:** Technical stakeholders, curriculum designers, and reviewers who need a concise rationale for *why* this stack is composed the way it is—not a vendor comparison.

**Scope:** Open-source and commodity components used across the Docker Compose deployment, console, and research notebooks.

---

## 1. Goals driving technology choices

The project optimizes for:

1. **Reproducibility** — One command brings up the full pipeline on a laptop-class machine.
2. **Interpretability** — Small services, explicit YAML policy, typed JSON schemas, and human-readable rationales.
3. **Privacy-by-design** — Minimize data movement; pseudonymize early; allowlist outbound calls.
4. **Pedagogy** — Students can read service code and configs without navigating a proprietary SOC platform.
5. **Research ethics** — Clear boundaries: LLM as explainer, audit ledger, optional federated learning without centralizing raw events.

---

## 2. Container platform: Docker & Compose

**Technologies:** Docker Engine, Docker Compose v2.

**Why:** Compose provides a **declarative system diagram** (`docker-compose.yml`) that matches how papers and labs describe multi-service systems. Networking, volumes, and environment injection are versionable and reviewable. Alternatives (Kubernetes, Nomad) add operational depth that distracts from the research goals for this codebase.

---

## 3. Backend services: Python & FastAPI

**Technologies:** Python 3.x, **FastAPI**, **Pydantic**, **Uvicorn** (typical ASGI server).

**Why:**

- **FastAPI** offers automatic OpenAPI documentation, async-capable HTTP, and dependency injection—ideal for many small microservices with shared auth patterns.
- **Pydantic** enforces **shared schemas** (`shared/schemas/`) so detector, orchestrator, audit, and console agree on decision-card shape—a teaching and correctness win.
- Python matches the **ML / notebooks / data science** ecosystem used in fairness and federated-learning modules.

---

## 4. Operator interface: React, TypeScript, Vite, Tailwind

**Technologies:** **React 18**, **TypeScript**, **Vite** (bundler/dev server), **Tailwind CSS**, **React Router**.

**Why:**

- **TypeScript** reduces UI regressions when APIs evolve.
- **Vite** gives fast local dev and a static production build served by **nginx**—no Node runtime in production, shrinking attack surface and resource use.
- **Tailwind** enables a consistent **dark SOC-style** UI without a heavy component framework lock-in.

The console deliberately **proxies** backends (`/api/...`) so operators need one origin and one TLS story (if terminated in front of nginx).

---

## 5. Real-time updates: Server-Sent Events (SSE)

**Technologies:** Browser `EventSource`, FastAPI streaming response, nginx proxy buffering disabled for the stream route.

**Why:** SSE is **simplex server→client**, HTTP/1.1 friendly, and sufficient for alert feeds. WebSockets would add reconnect and routing complexity without a clear benefit for append-only notifications.

---

## 6. Decision persistence: JSONL + hash chain

**Technologies:** Append-only **JSON Lines** files, HMAC-based **hash chaining** per record.

**Why:** JSONL is **human-greppable**, diff-friendly, and easy to explain in class. A hash chain provides **tamper-evidence** without requiring a full blockchain. SQL databases could serve the same role but add schema migration and ORM overhead for a teaching stack.

---

## 7. Optional search & correlation: OpenSearch

**Technologies:** **OpenSearch** (Elasticsearch-compatible API).

**Why:** Operators expect **SIEM-like** search, timelines, and facets. OpenSearch runs locally in Compose, supports index templates, and aligns with industry vocabulary for labs.

---

## 8. Threat enrichment: OSINT microservice

**Technologies:** Pluggable Python providers, HTTP client with **allowlisted scopes** (`scopes.yaml`), TTL cache, rate limiting.

**Why:** Centralizing OSINT in one service enforces **egress policy**, **caching**, and **indicator caps**—privacy and cost controls that are hard to guarantee if every agent called the internet independently.

---

## 9. Bounded AI: LLM assistant & Ollama

**Technologies:** **Ollama** (default local inference), optional OpenAI-compatible and Anthropic APIs; strict JSON schema for responses.

**Why:**

- **Local student model** supports air-gapped demos and FERPA-sensitive discussions.
- **Teacher / student** split supports **distillation research** without granting the LLM policy authority.
- Schema validation prevents **free-text** responses from breaking downstream UI and audit fields.

---

## 10. Federated learning: FedAvg-style logistic regression

**Technologies:** Lightweight **HTTP round** between clients and aggregator; shared volume or JSON for global weights; **scikit-learn**-style linear model semantics in documentation and notebooks.

**Why:** Full horizontal FL frameworks (Flower, PySyft) are powerful but opaque in a short course. Here, **updates are explicit coefficients** students can inspect—linking to fairness and drift discussions in `notebooks/`.

---

## 11. Traffic telemetry: streaming windows & online detectors

**Technologies:** In-memory **rolling windows**, **EWMA / z-score**, **rate burst**, optional **Isolation Forest**; adapters for Zeek, Suricata, NetFlow, syslog.

**Why:** Demonstrates **aggregate-only** anomaly detection with **k-anonymity-style** gating before emission—complementing the message-based LMS path and reinforcing privacy narratives.

---

## 12. Integrations service: connector isolation

**Technologies:** Separate **integrations** FastAPI app, per-provider modules, **YAML allowlists**, rate limiter.

**Why:** Keeps vendor SDK complexity and credentials **out** of the hot path of scoring. Failures degrade to warnings on `/sync` without taking down ingest.

---

## 13. Summary table

| Layer | Technology | Primary rationale |
|-------|------------|-------------------|
| Packaging | Docker Compose | Reproducible multi-agent lab |
| APIs | FastAPI + Pydantic | Typed, teachable microservices |
| UI | React + TS + Vite + Tailwind | Modern SPA, static deploy |
| Live updates | SSE | Simple server-push alerts |
| Ledger | JSONL + HMAC chain | Auditable, inspectable |
| Search | OpenSearch | SIEM-like UX optional |
| AI | Ollama + optional APIs | Local-first, bounded role |
| FL | Custom FedAvg HTTP | Interpretable coefficients |
| Traffic | Windowed detectors | Privacy-preserving telemetry |

---

## 14. Limitations (explicit)

This stack is **not** a certified enterprise SOC product. It omits enterprise IAM integration, horizontal HA, advanced SOAR, and full CMMC/NIST control implementations—it **illustrates** concepts aligned with those frameworks as described in the root README and Compliance Hub.

---

*Citation: cite the repository and associated academic work as directed in the root `README.md`.*
