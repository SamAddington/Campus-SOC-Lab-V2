# Training manual — new users

Welcome. This guide gets you from **zero** to a **confident demo operator** of the Agentic SOC workshop stack in one sitting. It assumes Docker is installed and you are using **synthetic or anonymized data only** (see the research notice in the root `README.md`).

---

## 1. Before you start (5 minutes)

1. **Clone** the repository and copy environment template:
   - `cp .env.example .env`
2. **Set secrets** (even for local lab): change at least `HMAC_SECRET`, `SOC_API_KEY`, and `AUDIT_SIGNING_KEY` from placeholder values.
3. **Start the stack**:
   - `docker compose build && docker compose up -d`
4. **Open the console**: `http://localhost:8080`

You do **not** need to memorize service ports: the console proxies APIs under `/api/...`.

---

## 2. First login to the UI

### 2.1 API access (required for most actions)

1. Go to **Settings** (sidebar).
2. Under **API access**, paste the same value as **`SOC_API_KEY`** from your `.env` / compose configuration.
3. Save. The browser stores it as `localStorage.soc_api_key` and sends it as `X-API-Key` on console API calls.

Without this, Simulator, Overrides, and many read APIs will fail with auth errors.

### 2.2 Optional OIDC sign-in

If your deployment was **built** with `VITE_OIDC_ISSUER` and `VITE_OIDC_CLIENT_ID`, you may see **Sign in** in the top bar. That stores a JWT as `soc_jwt` for Bearer authentication. Your IdP must issue tokens the **collector** trusts (JWKS/issuer/audience). Workshop-only setups often use API key only.

### 2.3 Customize labels (optional)

Still in **Settings**: program name, analyst name, tenant label, theme. These are **cosmetic** and stored locally — they do not change server authorization.

---

## 3. Guided tour (15 minutes)

Follow this order once:

| Step | Page | What to do |
|-----:|------|------------|
| 1 | **Services** | Confirm tiles are green (or note any red service). |
| 2 | **Dashboard** | Observe KPI tiles; watch for live SSE indicator (alerts feed). |
| 3 | **Simulator** | Pick a scenario (e.g. `phishing_burst`) → **Run**. |
| 4 | **Alerts** | See new rows appear; open one alert. |
| 5 | **Alert detail** | Walk the tabs: Summary → Detector → Policy → OSINT → LLM → Federated → History. |
| 6 | **Traffic** | Skim status; optional: synthetic generator controls if enabled. |
| 7 | **Compliance Hub** | Read how controls map to the stack (orientation). |
| 8 | **Audit** | Run integrity verify; understand retention is serious in real use. |
| 9 | **Help** | In-app glossary and data-flow diagram for recap. |

---

## 4. Core concepts (plain language)

- **Decision card**: One immutable record per pipeline decision — scores, policy, OSINT, LLM metadata, final action.
- **Actions**: Typically `allow`, `queue_for_review`, or `escalate` — set by **policy**, not by the LLM.
- **LLM role**: **Explainer only** — it cannot change the action. If LLM fails, you still get a deterministic fallback explanation.
- **Override**: A human reviewer action logged separately in the audit ledger (transparency for teaching).

---

## 5. Hands-on exercises

### Exercise A — Generate traffic

1. Simulator → choose **`mixed_benign_noise`** or **`phishing_burst`** → Run.
2. Alerts → filter by severity or text.
3. Open one card → **Policy** tab → note `policy_rule_id`.

### Exercise B — Human review

1. Find an alert with **queue_for_review** or **escalate**.
2. Use **Override** (where available) with a short reason.
3. Audit → confirm override and decision streams make sense.

### Exercise C — Traffic anomaly (if enabled)

1. **Traffic** page → review recent anomalies (aggregate-only telemetry).
2. Read `docs/traffic_anomaly.md` for what “no raw IPs” means pedagogically.

---

## 6. Where to learn more

| Goal | Resource |
|------|----------|
| Architecture | Root `README.md`, `manual/technical-manual.md` |
| Technology choices | `manual/whitepaper-technologies.md` |
| LMS / Meraki / etc. connectors | `docs/integrations/README.md` |
| Privacy & FERPA mindset | `docs/privacy_model.md`, `governance_checklist.md` |
| Notebooks | JupyterLab `http://localhost:8888` (default token in compose) |

---

## 7. Safety checklist (every session)

- [ ] Using **non-production** data only.
- [ ] **Secrets** not committed to git (`.env` is gitignored).
- [ ] **Hosted LLM** off unless you intend external API use (`TEACHER_PROVIDER`, keys).
- [ ] Students understand **overrides** and **audit** as learning artifacts, not real SOC authority.

---

*For instructors: pair this document with a live walkthrough of Simulator → Alerts → Policy tab → Audit integrity.*
