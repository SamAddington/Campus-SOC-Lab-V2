# SOC Training Labs — student instructions

## 1) What this program is (concept + purpose)

This project is a **research / teaching SOC (Security Operations Center) lab stack**. It is intentionally designed to be:

- **Interpretable**: the detector uses transparent features and rule-based scoring (optionally with a tiny ML “second opinion”).
- **Auditable**: decisions and trainee actions are written to an append-only **audit ledger**; results can be reviewed later.
- **Safe for learning**: the LLM assistant is a **bounded explainer**. It provides analysis and coaching but does **not** take actions.
- **End-to-end**: you can generate data (simulator), ingest it (collector), score it (detector), apply policy (policy engine),
  assemble decisions (orchestrator), store evidence (audit), and view everything in one UI (console).

Your goal in this lab is to practice the **core SOC workflow**:

1) Open a case with an accurate summary + severity.
2) Document concrete indicators and observations.
3) Scope the incident (who/what/when/how, and what you will pivot on next).
4) Propose safe response steps.
5) Complete the run and review the **After Action Report** including the **LLM grader feedback** (when enabled).

> **Important**: This is a training environment. Do not connect it to real production identity/email/network systems.

---

## 2) System design (components and how they fit together)

You will interact primarily with the **SOC Console** (web UI). Behind the scenes are multiple small services:

- **`console`**: the web UI (Training, Alerts, Simulator, Settings, Help).
- **`audit`**: the append-only ledger. Training runs + actions + reports are stored here.
- **`llm_assistant`**: produces structured grading feedback (pass/fail, letter grade, coaching) when enabled.
- **`collector` / `detector` / `policy_engine` / `orchestrator`**: the SOC pipeline services (used more heavily by Simulator/Alerts).

Training data flow (simplified):

```text
Console (Training page)  →  audit (/training/* endpoints)  →  llm_assistant (/grade_training)
          │                           │
          └── you record actions       └── produces After Action Report (AAR)
```

---

## 3) Lab requirements (what you must do)

### Challenge completion rule

- You must complete **5 challenges out of 12** available in the **Training** module.
- For **each** of the 5 challenges you choose, you must earn **≥ 80%**.

### Evidence you must submit

For **each completed challenge**, submit screenshots showing:

1) Your **score** (≥ 80%).
2) The **LLM grader output** in the After Action Report (AAR) (pass/fail, letter grade, and feedback text).

> If your deployment has LLM grading disabled, ask your instructor before submitting; screenshots must include the AAR section.

---

## 4) Setup and login

### Step 1 — Start the stack

From the project root:

```bash
cp .env.example .env
docker compose build
docker compose up -d
```

Open the console at **`http://localhost:8080`**.

### Step 2 — Configure console settings (required)

In the console:

1) Go to **Settings**
2) Set:
   - **Analyst name** (your name)
   - **Analyst ID** (your student ID or a short handle; e.g., `student-17`)
3) In **API access**, enter the **SOC API key** assigned for your class (provided by your instructor).

Optional:

- If you feel motion/animation is distracting, enable **Reduce motion** in Settings. (The DDoS map and some visuals will stop animating.)

---

## 5) How to complete a training challenge (step-by-step)

### Step 1 — Pick a challenge

1) Open **Training**
2) In the **Challenge** dropdown, select a challenge
3) Click **Start run**

### Step 2 — Read the briefing + example visualization

Each challenge includes:

- A **Briefing** describing the scenario and constraints
- A challenge-specific **example/visualization panel** (e.g., sign-in timeline, mailbox rule chain, ransomware blast-radius grid)

Use these to identify:

- Timeline details
- Concrete indicators (domains/links, sign-in anomalies, endpoint behaviors, destinations, etc.)
- Likely scope and safe response steps

### Step 3 — Record your actions in the “Actions” card

You will complete the challenge by recording four action types:

1) **Open case**
   - Enter a clear title
   - Choose a severity (low/medium/high/critical)
   - Click **Record case creation**

2) **Indicators / notes**
   - Write at least 2 concrete indicators (examples vary by challenge)
   - Click **Record note**

3) **Scope statement**
   - Describe who/what/when/how
   - Describe what you will pivot on next (other accounts, hosts, endpoints, logs, destinations, etc.)
   - Click **Record scope**

4) **Response plan**
   - Provide safe, realistic steps (containment, monitoring, communications, coordination)
   - Click **Record plan**

### Step 4 — Complete the run and read the AAR

1) Click **Complete run**
2) Scroll to **After Action Report**
3) Confirm you earned **≥ 80%**
4) Capture screenshots for submission:
   - Score line (≥ 80%)
   - The grader output section in the AAR (pass/fail, letter grade, feedback)

---

## 6) Guidance for scoring ≥ 80% (what “good” looks like)

Your score is based on whether you complete the required objectives. The grader feedback is meant to evaluate quality and provide coaching.

To consistently score ≥ 80%:

- **Be specific**: write indicators that can be hunted (sender pattern, link theme, risky location, repeated failures, destination domains).
- **Separate facts vs. hypotheses**: “Observed X” vs “Suspect Y”.
- **Scope clearly**: affected users, assets, apps, timeframe, and next pivots.
- **Response steps must be safe and staged**:
  - contain (where appropriate)
  - preserve evidence
  - coordinate with IT/IAM/app/network/HR/legal based on scenario
  - communicate appropriately

---

## 7) Suggested challenge menu (pick any 5)

You may pick any 5 challenges from the Training dropdown. Common options include:

- Account compromise (O365/Google)
- Business Email Compromise (BEC)
- Credential stuffing / brute force
- DDoS / service disruption
- Web app attack (SQLi/XSS/credential leak)
- Endpoint malware (trojan/infostealer)
- Ransomware outbreak
- Vulnerability exploitation (critical CVE)
- Data exfiltration
- Insider misuse / improper access

---

## 8) Submission checklist

For **each** of your 5 completed challenges:

- Screenshot showing **score ≥ 80%**
- Screenshot showing **LLM grader output** in the AAR (pass/fail, letter grade, feedback)

Submit all screenshots plus your name and analyst ID.

