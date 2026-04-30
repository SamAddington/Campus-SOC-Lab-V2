# Governance Checklist for Resource-Constrained Campus SOCs

*Agentic AI for Resource-Constrained Campus SOCs: Hands-On, Interpretable Defense*  
**Version 1.0 – WiCyS 2026 Workshop Release**

This checklist operationalizes the governance, privacy, fairness, and human-in-the-loop commitments described in the workshop abstract. It is intended for community colleges, minority-serving institutions, rural campuses, and any environment where cybersecurity teams operate with limited staffing and budgets.

The checklist is divided into six domains, each with testable items that can be implemented using the Docker images and notebooks provided in this workshop.

## 1. Data Reduction and Anonymization

### 1.1 Inputs
- [ ] Remove all direct identifiers (full emails, names, student IDs) before ingestion.
- [ ] Only store hashed identifiers in the `anon_user` field.
- [ ] Extract email domain only when needed for risk analysis.
- [ ] Accept logs only from approved export sources (LMS, email gateway, helpdesk system).
- [ ] Confirm `HMAC_SECRET` is set to a non-default value in every non-workshop deployment. Verify `GET /health` on the collector and the integrations service both report `hmac_keyed: true`.
- [ ] Rotate `HMAC_SECRET` on the schedule defined in local data-handling policy. Treat rotation as a new deployment (old hashes no longer match new ones).

### 1.4 LMS integrations (Phase 2)
- [ ] Every LMS provider has a documented path allowlist in `integrations/scopes.yaml` and a matching `docs/integrations/<provider>.md`.
- [ ] Provider credentials come from env / secret store; no credentials are committed to the repo.
- [ ] A `POST /sync/{provider}` dry-run has been reviewed by an analyst; the ``first_sample`` output contains no raw user ids or emails.
- [ ] The LMS account backing the API token has the minimum scopes required for the allowlisted endpoints; this is reviewed quarterly.
- [ ] Rate-limit settings in `integrations/rate_limiter.py` match the vendor's published limits for the token tier in use.

### 1.6 OSINT enrichment (Phase 4)
- [ ] `osint` `GET /health` reports `hmac_keyed: true` in every non-workshop deployment.
- [ ] Every provider in `osint/scopes.yaml` has a matching section in `docs/osint.md` and only the endpoints that the provider class actually calls are listed.
- [ ] Provider API keys come from env / secret store; no keys are committed. Leaving a key blank keeps that provider disabled.
- [ ] `OSINT_REJECT_PRIVATE_IPS=1` (default); the first test indicator used by the operator should be a private address to verify it is dropped at extraction.
- [ ] `OSINT_MAX_URLS`, `OSINT_MAX_DOMAINS`, `OSINT_MAX_IPS`, `OSINT_MAX_HASHES` are documented and justified against the deployment's event volume.
- [ ] Per-provider `OSINT_*_RPM` rate limits match each vendor's published free-tier limit for the token in use.
- [ ] A sample `POST /enrich_event` has been reviewed; the response body contains no `user_id`, `email`, or full message text.
- [ ] `policy_engine/rules.yaml` contains the `OSINT-MALICIOUS-001` and `OSINT-SUSPICIOUS-001` rules and no rule permits an automated *enforcement* action for `feature_flags.osint_verdict` matches.
- [ ] `ENABLE_OSINT_ENRICHMENT=0` path has been tested: orchestrator continues to process events when the osint service is down or disabled.
- [ ] Cache statistics (`GET /cache/stats`) are reviewed periodically; unusually high `misses` per event or consistent `error` verdicts indicate a provider outage that should be ticketed.
- [ ] Decision cards include `osint_verdict`, `osint_score`, and `osint_providers_used` when enrichment ran; reviewers spot-check that `osint_short_explanation` matches the listed providers.

### 1.5 Realtime traffic + anomaly detection (Phase 3)
- [ ] `traffic_ingestor` `GET /health` reports `hmac_keyed: true` in every non-workshop deployment.
- [ ] Subnet bucket prefixes (`TRAFFIC_IPV4_PREFIX`, `TRAFFIC_IPV6_PREFIX`) are set to values compliant with local privacy policy (defaults are `/24` and `/64`).
- [ ] `TRAFFIC_K_ANON_MIN` is documented and justified for the deployment's traffic volume (default 5).
- [ ] `TRAFFIC_WARMUP_WINDOWS` is long enough that no detector can fire before a baseline is established; an analyst has verified this by inspecting `GET /detectors` after boot.
- [ ] No adapter or detector retains per-flow records; only aggregate window stats are kept (verified by code review of `features/windows.py`).
- [ ] Synthetic traffic mode is disabled (`TRAFFIC_SYNTHETIC_ENABLED=0`) in production deployments.
- [ ] `policy_engine/rules.yaml` contains `TRAFFIC-ANOMALY-HIGH-001` / `-MED-001` / `-LOW-001` and no rule permits an automated *enforcement* action for `source: traffic_anomaly`.
- [ ] Traffic anomalies are always emitted with `consent_use_for_distillation=false` (verified by inspecting a sample decision card).
- [ ] Detection thresholds (`TRAFFIC_EWMA_Z`, `TRAFFIC_RATE_BURST_MULT`, `TRAFFIC_ISOFOREST_CONTAMINATION`) are reviewed after each semester's first-week traffic to ensure false-positive rates are acceptable across subnets.

### 1.2 Storage
- [ ] Store only minimal fields needed for classification.
- [ ] Confirm that `ingested_events.jsonl` contains no sensitive fields.
- [ ] Ensure retention does not exceed campus policy.

### 1.3 Access Control
- [ ] Notebook access secured by token or password.
- [ ] Only designated analysts or instructors may run equity or threshold-tuning notebooks.
- [ ] Students or interns must work only with anonymized logs.

## 2. Transparency and Interpretability

### 2.1 Rule Logic
- [ ] Document all risk factors used in `detector/app.py`.
- [ ] Provide plain-language explanations for each indicator.
- [ ] Keep risk weights and thresholds in visible code or notebook cells.

### 2.2 Explainability Outputs
- [ ] Confirm each `/score` response includes a brief explanation in natural language.
- [ ] Explanations must be suitable for helpdesk or student workers with minimal training.
- [ ] Analysts must validate explanations before modifying thresholds.

### 2.3 LLM Tier Transparency
- [ ] Every decision card records `llm_tier` (`teacher` / `student` / `fallback`), `llm_provider`, and `llm_model`.
- [ ] Operators document in `docs/llm_teacher_student.md` which provider and model serve each tier, and whether the teacher is a hosted API.
- [ ] When a hosted teacher is used, the corresponding API key is sourced from environment / secret store (never committed) and budget limits are set with the vendor.
- [ ] Fallback rate per language is reviewed before promoting the student (`notebooks/05_teacher_student_eval.ipynb`).

## 3. Fairness and Language Equity

### 3.1 Data Logging for Equity Review
- [ ] Ensure language field is captured for every event when available.
- [ ] Store group-level metadata (domain, language) but not identity-level data.
- [ ] Log detection outcomes (`low_risk`, `medium_risk`, `high_risk`) per event.

### 3.2 Fairness Evaluation
- [ ] Run the fairness notebook at least once per semester.
- [ ] Compare risk-score distributions across language groups.
- [ ] Compare risk-score distributions across email domains.
- [ ] Identify disparities in false-positive or escalation rates using simple metrics.

### 3.3 Equity Adjustments
- [ ] Adjust thresholds if they disproportionately flag specific groups.
- [ ] Document threshold changes in `docs/threshold_changes.md`.
- [ ] Provide justification for each change using evidence from notebooks.

## 4. Human-in-the-Loop Triage

### 4.1 Escalation Path
- [ ] High-risk events must always be reviewed by a human before action.
- [ ] Medium-risk events go to a review queue for junior analysts or trained student workers.
- [ ] Low-risk events do not require human review but remain logged for audit.

### 4.2 Override Authority
- [ ] Analysts may override detector labels but must record rationale.
- [ ] Overrides logged in `docs/overrides_log.md`.

### 4.3 Reviewer Guidelines
- [ ] Reviewers must consult runbooks for LMS phishing indicators, email spoofing red flags, and foreign-language message handling.
- [ ] All reviewers receive training aligned with local campus accessibility and language policies.

## 5. Safe Operation and Misuse Prevention

### 5.1 Pipeline Integrity
- [ ] Verify collector and detector containers before deployment.
- [ ] Do not allow students to run containers with elevated host privileges.
- [ ] Disable outbound network access from containers unless explicitly needed.

### 5.2 Misuse Prevention
- [ ] Prevent unauthorized users from modifying feature weights or thresholds.
- [ ] Review logs for unusual ingestion patterns.
- [ ] Protect scoring endpoints from external exposure.
- [ ] Distillation corpora must only include records with `consent_use_for_distillation=true` or records from the synthetic simulator. Verify via `POST /export_corpus` response counters.

### 5.3 Resource Constraints
- [ ] Ensure CPU and memory limits are defined if required for local environments.
- [ ] System must run on standard laptops without raising resource warnings.

## 6. Documentation, Training, and Reproducibility

### 6.1 Documentation Artifacts
- [ ] `README.md` includes full setup instructions.
- [ ] `governance_checklist.md` included.
- [ ] Runbooks included in `docs/runbooks/`.
- [ ] Seed datasets included in `data/`.

### 6.2 Reproducibility
- [ ] All notebooks run deterministically with the provided seed logs.
- [ ] All threshold-tuning steps are reproducible using the same CSVs.
- [ ] Users can clone the repo and run the full pipeline on laptops quickly.

### 6.3 Licensing and Open Access
- [ ] Release materials under a permissive open-source license.
- [ ] Do not include proprietary vendor code.
- [ ] Ensure all content is accessible to institutions without commercial cybersecurity tools.
