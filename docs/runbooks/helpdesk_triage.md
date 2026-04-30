# Helpdesk Triage Runbook – WiCyS SOC Workshop Stack

This runbook explains how student workers, helpdesk staff, or junior analysts should handle alerts produced by the WiCyS SOC Detector (`detector/app.py`).

The detector returns:

- `risk_score` (0.0–1.0)
- `label` (`low_risk`, `medium_risk`, `high_risk`)
- `action` (`allow`, `queue_for_review`, `escalate`)
- `explanation` (plain-language reason)

## 1. Roles and Scope

- **Helpdesk or Student Worker**
  - Reviews events with `action == "queue_for_review"`.
  - Follows scripted checks and escalates when needed.
- **Analyst or Security Lead**
  - Reviews events with `action == "escalate"`.
  - Updates runbooks and thresholds.
- **Instructor or Supervisor**
  - Approves major changes to rules, thresholds, and workflows.

## 2. Triage Decision Tree

### 2.1 Low-Risk Events

**Condition:** `action == "allow"`

- No immediate triage required.
- Event remains logged for audit and future tuning.
- No contact with user unless part of a separate policy.

### 2.2 Medium-Risk Events

**Condition:** `action == "queue_for_review"`

1. Read the explanation.
2. Check message context.
3. Decide whether the message appears legitimate, uncertain, or clearly malicious.

If legitimate:
- Mark as benign in the ticketing system.
- Add a short note.

If uncertain:
- Escalate to the security lead.
- Attach supporting details if available.

If clearly malicious:
- Reclassify as phishing.
- Escalate to the security lead.
- Consider quarantine or temporary blocking if tools are available.

### 2.3 High-Risk Events

**Condition:** `action == "escalate"`

Always requires a human analyst.

Immediate checks:
- Confirm recipient address or domain is part of the campus.
- Look for known malicious patterns.

Containment options:
- Quarantine the message in the email system.
- Block sender domain or IP if supported.
- Warn targeted users via official channels.

Follow-up:
- Open an incident record.
- Attach the anonymized log, detector explanation, and analyst notes.

## 3. Handling Non-English or Multilingual Messages

1. Do not assume higher risk just because the language is unfamiliar.
2. If explanation suggests risk indicators, treat the message the same way as an English message with the same indicators.
3. If translation tools are used, document that translation occurred.

## 4. Overriding the Detector

Only analysts or supervisors may override.

### 4.1 When to Override

- Clear template email incorrectly scored as high risk.
- Obvious phishing scored as low risk.
- Any case where human judgment strongly contradicts the automated label.

### 4.2 How to Document an Override

Record each override in `docs/overrides_log.md` with:

- Date and time
- Original label and action
- New label and action
- Short rationale

## 5. Feedback Loop and Improvements

At least once per term, the analyst or instructor should:

1. Review escalation counts, override logs, and fairness notebook results.
2. Identify common false-positive patterns or groups disproportionately escalated.
3. Propose threshold adjustments, explanation edits, or new rules.

All changes should be recorded in `docs/threshold_changes.md` or through version control with clear commit messages.

## 6. Communication With End Users

When contacting end users about suspicious activity:

- Use official campus channels.
- Avoid blaming language.
- Provide a short explanation.
- Encourage reporting of future suspicious emails through the helpdesk.
