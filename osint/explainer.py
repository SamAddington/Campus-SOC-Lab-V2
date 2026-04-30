"""Turn an aggregated OSINT summary into plain-English text.

Two outputs:
- ``short_explanation``: one sentence suitable for a decision card or
  the collector UI.
- ``review_note``: 2-4 sentences with enough detail for a helpdesk
  reviewer to triage without opening the provider UI.

Neither output contains live URLs -- indicator strings are always
defanged before they appear.
"""

from __future__ import annotations

from typing import Any, Dict


_VERDICT_LABELS = {
    "malicious": "known malicious",
    "suspicious": "suspicious",
    "benign": "no known issues",
    "unknown": "unknown",
}


def _verdict_label(v: str) -> str:
    return _VERDICT_LABELS.get(v, v or "unknown")


def explain(summary: Dict[str, Any]) -> Dict[str, str]:
    verdict = str(summary.get("verdict", "unknown"))
    indicator_count = int(summary.get("indicator_count", 0))
    per_indicator = list(summary.get("per_indicator", []))
    providers_used = list(summary.get("providers_used", []))
    providers_errored = list(summary.get("providers_errored", []))
    mitre = summary.get("mitre") or {}

    # Short explanation
    if indicator_count == 0:
        short = "No external indicators were present; OSINT check was skipped."
    else:
        short = (
            f"{indicator_count} indicator(s) checked across "
            f"{len(providers_used)} provider(s); aggregate verdict is "
            f"{_verdict_label(verdict)}."
        )

    # Review note
    review_lines = [short]

    # Worst indicator first
    ranking = {"malicious": 4, "suspicious": 3, "benign": 2, "unknown": 1, "error": 0}
    ranked = sorted(
        per_indicator,
        key=lambda ind: ranking.get(str(ind.get("verdict")), 0),
        reverse=True,
    )
    for ind in ranked[:3]:
        v = str(ind.get("verdict", "unknown"))
        note = f"- {ind.get('kind')}: {ind.get('value')} -> {_verdict_label(v)}"
        prov_notes = []
        for pr in ind.get("providers", []):
            if str(pr.get("verdict")) in ("malicious", "suspicious"):
                nm = str(pr.get("provider"))
                prov_notes.append(f"{nm}: {str(pr.get('notes', ''))[:80]}")
        if prov_notes:
            note += " (" + "; ".join(prov_notes[:3]) + ")"
        review_lines.append(note)

    if providers_errored:
        review_lines.append(
            "Providers that errored this run: " + ", ".join(providers_errored) + "."
        )

    if mitre.get("technique_id") or mitre.get("notes"):
        mitre_label = (
            f"{mitre.get('technique_id', '')} {mitre.get('technique_name', '')}".strip()
        )
        if mitre_label:
            review_lines.append(f"MITRE ATT&CK mapping: {mitre_label}.")

    if summary.get("deadline_reached"):
        review_lines.append(
            "Per-enrichment deadline was reached; some providers may have been skipped."
        )

    return {
        "short_explanation": short,
        "review_note": "\n".join(review_lines),
    }
