"""MITRE ATT&CK context provider (local, no external calls).

This provider does not look up the indicator itself; instead it maps
the *event_type* and *aggregated verdict* to a short MITRE ATT&CK
tactic/technique label that reviewers can cite in their runbook. We
keep it local so we always have *some* context to attach, even when
every external provider is unreachable or disabled.

The mapping is deliberately coarse; operators are expected to refine
it over time.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import Finding, OSINTProvider, Verdict


_MAP = [
    # (match_tokens, tactic, technique_id, technique_name)
    (("phish", "password", "urgent", "gift", "credential"),
     "Initial Access", "T1566", "Phishing"),
    (("traffic_anomaly", "burst", "fanout", "ewma"),
     "Command and Control / Discovery", "T1046",
     "Network Service Discovery"),
    (("malware", "dropper", "payload"),
     "Execution", "T1204", "User Execution"),
    (("login_fail", "brute", "credential_stuffing"),
     "Credential Access", "T1110", "Brute Force"),
]


def _lookup(tokens: str) -> Optional[Dict[str, str]]:
    t = tokens.lower()
    for keywords, tactic, tid, name in _MAP:
        if any(k in t for k in keywords):
            return {"tactic": tactic, "technique_id": tid, "technique_name": name}
    return None


class MITREProvider(OSINTProvider):
    name = "mitre"
    supports_url = True
    supports_domain = True
    supports_ip = True
    supports_hash = True

    def context_for(self, *, event_type: str, message: str,
                    aggregated_verdict: Verdict) -> Finding:
        """Produce a contextual finding for a whole event.

        This is called by the aggregator after all indicator lookups,
        not per-indicator. We keep the same ``Finding`` shape so
        downstream code can treat it uniformly.
        """
        tokens = f"{event_type} {message}"
        mapped = _lookup(tokens) or {}
        if not mapped:
            return Finding(self.name, Verdict.UNKNOWN, 0.0,
                           "no local MITRE mapping for this event_type")
        score = 0.3 if aggregated_verdict == Verdict.UNKNOWN else 0.5
        return Finding(
            provider=self.name,
            verdict=Verdict.UNKNOWN,
            score=score,
            notes=(
                f"MITRE ATT&CK mapping: {mapped['technique_id']} "
                f"{mapped['technique_name']} ({mapped['tactic']})"
            ),
            evidence=mapped,
        )

    # Default per-indicator methods return UNKNOWN; MITRE is used via
    # context_for instead.
