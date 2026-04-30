"""Provider contract.

Every provider returns a ``Finding`` per indicator it was asked to
check. The aggregator reduces all providers' findings for one indicator
into a single verdict; the explainer turns the aggregated result into
English.

We only ever store the three structured fields (``verdict``,
``score``, ``notes``) and a small ``evidence`` dict. Raw response
bodies are never forwarded to downstream services or persisted, which
keeps the attack surface of caching/audit small.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"
    ERROR = "error"


_SEVERITY_RANK = {
    Verdict.MALICIOUS: 4,
    Verdict.SUSPICIOUS: 3,
    Verdict.UNKNOWN: 1,
    Verdict.BENIGN: 2,
    Verdict.ERROR: 0,
}


@dataclass
class Finding:
    provider: str
    verdict: Verdict
    score: float
    notes: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    elapsed_ms: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out = {
            "provider": self.provider,
            "verdict": self.verdict.value,
            "score": round(float(self.score), 4),
            "notes": self.notes[:280],
            "elapsed_ms": self.elapsed_ms,
        }
        if self.evidence:
            out["evidence"] = self.evidence
        if self.error:
            out["error"] = self.error[:200]
        return out


class OSINTProvider:
    name: str = "base"

    supports_url: bool = False
    supports_domain: bool = False
    supports_ip: bool = False
    supports_hash: bool = False

    def check_url(self, url: str) -> Finding:
        return Finding(self.name, Verdict.UNKNOWN, 0.0, "url check not supported")

    def check_domain(self, domain: str) -> Finding:
        return Finding(self.name, Verdict.UNKNOWN, 0.0, "domain check not supported")

    def check_ip(self, ip: str) -> Finding:
        return Finding(self.name, Verdict.UNKNOWN, 0.0, "ip check not supported")

    def check_hash(self, kind: str, value: str) -> Finding:
        return Finding(self.name, Verdict.UNKNOWN, 0.0, f"{kind} check not supported")


def aggregate_verdict(findings: List[Finding]) -> Verdict:
    """Reduce a list of provider findings to a single verdict.

    Rule: take the most severe non-error verdict. Ties broken in favor
    of ``malicious`` > ``suspicious`` > ``benign`` > ``unknown``.
    If every provider errored, return ``unknown`` (not ``error``) so
    downstream code doesn't over-react to a transient outage.
    """
    if not findings:
        return Verdict.UNKNOWN
    non_error = [f for f in findings if f.verdict != Verdict.ERROR]
    if not non_error:
        return Verdict.UNKNOWN
    best = max(non_error, key=lambda f: _SEVERITY_RANK.get(f.verdict, 0))
    return best.verdict
