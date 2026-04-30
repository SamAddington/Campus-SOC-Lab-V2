"""Detector interface.

A detector consumes a closed ``WindowBucket`` and may return zero or
more ``Anomaly`` records. Detectors are expected to be cheap and online
-- anything that needs a heavy model (e.g. IsolationForest) refits
periodically rather than per-window.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from features import WindowBucket, WindowKey


@dataclass
class Anomaly:
    detector: str
    score: float
    severity: str
    window_key: WindowKey
    window_start: float
    window_end: float
    description: str
    features: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector": self.detector,
            "score": round(float(self.score), 4),
            "severity": self.severity,
            "window_key": {
                "src_subnet_hash": self.window_key[0],
                "service": self.window_key[1],
                "protocol": self.window_key[2],
            },
            "window_start": self.window_start,
            "window_end": self.window_end,
            "description": self.description,
            "features": self.features,
        }


class AnomalyDetector:
    """Abstract base class for all detectors."""

    name: str = "base"

    def observe(self, bucket: WindowBucket) -> List[Anomaly]:
        raise NotImplementedError

    def state_snapshot(self) -> Dict[str, Any]:
        return {"name": self.name}
