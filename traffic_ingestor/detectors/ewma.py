"""Exponentially-weighted moving-average z-score detector.

For each (group, feature) the detector keeps a running EWMA mean and
EWMA variance, using Welford-style updates so we never store a history.
After a warmup period we compute ``z = (x - mu) / sqrt(var)`` and flag
any window whose z exceeds ``z_threshold``.

Why EWMA rather than a sliding mean?
- Constant memory per group.
- Responds to regime changes without hard re-windowing.
- Fairness-friendly: no group is singled out by virtue of appearing for
  the first time; each starts with its own baseline.
"""

from __future__ import annotations

import math
from typing import Dict, List, Tuple

from features import WindowBucket, WindowKey

from .base import Anomaly, AnomalyDetector


_FEATURES = ("flow_count", "unique_dst_count", "unique_port_count", "bytes_total")


class EwmaZScoreDetector(AnomalyDetector):
    name = "ewma_zscore"

    def __init__(self, *, alpha: float, z_threshold: float,
                 warmup: int, sev_high_z: float, sev_medium_z: float):
        self._alpha = float(alpha)
        self._z_threshold = float(z_threshold)
        self._warmup = int(warmup)
        self._sev_high_z = float(sev_high_z)
        self._sev_medium_z = float(sev_medium_z)
        # (key, feature) -> (count, mean, var)
        self._state: Dict[Tuple[WindowKey, str], Tuple[int, float, float]] = {}

    # ---- internals ----

    def _update(self, key: WindowKey, feat: str, value: float) -> Tuple[int, float, float]:
        prev = self._state.get((key, feat), (0, 0.0, 0.0))
        count, mean, var = prev
        count += 1
        if count == 1:
            mean = value
            var = 0.0
        else:
            delta = value - mean
            mean = mean + self._alpha * delta
            var = (1 - self._alpha) * (var + self._alpha * delta * delta)
        self._state[(key, feat)] = (count, mean, var)
        return count, mean, var

    def _severity(self, z: float) -> str:
        if z >= self._sev_high_z:
            return "high"
        if z >= self._sev_medium_z:
            return "medium"
        return "low"

    # ---- detector API ----

    def observe(self, bucket: WindowBucket) -> List[Anomaly]:
        out: List[Anomaly] = []
        for key, stats in bucket.groups.items():
            feats = stats.to_feature_vector()
            best_z = 0.0
            triggering_feat = None
            mean_at_trigger = 0.0
            for f in _FEATURES:
                value = feats[f]
                count, mean, var = self._update(key, f, value)
                if count <= self._warmup or var <= 1e-9:
                    continue
                z = (value - mean) / math.sqrt(var)
                if z >= self._z_threshold and z > best_z:
                    best_z = z
                    triggering_feat = f
                    mean_at_trigger = mean
            if triggering_feat and best_z >= self._z_threshold:
                out.append(Anomaly(
                    detector=self.name,
                    score=best_z,
                    severity=self._severity(best_z),
                    window_key=key,
                    window_start=bucket.window_start,
                    window_end=bucket.window_end,
                    description=(
                        f"{triggering_feat}={feats[triggering_feat]:.0f} is "
                        f"{best_z:.2f}sigma above EWMA baseline "
                        f"(mu~{mean_at_trigger:.1f}) for "
                        f"service={key[1]} protocol={key[2]}"
                    ),
                    features=feats,
                ))
        return out

    def state_snapshot(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "tracked_series": len(self._state),
            "alpha": self._alpha,
            "z_threshold": self._z_threshold,
            "warmup": self._warmup,
        }
