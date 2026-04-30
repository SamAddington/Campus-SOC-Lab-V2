"""Simple rate-burst detector.

Flags groups whose flow count is more than ``multiplier`` times their
running median flow count. Intended as a cheap, human-understandable
check to complement the EWMA detector.
"""

from __future__ import annotations

from collections import deque
from typing import Deque, Dict, List

from features import WindowBucket, WindowKey

from .base import Anomaly, AnomalyDetector


class RateBurstDetector(AnomalyDetector):
    name = "rate_burst"

    def __init__(self, *, multiplier: float, warmup: int, history: int = 30):
        self._multiplier = float(multiplier)
        self._warmup = int(warmup)
        self._history: Dict[WindowKey, Deque[float]] = {}
        self._history_len = int(history)

    def _median(self, samples: Deque[float]) -> float:
        if not samples:
            return 0.0
        ordered = sorted(samples)
        mid = len(ordered) // 2
        if len(ordered) % 2 == 1:
            return ordered[mid]
        return 0.5 * (ordered[mid - 1] + ordered[mid])

    def observe(self, bucket: WindowBucket) -> List[Anomaly]:
        out: List[Anomaly] = []
        for key, stats in bucket.groups.items():
            hist = self._history.get(key)
            if hist is None:
                hist = deque(maxlen=self._history_len)
                self._history[key] = hist

            flow_count = float(stats.flow_count)
            if len(hist) < self._warmup:
                hist.append(flow_count)
                continue

            median = self._median(hist)
            hist.append(flow_count)

            if median <= 0:
                continue
            ratio = flow_count / median
            if ratio < self._multiplier:
                continue

            severity = "high" if ratio >= self._multiplier * 2 else "medium"
            feats = stats.to_feature_vector()
            out.append(Anomaly(
                detector=self.name,
                score=ratio,
                severity=severity,
                window_key=key,
                window_start=bucket.window_start,
                window_end=bucket.window_end,
                description=(
                    f"flow_count={int(flow_count)} is {ratio:.1f}x the median "
                    f"({median:.1f}) over the last {len(hist)} windows for "
                    f"service={key[1]}"
                ),
                features=feats,
            ))
        return out

    def state_snapshot(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "tracked_series": len(self._history),
            "multiplier": self._multiplier,
            "warmup": self._warmup,
            "history_len": self._history_len,
        }
