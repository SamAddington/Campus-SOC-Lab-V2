"""IsolationForest-based detector for multi-feature outliers.

We do not fit per window (too expensive and too noisy). Instead:

1. Accumulate observed feature vectors in a rolling buffer.
2. Every ``refit_every`` closed windows, re-fit an IsolationForest on
   the buffer. Until the first fit we return no anomalies.
3. For each new bucket, score each group's feature vector; emit an
   anomaly when ``decision_function`` is below the fitted threshold.

This gives us a non-parametric outlier detector with bounded CPU cost
and no network-specific tuning required.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Deque, Dict, List, Optional

import numpy as np

from features import WindowBucket

from .base import Anomaly, AnomalyDetector


try:
    from sklearn.ensemble import IsolationForest
    _HAS_SKLEARN = True
except Exception:  # pragma: no cover
    IsolationForest = None  # type: ignore[assignment]
    _HAS_SKLEARN = False


_FEATURE_ORDER = (
    "flow_count",
    "bytes_total",
    "packets_total",
    "unique_dst_count",
    "unique_port_count",
)


class IsolationForestDetector(AnomalyDetector):
    name = "isoforest"

    def __init__(self, *, refit_every: int, contamination: float,
                 warmup: int, max_buffer: int = 5_000):
        self._refit_every = max(5, int(refit_every))
        self._contamination = float(contamination)
        self._warmup = int(warmup)
        self._buffer: Deque[List[float]] = deque(maxlen=int(max_buffer))
        self._model: Optional[object] = None
        self._lock = threading.Lock()
        self._fits = 0
        self._observed_buckets = 0

    def _vec(self, stats) -> List[float]:
        f = stats.to_feature_vector()
        return [f[name] for name in _FEATURE_ORDER]

    def _refit_if_due(self) -> None:
        if not _HAS_SKLEARN:
            return
        if self._observed_buckets % self._refit_every != 0:
            return
        if len(self._buffer) < max(50, self._warmup):
            return
        arr = np.asarray(list(self._buffer), dtype=float)
        try:
            model = IsolationForest(
                n_estimators=100,
                contamination=self._contamination,
                random_state=42,
            )
            model.fit(arr)
            with self._lock:
                self._model = model
                self._fits += 1
        except Exception:
            return

    def observe(self, bucket: WindowBucket) -> List[Anomaly]:
        if not _HAS_SKLEARN:
            return []
        self._observed_buckets += 1

        # Collect feature vectors for this bucket and push into buffer.
        keys = list(bucket.groups.keys())
        if not keys:
            return []
        vectors = [self._vec(bucket.groups[k]) for k in keys]
        for v in vectors:
            self._buffer.append(v)

        self._refit_if_due()

        with self._lock:
            model = self._model
        if model is None:
            return []

        arr = np.asarray(vectors, dtype=float)
        try:
            scores = model.decision_function(arr)
            preds = model.predict(arr)
        except Exception:
            return []

        out: List[Anomaly] = []
        for key, stats, score, pred in zip(keys, (bucket.groups[k] for k in keys), scores, preds):
            if pred != -1:
                continue
            feats = stats.to_feature_vector()
            magnitude = -float(score)
            severity = "high" if magnitude > 0.15 else "medium"
            out.append(Anomaly(
                detector=self.name,
                score=magnitude,
                severity=severity,
                window_key=key,
                window_start=bucket.window_start,
                window_end=bucket.window_end,
                description=(
                    f"IsolationForest flagged window (score={magnitude:.3f}) "
                    f"for service={key[1]} protocol={key[2]}"
                ),
                features=feats,
            ))
        return out

    def state_snapshot(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "sklearn_available": _HAS_SKLEARN,
            "buffer_size": len(self._buffer),
            "refits": self._fits,
            "refit_every": self._refit_every,
            "contamination": self._contamination,
            "model_fitted": self._model is not None,
        }
