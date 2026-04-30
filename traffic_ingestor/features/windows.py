"""Rolling time-bucketed windows over normalized flows.

Design:
- Time is bucketed into fixed-size windows (``window_seconds``).
- For each window we keep per-group stats keyed by
  ``(src_subnet_hash, service, protocol)``.
- Old windows past ``max_windows_retained`` are evicted automatically.

We explicitly do NOT keep individual flow records around. Detectors see
only aggregate counters, so the in-memory footprint is bounded by the
number of active groups per window times ``max_windows_retained``.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple

from .flow import FlowRecord


WindowKey = Tuple[str, str, str]  # (src_subnet_hash, service, protocol)


@dataclass
class WindowStats:
    """Aggregate stats for one (group, window) cell."""

    flow_count: int = 0
    bytes_total: int = 0
    packets_total: int = 0
    unique_dst: set = field(default_factory=set)
    unique_ports: set = field(default_factory=set)

    def add(self, flow: FlowRecord) -> None:
        self.flow_count += 1
        self.bytes_total += flow.bytes_total
        self.packets_total += flow.packets_total
        if flow.dst_subnet_hash:
            self.unique_dst.add(flow.dst_subnet_hash)
        if flow.dst_port:
            self.unique_ports.add(flow.dst_port)

    def to_feature_vector(self) -> Dict[str, float]:
        return {
            "flow_count": float(self.flow_count),
            "bytes_total": float(self.bytes_total),
            "packets_total": float(self.packets_total),
            "unique_dst_count": float(len(self.unique_dst)),
            "unique_port_count": float(len(self.unique_ports)),
        }


@dataclass
class WindowBucket:
    """All group stats for one window."""

    window_start: float
    window_end: float
    groups: Dict[WindowKey, WindowStats] = field(default_factory=dict)

    def record(self, flow: FlowRecord) -> None:
        key: WindowKey = (flow.src_subnet_hash, flow.service, flow.protocol)
        stats = self.groups.get(key)
        if stats is None:
            stats = WindowStats()
            self.groups[key] = stats
        stats.add(flow)


class WindowStore:
    """Thread-safe ring of recent windows."""

    def __init__(self, window_seconds: int, max_windows: int):
        self._window_seconds = max(1, int(window_seconds))
        self._max = max(1, int(max_windows))
        self._buckets: "OrderedDict[float, WindowBucket]" = OrderedDict()
        self._lock = threading.RLock()

    # ---- bucket helpers ----

    def _bucket_start(self, ts: float) -> float:
        return float(int(ts) // self._window_seconds * self._window_seconds)

    def _get_or_create(self, ts: float) -> WindowBucket:
        start = self._bucket_start(ts)
        bucket = self._buckets.get(start)
        if bucket is None:
            bucket = WindowBucket(window_start=start, window_end=start + self._window_seconds)
            self._buckets[start] = bucket
            self._evict()
        return bucket

    def _evict(self) -> None:
        while len(self._buckets) > self._max:
            self._buckets.popitem(last=False)

    # ---- public ----

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    def record(self, flow: FlowRecord) -> None:
        with self._lock:
            bucket = self._get_or_create(flow.timestamp)
            bucket.record(flow)

    def current_window_start(self, now: float = None) -> float:
        return self._bucket_start(now if now is not None else time.time())

    def closed_windows(self, now: float = None) -> List[WindowBucket]:
        """Return all buckets whose ``window_end`` <= now, excluding the
        currently-open window. Detectors should run on these."""
        now = now if now is not None else time.time()
        with self._lock:
            return [b for b in self._buckets.values() if b.window_end <= now]

    def open_window(self, now: float = None) -> WindowBucket:
        now = now if now is not None else time.time()
        with self._lock:
            return self._get_or_create(now)

    def iter_all(self) -> Iterable[WindowBucket]:
        with self._lock:
            return list(self._buckets.values())

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "window_seconds": self._window_seconds,
                "retained": len(self._buckets),
                "max_retained": self._max,
                "windows": [
                    {
                        "window_start": b.window_start,
                        "window_end": b.window_end,
                        "group_count": len(b.groups),
                        "sample_groups": [
                            {
                                "key": list(k),
                                **stats.to_feature_vector(),
                            }
                            for k, stats in list(b.groups.items())[:3]
                        ],
                    }
                    for b in self._buckets.values()
                ],
            }
