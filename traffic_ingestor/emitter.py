"""Emit anomalies back to the collector as synthesized events.

We deliberately reuse the existing ``/ingest`` endpoint so the rest of
the stack (policy engine, orchestrator, audit, LLM assistant) treats
traffic anomalies exactly like any other signal, and governance
invariants continue to apply.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

import requests

from detectors import Anomaly


_LOG = logging.getLogger("traffic_ingestor.emitter")


class AnomalyEmitter:
    def __init__(self, *, collector_url: str, enabled: bool = True,
                 k_anonymity_min: int = 5):
        self._collector_url = collector_url.rstrip("/")
        self._enabled = bool(enabled)
        self._k_min = int(k_anonymity_min)
        self._recent: List[Dict[str, Any]] = []
        self._dropped_low_k = 0
        self._sent_ok = 0
        self._sent_err = 0

    # ---- helpers ----

    def _event_type(self, a: Anomaly) -> str:
        # Severity-first so policy rules can match by equality without
        # needing wildcard support in the engine. Detector name is still
        # visible in the description and anomaly dict.
        return f"traffic_anomaly_{a.severity}"

    def _message(self, a: Anomaly) -> str:
        return a.description

    def _user_id(self, a: Anomaly) -> str:
        sh = a.window_key[0] or "unknown"
        return f"subnet:{sh}"

    def _email(self, a: Anomaly) -> str:
        sh = a.window_key[0] or "unknown"
        return f"{sh}@network.invalid"

    def _payload(self, a: Anomaly) -> Dict[str, Any]:
        return {
            "user_id": self._user_id(a),
            "email": self._email(a),
            "source": "traffic_anomaly",
            "message": self._message(a),
            "event_type": self._event_type(a),
            "language": "en",
            "consent_use_for_distillation": False,
        }

    # ---- emission ----

    def emit(self, anomalies: List[Anomaly], *, peer_group_count: int) -> Dict[str, Any]:
        sent: List[Dict[str, Any]] = []
        suppressed = 0
        for a in anomalies:
            if peer_group_count < self._k_min:
                self._dropped_low_k += 1
                suppressed += 1
                continue
            record = {
                "anomaly": a.to_dict(),
                "peer_group_count": peer_group_count,
                "ts": time.time(),
                "forwarded": False,
            }
            if self._enabled:
                try:
                    resp = requests.post(
                        f"{self._collector_url}/ingest",
                        json=self._payload(a),
                        timeout=5,
                    )
                    resp.raise_for_status()
                    record["forwarded"] = True
                    self._sent_ok += 1
                except Exception as exc:  # pragma: no cover
                    _LOG.warning("emit failed: %s", exc)
                    record["forward_error"] = str(exc)[:200]
                    self._sent_err += 1
            sent.append(record)
            self._recent.append(record)
            if len(self._recent) > 200:
                self._recent = self._recent[-200:]
        return {
            "emitted": len(sent),
            "suppressed_k_anonymity": suppressed,
            "peer_group_count": peer_group_count,
            "k_anonymity_min": self._k_min,
        }

    def recent(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        if limit is None:
            return list(self._recent)
        return list(self._recent[-int(limit):])

    def status(self) -> Dict[str, Any]:
        return {
            "collector_url": self._collector_url,
            "enabled": self._enabled,
            "k_anonymity_min": self._k_min,
            "sent_ok": self._sent_ok,
            "sent_err": self._sent_err,
            "dropped_low_k": self._dropped_low_k,
            "recent_count": len(self._recent),
        }
