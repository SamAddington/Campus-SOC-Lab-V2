"""Per-provider sync state persistence.

Each provider keeps a small JSON file tracking the last successful sync,
the last event identifier it observed, and a running ingest count. This
makes ``POST /sync/{provider}`` idempotent across runs and avoids
re-submitting the same event to the collector.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


_LOCK = threading.Lock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_path(state_dir: Path, provider: str) -> Path:
    return state_dir / f"{provider}.json"


def load(state_dir: Path, provider: str) -> Dict[str, Any]:
    path = state_path(state_dir, provider)
    if not path.exists():
        return {
            "provider": provider,
            "last_sync_at": None,
            "last_event_id": None,
            "total_events_ingested": 0,
            "last_error": None,
        }
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"provider": provider, "last_sync_at": None, "corrupt": True}


def save(state_dir: Path, provider: str, data: Dict[str, Any]) -> None:
    path = state_path(state_dir, provider)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def record_sync(
    state_dir: Path,
    provider: str,
    *,
    ingested: int,
    last_event_id: Optional[str],
    error: Optional[str] = None,
) -> Dict[str, Any]:
    with _LOCK:
        current = load(state_dir, provider)
        current["provider"] = provider
        current["last_sync_at"] = utc_now()
        current["total_events_ingested"] = int(current.get("total_events_ingested", 0)) + ingested
        if last_event_id:
            current["last_event_id"] = last_event_id
        current["last_error"] = error
        save(state_dir, provider, current)
        return current
