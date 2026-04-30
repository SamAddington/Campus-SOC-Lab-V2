from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class SpoolConfig:
    enabled: bool = False
    directory: Path = Path("/app/data/siem_spool")
    max_bytes: int = 200 * 1024 * 1024  # 200MB
    max_files: int = 1000
    flush_interval_seconds: float = 5.0
    batch_size: int = 200
    max_attempts: int = 50


def _truthy(v: str) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def load_spool_config() -> SpoolConfig:
    return SpoolConfig(
        enabled=_truthy(os.getenv("SIEM_SPOOL_ENABLED", "")),
        directory=Path(os.getenv("SIEM_SPOOL_DIR", "/app/data/siem_spool")),
        max_bytes=int(os.getenv("SIEM_SPOOL_MAX_BYTES", str(200 * 1024 * 1024)) or str(200 * 1024 * 1024)),
        max_files=int(os.getenv("SIEM_SPOOL_MAX_FILES", "1000") or "1000"),
        flush_interval_seconds=float(os.getenv("SIEM_SPOOL_FLUSH_INTERVAL", "5") or "5"),
        batch_size=int(os.getenv("SIEM_SPOOL_BATCH_SIZE", "200") or "200"),
        max_attempts=int(os.getenv("SIEM_SPOOL_MAX_ATTEMPTS", "50") or "50"),
    )


class DiskSpool:
    """Very small, durable, file-based queue (JSONL segments).

    - Appends records to `pending-*.jsonl`
    - Flush reads oldest segment(s) and re-writes failed items to a new segment
    - Deletes fully-processed segments

    This is intentionally simple and dependency-free.
    """

    def __init__(self, cfg: SpoolConfig):
        self.cfg = cfg
        self.cfg.directory.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._stats_path = self.cfg.directory / "spool_stats.json"
        self._stats = self._load_stats()

    def _load_stats(self) -> Dict[str, Any]:
        try:
            if self._stats_path.exists():
                return json.loads(self._stats_path.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {
            "v": 1,
            "enqueued": 0,
            "delivered": 0,
            "requeued": 0,
            "dropped_max_bytes": 0,
            "dropped_max_files": 0,
            "dropped_max_attempts": 0,
        }

    def _save_stats(self) -> None:
        try:
            self._stats_path.write_text(json.dumps(self._stats, indent=2, sort_keys=True), encoding="utf-8")
        except Exception:
            pass

    def _segments(self, dest: Optional[str] = None) -> List[Path]:
        if dest:
            segs = sorted(self.cfg.directory.glob(f"pending-{dest}-*.jsonl"))
        else:
            segs = sorted(self.cfg.directory.glob("pending-*.jsonl"))
        return segs

    def _bytes_on_disk(self) -> int:
        total = 0
        for p in self.cfg.directory.glob("*.jsonl"):
            try:
                total += p.stat().st_size
            except Exception:
                pass
        return total

    def _oldest_created_at(self, seg: Path) -> Optional[float]:
        try:
            with open(seg, "r", encoding="utf-8") as f:
                line = f.readline()
            if not line:
                return None
            rec = json.loads(line)
            v = rec.get("created_at")
            return float(v) if v is not None else None
        except Exception:
            return None

    def status(self) -> Dict[str, Any]:
        with self._lock:
            segs = self._segments()
            dests: Dict[str, Dict[str, Any]] = {}
            for seg in segs:
                # pending-<dest>-<ts>.jsonl
                name = seg.name
                parts = name.split("-", 2)
                dest = parts[1] if len(parts) >= 3 else "unknown"
                dests.setdefault(dest, {"segments": 0, "bytes": 0, "oldest_created_at": None})
                dests[dest]["segments"] += 1
                try:
                    dests[dest]["bytes"] += seg.stat().st_size
                except Exception:
                    pass

            now = time.time()
            for dest, info in dests.items():
                oldest_seg = self._segments(dest=dest)[0] if self._segments(dest=dest) else None
                oldest = self._oldest_created_at(oldest_seg) if oldest_seg else None
                info["oldest_age_seconds"] = (now - oldest) if oldest else None

            return {
                "enabled": self.cfg.enabled,
                "dir": str(self.cfg.directory),
                "segments_total": len(segs),
                "bytes_total": self._bytes_on_disk(),
                "by_destination": dests,
                "stats": dict(self._stats),
            }

    def enqueue(self, *, dest: str, event: Dict[str, Any], error: str) -> bool:
        if not self.cfg.enabled:
            return False
        rec = {
            "v": 1,
            "dest": dest,
            "event": event,
            "attempts": 0,
            "last_error": error,
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False, default=str)
        with self._lock:
            # Apply coarse disk limits: refuse enqueue if we're beyond cap.
            if self._bytes_on_disk() >= self.cfg.max_bytes:
                self._stats["dropped_max_bytes"] = int(self._stats.get("dropped_max_bytes", 0)) + 1
                self._save_stats()
                return False
            segs = self._segments()
            if len(segs) >= self.cfg.max_files:
                self._stats["dropped_max_files"] = int(self._stats.get("dropped_max_files", 0)) + 1
                self._save_stats()
                return False
            safe_dest = "".join(ch for ch in (dest or "unknown") if ch.isalnum() or ch in {"_", "-"}).strip() or "unknown"
            path = self.cfg.directory / f"pending-{safe_dest}-{int(time.time())}.jsonl"
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._stats["enqueued"] = int(self._stats.get("enqueued", 0)) + 1
            self._save_stats()
        return True

    def flush_once(self, *, emit_one, dest: Optional[str] = None) -> Dict[str, Any]:
        """Try to deliver a batch of queued records.

        `emit_one(dest, event) -> {ok: bool, ...}`
        """
        if not self.cfg.enabled:
            return {"enabled": False, "processed": 0, "delivered": 0, "requeued": 0}

        delivered = 0
        requeued: List[Dict[str, Any]] = []
        processed = 0

        seg, lines = self._read_batch(dest=dest)
        if seg is None:
            return {"enabled": True, "processed": 0, "delivered": 0, "requeued": 0}
        if lines is None:
            return {"enabled": True, "processed": 0, "delivered": 0, "requeued": 0, "error": "read_failed"}

        # Emit outside lock (avoid blocking enqueue during network IO).
        for line in lines:
            try:
                rec = json.loads(line)
            except Exception:
                processed += 1
                continue
            dest = str(rec.get("dest") or "")
            event = rec.get("event")
            attempts = int(rec.get("attempts") or 0)
            processed += 1

            ok, updated = self._handle_one_record(rec, dest, event, attempts, emit_one)
            if ok:
                delivered += 1
            elif updated is not None:
                requeued.append(updated)

        # Rewrite segment: drop emitted lines, keep remaining tail + any requeued.
        self._rewrite_segment(seg=seg, processed_lines=len(lines), requeued=requeued)
        with self._lock:
            self._stats["delivered"] = int(self._stats.get("delivered", 0)) + delivered
            self._stats["requeued"] = int(self._stats.get("requeued", 0)) + len(requeued)
            self._save_stats()

        return {
            "enabled": True,
            "processed": processed,
            "delivered": delivered,
            "requeued": len(requeued),
        }

    def _read_batch(self, *, dest: Optional[str]) -> Tuple[Optional[Path], Optional[List[str]]]:
        with self._lock:
            segs = self._segments(dest=dest)
            if not segs:
                return None, None
            seg = segs[0]
            lines: List[str] = []
            try:
                with open(seg, "r", encoding="utf-8") as f:
                    for _ in range(self.cfg.batch_size):
                        line = f.readline()
                        if not line:
                            break
                        lines.append(line)
            except Exception:
                return seg, None
            return seg, lines

    def _handle_one_record(self, rec: Dict[str, Any], dest: str, event: Any, attempts: int, emit_one) -> Tuple[bool, Optional[Dict[str, Any]]]:
        if not dest or not isinstance(event, dict):
            return False, None
        if attempts >= self.cfg.max_attempts:
            with self._lock:
                self._stats["dropped_max_attempts"] = int(self._stats.get("dropped_max_attempts", 0)) + 1
                self._save_stats()
            return False, None
        result = emit_one(dest, event)
        ok = bool(result.get("ok"))
        if ok:
            return True, None
        rec["attempts"] = attempts + 1
        rec["last_error"] = str(result.get("error") or result.get("body") or "emit_failed")[:200]
        rec["updated_at"] = time.time()
        return False, rec

    def _rewrite_segment(self, *, seg: Path, processed_lines: int, requeued: List[Dict[str, Any]]) -> None:
        with self._lock:
            try:
                remaining: List[str] = []
                with open(seg, "r", encoding="utf-8") as f:
                    for _ in range(processed_lines):
                        _ = f.readline()
                    remaining = f.readlines()

                tmp = self.cfg.directory / f"pending-{int(time.time())}-rewrite.jsonl"
                with open(tmp, "w", encoding="utf-8") as out:
                    for r in requeued:
                        out.write(json.dumps(r, separators=(",", ":"), ensure_ascii=False, default=str) + "\n")
                    for tail in remaining:
                        out.write(tail)

                seg.unlink(missing_ok=True)  # type: ignore[arg-type]
                tmp.rename(seg)
            except Exception:
                pass

