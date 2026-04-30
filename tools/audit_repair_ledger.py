from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def record_signature(signing_key: str, payload: str) -> str:
    import hashlib
    import hmac

    return hmac.new(signing_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def iter_json_objects(path: Path) -> Iterable[Dict[str, Any]]:
    """Yield JSON objects from a .jsonl file.

    - Skips blank lines
    - Skips lines that are not valid JSON objects
    """
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                yield obj


def rewrite_with_chain(rows: List[Dict[str, Any]], signing_key: str) -> List[Dict[str, Any]]:
    prev = ""
    out: List[Dict[str, Any]] = []
    for r in rows:
        row = dict(r)
        row.pop("record_hash", None)
        row.pop("previous_hash", None)
        row["previous_hash"] = prev
        canonical = json.dumps(row, sort_keys=True)
        row["record_hash"] = record_signature(signing_key, canonical)
        prev = row["record_hash"]
        out.append(row)
    return out


def repair_file(path: Path, signing_key: str) -> Tuple[int, Path]:
    rows = list(iter_json_objects(path))
    repaired = rewrite_with_chain(rows, signing_key)

    backup = path.with_suffix(path.suffix + ".bak")
    tmp = path.with_suffix(path.suffix + ".tmp")

    if path.exists():
        shutil.copy2(path, backup)

    with tmp.open("w", encoding="utf-8") as f:
        for row in repaired:
            f.write(json.dumps(row) + "\n")

    tmp.replace(path)
    return len(repaired), backup


def main() -> int:
    p = argparse.ArgumentParser(description="Repair audit ledger JSONL by re-hash-chaining records.")
    p.add_argument("--ledger-dir", default=str(Path("audit/ledger")), help="Path to audit ledger directory")
    p.add_argument(
        "--files",
        default="decision_cards.jsonl,simulation_runs.jsonl",
        help="Comma-separated list of ledger files to repair",
    )
    p.add_argument(
        "--signing-key",
        default=os.getenv("AUDIT_SIGNING_KEY", ""),
        help="Signing key (defaults to AUDIT_SIGNING_KEY env var)",
    )
    args = p.parse_args()

    key = (args.signing_key or "").strip()
    if not key:
        raise SystemExit("Missing --signing-key (or AUDIT_SIGNING_KEY env var).")

    ledger_dir = Path(args.ledger_dir)
    files = [f.strip() for f in str(args.files).split(",") if f.strip()]

    for name in files:
        path = ledger_dir / name
        n, backup = repair_file(path, key)
        print(f"Repaired {path} ({n} records). Backup at {backup}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

