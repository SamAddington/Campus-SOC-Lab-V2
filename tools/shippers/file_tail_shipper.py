from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

import requests


def post_ingest(
    *,
    collector_url: str,
    api_key: str,
    source: str,
    event_type: str,
    message: str,
    user_id: str = "host",
    email: str = "host@example.invalid",
    language: str = "en",
) -> None:
    payload = {
        "user_id": user_id,
        "email": email,
        "source": source,
        "message": message,
        "event_type": event_type,
        "language": language,
        "consent_use_for_distillation": False,
    }
    r = requests.post(
        f"{collector_url.rstrip('/')}/ingest",
        json=payload,
        timeout=15,
        headers={"X-API-Key": api_key},
    )
    r.raise_for_status()


def tail_file(path: Path, *, seek_end: bool = True) -> None:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        if seek_end:
            f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.25)
                continue
            yield line.rstrip("\n")


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Tail a file and forward lines to collector /ingest.")
    p.add_argument("--file", required=True, help="Path to file to tail")
    p.add_argument("--collector-url", default=os.getenv("COLLECTOR_URL", "http://localhost:8001"))
    p.add_argument("--api-key", default=os.getenv("SOC_API_KEY", ""))
    p.add_argument("--source", default="server_log")
    p.add_argument("--event-type", default="log_line")
    p.add_argument("--user-id", default="host")
    p.add_argument("--email", default="host@example.invalid")
    p.add_argument("--no-seek-end", action="store_true", help="Start at beginning instead of tailing from end")
    args = p.parse_args(argv)

    if not args.api_key:
        print("Missing --api-key (or SOC_API_KEY env var).", file=sys.stderr)
        return 2

    path = Path(args.file)
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        return 2

    for line in tail_file(path, seek_end=not args.no_seek_end):
        if not line.strip():
            continue
        try:
            post_ingest(
                collector_url=args.collector_url,
                api_key=args.api_key,
                source=args.source,
                event_type=args.event_type,
                message=line[:5000],
                user_id=args.user_id,
                email=args.email,
            )
        except Exception as e:
            # Back off briefly on transient errors; do not exit on a single failure.
            print(json.dumps({"error": e.__class__.__name__, "detail": str(e)[:200]}), file=sys.stderr)
            time.sleep(1.0)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

