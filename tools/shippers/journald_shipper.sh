#!/usr/bin/env bash
set -euo pipefail

# Stream journald entries and forward to the collector /ingest endpoint.
#
# Requirements: journalctl, python3
#
# Env vars:
#   COLLECTOR_URL (default http://localhost:8001)
#   SOC_API_KEY   (required)
#   LOG_UNIT      (optional, e.g. ssh.service)

COLLECTOR_URL="${COLLECTOR_URL:-http://localhost:8001}"
SOC_API_KEY="${SOC_API_KEY:-}"
LOG_UNIT="${LOG_UNIT:-}"

if [[ -z "$SOC_API_KEY" ]]; then
  echo "Missing SOC_API_KEY env var" >&2
  exit 2
fi

J_ARGS=(-f -o json)
if [[ -n "$LOG_UNIT" ]]; then
  J_ARGS+=(-u "$LOG_UNIT")
fi

journalctl "${J_ARGS[@]}" | python3 - <<'PY'
import json, os, sys, time, requests

collector = os.environ.get("COLLECTOR_URL", "http://localhost:8001").rstrip("/")
api_key = os.environ["SOC_API_KEY"]
unit = os.environ.get("LOG_UNIT","")

def post(msg: str):
    payload = {
        "user_id": "host",
        "email": "host@example.invalid",
        "source": "journald" if not unit else f"journald:{unit}",
        "message": msg[:5000],
        "event_type": "journald",
        "language": "en",
        "consent_use_for_distillation": False,
    }
    r = requests.post(f"{collector}/ingest", json=payload, timeout=15, headers={"X-API-Key": api_key})
    r.raise_for_status()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
        msg = obj.get("MESSAGE") or ""
        if not msg:
            continue
        post(msg)
    except Exception as e:
        print(f"warn: {e.__class__.__name__}: {str(e)[:120]}", file=sys.stderr)
        time.sleep(0.5)
PY

