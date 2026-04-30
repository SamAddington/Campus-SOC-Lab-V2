from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import json
import os
import time
import requests

app = FastAPI(title="WiCyS Simulator")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
SCENARIOS_DIR = Path("/app/scenarios")

ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8021")
AUDIT_URL = os.getenv("AUDIT_URL", "http://audit:8022")
SOC_API_KEY = os.getenv("SOC_API_KEY", "change-me-dev-api-key")

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class RunScenarioRequest(BaseModel):
    scenario_id: str
    target_url: Optional[str] = None
    pace_ms: int = 500
    stop_on_error: bool = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def scenario_path_from_id(scenario_id: str) -> Path:
    return SCENARIOS_DIR / f"{scenario_id}.json"


def load_scenario(scenario_id: str) -> Dict[str, Any]:
    path = scenario_path_from_id(scenario_id)
    if not path.exists():
        raise FileNotFoundError(f"Scenario not found: {path}")

    data = load_json(path)
    if "scenario_id" not in data:
        data["scenario_id"] = scenario_id
    if "events" not in data or not isinstance(data["events"], list):
        raise ValueError("Scenario file must contain an 'events' list")

    return data


def post_json(url: str, payload: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
    resp = requests.post(
        url,
        json=payload,
        timeout=timeout,
        headers={"X-API-Key": SOC_API_KEY},
    )
    try:
      data = resp.json()
    except Exception:
      data = {"detail": resp.text}
    return {
        "ok": resp.ok,
        "status_code": resp.status_code,
        "data": data,
    }


def log_simulation_run(summary: Dict[str, Any]) -> None:
    try:
        requests.post(
            f"{AUDIT_URL}/log_simulation_run",
            json=summary,
            timeout=10,
            headers={"X-API-Key": SOC_API_KEY},
        )
    except Exception:
        pass


@app.get("/")
def serve_index():
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Simulator dashboard not found.")
    return FileResponse(index_path)


@app.get("/health")
def health():
    return {"status": "up"}


@app.get("/scenarios")
def scenarios():
    items: List[Dict[str, Any]] = []

    if not SCENARIOS_DIR.exists():
        return {"count": 0, "items": []}

    for path in sorted(SCENARIOS_DIR.glob("*.json")):
        try:
            data = load_json(path)
            items.append(
                {
                    "scenario_id": data.get("scenario_id", path.stem),
                    "description": data.get("description", ""),
                    "event_count": len(data.get("events", [])),
                    "file": path.name,
                }
            )
        except Exception as e:
            items.append(
                {
                    "scenario_id": path.stem,
                    "description": f"Failed to parse: {str(e)}",
                    "event_count": 0,
                    "file": path.name,
                }
            )

    return {"count": len(items), "items": items}


@app.get("/scenario/{scenario_id}")
def scenario_detail(scenario_id: str):
    try:
        scenario = load_scenario(scenario_id)
        return scenario
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/run_scenario")
def run_scenario(req: RunScenarioRequest):
    try:
        scenario = load_scenario(req.scenario_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    target_url = req.target_url or f"{ORCHESTRATOR_URL}/process_event"
    events = scenario.get("events", [])

    if not events:
        raise HTTPException(status_code=400, detail="Scenario contains no events")

    started_at = utc_now()
    results: List[Dict[str, Any]] = []
    success_count = 0
    error_count = 0

    for idx, event in enumerate(events, start=1):
        event_id = event.get("event_id")
        payload = event.get("payload")

        if not event_id or not payload:
            error_count += 1
            results.append(
                {
                    "index": idx,
                    "event_id": event_id,
                    "ok": False,
                    "status_code": 400,
                    "detail": "Each event must contain 'event_id' and 'payload'",
                }
            )
            if req.stop_on_error:
                break
            continue

        request_body = {
            "event_id": event_id,
            "payload": payload,
            "scenario_id": scenario["scenario_id"],
        }

        response = post_json(target_url, request_body)

        if response["ok"]:
            success_count += 1
        else:
            error_count += 1

        results.append(
            {
                "index": idx,
                "event_id": event_id,
                "ok": response["ok"],
                "status_code": response["status_code"],
                "response": response["data"],
            }
        )

        if not response["ok"] and req.stop_on_error:
            break

        if idx < len(events) and req.pace_ms > 0:
            time.sleep(req.pace_ms / 1000.0)

    ended_at = utc_now()

    summary = {
        "scenario_id": scenario["scenario_id"],
        "description": scenario.get("description", ""),
        "target_url": target_url,
        "pace_ms": req.pace_ms,
        "total_events": len(events),
        "success_count": success_count,
        "error_count": error_count,
        "started_at": started_at,
        "ended_at": ended_at,
    }

    log_simulation_run(summary)

    return {
        "status": "completed",
        "summary": summary,
        "results": results,
    }