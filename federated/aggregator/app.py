from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
from typing import List, Dict
from datetime import datetime, timezone
import json

app = FastAPI(title="WiCyS Federated Aggregator")

SHARED_DIR = Path("/app/shared")
SHARED_DIR.mkdir(parents=True, exist_ok=True)

UPDATES_PATH = SHARED_DIR / "updates.json"
GLOBAL_MODEL_PATH = SHARED_DIR / "global_model.json"
ROUND_STATE_PATH = SHARED_DIR / "round_state.json"

EXPECTED_CLIENTS = ["client_a", "client_b", "client_c"]


class ModelUpdate(BaseModel):
    client_id: str
    sample_count: int
    feature_order: List[str]
    coef: List[float]
    intercept: float


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path, default):
    if path.exists():
        return json.loads(path.read_text())
    return default


def save_json(path: Path, data):
    path.write_text(json.dumps(data, indent=2))


def ensure_round_state():
    state = load_json(
        ROUND_STATE_PATH,
        {
            "round": 1,
            "expected_clients": EXPECTED_CLIENTS,
            "received_updates": [],
            "status": "collecting",
            "updated_at": utc_now(),
        },
    )
    save_json(ROUND_STATE_PATH, state)
    return state


@app.on_event("startup")
def startup():
    ensure_round_state()
    if not UPDATES_PATH.exists():
        save_json(UPDATES_PATH, {"updates": []})


@app.get("/health")
def health():
    return {"status": "up"}


@app.get("/status")
def status():
    return load_json(ROUND_STATE_PATH, {})


@app.post("/submit_update")
def submit_update(update: ModelUpdate):
    state = ensure_round_state()
    updates_doc = load_json(UPDATES_PATH, {"updates": []})

    # basic validation
    if update.client_id not in state["expected_clients"]:
        raise HTTPException(status_code=400, detail="Unknown client_id")

    # replace existing update from same client for current round
    filtered = [
        u for u in updates_doc["updates"]
        if not (u["client_id"] == update.client_id and u["round"] == state["round"])
    ]

    record = update.dict()
    record["round"] = state["round"]
    record["submitted_at"] = utc_now()
    filtered.append(record)
    updates_doc["updates"] = filtered
    save_json(UPDATES_PATH, updates_doc)

    received = sorted({
        u["client_id"] for u in updates_doc["updates"]
        if u["round"] == state["round"]
    })
    state["received_updates"] = received
    state["updated_at"] = utc_now()
    save_json(ROUND_STATE_PATH, state)

    return {
        "status": "accepted",
        "round": state["round"],
        "received_updates": received,
    }


@app.post("/aggregate")
def aggregate():
    state = ensure_round_state()
    updates_doc = load_json(UPDATES_PATH, {"updates": []})
    round_updates = [u for u in updates_doc["updates"] if u["round"] == state["round"]]

    if not round_updates:
        raise HTTPException(status_code=400, detail="No updates available for current round")

    feature_order = round_updates[0]["feature_order"]
    dim = len(feature_order)

    for u in round_updates:
        if u["feature_order"] != feature_order:
            raise HTTPException(status_code=400, detail="Feature order mismatch across clients")
        if len(u["coef"]) != dim:
            raise HTTPException(status_code=400, detail="Coefficient dimension mismatch")

    total_samples = sum(u["sample_count"] for u in round_updates)
    if total_samples <= 0:
        raise HTTPException(status_code=400, detail="Total sample count must be > 0")

    weighted_coef = [0.0] * dim
    weighted_intercept = 0.0

    for u in round_updates:
        n = u["sample_count"]
        for i in range(dim):
            weighted_coef[i] += n * u["coef"][i]
        weighted_intercept += n * u["intercept"]

    global_coef = [v / total_samples for v in weighted_coef]
    global_intercept = weighted_intercept / total_samples

    global_model = {
        "round": state["round"],
        "feature_order": feature_order,
        "coef": global_coef,
        "intercept": global_intercept,
        "num_clients": len(round_updates),
        "total_samples": total_samples,
        "updated_at": utc_now(),
    }
    save_json(GLOBAL_MODEL_PATH, global_model)

    state["status"] = "aggregated"
    state["updated_at"] = utc_now()
    save_json(ROUND_STATE_PATH, state)

    return {
        "status": "aggregated",
        "round": state["round"],
        "num_clients": len(round_updates),
        "total_samples": total_samples,
        "global_model_path": str(GLOBAL_MODEL_PATH),
    }


@app.get("/global_model")
def get_global_model():
    if not GLOBAL_MODEL_PATH.exists():
        raise HTTPException(status_code=404, detail="Global model not available yet")
    return load_json(GLOBAL_MODEL_PATH, {})