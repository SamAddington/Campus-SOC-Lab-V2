from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import pandas as pd
import requests
from sklearn.linear_model import LogisticRegression

app = FastAPI(title="WiCyS Federated Client C")

CLIENT_ID = "client_c"
DATA_PATH = Path("/app/data/client_c_events.csv")

FEATURE_ORDER = [
    "contains_link",
    "contains_password",
    "contains_urgent",
    "contains_reward",
    "len_message_scaled",
]


class TrainRequest(BaseModel):
    round: int


class TrainAndSubmitRequest(BaseModel):
    round: int
    aggregator_url: str


def extract_features(message: str):
    msg = str(message).lower()

    contains_link = int(("http" in msg) or ("https" in msg))
    contains_password = int(
        ("password" in msg)
        or ("passphrase" in msg)
        or ("reset" in msg)
        or ("contraseña" in msg)
        or ("cuenta" in msg)
    )
    contains_urgent = int(
        ("urgent" in msg)
        or ("immediately" in msg)
        or ("expire" in msg)
        or ("urgente" in msg)
        or ("ahora" in msg)
    )
    contains_reward = int(
        ("gift card" in msg)
        or ("bonus" in msg)
        or ("reward" in msg)
        or ("premio" in msg)
    )
    len_message_scaled = min(len(msg) / 200.0, 1.0)

    return {
        "contains_link": contains_link,
        "contains_password": contains_password,
        "contains_urgent": contains_urgent,
        "contains_reward": contains_reward,
        "len_message_scaled": len_message_scaled,
    }


def load_dataset():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)

    if "message" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must contain 'message' and 'label' columns")

    feature_rows = [extract_features(msg) for msg in df["message"].fillna("")]
    X = pd.DataFrame(feature_rows)[FEATURE_ORDER]
    y = df["label"].astype(int)

    return df, X, y


def train_local_model():
    _, X, y = load_dataset()

    if y.nunique() < 2:
        raise ValueError("Local dataset must contain at least two classes for logistic regression")

    model = LogisticRegression(max_iter=500)
    model.fit(X, y)

    return {
        "client_id": CLIENT_ID,
        "sample_count": int(len(X)),
        "feature_order": FEATURE_ORDER,
        "coef": model.coef_[0].tolist(),
        "intercept": float(model.intercept_[0]),
    }


@app.get("/health")
def health():
    return {"status": "up", "client_id": CLIENT_ID}


@app.get("/dataset_info")
def dataset_info():
    df, _, y = load_dataset()
    label_counts = {str(k): int(v) for k, v in y.value_counts().to_dict().items()}
    return {
        "client_id": CLIENT_ID,
        "rows": int(len(df)),
        "label_distribution": label_counts,
    }


@app.post("/train_local")
def train_local(req: TrainRequest):
    try:
        result = train_local_model()
        result["round"] = req.round
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/train_and_submit")
def train_and_submit(req: TrainAndSubmitRequest):
    try:
        update = train_local_model()

        resp = requests.post(
            f"{req.aggregator_url.rstrip('/')}/submit_update",
            json={
                "client_id": update["client_id"],
                "sample_count": update["sample_count"],
                "feature_order": update["feature_order"],
                "coef": update["coef"],
                "intercept": update["intercept"],
            },
            timeout=30,
        )
        resp.raise_for_status()

        return {
            "status": "submitted",
            "client_id": CLIENT_ID,
            "round": req.round,
            "aggregator_response": resp.json(),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))