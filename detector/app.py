from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any
from pathlib import Path
import json
import os
import math

app = FastAPI(title="WiCyS SOC Detector", version="0.1.0")

FEDERATED_MODEL_PATH = Path("/app/federated_shared/global_model.json")

USE_ML = os.getenv("USE_ML", "0") == "1"
USE_FEDERATED = os.getenv("USE_FEDERATED", "0") == "1"

ML_COEFFS = {
    "intercept": -2.0,
    "contains_link": 1.0,
    "contains_password": 1.5,
    "contains_urgent": 0.8,
    "contains_reward": 0.7,
}


class DetectorInput(BaseModel):
    anon_record: Dict[str, Any]
    features: Dict[str, Any]


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def load_federated_model():
    if not FEDERATED_MODEL_PATH.exists():
        return None

    try:
        with open(FEDERATED_MODEL_PATH, "r", encoding="utf-8") as f:
            model = json.load(f)
        return model
    except Exception:
        return None


def score_with_federated_model(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute a federated logistic second-opinion score.

    Expected model format:
    {
      "feature_order": [...],
      "coef": [...],
      "intercept": ...,
      "round": ...   # optional
    }
    """
    model = load_federated_model()
    if not model:
        return {
            "used_federated": False,
            "risk_score_fl": None,
            "reason": "Federated global model not available.",
            "model_round": None,
        }

    try:
        feature_order = model["feature_order"]
        coef = model["coef"]
        intercept = float(model["intercept"])
        model_round = model.get("round")

        if len(feature_order) != len(coef):
            return {
                "used_federated": False,
                "risk_score_fl": None,
                "reason": "Federated model dimension mismatch.",
                "model_round": model_round,
            }

        x = []
        for name in feature_order:
            val = features.get(name, 0.0)
            x.append(float(val))

        logit = intercept + sum(w * v for w, v in zip(coef, x))
        prob = sigmoid(logit)

        return {
            "used_federated": True,
            "risk_score_fl": round(prob, 4),
            "reason": "Federated global model applied successfully.",
            "model_round": model_round,
        }

    except Exception as e:
        return {
            "used_federated": False,
            "risk_score_fl": None,
            "reason": f"Federated scoring failed: {str(e)}",
            "model_round": None,
        }


def ml_risk_score(features: Dict[str, Any]) -> float:
    z = ML_COEFFS["intercept"]
    for name, weight in ML_COEFFS.items():
        if name == "intercept":
            continue
        val = 1.0 if features.get(name) else 0.0
        z += weight * val
    return sigmoid(z)


def score(features: Dict[str, Any]) -> Dict[str, Any]:
    risk_score_rule = 0.0
    explanation_parts = []

    if features.get("contains_link"):
        risk_score_rule += 0.3
        explanation_parts.append("Message contains a clickable link.")

    if features.get("contains_password"):
        risk_score_rule += 0.4
        explanation_parts.append("Mentions passwords or passphrases.")

    if features.get("contains_urgent"):
        risk_score_rule += 0.2
        explanation_parts.append("Uses urgent language (e.g., 'urgent', 'immediately').")

    if features.get("contains_reward"):
        risk_score_rule += 0.2
        explanation_parts.append("Offers rewards such as gift cards or bonuses.")

    if features.get("len_message", 0) > 400:
        risk_score_rule += 0.1
        explanation_parts.append("Unusually long message for this source.")

    risk_score_rule = max(0.0, min(1.0, risk_score_rule))

    # Start final score at the rule-based value
    risk_score_final = risk_score_rule

    # Optional local tiny ML second opinion
    if USE_ML:
        try:
            ml_risk = ml_risk_score(features)
            if ml_risk > risk_score_final:
                explanation_parts.append(
                    "ML safety model suggested higher risk based on feature pattern."
                )
                risk_score_final = ml_risk
        except Exception:
            pass

    # Optional federated second opinion
    federated_result = {
        "used_federated": False,
        "risk_score_fl": None,
        "reason": "Federated scoring disabled.",
        "model_round": None,
    }

    if USE_FEDERATED:
        federated_result = score_with_federated_model(features)

        if (
            federated_result.get("used_federated")
            and federated_result.get("risk_score_fl") is not None
        ):
            risk_score_fl = federated_result["risk_score_fl"]

            # Governance-friendly combination:
            # the federated model may only raise suspicion, never lower the score
            if risk_score_fl > risk_score_final:
                risk_score_final = risk_score_fl
                explanation_parts.append(
                    "Federated second-opinion model raised the final risk score."
                )

    risk_score_final = max(0.0, min(1.0, risk_score_final))

    if risk_score_final >= 0.7:
        label = "high_risk"
        action = "escalate"
    elif risk_score_final >= 0.4:
        label = "medium_risk"
        action = "queue_for_review"
    else:
        label = "low_risk"
        action = "allow"

    explanation = (
        " / ".join(explanation_parts)
        if explanation_parts
        else "No obvious phishing indicators detected."
    )

    return {
        "risk_score_rule": round(float(risk_score_rule), 4),
        "risk_score_final": round(float(risk_score_final), 4),
        "label": label,
        "action": action,
        "explanation": explanation,
        "federated_result": federated_result,
    }


@app.post("/score")
def score_endpoint(payload: DetectorInput):
    return score(payload.features)


@app.get("/health")
def health():
    return {"status": "up"}