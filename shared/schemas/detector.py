from pydantic import BaseModel, Field
from typing import Optional

from .base import SCHEMA_VERSION


class FederatedResultV1(BaseModel):
    used_federated: bool = False
    risk_score_fl: Optional[float] = None
    reason: str = ""
    model_round: Optional[int] = None


class DetectorResultV1(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    risk_score_rule: float
    risk_score_final: float
    label: str
    action: str
    explanation: str
    federated_result: FederatedResultV1 = Field(default_factory=FederatedResultV1)
