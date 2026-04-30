from pydantic import BaseModel, Field
from typing import Any, Dict

from .base import SCHEMA_VERSION


class IngestedEventV1(BaseModel):
    """One line of ``data/ingested_events.jsonl``."""

    schema_version: str = Field(default=SCHEMA_VERSION)
    anon_record: Dict[str, Any]
    features: Dict[str, Any]
    detector_result: Dict[str, Any]
    consent_use_for_distillation: bool = False
