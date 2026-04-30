"""Shared, versioned Pydantic schemas for the WiCyS SOC stack.

Every inter-service record is stamped with ``SCHEMA_VERSION`` so that the
audit ledger and downstream notebooks can safely evolve over time.

Backward-compat policy:
- Additive fields are allowed within a major version (``v1``).
- Removing or retyping a field requires bumping the version string
  (``v1`` -> ``v2``) AND keeping consumers able to read both.
"""

from .base import SCHEMA_VERSION
from .anon import AnonRecordV1
from .features import FeatureVectorV1
from .ingest import IngestedEventV1
from .detector import DetectorResultV1, FederatedResultV1
from .decision import DecisionCardV1
from .llm import (
    LLMAssistRequestV1,
    LLMAssistResponseV1,
    LLMTier,
    LLMMode,
)

__all__ = [
    "SCHEMA_VERSION",
    "AnonRecordV1",
    "FeatureVectorV1",
    "IngestedEventV1",
    "DetectorResultV1",
    "FederatedResultV1",
    "DecisionCardV1",
    "LLMAssistRequestV1",
    "LLMAssistResponseV1",
    "LLMTier",
    "LLMMode",
]
