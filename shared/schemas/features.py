from pydantic import BaseModel, Field

from .base import SCHEMA_VERSION


class FeatureVectorV1(BaseModel):
    """Interpretable, hand-crafted feature set used by the detector.

    Kept intentionally small so every feature has a plain-language explanation
    that can appear in a decision card without ML expertise.
    """

    schema_version: str = Field(default=SCHEMA_VERSION)
    contains_link: int = 0
    contains_password: int = 0
    contains_urgent: int = 0
    contains_reward: int = 0
    len_message: int = 0
