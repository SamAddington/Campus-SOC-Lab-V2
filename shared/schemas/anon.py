from pydantic import BaseModel, Field
from typing import Optional

from .base import SCHEMA_VERSION


class AnonRecordV1(BaseModel):
    """Anonymized event metadata. No raw PII allowed.

    ``user_id_hash`` and ``email_hash`` are per-deployment HMAC-SHA256 truncated
    to 16 hex chars. The HMAC secret lives only in the collector container's
    environment and is never logged or transmitted.
    """

    schema_version: str = Field(default=SCHEMA_VERSION)
    user_id_hash: str
    email_hash: str
    email_domain: Optional[str] = ""
    source: str
    event_type: str
    language: str = "en"
    # NOTE: message content is retained here because the detector needs it for
    # scoring. Downstream auditors should treat it as sensitive and prefer
    # summaries over full content where possible.
    message: str
