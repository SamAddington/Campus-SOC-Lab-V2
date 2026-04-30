"""HMAC-SHA256 anonymization used by integrations.

Matches the collector's algorithm exactly: both services share the same
``HMAC_SECRET`` so hashes remain consistent across the pipeline. This lets
the audit ledger link events from different sources for the same user
without either service ever seeing the raw identifier.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional


def hmac_hash(secret: str, value: Optional[str], length: int = 16) -> str:
    if value is None or value == "":
        return ""
    digest = hmac.new(
        secret.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:length]


def email_domain(email: Optional[str]) -> str:
    if not email or "@" not in email:
        return ""
    return email.split("@", 1)[1].lower().strip()
