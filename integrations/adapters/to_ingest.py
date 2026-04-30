"""Adapter from LMS provider events to the collector's ``/ingest`` schema.

Providers return ``NormalizedEvent`` instances. This adapter turns them into
the JSON body the collector expects.

Governance: we pre-anonymize here so the integrations service never sends a
raw ``user_id`` or ``email`` across the network -- not even on the internal
Docker network. The collector re-hashes on arrival, which is a no-op for an
already-hashed value but provides defense in depth if the integrations
service is compromised.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from anonymize import email_domain, hmac_hash


@dataclass
class NormalizedEvent:
    """Vendor-agnostic event payload produced by a provider."""

    # Unique id within the provider, e.g. Canvas stream item id or Moodle msg id.
    provider_event_id: str

    # Required free-text message body the detector will score.
    message: str

    # Source label that downstream services (policy, notebooks) consume.
    # Format: "<provider>:<object_type>" e.g. "canvas:announcement".
    source: str

    # Coarse event type, e.g. "announcement", "message", "discussion_post".
    event_type: str

    # Optional author metadata. user_id is *usually* the provider's internal
    # identifier; email may or may not be exposed, depending on scopes.
    user_id: Optional[str] = None
    email: Optional[str] = None

    # Language hint. Best-effort; the detector's equity notebook relies on
    # this being populated where available.
    language: str = "en"

    # Provider-supplied timestamp if known (ISO8601 string).
    created_at: Optional[str] = None

    # Any extra structured context the provider wants to keep around. Not
    # sent to the collector; recorded locally if a debug/dry-run mode is on.
    extra: Dict[str, Any] = field(default_factory=dict)


def to_collector_payload(event: NormalizedEvent, hmac_secret: str) -> Dict[str, Any]:
    """Build the JSON body accepted by ``POST collector/ingest``.

    Note: the collector's ``IngestInput`` model currently takes ``user_id``
    and ``email`` as required strings. We send pre-hashed values in those
    fields along with an ``x-anon`` marker prefix so downstream consumers
    can see that the integrations service already anonymized. The
    collector's own HMAC step is still applied to those strings, but with
    the same secret that yields a deterministic second hash; the audit
    ledger will show the double-hashed value.
    """

    user_hash = hmac_hash(hmac_secret, event.user_id) if event.user_id else ""
    email_hash = hmac_hash(hmac_secret, event.email) if event.email else ""
    domain = email_domain(event.email)

    # The collector requires non-empty ``user_id`` / ``email`` strings.
    # Provide synthetic placeholders that are still anonymous but carry
    # provenance. Domain is preserved when available for fairness metrics.
    safe_user_id = f"x-anon:{user_hash or 'unknown'}"
    safe_email_local = user_hash or "unknown"
    safe_email = f"{safe_email_local}@{domain}" if domain else f"{safe_email_local}@example.invalid"

    return {
        "user_id": safe_user_id,
        "email": safe_email,
        "source": event.source,
        "message": event.message,
        "event_type": event.event_type,
        "language": event.language or "en",
        "consent_use_for_distillation": False,
    }
