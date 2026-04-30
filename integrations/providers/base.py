"""Abstract base for LMS providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from adapters import NormalizedEvent
from config import ProviderConfig


@dataclass
class SyncResult:
    """Return value of a provider sync.

    ``events`` are the normalized events the adapter will pass to the
    collector. The caller is responsible for calling the collector and
    advancing the state file; the provider itself is purely a puller.
    """

    provider: str
    events: List[NormalizedEvent]
    next_cursor: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    # Provider-specific debug info, never returned to callers by default.
    debug: Dict[str, Any] = field(default_factory=dict)


class LMSProvider(ABC):
    name: str = "base"

    def __init__(self, cfg: ProviderConfig):
        self.cfg = cfg

    @property
    def configured(self) -> bool:
        return self.cfg.configured

    @abstractmethod
    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        """Pull recent events. ``since`` is provider-specific (timestamp,
        cursor, or event id). Implementations MUST return an empty
        ``SyncResult`` if the provider is not configured; they MUST NOT
        raise for missing credentials."""
        raise NotImplementedError

    def describe(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "configured": self.configured,
            "base_url": self.cfg.base_url,
            "allowed_paths": self.cfg.allowed_paths,
            "allowed_wsfunctions": self.cfg.allowed_wsfunctions,
        }
