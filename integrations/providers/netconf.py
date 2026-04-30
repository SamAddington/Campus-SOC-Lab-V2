from __future__ import annotations

import logging
import os
from typing import List, Optional

from adapters import NormalizedEvent

from .base import LMSProvider, SyncResult

log = logging.getLogger("netconf")


def _csv(s: str) -> List[str]:
    return [p.strip() for p in (s or "").replace(";", ",").split(",") if p.strip()]


class NETCONFProvider(LMSProvider):
    """NETCONF polling connector (read-only, minimal).

    Connects to each configured target and emits a short capability summary.
    """

    name = "netconf"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.targets = _csv(os.getenv("NETCONF_TARGETS", ""))
        self.username = os.getenv("NETCONF_USERNAME", "")
        self.password = os.getenv("NETCONF_PASSWORD", "")
        self.port = int(os.getenv("NETCONF_PORT", "830") or "830")
        self.allow = set(_csv(os.getenv("DEVICE_ALLOWLIST", "")))

    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        if not self.configured:
            return SyncResult(provider=self.name, events=[], warnings=["NETCONF_TARGETS not configured"])

        warnings: List[str] = []
        events: List[NormalizedEvent] = []

        try:
            from ncclient import manager  # type: ignore
        except Exception:
            return SyncResult(provider=self.name, events=[], warnings=["ncclient not installed in integrations image"])

        for host in self.targets[: max(1, limit)]:
            if self.allow and host not in self.allow:
                warnings.append(f"host {host} not in DEVICE_ALLOWLIST; skipped")
                continue
            try:
                with manager.connect(
                    host=host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    hostkey_verify=os.getenv("NETCONF_HOSTKEY_VERIFY", "0") == "1",
                    timeout=10,
                ) as m:
                    caps = list(m.server_capabilities)[:10]
                    msg = f"NETCONF connected host={host} caps={len(list(m.server_capabilities))}"
                    if caps:
                        msg += f" sample_cap={caps[0]}"
                    events.append(
                        NormalizedEvent(
                            provider_event_id=f"{host}:{self.port}",
                            message=msg,
                            source="netconf:poll",
                            event_type="device_poll",
                            user_id="",
                            email="",
                            language="en",
                            created_at=None,
                        )
                    )
            except Exception as e:
                warnings.append(f"{host} connect failed: {e.__class__.__name__}")

        return SyncResult(provider=self.name, events=events, next_cursor=None, warnings=warnings)

