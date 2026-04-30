from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional, Tuple

from adapters import NormalizedEvent

from .base import LMSProvider, SyncResult

log = logging.getLogger("snmp")


def _csv(s: str) -> List[str]:
    return [p.strip() for p in (s or "").replace(";", ",").split(",") if p.strip()]


def _parse_targets(raw: str) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    for t in _csv(raw):
        host = t
        port = 161
        if ":" in t:
            host, port_s = t.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                port = 161
        out.append((host.strip(), port))
    return out


class SNMPProvider(LMSProvider):
    """SNMP polling connector (read-only).

    The implementation is intentionally minimal: it GETs a small set of OIDs for
    each target and emits one summary event per target.
    """

    name = "snmp"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.targets = _parse_targets(os.getenv("SNMP_TARGETS", ""))
        self.community = os.getenv("SNMP_COMMUNITY", "public")
        self.oids = _csv(os.getenv("SNMP_OIDS", "1.3.6.1.2.1.1.3.0"))  # sysUpTime.0
        self.allow = set(_csv(os.getenv("DEVICE_ALLOWLIST", "")))

    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        if not self.configured:
            return SyncResult(provider=self.name, events=[], warnings=["SNMP_TARGETS not configured"])

        warnings: List[str] = []
        events: List[NormalizedEvent] = []

        try:
            from pysnmp.hlapi import (  # type: ignore
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                getCmd,
            )
        except Exception:
            return SyncResult(provider=self.name, events=[], warnings=["pysnmp not installed in integrations image"])

        for host, port in self.targets[: max(1, limit)]:
            if self.allow and host not in self.allow:
                warnings.append(f"host {host} not in DEVICE_ALLOWLIST; skipped")
                continue
            values: Dict[str, str] = {}
            for oid in self.oids[:20]:
                try:
                    it = getCmd(
                        SnmpEngine(),
                        CommunityData(self.community, mpModel=1),
                        UdpTransportTarget((host, port), timeout=2, retries=1),
                        ContextData(),
                        ObjectType(ObjectIdentity(oid)),
                    )
                    err_ind, err_stat, err_idx, var_binds = next(it)
                    if err_ind or err_stat:
                        continue
                    for name, val in var_binds:
                        values[str(name)] = str(val)
                except Exception:
                    continue

            msg = f"SNMP poll host={host} oids={len(values)}"
            if values:
                sample_k = next(iter(values.keys()))
                msg += f" sample[{sample_k}]={values[sample_k]}"

            events.append(
                NormalizedEvent(
                    provider_event_id=f"{host}:{port}",
                    message=msg,
                    source="snmp:poll",
                    event_type="device_poll",
                    user_id="",
                    email="",
                    language="en",
                    created_at=None,
                    extra={"oids": list(values.keys())[:10]},
                )
            )

        return SyncResult(provider=self.name, events=events, next_cursor=None, warnings=warnings)

