"""Normalized flow record.

Every adapter converts its vendor-specific format into a ``FlowRecord``.
Downstream code (windows, detectors) only works with normalized flows --
adapters are the only place that deals with Zeek quirks vs. Suricata vs.
NetFlow.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .privacy import bucket_ip, subnet_hash


@dataclass
class FlowRecord:
    """One flow observation. No payload, no raw IPs survive this struct.

    ``src_subnet_hash`` and ``dst_subnet_hash`` are the privacy-safe
    identifiers downstream code uses; ``src_ip`` / ``dst_ip`` are kept as
    ephemeral values only for the duration of normalization and are
    cleared before the record is stored.
    """

    timestamp: float
    src_subnet_hash: str
    dst_subnet_hash: str
    dst_port: int
    protocol: str
    bytes_total: int = 0
    packets_total: int = 0
    service: str = "unknown"
    vendor: str = "unknown"
    # Raw-source cleared after normalization.
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def clear_raw(self) -> None:
        self.src_ip = None
        self.dst_ip = None


def normalize_flow(
    *,
    secret: str,
    src_ip: Optional[str],
    dst_ip: Optional[str],
    dst_port: Optional[int],
    protocol: Optional[str],
    bytes_total: Optional[int] = 0,
    packets_total: Optional[int] = 0,
    service: Optional[str] = None,
    vendor: str = "unknown",
    ts: Optional[float] = None,
    ipv4_prefix: int = 24,
    ipv6_prefix: int = 64,
    extra: Optional[Dict[str, Any]] = None,
) -> Optional[FlowRecord]:
    """Normalize one vendor-specific flow. Returns ``None`` if the record
    lacks enough fields to be useful (no usable src/dst IP)."""

    src_bucket = bucket_ip(src_ip or "", ipv4_prefix, ipv6_prefix)
    dst_bucket = bucket_ip(dst_ip or "", ipv4_prefix, ipv6_prefix)
    if not src_bucket and not dst_bucket:
        return None

    rec = FlowRecord(
        timestamp=float(ts) if ts is not None else time.time(),
        src_subnet_hash=subnet_hash(secret, src_bucket),
        dst_subnet_hash=subnet_hash(secret, dst_bucket),
        dst_port=int(dst_port or 0),
        protocol=(protocol or "unknown").lower(),
        bytes_total=int(bytes_total or 0),
        packets_total=int(packets_total or 0),
        service=(service or "unknown").lower(),
        vendor=vendor,
        extra=dict(extra or {}),
    )
    rec.clear_raw()
    return rec
