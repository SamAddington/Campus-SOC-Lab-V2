"""Suricata EVE JSON adapter.

Handles ``event_type`` of ``flow`` and ``netflow``. Other event types
(``alert``, ``dns``, ``http``) are ignored here; adding them is possible
but would widen the data we keep.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from features import FlowRecord, normalize_flow


def _parse_ts(ts: Any) -> Optional[float]:
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        # Suricata uses ISO8601 with optional timezone
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def suricata_to_flow(record: Dict[str, Any], *, secret: str,
                     ipv4_prefix: int, ipv6_prefix: int) -> Optional[FlowRecord]:
    event_type = record.get("event_type")
    if event_type not in ("flow", "netflow"):
        return None

    flow = record.get("flow") or record.get("netflow") or {}
    bytes_to_server = flow.get("bytes_toserver", 0) or 0
    bytes_to_client = flow.get("bytes_toclient", 0) or 0
    pkts_to_server = flow.get("pkts_toserver", 0) or 0
    pkts_to_client = flow.get("pkts_toclient", 0) or 0

    return normalize_flow(
        secret=secret,
        src_ip=record.get("src_ip"),
        dst_ip=record.get("dest_ip"),
        dst_port=record.get("dest_port"),
        protocol=record.get("proto"),
        bytes_total=int(bytes_to_server) + int(bytes_to_client),
        packets_total=int(pkts_to_server) + int(pkts_to_client),
        service=record.get("app_proto") or "unknown",
        vendor="suricata",
        ts=_parse_ts(record.get("timestamp") or record.get("flow", {}).get("start")),
        ipv4_prefix=ipv4_prefix,
        ipv6_prefix=ipv6_prefix,
        extra={"flow_id": record.get("flow_id")} if record.get("flow_id") else None,
    )
