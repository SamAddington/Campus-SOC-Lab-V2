"""NetFlow / IPFIX adapter for ``goflow2`` JSON output.

``goflow2`` is the de-facto way to turn NetFlow/IPFIX into JSON that can
be consumed over HTTP or Kafka. The field names below match its default
JSON schema.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from features import FlowRecord, normalize_flow


_PROTO_NAMES = {
    1: "icmp",
    6: "tcp",
    17: "udp",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "icmpv6",
}


def _proto_name(value: Any) -> str:
    if isinstance(value, str):
        return value.lower()
    try:
        return _PROTO_NAMES.get(int(value), f"proto_{int(value)}")
    except Exception:
        return "unknown"


def netflow_to_flow(record: Dict[str, Any], *, secret: str,
                    ipv4_prefix: int, ipv6_prefix: int) -> Optional[FlowRecord]:
    ts = record.get("TimeFlowStart") or record.get("TimeReceived")
    if ts is not None:
        # goflow2 emits unix seconds as integer
        try:
            ts = float(ts)
        except Exception:
            ts = None

    return normalize_flow(
        secret=secret,
        src_ip=record.get("SrcAddr") or record.get("SrcIP"),
        dst_ip=record.get("DstAddr") or record.get("DstIP"),
        dst_port=record.get("DstPort"),
        protocol=_proto_name(record.get("Proto")),
        bytes_total=record.get("Bytes", 0),
        packets_total=record.get("Packets", 0),
        service="unknown",
        vendor="netflow",
        ts=ts,
        ipv4_prefix=ipv4_prefix,
        ipv6_prefix=ipv6_prefix,
    )
