"""Zeek ``conn.log`` JSON adapter.

Zeek emits one JSON object per connection when configured with
``LogAscii::use_json = T``. We care about the subset of fields that
identify a flow; everything else is ignored.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from features import FlowRecord, normalize_flow


def zeek_to_flow(record: Dict[str, Any], *, secret: str,
                 ipv4_prefix: int, ipv6_prefix: int) -> Optional[FlowRecord]:
    return normalize_flow(
        secret=secret,
        src_ip=record.get("id.orig_h") or record.get("src_ip"),
        dst_ip=record.get("id.resp_h") or record.get("dst_ip"),
        dst_port=record.get("id.resp_p") or record.get("dst_port"),
        protocol=record.get("proto"),
        bytes_total=(record.get("orig_bytes") or 0) + (record.get("resp_bytes") or 0),
        packets_total=(record.get("orig_pkts") or 0) + (record.get("resp_pkts") or 0),
        service=record.get("service") or "unknown",
        vendor="zeek",
        ts=record.get("ts"),
        ipv4_prefix=ipv4_prefix,
        ipv6_prefix=ipv6_prefix,
        extra={"uid": record.get("uid")} if record.get("uid") else None,
    )
