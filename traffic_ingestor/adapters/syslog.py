"""Minimal syslog adapter.

Parses common campus-firewall syslog message shapes ("%ASA-6-302013",
"SFW:", etc.) using a permissive regex. If the line cannot be parsed it
returns ``None`` and the caller drops it. This is intentionally
conservative -- we prefer dropping unparsable lines over guessing IP
positions wrong.
"""

from __future__ import annotations

import re
from typing import Optional

from features import FlowRecord, normalize_flow


_IP = r"(?:\d{1,3}\.){3}\d{1,3}"
_PORT = r"(?:\d+)"

# ``from SRC_IP/PORT to DST_IP/PORT`` or similar
_PATTERNS = [
    re.compile(
        rf"(?P<proto>tcp|udp|icmp)\b.*?"
        rf"(?P<src>{_IP})(?:[:/](?P<sport>{_PORT}))?"
        rf".*?(?P<dst>{_IP})(?:[:/](?P<dport>{_PORT}))?",
        re.IGNORECASE,
    ),
]


def syslog_to_flow(line: str, *, secret: str,
                   ipv4_prefix: int, ipv6_prefix: int) -> Optional[FlowRecord]:
    if not line:
        return None
    for pat in _PATTERNS:
        m = pat.search(line)
        if not m:
            continue
        return normalize_flow(
            secret=secret,
            src_ip=m.group("src"),
            dst_ip=m.group("dst"),
            dst_port=int(m.group("dport") or 0) or None,
            protocol=m.group("proto"),
            bytes_total=0,
            packets_total=1,
            service="unknown",
            vendor="syslog",
            ipv4_prefix=ipv4_prefix,
            ipv6_prefix=ipv6_prefix,
            extra={"raw_length": len(line)},
        )
    return None
