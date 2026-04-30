"""Privacy helpers for traffic data.

Two guarantees this module enforces:

1. No raw IPs ever leave the ingestor. Every address is bucketed to a
   subnet (default ``/24`` for IPv4, ``/64`` for IPv6) before any further
   processing, and then HMAC-hashed with the shared deployment secret.
2. No per-user anomaly signal is emitted unless at least ``k`` distinct
   peer groups were active in the same window. This is a weak but cheap
   k-anonymity check that prevents the detector from singling out one
   small subnet when overall network activity is sparse.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
from typing import Optional


def bucket_ip(ip: str, ipv4_prefix: int, ipv6_prefix: int) -> Optional[str]:
    """Return the network-string form for ``ip`` bucketed to a prefix.

    Returns ``None`` for malformed input so callers can drop the flow.
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    try:
        if isinstance(addr, ipaddress.IPv4Address):
            net = ipaddress.ip_network(f"{addr}/{ipv4_prefix}", strict=False)
        else:
            net = ipaddress.ip_network(f"{addr}/{ipv6_prefix}", strict=False)
    except ValueError:
        return None

    return str(net)


def subnet_hash(secret: str, bucketed: Optional[str], length: int = 16) -> str:
    """HMAC-SHA256 of the bucketed subnet string, truncated to ``length``."""
    if not bucketed:
        return ""
    digest = hmac.new(
        secret.encode("utf-8"),
        bucketed.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:length]


def k_anonymity_ok(group_count: int, k: int) -> bool:
    """True iff at least ``k`` peer groups contributed to the window."""
    return int(group_count) >= int(k)
