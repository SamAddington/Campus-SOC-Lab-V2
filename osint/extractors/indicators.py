"""Extract atomic indicators (URLs, domains, IPs, hashes) from free text.

This module is deliberately conservative:

- We only extract indicators; we do not transmit the surrounding text.
- Private / reserved IPs are rejected by default so the service cannot
  be used to probe internal ranges.
- URLs and domains are normalized (scheme lowercased, trailing dots
  stripped) so cache keys collapse trivial variants.
- Hashes are accepted only at standard lengths (MD5/32, SHA1/40,
  SHA256/64) to avoid false positives on random hex strings.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set
from urllib.parse import urlparse

from .defanging import refang


class IndicatorKind(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"


@dataclass
class IndicatorBundle:
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ipv4s: List[str] = field(default_factory=list)
    ipv6s: List[str] = field(default_factory=list)
    md5s: List[str] = field(default_factory=list)
    sha1s: List[str] = field(default_factory=list)
    sha256s: List[str] = field(default_factory=list)

    def total(self) -> int:
        return (
            len(self.urls) + len(self.domains) + len(self.ipv4s)
            + len(self.ipv6s) + len(self.md5s) + len(self.sha1s)
            + len(self.sha256s)
        )

    def is_empty(self) -> bool:
        return self.total() == 0

    def flat(self) -> List[tuple]:
        pairs = []
        pairs.extend((IndicatorKind.URL, v) for v in self.urls)
        pairs.extend((IndicatorKind.DOMAIN, v) for v in self.domains)
        pairs.extend((IndicatorKind.IPV4, v) for v in self.ipv4s)
        pairs.extend((IndicatorKind.IPV6, v) for v in self.ipv6s)
        pairs.extend((IndicatorKind.HASH_MD5, v) for v in self.md5s)
        pairs.extend((IndicatorKind.HASH_SHA1, v) for v in self.sha1s)
        pairs.extend((IndicatorKind.HASH_SHA256, v) for v in self.sha256s)
        return pairs


# --- regexes (intentionally strict, not exhaustive) -------------------------

_URL_RE = re.compile(
    r"https?://[^\s<>\"'\\]+",
    re.IGNORECASE,
)

_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9.-])"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)"
    r"(?![A-Za-z0-9.-])"
)

_IPV4_RE = re.compile(
    r"(?<!\d)"
    r"((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})"
    r"(?!\d)"
)

_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}"
    r"(?![0-9A-Fa-f:])"
)

_HASH_RE = re.compile(r"\b([A-Fa-f0-9]{32,64})\b")

_TLDS_MIN = (
    "com", "org", "net", "edu", "gov", "mil", "int",
    "io", "co", "us", "uk", "ca", "de", "fr", "jp", "cn", "ru",
    "xyz", "top", "info", "biz", "dev", "app", "site", "online",
)


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_multicast or addr.is_unspecified
    )


def normalize_domain(value: str) -> Optional[str]:
    v = value.strip().strip(".").lower()
    if not v or "." not in v:
        return None
    # Reject pure IP strings being matched as domains
    try:
        ipaddress.ip_address(v)
        return None
    except ValueError:
        pass
    tld = v.rsplit(".", 1)[-1]
    # Accept 2+ letter TLDs; if short, require it to be in a known list.
    if len(tld) < 2 or not tld.isalpha():
        return None
    if len(tld) == 2 or tld in _TLDS_MIN:
        return v
    # Allow longer alphabetic TLDs (e.g. "online", "website").
    return v


def normalize_url(value: str) -> Optional[str]:
    v = refang(value.strip())
    if not v:
        return None
    try:
        parsed = urlparse(v)
    except ValueError:
        return None
    if parsed.scheme.lower() not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    host = parsed.hostname
    if not host:
        return None
    # Reject internal hosts.
    try:
        if is_private_ip(host):
            return None
    except Exception:
        pass
    # Reconstruct with a normalized scheme/host; keep path+query.
    path = parsed.path or ""
    qs = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme.lower()}://{host.lower()}{path}{qs}"


def _unique_keep_order(values) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for v in values:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def extract_indicators(text: str, *,
                       reject_private_ips: bool = True) -> IndicatorBundle:
    """Extract indicators from free text into a bundle.

    Deduplicates and normalizes. Never raises -- bad matches are dropped.
    """
    if not text:
        return IndicatorBundle()

    refanged = refang(text)

    raw_urls = _URL_RE.findall(refanged)
    urls = _unique_keep_order(normalize_url(u) for u in raw_urls)

    # Domains: avoid re-counting the host of every URL we already have.
    url_hosts = set()
    for u in urls:
        try:
            h = urlparse(u).hostname
            if h:
                url_hosts.add(h.lower())
        except Exception:
            continue

    raw_domains = _DOMAIN_RE.findall(refanged)
    domains_list = []
    for d in raw_domains:
        n = normalize_domain(d)
        if n and n not in url_hosts:
            domains_list.append(n)
    domains = _unique_keep_order(domains_list)

    ipv4s_raw = _IPV4_RE.findall(refanged)
    ipv4s = []
    for ip in ipv4s_raw:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if reject_private_ips and is_private_ip(ip):
            continue
        ipv4s.append(ip)
    ipv4s = _unique_keep_order(ipv4s)

    ipv6s_raw = _IPV6_RE.findall(refanged)
    ipv6s = []
    for ip in ipv6s_raw:
        try:
            ipaddress.IPv6Address(ip)
        except ValueError:
            continue
        if reject_private_ips and is_private_ip(ip):
            continue
        ipv6s.append(ip.lower())
    ipv6s = _unique_keep_order(ipv6s)

    md5s: List[str] = []
    sha1s: List[str] = []
    sha256s: List[str] = []
    for h in _HASH_RE.findall(refanged):
        hl = h.lower()
        if len(hl) == 32:
            md5s.append(hl)
        elif len(hl) == 40:
            sha1s.append(hl)
        elif len(hl) == 64:
            sha256s.append(hl)
    md5s = _unique_keep_order(md5s)
    sha1s = _unique_keep_order(sha1s)
    sha256s = _unique_keep_order(sha256s)

    return IndicatorBundle(
        urls=urls,
        domains=domains,
        ipv4s=ipv4s,
        ipv6s=ipv6s,
        md5s=md5s,
        sha1s=sha1s,
        sha256s=sha256s,
    )
