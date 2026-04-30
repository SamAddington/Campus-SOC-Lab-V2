"""Indicator defanging / refanging.

Analysts and downstream systems routinely defang URLs and IPs
(``hxxp://evil[.]com``, ``1.1.1[.]1``) so they can be logged or shared
without being accidentally clicked or resolved.

We expose both directions so we can:
- refang incoming indicators that analysts pasted in already-defanged
  form before feeding them to lookups;
- defang the indicators we show back in explanations so copy-paste from
  a decision card never produces a live URL.
"""

from __future__ import annotations


_DEFANG_REPLACEMENTS = (
    ("http://", "hxxp://"),
    ("https://", "hxxps://"),
    ("ftp://", "fxp://"),
    (".", "[.]"),
    ("@", "[at]"),
)


def defang(value: str) -> str:
    out = value
    for a, b in _DEFANG_REPLACEMENTS:
        out = out.replace(a, b)
    return out


def refang(value: str) -> str:
    out = value
    for a, b in _DEFANG_REPLACEMENTS:
        out = out.replace(b, a)
    # Handle a few extra common variants.
    out = out.replace("[dot]", ".").replace("(dot)", ".")
    out = out.replace("hxxp", "http")
    return out
