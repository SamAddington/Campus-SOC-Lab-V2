from .base import (
    Finding,
    OSINTProvider,
    Verdict,
    aggregate_verdict,
)
from .virustotal import VirusTotalProvider
from .urlhaus import URLhausProvider
from .abuseipdb import AbuseIPDBProvider
from .otx import OTXProvider
from .phishtank import PhishtankProvider
from .openphish import OpenPhishProvider
from .mitre import MITREProvider

__all__ = [
    "Finding",
    "OSINTProvider",
    "Verdict",
    "aggregate_verdict",
    "VirusTotalProvider",
    "URLhausProvider",
    "AbuseIPDBProvider",
    "OTXProvider",
    "PhishtankProvider",
    "OpenPhishProvider",
    "MITREProvider",
]


def build_registry(cfg, http, rate_limits):
    """Factory: return {name -> provider instance} for every enabled provider."""
    registry = {}

    def _maybe(name, cls, **kwargs):
        pc = cfg.providers.get(name)
        if pc is None or not pc.enabled:
            return
        rate_limits.register(name, rate_per_minute=pc.requests_per_minute)
        registry[name] = cls(cfg=cfg, http=http, **kwargs)

    _maybe("virustotal", VirusTotalProvider)
    _maybe("urlhaus", URLhausProvider)
    _maybe("abuseipdb", AbuseIPDBProvider)
    _maybe("otx", OTXProvider)
    _maybe("phishtank", PhishtankProvider)
    _maybe("openphish", OpenPhishProvider)

    # MITRE is local-only so it ignores HTTP; always available.
    registry["mitre"] = MITREProvider()

    return registry
