"""SIEM egress emitters (best-effort) + optional durable spooling.

This package provides optional emitters that forward *already-anonymized*
records to external SIEM / log platforms.
"""

from .emitters import SIEMEmitters
from .spool import DiskSpool, SpoolConfig, load_spool_config

__all__ = ["SIEMEmitters", "DiskSpool", "SpoolConfig", "load_spool_config"]

