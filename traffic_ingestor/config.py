"""Configuration for the traffic ingestor + anomaly detector."""

from __future__ import annotations

import os
from dataclasses import dataclass


_DEFAULT_DEV_SECRET = "change-me-dev-only"


@dataclass(frozen=True)
class Config:
    # --- Downstream ---
    collector_url: str
    hmac_secret: str

    # --- Windowing ---
    window_seconds: int
    max_windows_retained: int

    # --- Privacy ---
    ipv4_bucket_prefix: int   # e.g. 24 -> /24 subnet
    ipv6_bucket_prefix: int   # e.g. 64 -> /64 subnet
    k_anonymity_min: int      # minimum peer groups per window before we emit

    # --- Detection ---
    warmup_windows: int
    ewma_alpha: float
    ewma_z_threshold: float
    rate_burst_multiplier: float
    isoforest_refit_every: int
    isoforest_contamination: float
    enable_ewma: bool
    enable_rate_burst: bool
    enable_isoforest: bool

    # --- Emission ---
    emit_to_collector: bool
    severity_high_z: float
    severity_medium_z: float

    # --- Synthetic traffic (workshop mode) ---
    synthetic_enabled: bool


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _get_bool(name: str, default: bool) -> bool:
    raw = (os.getenv(name) or "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


def load_config() -> Config:
    return Config(
        collector_url=os.getenv("COLLECTOR_URL", "http://collector:8001").rstrip("/"),
        hmac_secret=os.getenv("HMAC_SECRET", _DEFAULT_DEV_SECRET),
        window_seconds=_get_int("TRAFFIC_WINDOW_SECONDS", 60),
        max_windows_retained=_get_int("TRAFFIC_MAX_WINDOWS", 240),
        ipv4_bucket_prefix=_get_int("TRAFFIC_IPV4_PREFIX", 24),
        ipv6_bucket_prefix=_get_int("TRAFFIC_IPV6_PREFIX", 64),
        k_anonymity_min=_get_int("TRAFFIC_K_ANON_MIN", 5),
        warmup_windows=_get_int("TRAFFIC_WARMUP_WINDOWS", 15),
        ewma_alpha=_get_float("TRAFFIC_EWMA_ALPHA", 0.2),
        ewma_z_threshold=_get_float("TRAFFIC_EWMA_Z", 3.0),
        rate_burst_multiplier=_get_float("TRAFFIC_RATE_BURST_MULT", 5.0),
        isoforest_refit_every=_get_int("TRAFFIC_ISOFOREST_REFIT_EVERY", 30),
        isoforest_contamination=_get_float("TRAFFIC_ISOFOREST_CONTAMINATION", 0.05),
        enable_ewma=_get_bool("TRAFFIC_ENABLE_EWMA", True),
        enable_rate_burst=_get_bool("TRAFFIC_ENABLE_RATE_BURST", True),
        enable_isoforest=_get_bool("TRAFFIC_ENABLE_ISOFOREST", True),
        emit_to_collector=_get_bool("TRAFFIC_EMIT_TO_COLLECTOR", True),
        severity_high_z=_get_float("TRAFFIC_SEVERITY_HIGH_Z", 5.0),
        severity_medium_z=_get_float("TRAFFIC_SEVERITY_MEDIUM_Z", 3.0),
        synthetic_enabled=_get_bool("TRAFFIC_SYNTHETIC_ENABLED", False),
    )


def hmac_is_keyed(cfg: Config) -> bool:
    return cfg.hmac_secret != _DEFAULT_DEV_SECRET
