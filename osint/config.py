"""Configuration for the OSINT enrichment service."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml


_DEFAULT_DEV_SECRET = "change-me-dev-only"


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    enabled: bool
    base_url: str
    api_key: Optional[str]
    requests_per_minute: int
    allow: List[Dict[str, str]] = field(default_factory=list)
    extra: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Config:
    hmac_secret: str

    # Cache
    cache_ttl_clean_seconds: int
    cache_ttl_hit_seconds: int
    cache_max_entries: int

    # Indicator limits
    max_urls_per_event: int
    max_domains_per_event: int
    max_ips_per_event: int
    max_hashes_per_event: int

    # Per-call timeouts
    per_provider_timeout: int
    per_enrichment_deadline: int

    providers: Dict[str, ProviderConfig]

    # Governance
    reject_private_ips: bool
    scopes_path: str


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = (os.getenv(name) or "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


def _load_scopes(path: str) -> Dict[str, Dict]:
    p = Path(path)
    if not p.exists():
        return {}
    with open(p, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("providers") or {}


def load_config() -> Config:
    scopes_path = os.getenv("OSINT_SCOPES_PATH", "/app/scopes.yaml")
    scopes = _load_scopes(scopes_path)

    providers: Dict[str, ProviderConfig] = {}

    def _add(name: str, *, api_key_env: Optional[str], rpm_env: str,
             rpm_default: int, extra: Optional[Dict[str, str]] = None,
             enabled_default: bool = False) -> None:
        key = os.getenv(api_key_env) if api_key_env else None
        enabled = _env_bool(f"OSINT_{name.upper()}_ENABLED",
                            enabled_default and (api_key_env is None or bool(key)))
        # Providers without a required API key auto-enable if the scopes
        # file allows them; providers that need a key stay disabled until
        # the key is present, regardless of the env flag.
        if api_key_env and not key:
            enabled = False

        scope_entry = scopes.get(name, {})
        providers[name] = ProviderConfig(
            name=name,
            enabled=enabled,
            base_url=scope_entry.get("base_url", ""),
            api_key=key,
            requests_per_minute=_env_int(rpm_env, rpm_default),
            allow=list(scope_entry.get("allow", [])),
            extra=dict(extra or {}),
        )

    _add("virustotal", api_key_env="VT_API_KEY",
         rpm_env="OSINT_VT_RPM", rpm_default=4)
    _add("urlhaus", api_key_env=None,
         rpm_env="OSINT_URLHAUS_RPM", rpm_default=60, enabled_default=True)
    _add("abuseipdb", api_key_env="ABUSEIPDB_API_KEY",
         rpm_env="OSINT_ABUSEIPDB_RPM", rpm_default=30)
    _add("otx", api_key_env="OTX_API_KEY",
         rpm_env="OSINT_OTX_RPM", rpm_default=60)
    _add("phishtank", api_key_env="PHISHTANK_API_KEY",
         rpm_env="OSINT_PHISHTANK_RPM", rpm_default=30,
         extra={"app_key": os.getenv("PHISHTANK_APP_KEY", "")},
         enabled_default=True)
    _add("openphish", api_key_env=None,
         rpm_env="OSINT_OPENPHISH_RPM", rpm_default=1, enabled_default=True)

    return Config(
        hmac_secret=os.getenv("HMAC_SECRET", _DEFAULT_DEV_SECRET),
        cache_ttl_clean_seconds=_env_int("OSINT_CACHE_TTL_CLEAN", 24 * 3600),
        cache_ttl_hit_seconds=_env_int("OSINT_CACHE_TTL_HIT", 3600),
        cache_max_entries=_env_int("OSINT_CACHE_MAX_ENTRIES", 5000),
        max_urls_per_event=_env_int("OSINT_MAX_URLS", 5),
        max_domains_per_event=_env_int("OSINT_MAX_DOMAINS", 5),
        max_ips_per_event=_env_int("OSINT_MAX_IPS", 5),
        max_hashes_per_event=_env_int("OSINT_MAX_HASHES", 5),
        per_provider_timeout=_env_int("OSINT_PER_PROVIDER_TIMEOUT", 6),
        per_enrichment_deadline=_env_int("OSINT_PER_ENRICHMENT_DEADLINE", 25),
        providers=providers,
        reject_private_ips=_env_bool("OSINT_REJECT_PRIVATE_IPS", True),
        scopes_path=scopes_path,
    )


def hmac_is_keyed(cfg: Config) -> bool:
    return cfg.hmac_secret != _DEFAULT_DEV_SECRET
