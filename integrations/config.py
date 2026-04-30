"""Configuration for the integrations service.

All tunables come from environment variables. Credentials are never logged
or echoed back in responses; only booleans ("configured / not configured")
are exposed via ``/providers``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass(frozen=True)
class ProviderConfig:
    """Per-provider settings. ``configured`` is True iff the minimum set of
    credentials needed to actually issue requests is present."""

    name: str
    base_url: Optional[str] = None
    configured: bool = False
    # Raw environment values, redacted before being exposed.
    raw: Dict[str, str] = field(default_factory=dict)
    # Scope allowlist loaded from scopes.yaml.
    allowed_paths: List[str] = field(default_factory=list)
    allowed_wsfunctions: List[str] = field(default_factory=list)
    description: str = ""


@dataclass(frozen=True)
class ServiceConfig:
    collector_url: str
    hmac_secret: str
    api_key: str
    state_dir: Path
    scopes_path: Path
    providers: Dict[str, ProviderConfig]


_DEFAULT_DEV_SECRET = "change-me-dev-only"


def _load_scopes(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _canvas_cfg(scopes: Dict[str, Any]) -> ProviderConfig:
    base = (os.getenv("CANVAS_BASE_URL") or "").rstrip("/")
    token = os.getenv("CANVAS_API_TOKEN", "")
    scope = scopes.get("canvas", {})
    return ProviderConfig(
        name="canvas",
        base_url=base or None,
        configured=bool(base and token),
        raw={"CANVAS_API_TOKEN": token},
        allowed_paths=list(scope.get("allowed_paths", [])),
        description=str(scope.get("description", "")).strip(),
    )


def _blackboard_cfg(scopes: Dict[str, Any]) -> ProviderConfig:
    base = (os.getenv("BLACKBOARD_BASE_URL") or "").rstrip("/")
    client_id = os.getenv("BLACKBOARD_APP_KEY", "")
    client_secret = os.getenv("BLACKBOARD_APP_SECRET", "")
    scope = scopes.get("blackboard", {})
    return ProviderConfig(
        name="blackboard",
        base_url=base or None,
        configured=bool(base and client_id and client_secret),
        raw={
            "BLACKBOARD_APP_KEY": client_id,
            "BLACKBOARD_APP_SECRET": client_secret,
        },
        allowed_paths=list(scope.get("allowed_paths", [])),
        description=str(scope.get("description", "")).strip(),
    )


def _moodle_cfg(scopes: Dict[str, Any]) -> ProviderConfig:
    base = (os.getenv("MOODLE_BASE_URL") or "").rstrip("/")
    token = os.getenv("MOODLE_WSTOKEN", "")
    scope = scopes.get("moodle", {})
    return ProviderConfig(
        name="moodle",
        base_url=base or None,
        configured=bool(base and token),
        raw={"MOODLE_WSTOKEN": token},
        allowed_paths=[str(scope.get("base_endpoint", ""))] if scope.get("base_endpoint") else [],
        allowed_wsfunctions=list(scope.get("allowed_wsfunctions", [])),
        description=str(scope.get("description", "")).strip(),
    )


def _brightspace_cfg(scopes: Dict[str, Any]) -> ProviderConfig:
    base = (os.getenv("BRIGHTSPACE_BASE_URL") or "").rstrip("/")
    # Brightspace OAuth2 refresh-token flow
    client_id = os.getenv("BRIGHTSPACE_CLIENT_ID", "")
    client_secret = os.getenv("BRIGHTSPACE_CLIENT_SECRET", "")
    refresh_token = os.getenv("BRIGHTSPACE_REFRESH_TOKEN", "")
    scope = scopes.get("brightspace", {})
    return ProviderConfig(
        name="brightspace",
        base_url=base or None,
        configured=bool(base and client_id and client_secret and refresh_token),
        raw={
            "BRIGHTSPACE_CLIENT_ID": client_id,
            "BRIGHTSPACE_CLIENT_SECRET": client_secret,
            "BRIGHTSPACE_REFRESH_TOKEN": refresh_token,
        },
        allowed_paths=list(scope.get("allowed_paths", [])),
        description=str(scope.get("description", "")).strip(),
    )


def _meraki_cfg(scopes: Dict[str, Any]) -> ProviderConfig:
    base = (os.getenv("MERAKI_BASE_URL") or "https://api.meraki.com").rstrip("/")
    api_key = os.getenv("MERAKI_API_KEY", "")
    org_id = os.getenv("MERAKI_ORG_ID", "")
    scope = scopes.get("meraki", {})
    return ProviderConfig(
        name="meraki",
        base_url=base or None,
        configured=bool(base and api_key),
        raw={"MERAKI_API_KEY": api_key, "MERAKI_ORG_ID": org_id},
        allowed_paths=list(scope.get("allowed_paths", [])),
        description=str(scope.get("description", "")).strip(),
    )


def _duo_cfg(scopes: Dict[str, Any]) -> ProviderConfig:
    base = (os.getenv("DUO_BASE_URL") or "").rstrip("/")
    ikey = os.getenv("DUO_IKEY", "")
    skey = os.getenv("DUO_SKEY", "")
    scope = scopes.get("duo", {})
    return ProviderConfig(
        name="duo",
        base_url=base or None,
        configured=bool(base and ikey and skey),
        raw={"DUO_IKEY": ikey, "DUO_SKEY": skey},
        allowed_paths=list(scope.get("allowed_paths", [])),
        description=str(scope.get("description", "")).strip(),
    )


def _umbrella_cfg(scopes: Dict[str, Any]) -> ProviderConfig:
    base = (os.getenv("UMBRELLA_BASE_URL") or "https://reports.api.umbrella.com").rstrip("/")
    token = os.getenv("UMBRELLA_API_TOKEN", "")
    scope = scopes.get("umbrella", {})
    return ProviderConfig(
        name="umbrella",
        base_url=base or None,
        configured=bool(base and token),
        raw={"UMBRELLA_API_TOKEN": token},
        allowed_paths=list(scope.get("allowed_paths", [])),
        description=str(scope.get("description", "")).strip(),
    )


def _ise_cfg(scopes: Dict[str, Any]) -> ProviderConfig:
    base = (os.getenv("ISE_BASE_URL") or "").rstrip("/")
    user = os.getenv("ISE_USERNAME", "")
    pwd = os.getenv("ISE_PASSWORD", "")
    scope = scopes.get("ise", {})
    return ProviderConfig(
        name="ise",
        base_url=base or None,
        configured=bool(base and user and pwd),
        raw={"ISE_USERNAME": user, "ISE_PASSWORD": pwd},
        allowed_paths=list(scope.get("allowed_paths", [])),
        description=str(scope.get("description", "")).strip(),
    )


def _firepower_cfg(scopes: Dict[str, Any]) -> ProviderConfig:
    base = (os.getenv("FMC_BASE_URL") or "").rstrip("/")
    user = os.getenv("FMC_USERNAME", "")
    pwd = os.getenv("FMC_PASSWORD", "")
    domain = os.getenv("FMC_DOMAIN_UUID", "")
    scope = scopes.get("firepower", {})
    return ProviderConfig(
        name="firepower",
        base_url=base or None,
        configured=bool(base and user and pwd and domain),
        raw={"FMC_USERNAME": user, "FMC_PASSWORD": pwd, "FMC_DOMAIN_UUID": domain},
        allowed_paths=list(scope.get("allowed_paths", [])),
        description=str(scope.get("description", "")).strip(),
    )


def _snmp_cfg(scopes: Dict[str, Any]) -> ProviderConfig:
    # Device polling providers do not use HTTP allowlists; they use explicit
    # target allowlists via env vars and never egress to the public internet.
    targets = os.getenv("SNMP_TARGETS", "").strip()
    scope = scopes.get("snmp", {})
    return ProviderConfig(
        name="snmp",
        base_url=None,
        configured=bool(targets),
        raw={"SNMP_TARGETS": targets},
        allowed_paths=list(scope.get("allowed_paths", [])),
        description=str(scope.get("description", "")).strip(),
    )


def _netconf_cfg(scopes: Dict[str, Any]) -> ProviderConfig:
    targets = os.getenv("NETCONF_TARGETS", "").strip()
    scope = scopes.get("netconf", {})
    return ProviderConfig(
        name="netconf",
        base_url=None,
        configured=bool(targets),
        raw={"NETCONF_TARGETS": targets},
        allowed_paths=list(scope.get("allowed_paths", [])),
        description=str(scope.get("description", "")).strip(),
    )


def _restconf_cfg(scopes: Dict[str, Any]) -> ProviderConfig:
    base = (os.getenv("RESTCONF_BASE_URL") or "").rstrip("/")
    token = os.getenv("RESTCONF_BEARER_TOKEN", "")
    scope = scopes.get("restconf", {})
    return ProviderConfig(
        name="restconf",
        base_url=base or None,
        configured=bool(base and token),
        raw={"RESTCONF_BEARER_TOKEN": token},
        allowed_paths=list(scope.get("allowed_paths", [])),
        description=str(scope.get("description", "")).strip(),
    )


def _ssh_poll_cfg(scopes: Dict[str, Any]) -> ProviderConfig:
    targets = os.getenv("SSH_TARGETS", "").strip()
    scope = scopes.get("ssh_poll", {})
    return ProviderConfig(
        name="ssh_poll",
        base_url=None,
        configured=bool(targets),
        raw={"SSH_TARGETS": targets},
        allowed_paths=list(scope.get("allowed_paths", [])),
        description=str(scope.get("description", "")).strip(),
    )


def load_config() -> ServiceConfig:
    scopes_path = Path(os.getenv("SCOPES_PATH", "/app/scopes.yaml"))
    scopes = _load_scopes(scopes_path)

    collector_url = os.getenv("COLLECTOR_URL", "http://collector:8001").rstrip("/")
    hmac_secret = os.getenv("HMAC_SECRET", _DEFAULT_DEV_SECRET)
    api_key = os.getenv("SOC_API_KEY", "change-me-dev-api-key")

    state_dir = Path(os.getenv("INTEGRATION_STATE_DIR", "/app/integration_state"))
    state_dir.mkdir(parents=True, exist_ok=True)

    providers: Dict[str, ProviderConfig] = {
        "canvas": _canvas_cfg(scopes),
        "blackboard": _blackboard_cfg(scopes),
        "moodle": _moodle_cfg(scopes),
        "brightspace": _brightspace_cfg(scopes),
        # --- Cisco & device telemetry connectors (opt-in) ---
        "meraki": _meraki_cfg(scopes),
        "duo": _duo_cfg(scopes),
        "umbrella": _umbrella_cfg(scopes),
        "ise": _ise_cfg(scopes),
        "firepower": _firepower_cfg(scopes),
        "snmp": _snmp_cfg(scopes),
        "netconf": _netconf_cfg(scopes),
        "restconf": _restconf_cfg(scopes),
        "ssh_poll": _ssh_poll_cfg(scopes),
    }

    return ServiceConfig(
        collector_url=collector_url,
        hmac_secret=hmac_secret,
        api_key=api_key,
        state_dir=state_dir,
        scopes_path=scopes_path,
        providers=providers,
    )


def redact_provider(p: ProviderConfig) -> Dict[str, Any]:
    """Safe, publishable description. Never leaks secrets."""
    return {
        "name": p.name,
        "configured": p.configured,
        "base_url": p.base_url,
        "allowed_paths": p.allowed_paths,
        "allowed_wsfunctions": p.allowed_wsfunctions,
        "description": p.description,
        # Only booleans per secret, never the value.
        "credentials_present": {k: bool(v) for k, v in p.raw.items()},
    }


def hmac_is_keyed(cfg: ServiceConfig) -> bool:
    return cfg.hmac_secret != _DEFAULT_DEV_SECRET
