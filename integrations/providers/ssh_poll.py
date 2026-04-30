from __future__ import annotations

import logging
import os
from typing import List, Optional, Tuple

from adapters import NormalizedEvent

from .base import LMSProvider, SyncResult

log = logging.getLogger("ssh_poll")


def _csv(s: str) -> List[str]:
    return [p.strip() for p in (s or "").replace(";", ",").split(",") if p.strip()]


def _parse_targets(raw: str) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    for t in _csv(raw):
        host = t
        port = 22
        if ":" in t:
            host, port_s = t.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                port = 22
        out.append((host.strip(), port))
    return out


class SSHPollProvider(LMSProvider):
    """SSH polling connector (read-only, minimal).

    Runs a small set of operator-supplied commands and emits a summarized event.
    """

    name = "ssh_poll"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.targets = _parse_targets(os.getenv("SSH_TARGETS", ""))
        self.username = os.getenv("SSH_USERNAME", "")
        self.password = os.getenv("SSH_PASSWORD", "")
        self.key_path = os.getenv("SSH_PRIVATE_KEY", "")
        self.commands = _csv(os.getenv("SSH_COMMANDS", "show version"))
        self.allow = set(_csv(os.getenv("DEVICE_ALLOWLIST", "")))

    def sync(self, since: Optional[str] = None, limit: int = 50) -> SyncResult:
        if not self.configured:
            return SyncResult(provider=self.name, events=[], warnings=["SSH_TARGETS not configured"])

        try:
            import paramiko  # type: ignore
        except Exception:
            return SyncResult(provider=self.name, events=[], warnings=["paramiko not installed in integrations image"])

        warnings: List[str] = []
        events: List[NormalizedEvent] = []

        for host, port in self.targets[: max(1, limit)]:
            if self.allow and host not in self.allow:
                warnings.append(f"host {host} not in DEVICE_ALLOWLIST; skipped")
                continue

            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                kwargs = {
                    "hostname": host,
                    "port": port,
                    "username": self.username,
                    "timeout": 10,
                    "banner_timeout": 10,
                    "auth_timeout": 10,
                }
                if self.key_path:
                    kwargs["key_filename"] = self.key_path
                else:
                    kwargs["password"] = self.password
                client.connect(**kwargs)
                outputs: List[str] = []
                for cmd in self.commands[:5]:
                    _, stdout, stderr = client.exec_command(cmd, timeout=15)
                    out = (stdout.read() or b"").decode("utf-8", errors="replace").strip()
                    err = (stderr.read() or b"").decode("utf-8", errors="replace").strip()
                    text = out or err
                    if text:
                        outputs.append(text[:200])
                client.close()

                msg = f"SSH poll host={host} cmds={min(len(self.commands),5)} samples={len(outputs)}"
                if outputs:
                    msg += f" first={outputs[0].replace('\\n',' ')[:120]}"
                events.append(
                    NormalizedEvent(
                        provider_event_id=f"{host}:{port}",
                        message=msg,
                        source="ssh_poll:poll",
                        event_type="device_poll",
                        user_id="",
                        email="",
                        language="en",
                        created_at=None,
                    )
                )
            except Exception as e:
                warnings.append(f"{host} ssh failed: {e.__class__.__name__}")

        return SyncResult(provider=self.name, events=events, next_cursor=None, warnings=warnings)

