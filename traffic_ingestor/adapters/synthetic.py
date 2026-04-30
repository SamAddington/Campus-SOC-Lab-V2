"""Synthetic traffic generator for workshops and CI.

Purpose: produce realistic-enough normalized flows so detectors have
something to chew on when no real feed is attached. The generator is a
daemon thread that records flows into a supplied ``WindowStore`` and can
optionally inject a burst to demo anomaly detection on demand.
"""

from __future__ import annotations

import random
import threading
import time
from typing import List, Optional

from features import WindowStore, normalize_flow


_SERVICES = ["http", "https", "dns", "ssh", "smtp", "quic", "ntp", "unknown"]
_PROTOS = ["tcp", "udp"]
_BASE_SUBNETS = [f"10.{i}.0.0/24" for i in range(20, 35)]


def _rand_ip_in(network: str) -> str:
    base = network.split("/")[0]
    a, b, c, _ = base.split(".")
    return f"{a}.{b}.{c}.{random.randint(1, 254)}"


class SyntheticTrafficGenerator:
    def __init__(self, *, secret: str, store: WindowStore,
                 ipv4_prefix: int, ipv6_prefix: int):
        self._secret = secret
        self._store = store
        self._ipv4_prefix = ipv4_prefix
        self._ipv6_prefix = ipv6_prefix
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._burst_until: float = 0.0
        self._burst_subnet: Optional[str] = None
        self._burst_service: Optional[str] = None

    # ---- lifecycle ----

    def start(self, flows_per_second: int = 20) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._run,
            args=(flows_per_second,),
            name="synthetic-traffic",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()

    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def inject_burst(self, *, duration_seconds: int = 60,
                     subnet: Optional[str] = None,
                     service: Optional[str] = None) -> dict:
        now = time.time()
        self._burst_until = now + max(1, int(duration_seconds))
        self._burst_subnet = subnet or random.choice(_BASE_SUBNETS)
        self._burst_service = service or "http"
        return {
            "subnet": self._burst_subnet,
            "service": self._burst_service,
            "until": self._burst_until,
        }

    # ---- internals ----

    def _run(self, flows_per_second: int) -> None:
        interval = max(0.001, 1.0 / max(1, flows_per_second))
        while not self._stop_evt.is_set():
            self._emit_one()
            time.sleep(interval)

    def _emit_one(self) -> None:
        now = time.time()
        burst_active = now < self._burst_until

        if burst_active and self._burst_subnet and random.random() < 0.85:
            src_net = self._burst_subnet
            service = self._burst_service or "http"
            # A burst looks like one subnet fanning out to many dsts.
            dst_net = random.choice(_BASE_SUBNETS)
            bytes_total = random.randint(400, 5_000)
            packets = random.randint(2, 20)
        else:
            src_net = random.choice(_BASE_SUBNETS)
            dst_net = random.choice(_BASE_SUBNETS)
            service = random.choices(
                _SERVICES,
                weights=[25, 35, 15, 3, 4, 10, 2, 6],
                k=1,
            )[0]
            bytes_total = random.randint(100, 2_500)
            packets = random.randint(1, 10)

        flow = normalize_flow(
            secret=self._secret,
            src_ip=_rand_ip_in(src_net),
            dst_ip=_rand_ip_in(dst_net),
            dst_port=random.choice([53, 80, 443, 22, 25, 123, 8080]),
            protocol=random.choice(_PROTOS),
            bytes_total=bytes_total,
            packets_total=packets,
            service=service,
            vendor="synthetic",
            ts=now,
            ipv4_prefix=self._ipv4_prefix,
            ipv6_prefix=self._ipv6_prefix,
        )
        if flow is not None:
            self._store.record(flow)


def available_subnets() -> List[str]:
    return list(_BASE_SUBNETS)
