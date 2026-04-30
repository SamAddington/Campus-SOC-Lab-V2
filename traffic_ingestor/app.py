"""FastAPI application for the traffic ingestor + anomaly detector."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from config import Config, hmac_is_keyed, load_config
from features import FlowRecord, WindowStore, normalize_flow
from adapters import (
    SyntheticTrafficGenerator,
    netflow_to_flow,
    suricata_to_flow,
    syslog_to_flow,
    zeek_to_flow,
)
from detectors import (
    Anomaly,
    AnomalyDetector,
    EwmaZScoreDetector,
    IsolationForestDetector,
    RateBurstDetector,
)
from emitter import AnomalyEmitter


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
_LOG = logging.getLogger("traffic_ingestor")


CFG: Config = load_config()
STORE = WindowStore(CFG.window_seconds, CFG.max_windows_retained)

_DETECTORS: List[AnomalyDetector] = []
if CFG.enable_ewma:
    _DETECTORS.append(EwmaZScoreDetector(
        alpha=CFG.ewma_alpha,
        z_threshold=CFG.ewma_z_threshold,
        warmup=CFG.warmup_windows,
        sev_high_z=CFG.severity_high_z,
        sev_medium_z=CFG.severity_medium_z,
    ))
if CFG.enable_rate_burst:
    _DETECTORS.append(RateBurstDetector(
        multiplier=CFG.rate_burst_multiplier,
        warmup=CFG.warmup_windows,
    ))
if CFG.enable_isoforest:
    _DETECTORS.append(IsolationForestDetector(
        refit_every=CFG.isoforest_refit_every,
        contamination=CFG.isoforest_contamination,
        warmup=CFG.warmup_windows,
    ))

EMITTER = AnomalyEmitter(
    collector_url=CFG.collector_url,
    enabled=CFG.emit_to_collector,
    k_anonymity_min=CFG.k_anonymity_min,
)

SYNTHETIC = SyntheticTrafficGenerator(
    secret=CFG.hmac_secret,
    store=STORE,
    ipv4_prefix=CFG.ipv4_bucket_prefix,
    ipv6_prefix=CFG.ipv6_bucket_prefix,
)

_PROCESSED_WINDOWS: set = set()
_DETECTION_LOCK = threading.Lock()
_LOOP_STOP = threading.Event()
_LOOP_THREAD: Optional[threading.Thread] = None


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class FlowIn(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_total: Optional[int] = 0
    packets_total: Optional[int] = 0
    service: Optional[str] = None
    vendor: Optional[str] = "manual"
    ts: Optional[float] = None


class VendorPayload(BaseModel):
    records: List[Dict[str, Any]] = Field(default_factory=list)


class SyslogPayload(BaseModel):
    lines: List[str] = Field(default_factory=list)


class SyntheticStart(BaseModel):
    flows_per_second: int = 20


class SyntheticBurst(BaseModel):
    duration_seconds: int = 60
    subnet: Optional[str] = None
    service: Optional[str] = None


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------


app = FastAPI(title="Traffic Ingestor + Anomaly Detector", version="1.0.0")


@app.on_event("startup")
def _startup() -> None:
    global _LOOP_THREAD
    _LOOP_STOP.clear()
    _LOOP_THREAD = threading.Thread(
        target=_detection_loop, name="detection-loop", daemon=True
    )
    _LOOP_THREAD.start()
    if CFG.synthetic_enabled:
        SYNTHETIC.start()
        _LOG.info("synthetic traffic generator auto-started")


@app.on_event("shutdown")
def _shutdown() -> None:
    _LOOP_STOP.set()
    SYNTHETIC.stop()


# ---- ingestion endpoints --------------------------------------------------


def _record_flow(flow: Optional[FlowRecord]) -> bool:
    if flow is None:
        return False
    STORE.record(flow)
    return True


@app.post("/ingest/flow")
def ingest_flow(payload: FlowIn) -> Dict[str, Any]:
    flow = normalize_flow(
        secret=CFG.hmac_secret,
        src_ip=payload.src_ip,
        dst_ip=payload.dst_ip,
        dst_port=payload.dst_port,
        protocol=payload.protocol,
        bytes_total=payload.bytes_total,
        packets_total=payload.packets_total,
        service=payload.service,
        vendor=payload.vendor or "manual",
        ts=payload.ts,
        ipv4_prefix=CFG.ipv4_bucket_prefix,
        ipv6_prefix=CFG.ipv6_bucket_prefix,
    )
    if not _record_flow(flow):
        raise HTTPException(status_code=400, detail="flow could not be normalized (check src_ip/dst_ip)")
    return {"status": "ok", "window_seconds": CFG.window_seconds}


def _ingest_vendor(records: List[Dict[str, Any]], converter) -> Dict[str, Any]:
    accepted = 0
    dropped = 0
    for rec in records:
        flow = converter(
            rec,
            secret=CFG.hmac_secret,
            ipv4_prefix=CFG.ipv4_bucket_prefix,
            ipv6_prefix=CFG.ipv6_bucket_prefix,
        )
        if _record_flow(flow):
            accepted += 1
        else:
            dropped += 1
    return {"accepted": accepted, "dropped": dropped}


@app.post("/ingest/zeek")
def ingest_zeek(payload: VendorPayload) -> Dict[str, Any]:
    return _ingest_vendor(payload.records, zeek_to_flow)


@app.post("/ingest/suricata")
def ingest_suricata(payload: VendorPayload) -> Dict[str, Any]:
    return _ingest_vendor(payload.records, suricata_to_flow)


@app.post("/ingest/netflow")
def ingest_netflow(payload: VendorPayload) -> Dict[str, Any]:
    return _ingest_vendor(payload.records, netflow_to_flow)


@app.post("/ingest/syslog")
def ingest_syslog(payload: SyslogPayload) -> Dict[str, Any]:
    accepted = 0
    dropped = 0
    for line in payload.lines:
        flow = syslog_to_flow(
            line,
            secret=CFG.hmac_secret,
            ipv4_prefix=CFG.ipv4_bucket_prefix,
            ipv6_prefix=CFG.ipv6_bucket_prefix,
        )
        if _record_flow(flow):
            accepted += 1
        else:
            dropped += 1
    return {"accepted": accepted, "dropped": dropped}


# ---- detection loop -------------------------------------------------------


def _run_detection_once(now: Optional[float] = None) -> Dict[str, Any]:
    with _DETECTION_LOCK:
        closed = STORE.closed_windows(now=now)
        produced: List[Anomaly] = []
        peer_total = 0
        processed_here: List[float] = []
        for bucket in closed:
            if bucket.window_start in _PROCESSED_WINDOWS:
                continue
            peer_total = max(peer_total, len(bucket.groups))
            for det in _DETECTORS:
                try:
                    produced.extend(det.observe(bucket))
                except Exception as exc:
                    _LOG.warning("detector %s failed: %s", det.name, exc)
            _PROCESSED_WINDOWS.add(bucket.window_start)
            processed_here.append(bucket.window_start)

        # Bound the processed-set so it cannot grow without limit.
        if len(_PROCESSED_WINDOWS) > CFG.max_windows_retained * 2:
            cutoff = sorted(_PROCESSED_WINDOWS)[-CFG.max_windows_retained:]
            _PROCESSED_WINDOWS.clear()
            _PROCESSED_WINDOWS.update(cutoff)

        emission = EMITTER.emit(produced, peer_group_count=peer_total)
        return {
            "windows_processed": len(processed_here),
            "anomalies_found": len(produced),
            **emission,
        }


def _detection_loop() -> None:
    interval = max(1, CFG.window_seconds // 2)
    while not _LOOP_STOP.is_set():
        try:
            _run_detection_once()
        except Exception as exc:  # pragma: no cover
            _LOG.warning("detection loop tick failed: %s", exc)
        _LOOP_STOP.wait(interval)


@app.post("/detect")
def run_detection_now() -> Dict[str, Any]:
    return _run_detection_once()


# ---- inspection endpoints ------------------------------------------------


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "traffic_ingestor",
        "window_seconds": CFG.window_seconds,
        "detectors": [d.name for d in _DETECTORS],
        "hmac_keyed": hmac_is_keyed(CFG),
        "emit_to_collector": CFG.emit_to_collector,
        "synthetic_running": SYNTHETIC.running(),
    }


@app.get("/windows")
def windows_snapshot() -> Dict[str, Any]:
    return STORE.snapshot()


@app.get("/detectors")
def detectors_snapshot() -> Dict[str, Any]:
    return {
        "detectors": [d.state_snapshot() for d in _DETECTORS],
        "warmup_windows": CFG.warmup_windows,
    }


@app.get("/anomalies")
def recent_anomalies(limit: int = 50) -> Dict[str, Any]:
    return {
        "recent": EMITTER.recent(limit=limit),
        "emitter": EMITTER.status(),
    }


@app.get("/status")
def status() -> Dict[str, Any]:
    return {
        "config": {
            "window_seconds": CFG.window_seconds,
            "max_windows_retained": CFG.max_windows_retained,
            "ipv4_bucket_prefix": CFG.ipv4_bucket_prefix,
            "ipv6_bucket_prefix": CFG.ipv6_bucket_prefix,
            "k_anonymity_min": CFG.k_anonymity_min,
            "warmup_windows": CFG.warmup_windows,
            "collector_url": CFG.collector_url,
            "emit_to_collector": CFG.emit_to_collector,
            "hmac_keyed": hmac_is_keyed(CFG),
        },
        "detectors": [d.state_snapshot() for d in _DETECTORS],
        "emitter": EMITTER.status(),
        "synthetic": {
            "running": SYNTHETIC.running(),
        },
        "current_window_start": STORE.current_window_start(),
    }


# ---- synthetic traffic endpoints -----------------------------------------


@app.post("/synthetic/start")
def synthetic_start(payload: Optional[SyntheticStart] = None) -> Dict[str, Any]:
    rate = (payload.flows_per_second if payload else 20)
    SYNTHETIC.start(flows_per_second=rate)
    return {"running": SYNTHETIC.running(), "flows_per_second": rate}


@app.post("/synthetic/stop")
def synthetic_stop() -> Dict[str, Any]:
    SYNTHETIC.stop()
    time.sleep(0.1)
    return {"running": SYNTHETIC.running()}


@app.post("/synthetic/burst")
def synthetic_burst(payload: SyntheticBurst) -> Dict[str, Any]:
    info = SYNTHETIC.inject_burst(
        duration_seconds=payload.duration_seconds,
        subnet=payload.subnet,
        service=payload.service,
    )
    return {"burst": info}
