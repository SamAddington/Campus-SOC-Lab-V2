# Realtime traffic + anomaly detection

The `traffic_ingestor` service is the Phase 3 addition that brings
network telemetry into the SOC stack. Its job is bounded and
deliberate: **normalize flow-level records, summarize them into rolling
windows, score those windows with cheap online detectors, and hand
anomalies back to the same `/ingest` endpoint every other signal flows
through**.

It never takes action on its own; like the LMS integrations it is a
*proposer*, not an *enforcer*.

## Design principles

1. **No payload, no raw IPs.** Every adapter normalizes into a
   `FlowRecord` whose only identifiers are HMAC-hashed subnet buckets
   (`/24` for IPv4, `/64` for IPv6 by default). The raw IP fields are
   cleared immediately after normalization.
2. **Aggregate-only scoring.** Detectors see summary stats per
   `(src_subnet_hash, service, protocol)` window -- flow count, unique
   destinations, unique ports, byte and packet totals. No per-flow
   records are retained.
3. **k-anonymity gate.** The emitter refuses to forward anomalies
   unless the triggering window had at least `TRAFFIC_K_ANON_MIN`
   distinct peer groups. This prevents the detector from fingerprinting
   one small subnet during quiet periods.
4. **Warmup is mandatory.** All detectors accumulate baselines for
   `TRAFFIC_WARMUP_WINDOWS` windows before they can fire. This is both
   a correctness and a fairness commitment: a group that has just
   appeared cannot immediately be flagged.
5. **Humans adjudicate.** `policy_engine/rules.yaml` routes every
   traffic anomaly to `queue_for_review` or `escalate`; no anomaly can
   result in automated enforcement.

## Inputs

| Adapter | Endpoint | Input shape |
|---|---|---|
| Zeek `conn.log` JSON | `POST /ingest/zeek` | `{ "records": [ {...}, ... ] }` |
| Suricata EVE JSON | `POST /ingest/suricata` | `{ "records": [ {...}, ... ] }` |
| NetFlow / IPFIX via `goflow2` | `POST /ingest/netflow` | `{ "records": [ {...}, ... ] }` |
| Firewall syslog | `POST /ingest/syslog` | `{ "lines": [ "...", "..." ] }` |
| Manual / test | `POST /ingest/flow` | single `FlowIn` object |

Typical wiring: run `goflow2`, Zeek, or Filebeat as the shipper and
point its HTTP output at the corresponding endpoint. Batches of a few
hundred records per call keep network overhead low.

## Detectors

| Detector | What it measures | Why |
|---|---|---|
| `ewma_zscore` | Per-series EWMA mean/var, z-score against the current window | Cheap, bounded memory, adapts to regime changes |
| `rate_burst` | Flow count vs running median over the last N windows | Easy to explain to humans |
| `isoforest` | Multi-feature IsolationForest, refitted every N windows | Catches joint-feature anomalies the other two miss |

All three can be toggled independently via `TRAFFIC_ENABLE_*` flags.
During workshops you will commonly disable `isoforest` because it needs
enough windows in the buffer to produce a model.

## Output

Each anomaly is posted to the collector as a synthetic event:

```json
{
  "user_id":  "subnet:<16-hex-hmac>",
  "email":    "<16-hex-hmac>@network.invalid",
  "source":   "traffic_anomaly",
  "event_type": "traffic_anomaly_high | traffic_anomaly_medium | traffic_anomaly_low",
  "message":  "<human-readable detector description>",
  "language": "en",
  "consent_use_for_distillation": false
}
```

The collector anonymizes and feature-extracts it like any other event,
the orchestrator calls policy and LLM assist, and the decision lands in
the audit ledger with `llm_tier`, `llm_provider`, `llm_model` metadata
intact.

Policy rules added in Phase 3:

* `TRAFFIC-ANOMALY-HIGH-001` &rarr; `escalate`, human review required
* `TRAFFIC-ANOMALY-MED-001` &rarr; `queue_for_review`, human review required
* `TRAFFIC-ANOMALY-LOW-001` &rarr; `allow`, logged only

Traffic anomalies never opt in to distillation (`consent_use_for_distillation: false`).

## Operational endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness + HMAC-keyed check + detector list |
| `GET /status` | Full config + detector + emitter state |
| `GET /windows` | Snapshot of retained rolling windows (for debugging) |
| `GET /detectors` | Per-detector state (tracked series, model fits, thresholds) |
| `GET /anomalies?limit=50` | Recent emitted anomalies with forward status |
| `POST /detect` | Run the detection loop once on-demand (useful in tests) |
| `POST /synthetic/start` / `/stop` | Toggle the workshop traffic generator |
| `POST /synthetic/burst` | Inject a scripted fan-out burst for demo runs |

## Workshop mode

For a classroom run without a real capture feed:

```bash
# in the host shell, with the stack up
curl -X POST localhost:8027/synthetic/start -d '{"flows_per_second": 40}'
# wait about TRAFFIC_WARMUP_WINDOWS * TRAFFIC_WINDOW_SECONDS seconds
curl -X POST localhost:8027/synthetic/burst -d '{"duration_seconds": 120, "service": "https"}'
# watch the audit ledger or /anomalies for detections
```

Setting `TRAFFIC_SYNTHETIC_ENABLED=1` auto-starts the generator on boot.

## Tuning cheat-sheet

| You observe | Lever to turn |
|---|---|
| Too many false positives | raise `TRAFFIC_EWMA_Z`, raise `TRAFFIC_RATE_BURST_MULT`, shrink `TRAFFIC_ISOFOREST_CONTAMINATION` |
| No anomalies ever | lower the above, shorten `TRAFFIC_WARMUP_WINDOWS` |
| Anomalies on tiny subnets | raise `TRAFFIC_K_ANON_MIN` |
| Detector "remembers" too long | raise `TRAFFIC_EWMA_ALPHA` (more weight on recent) |
| Memory growing | lower `TRAFFIC_MAX_WINDOWS`, lower IsolationForest buffer |

## Privacy posture summary

| Concern | How we address it |
|---|---|
| Raw IP leakage | Bucketed to `/24` or `/64` and HMAC-hashed before any storage |
| Re-identification | k-anonymity gate (`TRAFFIC_K_ANON_MIN`) plus keyed HMAC |
| Content inspection | Never performed -- only flow headers and aggregate counts |
| Long-term retention | Bounded by `TRAFFIC_MAX_WINDOWS`; no per-flow record is kept |
| Cross-service leakage | Anomalies emitted via the same `/ingest` path with the same anonymization contract |
| Distillation re-use | Traffic anomalies always emit `consent_use_for_distillation=false` |

## When not to trust a detection

* Within the warmup period (`GET /detectors` shows `tracked_series` low).
* When `GET /status` shows `peer_group_count` below `k_anonymity_min`.
* When the `isoforest` detector has not yet been fit
  (`model_fitted: false`).

In all of these cases the emitter suppresses anomalies, but the
reviewer should still confirm by inspecting `/windows` before acting.
