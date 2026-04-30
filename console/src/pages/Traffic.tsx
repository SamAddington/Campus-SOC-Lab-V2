import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  PlayCircle,
  RefreshCw,
  Siren,
  StopCircle,
  Zap,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, EmptyState, KeyValueGrid } from "@/components/ui/Card";
import { Chip, SeverityBadge } from "@/components/ui/Badge";
import { JsonView } from "@/components/ui/JsonView";
import {
  api,
  type TrafficAnomaly,
  type TrafficStatus,
  type TrafficWindowsSnapshot,
} from "@/lib/api";
import type { Severity } from "@/lib/format";
import { relativeTime } from "@/lib/format";

export function Traffic() {
  const [status, setStatus] = useState<TrafficStatus | null>(null);
  const [anomalies, setAnomalies] = useState<TrafficAnomaly[]>([]);
  const [windows, setWindows] = useState<TrafficWindowsSnapshot | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // synthetic controls
  const [fps, setFps] = useState(20);
  const [burstSeconds, setBurstSeconds] = useState(60);
  const [burstSubnet, setBurstSubnet] = useState("");
  const [burstService, setBurstService] = useState("");
  const [actionErr, setActionErr] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const [s, a, w] = await Promise.all([
        api.trafficStatus(),
        api.trafficAnomalies(100),
        api.trafficWindows().catch(() => null),
      ]);
      setStatus(s);
      setAnomalies(a.recent ?? []);
      setWindows(w);
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const id = window.setInterval(load, 5000);
    return () => window.clearInterval(id);
  }, []);

  const running = !!status?.synthetic?.running;

  const runAction = async (fn: () => Promise<unknown>, label: string) => {
    setActionErr(null);
    setActionMsg(null);
    try {
      const r = await fn();
      setActionMsg(`${label} ok`);
      // Refresh state immediately after an action.
      load();
      return r;
    } catch (e) {
      setActionErr((e as Error).message);
    }
  };

  const chartData = useMemo(() => buildWindowSeries(windows), [windows]);

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text">Traffic Ingestor</h1>
          <p className="mt-1 text-sm text-subtle">
            Privacy-preserving flow windows with EWMA z-score, rate-burst, and
            isolation-forest anomaly detectors.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={
              "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs " +
              (running
                ? "border-sev-low/40 bg-sev-low/10 text-sev-low"
                : "border-border bg-muted text-dim")
            }
          >
            <span
              className={
                "inline-block h-1.5 w-1.5 rounded-full " +
                (running ? "bg-sev-low animate-pulseDot" : "bg-dim")
              }
            />
            synthetic {running ? "running" : "stopped"}
          </span>
          <button onClick={load} className="btn" disabled={loading}>
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>
      </header>

      {err && (
        <div className="rounded-md border border-sev-critical/40 bg-sev-critical/10 p-3 text-sm text-sev-critical">
          {err}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Configuration" className="xl:col-span-1">
          {status ? (
            <KeyValueGrid
              rows={[
                { k: "Window", v: <span className="mono">{status.config.window_seconds}s</span> },
                { k: "Retention", v: <span className="mono">{status.config.max_windows_retained}</span> },
                { k: "k-anonymity min", v: <span className="mono">{status.config.k_anonymity_min}</span> },
                { k: "Warmup", v: <span className="mono">{status.config.warmup_windows}</span> },
                { k: "IPv4 prefix", v: <span className="mono">/{status.config.ipv4_bucket_prefix}</span> },
                { k: "IPv6 prefix", v: <span className="mono">/{status.config.ipv6_bucket_prefix}</span> },
                {
                  k: "Emit to collector",
                  v: (
                    <SeverityBadge severity={status.config.emit_to_collector ? "low" : "info"}>
                      {status.config.emit_to_collector ? "enabled" : "disabled"}
                    </SeverityBadge>
                  ),
                },
                {
                  k: "HMAC keyed",
                  v: (
                    <SeverityBadge severity={status.config.hmac_keyed ? "low" : "medium"}>
                      {status.config.hmac_keyed ? "yes" : "no"}
                    </SeverityBadge>
                  ),
                },
                {
                  k: "Current window",
                  v: (
                    <span className="mono">
                      {status.current_window_start
                        ? new Date(status.current_window_start * 1000).toISOString().replace("T", " ").replace(/\..+/, " UTC")
                        : "—"}
                    </span>
                  ),
                },
              ]}
            />
          ) : (
            <div className="text-xs text-dim">Loading…</div>
          )}
        </Card>

        <Card title="Detectors" className="xl:col-span-2">
          {status && status.detectors.length ? (
            <ul className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              {status.detectors.map((d, i) => {
                const name = (d as any).name as string;
                const samples = (d as any).samples ?? (d as any).observations ?? null;
                const warmedUp = (d as any).warmed_up ?? (d as any).ready ?? null;
                return (
                  <li
                    key={`${name}-${i}`}
                    className="rounded-lg border border-border bg-muted p-3"
                  >
                    <div className="flex items-center justify-between">
                      <div className="mono text-sm text-text">{name}</div>
                      <SeverityBadge severity={warmedUp ? "low" : "medium"}>
                        {warmedUp ? "ready" : "warming"}
                      </SeverityBadge>
                    </div>
                    {samples !== null && (
                      <div className="mt-1 text-[11px] text-dim">
                        samples · <span className="mono">{String(samples)}</span>
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          ) : (
            <EmptyState
              title="No detectors enabled"
              description="Set TRAFFIC_ENABLE_* env vars in docker-compose to enable EWMA / rate-burst / isolation-forest."
            />
          )}
        </Card>

        <Card
          title="Synthetic traffic"
          subtitle="Generate anonymised flows to prime detectors in workshop mode."
          className="xl:col-span-3"
        >
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="rounded-lg border border-border bg-muted p-3">
              <div className="label mb-2">Continuous stream</div>
              <div className="flex flex-wrap items-end gap-2">
                <div>
                  <label className="label">flows/sec</label>
                  <input
                    type="number"
                    min={1}
                    className="input mt-1 w-28"
                    value={fps}
                    onChange={(e) => setFps(Number(e.target.value || 0))}
                  />
                </div>
                <button
                  className="btn btn-primary"
                  disabled={running}
                  onClick={() => runAction(() => api.syntheticStart({ flows_per_second: fps }), "start")}
                >
                  <PlayCircle size={14} />
                  Start
                </button>
                <button
                  className="btn"
                  disabled={!running}
                  onClick={() => runAction(() => api.syntheticStop(), "stop")}
                >
                  <StopCircle size={14} />
                  Stop
                </button>
              </div>
            </div>

            <div className="rounded-lg border border-border bg-muted p-3">
              <div className="label mb-2">One-shot burst</div>
              <div className="flex flex-wrap items-end gap-2">
                <div>
                  <label className="label">duration (s)</label>
                  <input
                    type="number"
                    min={1}
                    className="input mt-1 w-28"
                    value={burstSeconds}
                    onChange={(e) => setBurstSeconds(Number(e.target.value || 0))}
                  />
                </div>
                <div className="flex-1">
                  <label className="label">subnet (opt)</label>
                  <input
                    className="input mt-1"
                    placeholder="e.g. 10.1.2.0/24"
                    value={burstSubnet}
                    onChange={(e) => setBurstSubnet(e.target.value)}
                  />
                </div>
                <div className="flex-1">
                  <label className="label">service (opt)</label>
                  <input
                    className="input mt-1"
                    placeholder="e.g. ssh"
                    value={burstService}
                    onChange={(e) => setBurstService(e.target.value)}
                  />
                </div>
                <button
                  className="btn btn-primary"
                  onClick={() =>
                    runAction(
                      () =>
                        api.syntheticBurst({
                          duration_seconds: burstSeconds,
                          subnet: burstSubnet || undefined,
                          service: burstService || undefined,
                        }),
                      "burst",
                    )
                  }
                >
                  <Zap size={14} />
                  Inject burst
                </button>
              </div>
            </div>
          </div>

          <div className="mt-3 flex gap-3 text-xs">
            <button
              className="btn"
              onClick={() => runAction(() => api.trafficDetect(), "detect")}
            >
              <Siren size={14} />
              Run detection now
            </button>
            {actionMsg && <span className="self-center text-sev-low">{actionMsg}</span>}
            {actionErr && <span className="self-center text-sev-critical">{actionErr}</span>}
          </div>
        </Card>

        <Card
          title="Traffic volume"
          subtitle="Total bytes / flows per closed window (privacy-preserving aggregates)."
          className="xl:col-span-3"
        >
          <div className="h-[220px] w-full">
            {chartData.length === 0 ? (
              <EmptyState
                title="No windows observed"
                description="Ingest flows or enable the synthetic generator."
                icon={<Activity size={22} />}
              />
            ) : (
              <ResponsiveContainer>
                <AreaChart data={chartData} margin={{ top: 4, right: 12, left: -10, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gFlows" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.55} />
                      <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gGroups" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#60a5fa" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="#60a5fa" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#1f2a37" strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="label"
                    stroke="#64748b"
                    tick={{ fill: "#94a3b8", fontSize: 11 }}
                    tickLine={false}
                    axisLine={{ stroke: "#1f2a37" }}
                  />
                  <YAxis
                    stroke="#64748b"
                    tick={{ fill: "#94a3b8", fontSize: 11 }}
                    tickLine={false}
                    axisLine={{ stroke: "#1f2a37" }}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#0f141b",
                      border: "1px solid #1f2a37",
                      borderRadius: 8,
                      fontSize: 12,
                      color: "#e5e7eb",
                    }}
                    labelStyle={{ color: "#94a3b8" }}
                  />
                  <Area
                    type="monotone"
                    dataKey="flows"
                    name="flows"
                    stroke="#22d3ee"
                    fill="url(#gFlows)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="groups"
                    name="groups"
                    stroke="#60a5fa"
                    fill="url(#gGroups)"
                    strokeWidth={1.5}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        <Card
          title="Recent anomalies"
          subtitle="Per-window findings from the enabled detectors."
          className="xl:col-span-3"
        >
          {anomalies.length === 0 ? (
            <EmptyState
              title="No anomalies detected yet"
              description="Detectors need a warmup period. Start the synthetic generator or ingest flows."
              icon={<Siren size={22} />}
            />
          ) : (
            <div className="overflow-hidden rounded-lg border border-border">
              <table className="w-full border-collapse text-sm">
                <thead className="bg-muted/60 text-left text-[11px] uppercase tracking-wider text-dim">
                  <tr>
                    <th className="px-3 py-2">Severity</th>
                    <th className="px-3 py-2">Detector</th>
                    <th className="px-3 py-2">Window</th>
                    <th className="px-3 py-2">Group</th>
                    <th className="px-3 py-2">Score</th>
                    <th className="px-3 py-2">Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {anomalies.slice(0, 50).map((a, i) => {
                    const sev = mapSeverity(a.severity);
                    return (
                      <tr key={i} className="border-t border-border/80">
                        <td className="px-3 py-2">
                          <SeverityBadge severity={sev}>{String(a.severity)}</SeverityBadge>
                        </td>
                        <td className="px-3 py-2 mono">{a.detector}</td>
                        <td className="px-3 py-2 text-subtle">
                          {a.window_start
                            ? relativeTime(new Date(a.window_start * 1000).toISOString())
                            : "—"}
                        </td>
                        <td className="px-3 py-2">
                          {a.group_key ? <Chip>{a.group_key}</Chip> : <span className="text-dim">—</span>}
                        </td>
                        <td className="px-3 py-2 mono">
                          {typeof a.z === "number"
                            ? `z=${a.z.toFixed(2)}`
                            : typeof a.score === "number"
                            ? a.score.toFixed(2)
                            : "—"}
                        </td>
                        <td className="px-3 py-2 text-subtle">
                          {a.reason ?? ""}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {status && (
          <Card title="Status (raw)" className="xl:col-span-3">
            <JsonView value={status} />
          </Card>
        )}
      </div>
    </div>
  );
}

function mapSeverity(s: string | undefined): Severity {
  switch ((s || "").toLowerCase()) {
    case "high":
    case "critical":
      return "critical";
    case "medium":
      return "high";
    case "low":
      return "medium";
    default:
      return "info";
  }
}

function buildWindowSeries(w: TrafficWindowsSnapshot | null) {
  if (!w || !Array.isArray(w.windows) || w.windows.length === 0) return [];
  const sorted = [...w.windows].sort((a, b) => a.window_start - b.window_start);
  return sorted.map((b) => {
    const totals = b.totals || {};
    const flows = Number(totals.flows ?? totals.flows_total ?? totals.packets_total ?? 0);
    const d = new Date(b.window_start * 1000);
    const pad = (n: number) => String(n).padStart(2, "0");
    return {
      label: `${pad(d.getHours())}:${pad(d.getMinutes())}`,
      flows,
      groups: b.group_count ?? 0,
    };
  });
}
