import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  Bell,
  BrainCircuit,
  Globe2,
  Radio,
  ShieldCheck,
  TrendingUp,
} from "lucide-react";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, EmptyState } from "@/components/ui/Card";
import { SeverityBadge } from "@/components/ui/Badge";
import { api, type AuditSummary, type CollectorSiemSpoolStatus, type DecisionCard } from "@/lib/api";
import { subscribe } from "@/lib/sse";
import {
  actionSeverity,
  formatScore,
  relativeTime,
  sevTextClass,
  severityFromScore,
  truncateMiddle,
} from "@/lib/format";

// Prefer a bundled map asset so the dashboard works offline / behind strict egress controls.
// (External CDNs are often blocked in SOC environments.)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
import world110m from "world-atlas/countries-110m.json";

const TIME_RANGES = [
  { id: "15m", label: "15m", spanMs: 15 * 60 * 1000, bucketMs: 60 * 1000 },
  { id: "1h", label: "1h", spanMs: 60 * 60 * 1000, bucketMs: 5 * 60 * 1000 },
  { id: "24h", label: "24h", spanMs: 24 * 60 * 60 * 1000, bucketMs: 60 * 60 * 1000 },
  { id: "7d", label: "7d", spanMs: 7 * 24 * 60 * 60 * 1000, bucketMs: 6 * 60 * 60 * 1000 },
  { id: "custom", label: "custom", spanMs: 0, bucketMs: 60 * 60 * 1000 },
] as const;

type TimeRangeId = (typeof TIME_RANGES)[number]["id"];

export function Dashboard() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [summary, setSummary] = useState<AuditSummary | null>(null);
  const [cards, setCards] = useState<DecisionCard[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [live, setLive] = useState(false);
  const [rangeId, setRangeId] = useState<TimeRangeId>("1h");
  const [customMinutes, setCustomMinutes] = useState<number>(180);
  const [q, setQ] = useState("");
  const [fSource, setFSource] = useState("");
  const [fEventType, setFEventType] = useState("");
  const [fAction, setFAction] = useState("");
  const [fSeverity, setFSeverity] = useState("");
  const [fScenario, setFScenario] = useState("");
  const [fPolicyRule, setFPolicyRule] = useState("");
  const [fLanguage, setFLanguage] = useState("");
  const [spool, setSpool] = useState<CollectorSiemSpoolStatus | null>(null);
  const [svc, setSvc] = useState<Record<string, "up" | "down" | "unknown">>({
    audit: "unknown",
    collector: "unknown",
    orchestrator: "unknown",
    detector: "unknown",
  });
  const [hover, setHover] = useState<{
    point: ThreatMapPoint;
    x: number;
    y: number;
  } | null>(null);
  const cardsRef = useRef<DecisionCard[]>([]);

  // URL -> state (shareable dashboard)
  useEffect(() => {
    const r = (searchParams.get("range") ?? "1h") as TimeRangeId;
    setRangeId(TIME_RANGES.some((x) => x.id === r) ? r : "1h");
    const cm = Number(searchParams.get("custom_min") ?? "180");
    setCustomMinutes(Number.isFinite(cm) && cm > 0 ? cm : 180);
    setQ(searchParams.get("q") ?? "");
    setFSource(searchParams.get("source") ?? "");
    setFEventType(searchParams.get("event_type") ?? "");
    setFAction(searchParams.get("action") ?? "");
    setFSeverity(searchParams.get("severity") ?? "");
    setFScenario(searchParams.get("scenario") ?? "");
    setFPolicyRule(searchParams.get("policy_rule") ?? "");
    setFLanguage(searchParams.get("language") ?? "");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // state -> URL
  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    const setOrDel = (k: string, v: string) => {
      const val = v.trim();
      if (val) next.set(k, val);
      else next.delete(k);
    };
    next.set("range", rangeId);
    if (rangeId === "custom") next.set("custom_min", String(customMinutes));
    else next.delete("custom_min");
    setOrDel("q", q);
    setOrDel("source", fSource);
    setOrDel("event_type", fEventType);
    setOrDel("action", fAction);
    setOrDel("severity", fSeverity);
    setOrDel("scenario", fScenario);
    setOrDel("policy_rule", fPolicyRule);
    setOrDel("language", fLanguage);
    setSearchParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rangeId, customMinutes, q, fSource, fEventType, fAction, fSeverity, fScenario, fPolicyRule, fLanguage]);

  // initial load + slow polling fallback
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [s, c] = await Promise.all([api.summary(), api.decisionCards(1000)]);
        if (cancelled) return;
        setSummary(s);
        const sorted = (c.items ?? []).slice().reverse();
        setCards(sorted);
        cardsRef.current = sorted;
        setErr(null);
      } catch (e) {
        if (!cancelled) setErr((e as Error).message);
      }
    };
    load();
    const id = globalThis.setInterval(load, 30_000);
    return () => {
      cancelled = true;
      globalThis.clearInterval(id);
    };
  }, []);

  // live SSE
  useEffect(() => {
    const unsub = subscribe<DecisionCard>(
      api.auditStreamUrl(),
      ["decision", "hello"],
      {
        onOpen: () => setLive(true),
        onError: () => setLive(false),
        onEvent: (evt, data) => {
          if (evt === "hello") return;
          if (evt === "decision" && data?.decision_card_id) {
            const next = [data, ...cardsRef.current].slice(0, 1000);
            cardsRef.current = next;
            setCards(next);
            setSummary((s) => {
              if (!s) return s;
              const k = data.permitted_action ?? "unknown";
              return {
                ...s,
                total_decisions: s.total_decisions + 1,
                action_counts: {
                  ...s.action_counts,
                  [k]: (s.action_counts[k] ?? 0) + 1,
                },
              };
            });
          }
        },
      },
    );
    return unsub;
  }, []);

  // SIEM spool + service health (for trust signals)
  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const [sp, a, c, o, d] = await Promise.all([
          api.collectorSiemSpoolStatus(),
          api.health("audit").then(() => "up").catch(() => "down"),
          api.health("collector").then(() => "up").catch(() => "down"),
          api.health("orchestrator").then(() => "up").catch(() => "down"),
          api.health("detector").then(() => "up").catch(() => "down"),
        ]);
        if (cancelled) return;
        setSpool(sp);
        setSvc({ audit: a, collector: c, orchestrator: o, detector: d } as any);
      } catch {
        /* ignore */
      }
    };
    poll();
    const id = globalThis.setInterval(poll, 15_000);
    return () => {
      cancelled = true;
      globalThis.clearInterval(id);
    };
  }, []);

  const { spanMs, bucketMs } = useMemo(() => {
    const spec = TIME_RANGES.find((x) => x.id === rangeId)!;
    if (rangeId === "custom") {
      const span = Math.max(5 * 60 * 1000, customMinutes * 60 * 1000);
      const bucket =
        span <= 60 * 60 * 1000
          ? 5 * 60 * 1000
          : span <= 24 * 60 * 60 * 1000
          ? 60 * 60 * 1000
          : 6 * 60 * 60 * 1000;
      return { spanMs: span, bucketMs: bucket };
    }
    return { spanMs: spec.spanMs, bucketMs: spec.bucketMs };
  }, [rangeId, customMinutes]);

  const now = Date.now();
  const cutoff = now - spanMs;

  const filteredCards = useMemo(() => {
    const query = q.trim().toLowerCase();
    return cards.filter((c) => {
      const t = Date.parse(c.timestamp);
      if (!Number.isNaN(t) && t < cutoff) return false;
      if (fSource.trim() && c.source !== fSource.trim()) return false;
      if (fEventType.trim() && c.event_type !== fEventType.trim()) return false;
      if (fAction.trim() && c.permitted_action !== fAction.trim()) return false;
      if (fScenario.trim() && (c.scenario_id ?? "") !== fScenario.trim()) return false;
      if (fPolicyRule.trim() && c.policy_rule_id !== fPolicyRule.trim()) return false;
      if (fLanguage.trim() && (c.language ?? "") !== fLanguage.trim()) return false;
      if (fSeverity.trim() && actionSeverity(c.permitted_action) !== fSeverity.trim()) return false;
      if (!query) return true;
      return [
        c.event_id,
        c.decision_card_id,
        c.source,
        c.event_type,
        c.label,
        c.policy_rule_id,
        c.scenario_id ?? "",
        c.language ?? "",
      ]
        .join(" ")
        .toLowerCase()
        .includes(query);
    });
  }, [cards, q, cutoff, fSource, fEventType, fAction, fScenario, fPolicyRule, fLanguage, fSeverity]);

  const previousCards = useMemo(() => {
    const prevCutoff = cutoff - spanMs;
    return cards.filter((c) => {
      const t = Date.parse(c.timestamp);
      return !Number.isNaN(t) && t >= prevCutoff && t < cutoff;
    });
  }, [cards, cutoff, spanMs]);

  const totalsNow = useMemo(() => summarizeActions(filteredCards), [filteredCards]);
  const totalsPrev = useMemo(() => summarizeActions(previousCards), [previousCards]);

  const lastDecisionTs = cards.length ? Date.parse(cards[0].timestamp) : 0;
  const lagSeconds = lastDecisionTs ? Math.max(0, Math.round((now - lastDecisionTs) / 1000)) : null;
  const ratePerMin = spanMs ? filteredCards.length / (spanMs / 60000) : 0;

  const chartData = useMemo(() => {
    const buckets = buildTimeSeries(filteredCards, { cutoff, bucketMs });
    return addBaseline(buckets, 5);
  }, [filteredCards, cutoff, bucketMs]);
  const mapPoints = useMemo(() => buildThreatMapPoints(filteredCards, { limit: 450 }), [filteredCards]);
  const geoSummary = useMemo(() => buildGeoSummary(filteredCards), [filteredCards]);

  const alertsUrl = (patch: Partial<{
    q: string;
    action: string;
    source: string;
    event_type: string;
    policy_rule: string;
    scenario: string;
    language: string;
    osint_verdict: string;
    since_ms: number;
  }>) => {
    const params = new URLSearchParams();
    const setOrDel = (k: string, v: string) => {
      const val = (v ?? "").trim();
      if (val) params.set(k, val);
      else params.delete(k);
    };

    setOrDel("q", q);
    setOrDel("action", fAction);
    setOrDel("source", fSource);
    setOrDel("event_type", fEventType);
    setOrDel("policy_rule", fPolicyRule);
    setOrDel("scenario", fScenario);
    setOrDel("language", fLanguage);
    // Severity is a dashboard-only token today; Alerts does not have a field for it.

    if (cutoff > 0) params.set("since_ms", String(cutoff));

    // Apply patch overrides last (so drilldown can override tokens).
    if (patch.q !== undefined) setOrDel("q", patch.q);
    if (patch.action !== undefined) setOrDel("action", patch.action);
    if (patch.source !== undefined) setOrDel("source", patch.source);
    if (patch.event_type !== undefined) setOrDel("event_type", patch.event_type);
    if (patch.policy_rule !== undefined) setOrDel("policy_rule", patch.policy_rule);
    if (patch.scenario !== undefined) setOrDel("scenario", patch.scenario);
    if (patch.language !== undefined) setOrDel("language", patch.language);
    if (patch.osint_verdict !== undefined) setOrDel("osint_verdict", patch.osint_verdict);
    if (patch.since_ms !== undefined) params.set("since_ms", String(patch.since_ms));

    const qs = params.toString();
    return `/alerts${qs ? `?${qs}` : ""}`;
  };

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text">Operations Overview</h1>
          <p className="mt-1 text-sm text-subtle">
            Live view of decision cards, triage actions, and enrichment coverage.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span
            className={
              "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 " +
              (live
                ? "border-sev-low/40 bg-sev-low/10 text-sev-low"
                : "border-border bg-muted text-dim")
            }
          >
            <span
              className={
                "inline-block h-1.5 w-1.5 rounded-full " +
                (live ? "bg-sev-low animate-pulseDot" : "bg-dim")
              }
            />
            {live ? "live" : "disconnected"}
          </span>
        </div>
      </header>

      <Card
        title="Global time & filters"
        subtitle="One time range drives every panel. Filters persist in the URL for sharing."
      >
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex items-center gap-1">
            {TIME_RANGES.map((r) => (
              <button
                key={r.id}
                onClick={() => setRangeId(r.id)}
                className={
                  "rounded-md border px-2 py-1 text-[11px] transition-colors " +
                  (rangeId === r.id
                    ? "border-accent/50 bg-accent/10 text-accent"
                    : "border-border bg-muted text-subtle hover:text-text")
                }
              >
                {r.label}
              </button>
            ))}
          </div>
          {rangeId === "custom" && (
            <label className="block">
              <div className="label mb-1">Custom minutes</div>
              <input
                className="input w-[140px]"
                type="number"
                min={5}
                max={10080}
                value={customMinutes}
                onChange={(e) => setCustomMinutes(Number(e.target.value))}
              />
            </label>
          )}
          <label className="block flex-1 min-w-[220px]">
            <div className="label mb-1">Search</div>
            <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="text search…" />
          </label>
          <Token label="Source" value={fSource} onChange={setFSource} placeholder="email_gateway" />
          <Token label="Event type" value={fEventType} onChange={setFEventType} placeholder="suspicious_email" />
          <Token label="Action" value={fAction} onChange={setFAction} placeholder="escalate" />
          <Token label="Severity" value={fSeverity} onChange={setFSeverity} placeholder="critical" />
          <Token label="Scenario" value={fScenario} onChange={setFScenario} placeholder="phishing_burst" />
          <Token label="Policy rule" value={fPolicyRule} onChange={setFPolicyRule} placeholder="EMAIL-HIGH-001" />
          <Token label="Language" value={fLanguage} onChange={setFLanguage} placeholder="en" />
          <div className="ml-auto text-xs text-dim">
            <div className="mono">{filteredCards.length} cards in range</div>
            {lagSeconds !== null && <div>last decision: {lagSeconds}s ago</div>}
          </div>
        </div>
      </Card>

      {err && (
        <div className="rounded-lg border border-sev-critical/40 bg-sev-critical/10 p-3 text-sm text-sev-critical">
          {err}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile
          label="Total decisions"
          value={filteredCards.length}
          icon={<Bell size={16} />}
          hint={`${summary?.total_overrides ?? 0} overrides`}
          delta={deltaPct(filteredCards.length, totalsPrev.total)}
        />
        <StatTile
          label="Escalated"
          value={totalsNow.escalate}
          icon={<AlertTriangle size={16} />}
          tone="critical"
          hint={
            filteredCards.length
              ? `${((totalsNow.escalate / filteredCards.length) * 100).toFixed(0)}% of all`
              : "—"
          }
          delta={deltaPct(totalsNow.escalate, totalsPrev.escalate)}
        />
        <StatTile
          label="Queued for review"
          value={totalsNow.queue_for_review}
          icon={<TrendingUp size={16} />}
          tone="medium"
          hint={
            filteredCards.length
              ? `${((totalsNow.queue_for_review / filteredCards.length) * 100).toFixed(0)}% of all`
              : "—"
          }
          delta={deltaPct(totalsNow.queue_for_review, totalsPrev.queue_for_review)}
        />
        <StatTile
          label="Allowed"
          value={totalsNow.allow}
          icon={<ShieldCheck size={16} />}
          tone="low"
          hint={
            filteredCards.length
              ? `${((totalsNow.allow / filteredCards.length) * 100).toFixed(0)}% of all`
              : "—"
          }
          delta={deltaPct(totalsNow.allow, totalsPrev.allow)}
        />
      </div>

      <Card
        title="Action mix over time"
        subtitle="Bucketed by time (global range) — stacked by permitted action. Click a segment to filter action."
        action={<span className="mono text-xs text-dim">{ratePerMin.toFixed(1)}/min</span>}
      >
        <div className="h-[280px] w-full">
          {chartData.length === 0 ? (
            <EmptyState
              title="No decisions in window"
              description="Run the simulator or POST an event to populate the chart."
              icon={<Radio size={22} />}
            />
          ) : (
            <ResponsiveContainer>
              <BarChart
                data={chartData}
                margin={{ top: 4, right: 12, left: -14, bottom: 0 }}
              >
                <CartesianGrid stroke="#1f2a37" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="label"
                  stroke="#64748b"
                  tick={{ fill: "#94a3b8", fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ stroke: "#1f2a37" }}
                />
                <YAxis
                  allowDecimals={false}
                  stroke="#64748b"
                  tick={{ fill: "#94a3b8", fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ stroke: "#1f2a37" }}
                />
                <Tooltip
                  cursor={{ fill: "rgba(34, 211, 238, 0.06)" }}
                  contentStyle={{
                    background: "#0f141b",
                    border: "1px solid #1f2a37",
                    borderRadius: 8,
                    fontSize: 12,
                    color: "#e5e7eb",
                  }}
                  labelStyle={{ color: "#94a3b8" }}
                />
                <Legend
                  wrapperStyle={{ fontSize: 11, color: "#94a3b8" }}
                  iconType="circle"
                />
                <Line
                  type="monotone"
                  dataKey="baseline"
                  name="baseline"
                  stroke="#22d3ee"
                  strokeWidth={1.5}
                  dot={false}
                  isAnimationActive={false}
                />
                <Bar
                  dataKey="allow"
                  name="allow"
                  stackId="a"
                  fill="#34d399"
                  radius={[0, 0, 0, 0]}
                  onClick={(_, idx) => {
                    setFAction("allow");
                    const ts = chartData[idx]?.ts;
                    if (ts) globalThis.location.assign(alertsUrl({ action: "allow", since_ms: ts }));
                  }}
                />
                <Bar
                  dataKey="queue_for_review"
                  name="queue"
                  stackId="a"
                  fill="#fbbf24"
                  onClick={(_, idx) => {
                    setFAction("queue_for_review");
                    const ts = chartData[idx]?.ts;
                    if (ts) globalThis.location.assign(alertsUrl({ action: "queue_for_review", since_ms: ts }));
                  }}
                />
                <Bar
                  dataKey="escalate"
                  name="escalate"
                  stackId="a"
                  fill="#f43f5e"
                  radius={[4, 4, 0, 0]}
                  onClick={(_, idx) => {
                    setFAction("escalate");
                    const ts = chartData[idx]?.ts;
                    if (ts) globalThis.location.assign(alertsUrl({ action: "escalate", since_ms: ts }));
                  }}
                />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </Card>

      <Card
        title="Geo summary + map"
        subtitle="Map + ranked summaries (global range). Click dots to open the alert; hover for details."
        action={<span className="mono text-xs text-dim">{mapPoints.length} points</span>}
      >
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <div className="relative h-[340px] w-full overflow-hidden rounded-lg border border-border bg-muted/20">
          <ComposableMap
            projection="geoMercator"
            projectionConfig={{ scale: 140 }}
            style={{ width: "100%", height: "100%" }}
          >
            <Geographies geography={world110m as any}>
              {({ geographies }: { geographies: unknown[] }) =>
                geographies.map((geo: any) => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill="#0b1220"
                    stroke="#1f2a37"
                    strokeWidth={0.5}
                    style={{
                      default: { outline: "none" },
                      hover: { outline: "none", fill: "#0f1a2d" },
                      pressed: { outline: "none" },
                    }}
                  />
                ))
              }
            </Geographies>

            {mapPoints.map((p) => (
              <Marker key={p.key} coordinates={p.coordinates}>
                <g
                  role={p.decisionCardId ? "button" : undefined}
                  tabIndex={p.decisionCardId ? 0 : -1}
                  style={{ cursor: p.decisionCardId ? "pointer" : "default" }}
                  onKeyDown={(e) => {
                    if (!p.decisionCardId) return;
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      globalThis.location.assign(`/alerts/${encodeURIComponent(p.decisionCardId)}`);
                    }
                  }}
                  onClick={() => {
                    if (p.decisionCardId) {
                      globalThis.location.assign(`/alerts/${encodeURIComponent(p.decisionCardId)}`);
                    }
                  }}
                  onMouseEnter={(e) => {
                    const rect = e.currentTarget.ownerSVGElement?.getBoundingClientRect();
                    const x = rect ? (e as any).clientX - rect.left : (e as any).clientX;
                    const y = rect ? (e as any).clientY - rect.top : (e as any).clientY;
                    setHover({ point: p, x, y });
                  }}
                  onMouseMove={(e) => {
                    const rect = e.currentTarget.ownerSVGElement?.getBoundingClientRect();
                    const x = rect ? (e as any).clientX - rect.left : (e as any).clientX;
                    const y = rect ? (e as any).clientY - rect.top : (e as any).clientY;
                    setHover((h) => (h ? { ...h, x, y } : h));
                  }}
                  onMouseLeave={() => setHover(null)}
                >
                  <circle
                    r={p.radius}
                    fill={p.fill}
                    fillOpacity={0.8}
                    stroke={p.stroke}
                    strokeWidth={1}
                  />
                </g>
              </Marker>
            ))}
          </ComposableMap>

          {hover && (
            <div
              className="pointer-events-none absolute z-10 w-[260px] -translate-x-1/2 -translate-y-full rounded-md border border-border bg-panel px-3 py-2 text-[12px] text-text shadow-lg"
              style={{ left: hover.x, top: hover.y - 10 }}
            >
              <div className="flex items-center justify-between gap-3">
                <span className="font-medium">{hover.point.actionLabel}</span>
                <span className="mono text-subtle">{hover.point.scoreLabel}</span>
              </div>
              <div className="mt-1 text-[11px] text-subtle">
                {hover.point.source} · {relativeTime(hover.point.timestamp)}
              </div>
              <div className="mt-2 mono text-[11px] text-dim">
                {truncateMiddle(hover.point.key, 26)}
              </div>
              <div className="mt-2 text-[11px] text-dim">{hover.point.legendLabel}</div>
            </div>
          )}
            </div>
            <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-dim">
              <div>
                Points are derived from decision card IDs (not raw IPs) to avoid exposing personal data while still
                showing global volume and severity.
              </div>
              <div className="flex items-center gap-3">
                <LegendDot fill="#f43f5e" stroke="#fb7185" label="critical (escalate)" />
                <LegendDot fill="#fbbf24" stroke="#fcd34d" label="medium (queue)" />
                <LegendDot fill="#34d399" stroke="#6ee7b7" label="low (allow)" />
                <LegendDot fill="#38bdf8" stroke="#7dd3fc" label="info/other" />
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <MiniRank title="Top sources" items={geoSummary.topSources} onPick={(v) => setFSource(v)} />
            <MiniRank title="Top policy rules" items={geoSummary.topRules} onPick={(v) => setFPolicyRule(v)} />
            <MiniRank title="Top scenarios" items={geoSummary.topScenarios} onPick={(v) => setFScenario(v)} />
            <MiniRank title="Top actions" items={geoSummary.topActions} onPick={(v) => setFAction(v)} />
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title="Freshness & health" subtitle="Trust signals (global range)">
          <div className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-subtle">SSE</span>
              <span className={live ? "text-sev-low" : "text-dim"}>{live ? "connected" : "polling"}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-subtle">Last decision</span>
              <span className="mono">{lagSeconds === null ? "—" : `${lagSeconds}s ago`}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-subtle">Rate</span>
              <span className="mono">{ratePerMin.toFixed(1)}/min</span>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-2 text-[12px]">
              <HealthChip label="audit" status={svc.audit} />
              <HealthChip label="collector" status={svc.collector} />
              <HealthChip label="orchestrator" status={svc.orchestrator} />
              <HealthChip label="detector" status={svc.detector} />
            </div>
            <div className="mt-3 rounded-md border border-border bg-muted/30 p-2 text-[12px]">
              <div className="label mb-1">SIEM spool</div>
              <div className="mono text-subtle">
                {spool ? JSON.stringify(spool.spool).slice(0, 160) : "—"}
              </div>
            </div>
          </div>
        </Card>

        <Card title="Notables" subtitle="Queue-style summary (Splunk-like)">
          <NotablesPanel cards={filteredCards} />
        </Card>

        <Card title="OSINT coverage" subtitle="Enrichment verdicts in range">
          <div className="mb-4 flex items-center gap-2 text-xs text-subtle">
            <Globe2 size={14} className="text-accent" />
            <span className="mono">
              {filteredCards.filter((c) => c.osint_enabled && !c.osint_skipped).length} / {filteredCards.length} enriched
            </span>
          </div>
          <DistributionList
            counts={summarizeOsintVerdicts(filteredCards)}
            onPick={(k) => globalThis.location.assign(alertsUrl({ osint_verdict: k }))}
          />
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card
          className="xl:col-span-2"
          title="Recent alerts"
          subtitle="Latest decision cards from the audit ledger"
          action={
            <Link to="/alerts" className="btn">
              View all
            </Link>
          }
        >
          {filteredCards.length === 0 ? (
            <EmptyState
              title="No decision cards yet"
              description="Run the simulator or POST to /process_event to populate the ledger."
              icon={<Bell size={22} />}
            />
          ) : (
            <ul className="divide-y divide-border">
              {filteredCards.slice(0, 10).map((c) => {
                const sev = actionSeverity(c.permitted_action);
                return (
                  <li key={c.decision_card_id}>
                    <Link
                      to={`/alerts/${encodeURIComponent(c.decision_card_id)}`}
                      className="grid grid-cols-[auto_1fr_auto] items-center gap-4 px-1 py-2 hover:bg-muted/60 rounded-md"
                    >
                      <SeverityBadge severity={sev}>
                        {c.permitted_action.replaceAll("_", " ")}
                      </SeverityBadge>
                      <div className="min-w-0">
                        <div className="truncate text-sm text-text">
                          {c.label || c.event_type}{" "}
                          <span className="text-subtle">· {c.source}</span>
                        </div>
                        <div className="mono truncate text-[11px] text-dim">
                          {truncateMiddle(c.event_id, 28)} · rule={c.policy_rule_id}
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="text-right">
                          <div className="label">Score</div>
                          <div
                            className={`mono text-sm font-semibold ${
                              sevTextClass[severityFromScore(c.risk_score_final)]
                            }`}
                          >
                            {formatScore(c.risk_score_final)}
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="label">When</div>
                          <div className="text-xs text-subtle">
                            {relativeTime(c.timestamp)}
                          </div>
                        </div>
                      </div>
                    </Link>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        <Card title="OSINT coverage" subtitle="Enrichment verdicts across decisions">
          <div className="mb-4 flex items-center gap-2 text-xs text-subtle">
            <Globe2 size={14} className="text-accent" />
            <span className="mono">
              {filteredCards.filter((c) => c.osint_enabled && !c.osint_skipped).length} / {filteredCards.length} enriched
            </span>
          </div>
          <DistributionList
            counts={summarizeOsintVerdicts(filteredCards)}
            onPick={(k) => globalThis.location.assign(`/alerts?osint_verdict=${encodeURIComponent(k)}&since_ms=${cutoff}`)}
          />
        </Card>

        <Card title="Policy rules fired">
          <DistributionList
            counts={summarizeBy(filteredCards, (c) => c.policy_rule_id || "unknown")}
            mono
            onPick={(k) => globalThis.location.assign(alertsUrl({ policy_rule: k }))}
          />
        </Card>

        <Card title="LLM providers" subtitle="Where analyst summaries came from">
          <div className="mb-3 flex items-center gap-2 text-xs text-subtle">
            <BrainCircuit size={14} className="text-accent" />
            <span>Tier / provider breakdown</span>
          </div>
          <DistributionList
            counts={summarizeBy(filteredCards, (c) => (c.llm_used ? (c.llm_provider ?? "used") : "fallback"))}
            mono
          />
        </Card>

        <Card title="Scenarios replayed">
          <DistributionList
            counts={summarizeBy(filteredCards, (c) => c.scenario_id || "none")}
            mono
            onPick={(k) => globalThis.location.assign(alertsUrl({ scenario: k }))}
          />
        </Card>
      </div>
    </div>
  );
}

function StatTile({
  label,
  value,
  icon,
  tone,
  hint,
  delta,
}: Readonly<{
  label: string;
  value: number | string;
  icon: React.ReactNode;
  tone?: "critical" | "medium" | "low" | "info";
  hint?: string;
  delta?: number | null;
}>) {
  const accent = {
    critical: "text-sev-critical",
    medium: "text-sev-medium",
    low: "text-sev-low",
    info: "text-sev-info",
  }[tone ?? "info"];
  return (
    <div className="card px-4 py-3">
      <div className="flex items-center justify-between">
        <div className="label">{label}</div>
        <span className={accent}>{icon}</span>
      </div>
      <div className="mt-2 font-mono text-2xl font-semibold text-text">{value}</div>
      <div className="mt-1 flex items-center justify-between gap-2 text-[11px] text-dim">
        <span>{hint ?? ""}</span>
        {typeof delta === "number" && (
          <span className={`mono ${delta >= 0 ? "text-sev-low" : "text-sev-critical"}`}>
            {delta >= 0 ? "+" : ""}
            {delta.toFixed(0)}%
          </span>
        )}
      </div>
    </div>
  );
}

function DistributionList({
  counts,
  mono,
  onPick,
}: Readonly<{
  counts: Record<string, number>;
  mono?: boolean;
  onPick?: (key: string) => void;
}>) {
  const pretty = (k: string) => {
    const key = (k || "").trim();
    const map: Record<string, string> = {
      unknown: "unknown (insufficient signal)",
      not_used: "not used",
      disabled: "disabled",
      skipped: "skipped",
      no_verdict: "no verdict",
      no_indicators: "no indicators extracted",
      unspecified: "unspecified",
      none: "none",
    };
    return map[key] ?? key;
  };

  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const max = entries.reduce((m, [, n]) => Math.max(m, n), 0) || 1;
  if (!entries.length)
    return <div className="text-xs text-dim">No data yet.</div>;
  return (
    <ul className="space-y-2">
      {entries.map(([k, v]) => (
        <li key={k} className="text-sm">
          <div className="flex items-center justify-between">
            {onPick ? (
              <button
                type="button"
                className={mono ? "mono truncate text-left hover:text-text" : "truncate text-left hover:text-text"}
                onClick={() => onPick(k)}
                title="Click to drill down"
              >
                {pretty(k)}
              </button>
            ) : (
              <span className={mono ? "mono truncate" : "truncate"}>{pretty(k)}</span>
            )}
            <span className="mono text-subtle">{v}</span>
          </div>
          <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-elev">
            <div
              className="h-full rounded-full bg-accent/70"
              style={{ width: `${(v / max) * 100}%` }}
            />
          </div>
        </li>
      ))}
    </ul>
  );
}

// ---------- helpers ----------

type Bucket = {
  ts: number;
  label: string;
  allow: number;
  queue_for_review: number;
  escalate: number;
  total: number;
  baseline?: number;
};

function buildTimeSeries(cards: DecisionCard[], opts: { cutoff: number; bucketMs: number }): Bucket[] {
  if (cards.length === 0) return [];
  const now = Date.now();
  const filtered = cards
    .map((c) => ({ t: Date.parse(c.timestamp), a: c.permitted_action }))
    .filter((x) => !Number.isNaN(x.t) && x.t >= opts.cutoff);

  if (filtered.length === 0) return [];

  const bucketMs = opts.bucketMs;
  const endBucket = Math.floor(now / bucketMs) * bucketMs;
  const startBucket = Math.floor(opts.cutoff / bucketMs) * bucketMs;

  const buckets = new Map<number, Bucket>();
  for (let t = startBucket; t <= endBucket; t += bucketMs) {
    buckets.set(t, {
      ts: t,
      label: formatBucketLabel(t, bucketMs),
      allow: 0,
      queue_for_review: 0,
      escalate: 0,
      total: 0,
    });
  }
  for (const x of filtered) {
    const k = Math.floor(x.t / bucketMs) * bucketMs;
    const b = buckets.get(k);
    if (!b) continue;
    if (x.a === "allow") b.allow++;
    else if (x.a === "queue_for_review") b.queue_for_review++;
    else if (x.a === "escalate") b.escalate++;
    b.total++;
  }
  return Array.from(buckets.values()).sort((a, b) => a.ts - b.ts);
}

function formatBucketLabel(ts: number, bucketMs: number): string {
  const d = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, "0");
  if (bucketMs < 60 * 60 * 1000) return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  if (bucketMs <= 6 * 60 * 60 * 1000) return `${pad(d.getHours())}:00`;
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:00`;
}

// ---------- threat map ----------

type ThreatMapPoint = {
  key: string;
  coordinates: [number, number]; // [lon, lat]
  fill: string;
  stroke: string;
  radius: number;
  timestamp: string;
  source: string;
  permitted_action: string;
  risk_score_final: number;
  actionLabel: string;
  scoreLabel: string;
  legendLabel: string;
  decisionCardId?: string;
};

function fnv1a32(input: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    // 32-bit FNV-1a prime multiplication
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

function toUnitFloat(u32: number): number {
  return u32 / 0xffffffff;
}

function pseudoGeoFromKey(key: string): [number, number] {
  // Deterministic pseudo-location, intentionally not tied to user IPs.
  const h1 = fnv1a32(`${key}::lon`);
  const h2 = fnv1a32(`${key}::lat`);
  const lon = -180 + toUnitFloat(h1) * 360;
  // Avoid extreme poles for nicer rendering.
  const lat = -70 + toUnitFloat(h2) * 140;
  return [lon, lat];
}

function severityStyle(action: DecisionCard["permitted_action"]) {
  const sev = actionSeverity(action);
  if (sev === "critical") return { fill: "#f43f5e", stroke: "#fb7185", radius: 3.8 };
  if (sev === "medium") return { fill: "#fbbf24", stroke: "#fcd34d", radius: 3.2 };
  if (sev === "low") return { fill: "#34d399", stroke: "#6ee7b7", radius: 2.8 };
  return { fill: "#38bdf8", stroke: "#7dd3fc", radius: 2.8 };
}

function buildThreatMapPoints(cards: DecisionCard[], opts: { limit: number }): ThreatMapPoint[] {
  const recent = cards.slice(0, opts.limit);
  return recent.map((c) => {
    const key = c.decision_card_id || c.event_id || `${c.timestamp}-${c.source}`;
    const coordinates = pseudoGeoFromKey(key);
    const s = severityStyle(c.permitted_action);
    const actionLabel = (c.permitted_action || "unknown").replaceAll("_", " ");
    const scoreLabel = `score=${formatScore(c.risk_score_final)}`;
    const legendLabel = `severity=${actionSeverity(c.permitted_action)}`;
    return {
      key,
      coordinates,
      fill: s.fill,
      stroke: s.stroke,
      radius: s.radius,
      timestamp: c.timestamp,
      source: c.source,
      permitted_action: c.permitted_action,
      risk_score_final: c.risk_score_final,
      actionLabel,
      scoreLabel,
      legendLabel,
      decisionCardId: c.decision_card_id,
    };
  });
}

function LegendDot({
  fill,
  stroke,
  label,
}: Readonly<{
  fill: string;
  stroke: string;
  label: string;
}>) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className="inline-block h-2.5 w-2.5 rounded-full"
        style={{ background: fill, outline: `1px solid ${stroke}` }}
      />
      <span>{label}</span>
    </span>
  );
}

function Token({
  label,
  value,
  onChange,
  placeholder,
}: Readonly<{
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}>) {
  return (
    <label className="block min-w-[160px]">
      <div className="label mb-1">{label}</div>
      <input className="input" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
    </label>
  );
}

function summarizeActions(cards: DecisionCard[]) {
  let allow = 0;
  let queue_for_review = 0;
  let escalate = 0;
  for (const c of cards) {
    if (c.permitted_action === "allow") allow++;
    else if (c.permitted_action === "queue_for_review") queue_for_review++;
    else if (c.permitted_action === "escalate") escalate++;
  }
  return { allow, queue_for_review, escalate, total: cards.length };
}

function deltaPct(now: number, prev: number): number | null {
  if (!Number.isFinite(now) || !Number.isFinite(prev) || prev <= 0) return null;
  return ((now - prev) / prev) * 100;
}

function buildGeoSummary(cards: DecisionCard[]) {
  return {
    topSources: topN(cards.map((c) => c.source || "unknown")),
    topRules: topN(cards.map((c) => c.policy_rule_id || "unknown")),
    topScenarios: topN(cards.map((c) => c.scenario_id || "none")),
    topActions: topN(cards.map((c) => c.permitted_action || "unknown")),
  };
}

function topN(values: string[], n = 5): Array<{ k: string; v: number }> {
  const m = new Map<string, number>();
  for (const x of values) m.set(x, (m.get(x) ?? 0) + 1);
  return Array.from(m.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([k, v]) => ({ k, v }));
}

function MiniRank({
  title,
  items,
  onPick,
}: Readonly<{
  title: string;
  items: Array<{ k: string; v: number }>;
  onPick: (k: string) => void;
}>) {
  return (
    <div className="rounded-lg border border-border bg-muted/20 p-3">
      <div className="label mb-2">{title}</div>
      {items.length === 0 ? (
        <div className="text-xs text-dim">No data.</div>
      ) : (
        <ul className="space-y-1.5 text-sm">
          {items.map((it) => (
            <li
              key={it.k}
              className="rounded-md hover:bg-muted/50"
            >
              <button
                type="button"
                className="flex w-full items-center justify-between gap-2 px-2 py-1 text-left"
                onClick={() => onPick(it.k)}
                title="Click to filter"
              >
                <span className="truncate text-subtle">{it.k}</span>
                <span className="mono text-dim">{it.v}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function HealthChip({ label, status }: Readonly<{ label: string; status: "up" | "down" | "unknown" }>) {
  const cls =
    status === "up"
      ? "border-sev-low/40 bg-sev-low/10 text-sev-low"
      : status === "down"
      ? "border-sev-critical/40 bg-sev-critical/10 text-sev-critical"
      : "border-border bg-muted text-dim";
  return (
    <span className={"inline-flex items-center justify-between gap-2 rounded-md border px-2 py-1 " + cls}>
      <span className="mono">{label}</span>
      <span>{status}</span>
    </span>
  );
}

function NotablesPanel({ cards }: Readonly<{ cards: DecisionCard[] }>) {
  const now = Date.now();
  const last15 = now - 15 * 60 * 1000;
  const new15 = cards.filter((c) => Date.parse(c.timestamp) >= last15).length;
  const escalated = cards.filter((c) => c.permitted_action === "escalate").length;
  const queued = cards.filter((c) => c.permitted_action === "queue_for_review").length;
  const unreviewed = cards.filter((c) => c.requires_human_review && !c.final_human_action).length;
  const newestEscalations = cards.filter((c) => c.permitted_action === "escalate").slice(0, 5);
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2 text-sm">
        <div className="rounded-md border border-border bg-muted/20 p-2">
          <div className="label">New (15m)</div>
          <div className="mono text-lg text-text">{new15}</div>
        </div>
        <div className="rounded-md border border-border bg-muted/20 p-2">
          <div className="label">Unreviewed</div>
          <div className="mono text-lg text-text">{unreviewed}</div>
        </div>
        <div className="rounded-md border border-border bg-muted/20 p-2">
          <div className="label">Escalated</div>
          <div className="mono text-lg text-text">{escalated}</div>
        </div>
        <div className="rounded-md border border-border bg-muted/20 p-2">
          <div className="label">Queued</div>
          <div className="mono text-lg text-text">{queued}</div>
        </div>
      </div>
      <div className="rounded-lg border border-border bg-muted/20 p-3">
        <div className="label mb-2">Top 5 newest escalations</div>
        {newestEscalations.length === 0 ? (
          <div className="text-xs text-dim">No escalations in range.</div>
        ) : (
          <ul className="space-y-1.5 text-sm">
            {newestEscalations.map((c) => (
              <li key={c.decision_card_id}>
                <Link
                  to={`/alerts/${encodeURIComponent(c.decision_card_id)}`}
                  className="block rounded-md px-2 py-1 hover:bg-muted/50"
                >
                  <div className="truncate text-text">{c.label || c.event_type}</div>
                  <div className="flex items-center justify-between text-[11px] text-dim">
                    <span className="truncate">{c.source}</span>
                    <span className="mono">{relativeTime(c.timestamp)}</span>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function summarizeOsintVerdicts(cards: DecisionCard[]): Record<string, number> {
  const m: Record<string, number> = {};
  for (const c of cards) {
    const key =
      c.osint_enabled && !c.osint_skipped
        ? c.osint_verdict ?? "unknown"
        : c.osint_skipped
        ? "skipped"
        : c.osint_enabled === false
        ? "disabled"
        : "not_used";
    const k = String(key).toLowerCase();
    m[k] = (m[k] ?? 0) + 1;
  }
  return m;
}

function summarizeBy(cards: DecisionCard[], keyFn: (c: DecisionCard) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const c of cards) {
    const k = String(keyFn(c) || "unknown");
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

function addBaseline(buckets: Bucket[], windowSize: number): Bucket[] {
  const w = Math.max(1, windowSize);
  return buckets.map((b, idx) => {
    const start = Math.max(0, idx - w + 1);
    const slice = buckets.slice(start, idx + 1);
    const avg = slice.reduce((s, x) => s + (x.total ?? 0), 0) / slice.length;
    return { ...b, baseline: avg };
  });
}
