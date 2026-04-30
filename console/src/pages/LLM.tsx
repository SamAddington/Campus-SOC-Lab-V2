import { useCallback, useEffect, useMemo, useState } from "react";
import {
  RefreshCw,
  BrainCircuit,
  PlayCircle,
  GraduationCap,
  Cpu,
  AlertTriangle,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  api,
  type DecisionCard,
  type LLMAssistRequest,
  type LLMAssistResponse,
  type LLMProviderInfo,
  type LLMProvidersStatus,
} from "@/lib/api";
import { Card, EmptyState, KeyValueGrid } from "@/components/ui/Card";
import { Chip } from "@/components/ui/Badge";
import { JsonView } from "@/components/ui/JsonView";

type TimeWindow = "1h" | "6h" | "24h" | "7d";
const WINDOWS: Record<TimeWindow, number> = {
  "1h": 60 * 60 * 1000,
  "6h": 6 * 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
};
const BUCKETS: Record<TimeWindow, number> = {
  "1h": 12,
  "6h": 12,
  "24h": 12,
  "7d": 14,
};

const TIER_COLORS: Record<string, string> = {
  teacher: "#a78bfa",
  student: "#22d3ee",
  fallback: "#f59e0b",
};

export function LLM() {
  const [providers, setProviders] = useState<LLMProvidersStatus | null>(null);
  const [providersErr, setProvidersErr] = useState<string | null>(null);
  const [cards, setCards] = useState<DecisionCard[]>([]);
  const [cardsErr, setCardsErr] = useState<string | null>(null);
  const [window, setWindow] = useState<TimeWindow>("24h");
  const [loading, setLoading] = useState(false);

  const loadProviders = useCallback(async () => {
    try {
      const res = await api.llmProviders();
      setProviders(res);
      setProvidersErr(null);
    } catch (e) {
      setProvidersErr((e as Error).message);
    }
  }, []);

  const loadCards = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.decisionCards(500);
      setCards(res.items);
      setCardsErr(null);
    } catch (e) {
      setCardsErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadProviders();
    loadCards();
  }, [loadProviders, loadCards]);

  const filtered = useMemo(() => {
    const cutoff = Date.now() - WINDOWS[window];
    return cards.filter((c) => {
      const t = new Date(c.timestamp).getTime();
      return Number.isFinite(t) && t >= cutoff;
    });
  }, [cards, window]);

  const stats = useMemo(() => {
    let teacher = 0;
    let student = 0;
    let fallback = 0;
    let used = 0;
    const providerCounts: Record<string, number> = {};
    const modelCounts: Record<string, number> = {};
    const reasonCounts: Record<string, number> = {};
    for (const c of filtered) {
      if (c.llm_used) used++;
      const tier = (c.llm_tier ?? "fallback").toLowerCase();
      if (tier === "teacher") teacher++;
      else if (tier === "student") student++;
      else fallback++;
      if (c.llm_provider) providerCounts[c.llm_provider] = (providerCounts[c.llm_provider] ?? 0) + 1;
      if (c.llm_model) modelCounts[c.llm_model] = (modelCounts[c.llm_model] ?? 0) + 1;
      if (c.llm_reason) reasonCounts[c.llm_reason] = (reasonCounts[c.llm_reason] ?? 0) + 1;
    }
    return {
      total: filtered.length,
      used,
      teacher,
      student,
      fallback,
      providerCounts,
      modelCounts,
      reasonCounts,
    };
  }, [filtered]);

  const series = useMemo(() => buildTierSeries(filtered, window), [filtered, window]);

  const topReasons = useMemo(() => {
    return Object.entries(stats.reasonCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);
  }, [stats.reasonCounts]);

  return (
    <div className="space-y-4">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-text flex items-center gap-2">
            <BrainCircuit size={18} className="text-accent" /> LLM Assistant
          </h1>
          <p className="mt-1 max-w-3xl text-sm text-subtle">
            Observability for the teacher / student router. See which providers
            are wired up, how traffic is routed, and what the assistant actually
            returns when you feed it a decision card.
          </p>
        </div>
        <button
          className="btn"
          onClick={() => {
            loadProviders();
            loadCards();
          }}
          disabled={loading}
        >
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </header>

      {/* Providers */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <ProviderCard
          role="Teacher"
          icon={<GraduationCap size={14} className="text-purple-300" />}
          info={providers?.teacher}
        />
        <ProviderCard
          role="Student"
          icon={<Cpu size={14} className="text-accent" />}
          info={providers?.student}
        />
        <Card title="Routing modes">
          {providersErr ? (
            <div className="text-sm text-sev-critical">{providersErr}</div>
          ) : providers ? (
            <KeyValueGrid
              rows={[
                { k: "Default mode", v: <span className="mono">{providers.default_mode}</span> },
                {
                  k: "Human-review mode",
                  v: <span className="mono">{providers.human_review_mode}</span>,
                },
              ]}
            />
          ) : (
            <div className="text-sm text-dim">Loading…</div>
          )}
          <p className="mt-3 text-[11px] leading-relaxed text-dim">
            <b>student_only</b>: small on-device model.
            <br />
            <b>teacher_only</b>: large model only (offline curation).
            <br />
            <b>teacher_shadow</b>: student serves user; teacher shadowed for
            training.
            <br />
            <b>teacher_then_student_refine</b>: teacher drafts, student
            rewrites (reviewer path).
          </p>
        </Card>
      </div>

      {/* Routing over time */}
      <Card
        title="Routing over time"
        subtitle={
          <>
            Tier mix for recent decisions. Data comes from the audit ledger
            ({stats.total} cards in window).
          </>
        }
        action={
          <div className="flex items-center gap-1">
            {(Object.keys(WINDOWS) as TimeWindow[]).map((w) => (
              <button
                key={w}
                onClick={() => setWindow(w)}
                className={
                  "rounded-md border px-2 py-0.5 text-[11px] " +
                  (window === w
                    ? "border-accent/40 bg-accent/10 text-accent"
                    : "border-border bg-muted text-subtle hover:text-text")
                }
              >
                {w}
              </button>
            ))}
          </div>
        }
      >
        {cardsErr && (
          <div className="mb-3 rounded-md border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical">
            {cardsErr}
          </div>
        )}

        <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
          <div className="h-[240px] w-full">
            {series.length === 0 ? (
              <EmptyState
                title="No LLM-tagged decisions yet"
                description="Run a scenario in the Simulator to populate the ledger."
              />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={series}>
                  <CartesianGrid stroke="#1f2a37" strokeDasharray="3 3" />
                  <XAxis dataKey="label" tick={{ fill: "#9ca3af", fontSize: 11 }} />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: "#9ca3af", fontSize: 11 }}
                    width={32}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#0f141a",
                      border: "1px solid #1f2a37",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                    labelStyle={{ color: "#d1d5db" }}
                  />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Bar dataKey="teacher" stackId="a" fill={TIER_COLORS.teacher} />
                  <Bar dataKey="student" stackId="a" fill={TIER_COLORS.student} />
                  <Bar dataKey="fallback" stackId="a" fill={TIER_COLORS.fallback} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-2">
              <Tally label="Teacher" value={stats.teacher} color={TIER_COLORS.teacher} />
              <Tally label="Student" value={stats.student} color={TIER_COLORS.student} />
              <Tally label="Fallback" value={stats.fallback} color={TIER_COLORS.fallback} />
            </div>
            <div className="rounded-lg border border-border bg-muted/40 p-3">
              <div className="label mb-1">LLM actually used</div>
              <div className="text-lg font-semibold text-text">
                {stats.used}
                <span className="ml-2 text-xs font-normal text-dim">
                  / {stats.total} cards (
                  {stats.total ? Math.round((100 * stats.used) / stats.total) : 0}%)
                </span>
              </div>
            </div>
            <TopCounts title="Top providers" counts={stats.providerCounts} />
            <TopCounts title="Top models" counts={stats.modelCounts} />
          </div>
        </div>

        {topReasons.length > 0 && (
          <div className="mt-4 rounded-lg border border-border bg-muted/40 p-3">
            <div className="label mb-2">Top routing reasons</div>
            <ul className="space-y-1 text-[13px] text-subtle">
              {topReasons.map(([reason, count]) => (
                <li key={reason} className="flex items-center justify-between gap-3">
                  <span className="mono truncate">{reason}</span>
                  <span className="chip">{count}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>

      {/* Playground */}
      <Playground cards={cards} />
    </div>
  );
}

function ProviderCard({
  role,
  icon,
  info,
}: {
  role: string;
  icon: React.ReactNode;
  info?: LLMProviderInfo;
}) {
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          {icon} {role}
        </span>
      }
      action={
        info ? (
          info.enabled ? (
            <span className="inline-flex items-center gap-1 text-xs text-sev-low">
              <CheckCircle2 size={14} /> enabled
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-xs text-dim">
              <XCircle size={14} /> disabled
            </span>
          )
        ) : undefined
      }
    >
      {info ? (
        <KeyValueGrid
          rows={[
            { k: "Provider", v: <span className="mono">{info.provider}</span> },
            { k: "Model", v: <span className="mono">{info.model}</span> },
          ]}
        />
      ) : (
        <div className="text-sm text-dim">Loading…</div>
      )}
    </Card>
  );
}

function Tally({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-muted/40 p-2">
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-dim">
        <span
          className="inline-block h-2 w-2 rounded-full"
          style={{ background: color }}
        />
        {label}
      </div>
      <div className="mt-0.5 text-lg font-semibold text-text">{value}</div>
    </div>
  );
}

function TopCounts({
  title,
  counts,
}: {
  title: string;
  counts: Record<string, number>;
}) {
  const entries = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);
  if (entries.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-muted/40 p-3">
        <div className="label mb-1">{title}</div>
        <div className="text-xs text-dim">No data yet.</div>
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-border bg-muted/40 p-3">
      <div className="label mb-2">{title}</div>
      <ul className="space-y-1 text-[12.5px] text-subtle">
        {entries.map(([k, v]) => (
          <li key={k} className="flex items-center justify-between gap-3">
            <span className="mono truncate">{k}</span>
            <span className="chip">{v}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function buildTierSeries(cards: DecisionCard[], w: TimeWindow) {
  const buckets = BUCKETS[w];
  const totalMs = WINDOWS[w];
  const bucketMs = totalMs / buckets;
  const now = Date.now();
  const start = now - totalMs;
  const data: Array<{
    bucket: number;
    label: string;
    teacher: number;
    student: number;
    fallback: number;
  }> = [];
  for (let i = 0; i < buckets; i++) {
    const bucketStart = start + i * bucketMs;
    data.push({
      bucket: bucketStart,
      label: formatBucketLabel(bucketStart, w),
      teacher: 0,
      student: 0,
      fallback: 0,
    });
  }
  for (const c of cards) {
    const t = new Date(c.timestamp).getTime();
    if (!Number.isFinite(t) || t < start || t > now) continue;
    const idx = Math.min(buckets - 1, Math.floor((t - start) / bucketMs));
    const tier = (c.llm_tier ?? "fallback").toLowerCase();
    if (tier === "teacher") data[idx].teacher += 1;
    else if (tier === "student") data[idx].student += 1;
    else data[idx].fallback += 1;
  }
  return data;
}

function formatBucketLabel(tsMs: number, w: TimeWindow): string {
  const d = new Date(tsMs);
  if (w === "7d") {
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  }
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

/* ------------------------------ Playground ------------------------------ */

const MODE_OPTIONS: Array<{ value: NonNullable<LLMAssistRequest["mode"]>; label: string }> = [
  { value: "student_only", label: "student_only" },
  { value: "teacher_only", label: "teacher_only" },
  { value: "teacher_shadow", label: "teacher_shadow" },
  { value: "teacher_then_student_refine", label: "teacher_then_student_refine" },
];

const SAMPLE: LLMAssistRequest = {
  event_id: "evt-playground-001",
  source: "email_gateway",
  event_type: "suspicious_link",
  language: "en",
  risk_score_rule: 0.68,
  risk_score_fl: 0.71,
  risk_score_final: 0.74,
  label: "phishing_suspected",
  action: "queue_for_review",
  explanation: "Inbound email contained a look-alike domain and urgency language.",
  policy_rule_id: "pol-phish-001",
  policy_reason: "medium_risk_review",
  requires_human_review: true,
  features: { contains_urgency: 1, domain_age_days: 4, has_attachment: 0 },
  scenario_id: "phish_wave",
  mode: null,
};

function Playground({ cards }: { cards: DecisionCard[] }) {
  const [form, setForm] = useState<LLMAssistRequest>(SAMPLE);
  const [resp, setResp] = useState<LLMAssistResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [prefillId, setPrefillId] = useState<string>("");

  const loadFromCard = (id: string) => {
    setPrefillId(id);
    if (!id) return;
    const card = cards.find((c) => c.decision_card_id === id);
    if (!card) return;
    setForm({
      event_id: card.event_id,
      source: card.source,
      event_type: card.event_type,
      language: card.language || "en",
      risk_score_rule: card.risk_score_rule,
      risk_score_fl: card.risk_score_fl,
      risk_score_final: card.risk_score_final,
      label: card.label,
      action: card.permitted_action,
      explanation: card.explanation,
      policy_rule_id: card.policy_rule_id,
      policy_reason: card.explanation || "",
      requires_human_review: card.requires_human_review,
      features: {},
      scenario_id: card.scenario_id ?? null,
      mode: null,
    });
    setResp(null);
    setErr(null);
  };

  const submit = async () => {
    setRunning(true);
    setErr(null);
    try {
      const body: LLMAssistRequest = {
        ...form,
        mode: form.mode ?? null,
      };
      const res = await api.llmAssist(body);
      setResp(res);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <PlayCircle size={14} className="text-accent" /> Playground
        </span>
      }
      subtitle={
        <>
          Craft a request and call <span className="mono">POST /assist</span>.
          Safe to run — responses are returned to the console only and are not
          written to the audit ledger.
        </>
      }
    >
      <div className="grid gap-4 xl:grid-cols-2">
        {/* ---- Form ---- */}
        <div className="space-y-3">
          <div>
            <label className="label" htmlFor="pg-card">
              Prefill from recent decision
            </label>
            <select
              id="pg-card"
              className="input mt-1"
              value={prefillId}
              onChange={(e) => loadFromCard(e.target.value)}
            >
              <option value="">— none (edit the sample below) —</option>
              {cards.slice(0, 30).map((c) => (
                <option key={c.decision_card_id} value={c.decision_card_id}>
                  {c.decision_card_id} · {c.event_type} · {c.permitted_action}
                </option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <TextField label="event_id" value={form.event_id} onChange={(v) => setForm({ ...form, event_id: v })} mono />
            <TextField label="source" value={form.source} onChange={(v) => setForm({ ...form, source: v })} mono />
            <TextField label="event_type" value={form.event_type} onChange={(v) => setForm({ ...form, event_type: v })} mono />
            <TextField label="label" value={form.label} onChange={(v) => setForm({ ...form, label: v })} mono />
            <TextField label="action" value={form.action} onChange={(v) => setForm({ ...form, action: v })} mono />
            <TextField label="policy_rule_id" value={form.policy_rule_id} onChange={(v) => setForm({ ...form, policy_rule_id: v })} mono />
          </div>

          <div className="grid grid-cols-3 gap-2">
            <NumberField label="risk_score_rule" value={form.risk_score_rule} onChange={(v) => setForm({ ...form, risk_score_rule: v })} />
            <NumberField label="risk_score_fl" value={form.risk_score_fl ?? 0} onChange={(v) => setForm({ ...form, risk_score_fl: v })} />
            <NumberField label="risk_score_final" value={form.risk_score_final} onChange={(v) => setForm({ ...form, risk_score_final: v })} />
          </div>

          <div>
            <label className="label" htmlFor="pg-explanation">
              explanation
            </label>
            <textarea
              id="pg-explanation"
              className="input mt-1 min-h-[60px] font-mono text-[12.5px]"
              value={form.explanation}
              onChange={(e) => setForm({ ...form, explanation: e.target.value })}
            />
          </div>

          <div>
            <label className="label" htmlFor="pg-reason">
              policy_reason
            </label>
            <input
              id="pg-reason"
              className="input mt-1 font-mono text-[12.5px]"
              value={form.policy_reason}
              onChange={(e) => setForm({ ...form, policy_reason: e.target.value })}
            />
          </div>

          <div className="flex items-center gap-4">
            <label className="inline-flex items-center gap-2 text-sm text-subtle">
              <input
                type="checkbox"
                checked={!!form.requires_human_review}
                onChange={(e) =>
                  setForm({ ...form, requires_human_review: e.target.checked })
                }
              />
              requires_human_review
            </label>
            <div className="flex-1">
              <label className="label" htmlFor="pg-mode">
                mode (optional)
              </label>
              <select
                id="pg-mode"
                className="input mt-1 font-mono text-[12.5px]"
                value={form.mode ?? ""}
                onChange={(e) =>
                  setForm({
                    ...form,
                    mode:
                      e.target.value === ""
                        ? null
                        : (e.target.value as LLMAssistRequest["mode"]),
                  })
                }
              >
                <option value="">— server default —</option>
                {MODE_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center gap-3 pt-1">
            <button
              className="btn btn-primary"
              onClick={submit}
              disabled={running}
            >
              <PlayCircle size={14} /> {running ? "Calling…" : "Run /assist"}
            </button>
            <button
              className="btn"
              onClick={() => {
                setForm(SAMPLE);
                setPrefillId("");
                setResp(null);
                setErr(null);
              }}
              disabled={running}
            >
              Reset to sample
            </button>
            {err && (
              <span className="inline-flex items-center gap-1 text-xs text-sev-critical">
                <AlertTriangle size={14} /> {err}
              </span>
            )}
          </div>
        </div>

        {/* ---- Response ---- */}
        <div className="space-y-3">
          {!resp ? (
            <EmptyState
              title="No response yet"
              description="Fill in the form (or prefill from a recent alert) and click Run."
              icon={<BrainCircuit size={22} />}
            />
          ) : (
            <AssistResponseView resp={resp} />
          )}
        </div>
      </div>
    </Card>
  );
}

export function AssistResponseView({ resp }: { resp: LLMAssistResponse }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {resp.llm_used ? (
          <span className="inline-flex items-center gap-1 rounded-md border border-sev-low/40 bg-sev-low/10 px-2 py-0.5 text-[11px] text-sev-low">
            <CheckCircle2 size={12} /> llm_used
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 rounded-md border border-border bg-muted px-2 py-0.5 text-[11px] text-dim">
            <XCircle size={12} /> fallback
          </span>
        )}
        <Chip>tier: {resp.llm_tier}</Chip>
        {resp.llm_provider && <Chip>provider: {resp.llm_provider}</Chip>}
        {resp.llm_model && <Chip>model: {resp.llm_model}</Chip>}
      </div>
      <div className="rounded-lg border border-border bg-muted/40 p-3">
        <div className="label mb-1">Reason</div>
        <div className="mono text-[12.5px] text-subtle">{resp.llm_reason}</div>
      </div>
      <div className="rounded-lg border border-border bg-muted/40 p-3">
        <div className="label mb-1">Analyst summary</div>
        <p className="whitespace-pre-wrap text-sm leading-relaxed text-text">
          {resp.analyst_summary || "—"}
        </p>
      </div>
      <div className="rounded-lg border border-border bg-muted/40 p-3">
        <div className="label mb-1">Helpdesk explanation</div>
        <p className="whitespace-pre-wrap text-sm leading-relaxed text-text">
          {resp.helpdesk_explanation || "—"}
        </p>
      </div>
      <div className="rounded-lg border border-border bg-muted/40 p-3">
        <div className="label mb-1">Next steps</div>
        <ol className="list-decimal space-y-1 pl-5 text-sm text-text">
          {(resp.next_steps ?? []).length === 0 && (
            <li className="list-none text-dim">—</li>
          )}
          {(resp.next_steps ?? []).map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ol>
      </div>
      <details className="rounded-lg border border-border bg-muted/40 p-3">
        <summary className="cursor-pointer text-[12px] text-subtle">
          Raw JSON
        </summary>
        <div className="mt-2">
          <JsonView value={resp} />
        </div>
      </details>
    </div>
  );
}

function TextField({
  label,
  value,
  onChange,
  mono,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  mono?: boolean;
}) {
  const id = `pg-${label}`;
  return (
    <div>
      <label className="label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        className={`input mt-1 ${mono ? "font-mono text-[12.5px]" : ""}`}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

function NumberField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
}) {
  const id = `pg-${label}`;
  return (
    <div>
      <label className="label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        type="number"
        step="0.01"
        className="input mt-1 font-mono text-[12.5px]"
        value={Number.isFinite(value) ? value : 0}
        onChange={(e) => onChange(Number(e.target.value))}
      />
    </div>
  );
}
