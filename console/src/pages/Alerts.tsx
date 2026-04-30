import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Filter, RefreshCw, Search as SearchIcon, ShieldAlert } from "lucide-react";
import { api, type DecisionCard, type OverrideRecord } from "@/lib/api";
import { subscribe } from "@/lib/sse";
import { Card } from "@/components/ui/Card";
import { SeverityBadge, Chip } from "@/components/ui/Badge";
import {
  actionSeverity,
  formatScore,
  relativeTime,
  sevTextClass,
  severityFromScore,
  truncateMiddle,
} from "@/lib/format";
import { cn } from "@/lib/cn";

const ACTIONS = ["all", "escalate", "queue_for_review", "allow"] as const;
type ActionFilter = (typeof ACTIONS)[number];

export function Alerts() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [cards, setCards] = useState<DecisionCard[]>([]);
  const [overrides, setOverrides] = useState<OverrideRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [action, setAction] = useState<ActionFilter>("all");
  const [source, setSource] = useState<string>("");
  const [eventType, setEventType] = useState<string>("");
  const [policyRule, setPolicyRule] = useState<string>("");
  const [scenario, setScenario] = useState<string>("");
  const [language, setLanguage] = useState<string>("");
  const [osintVerdict, setOsintVerdict] = useState<string>("");
  const [sinceMs, setSinceMs] = useState<number>(0);
  const [live, setLive] = useState(false);
  const [highlightIds, setHighlightIds] = useState<Set<string>>(new Set());
  const cardsRef = useRef<DecisionCard[]>([]);

  const load = async () => {
    setLoading(true);
    try {
      const [r, o] = await Promise.all([api.decisionCards(500), api.overrides(200)]);
      const sorted = (r.items ?? []).slice().reverse();
      setCards(sorted);
      cardsRef.current = sorted;
      setOverrides((o.items ?? []) as OverrideRecord[]);
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // URL -> local state (drilldowns)
  useEffect(() => {
    const q = searchParams.get("q") ?? "";
    const a = (searchParams.get("action") ?? "all") as ActionFilter;
    const src = searchParams.get("source") ?? "";
    const et = searchParams.get("event_type") ?? "";
    const pr = searchParams.get("policy_rule") ?? "";
    const sc = searchParams.get("scenario") ?? "";
    const lang = searchParams.get("language") ?? "";
    const ov = searchParams.get("osint_verdict") ?? "";
    const since = Number(searchParams.get("since_ms") ?? "0");

    setQuery(q);
    setAction(ACTIONS.includes(a) ? a : "all");
    setSource(src);
    setEventType(et);
    setPolicyRule(pr);
    setScenario(sc);
    setLanguage(lang);
    setOsintVerdict(ov);
    setSinceMs(Number.isFinite(since) ? since : 0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // local state -> URL (shareable)
  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    const setOrDel = (k: string, v: string) => {
      const val = v.trim();
      if (val) next.set(k, val);
      else next.delete(k);
    };
    setOrDel("q", query);
    if (action && action !== "all") next.set("action", action);
    else next.delete("action");
    setOrDel("source", source);
    setOrDel("event_type", eventType);
    setOrDel("policy_rule", policyRule);
    setOrDel("scenario", scenario);
    setOrDel("language", language);
    setOrDel("osint_verdict", osintVerdict);
    if (sinceMs > 0) next.set("since_ms", String(sinceMs));
    else next.delete("since_ms");
    setSearchParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, action, source, eventType, policyRule, scenario, language, osintVerdict, sinceMs]);

  useEffect(() => {
    const unsub = subscribe<DecisionCard | OverrideRecord>(
      api.auditStreamUrl(),
      ["decision", "override", "hello"],
      {
        onOpen: () => setLive(true),
        onError: () => setLive(false),
        onEvent: (evt, data) => {
          if (!data || evt === "hello") return;
          if (evt === "decision") {
            const card = data as DecisionCard;
            const next = [card, ...cardsRef.current].slice(0, 1000);
            cardsRef.current = next;
            setCards(next);
            setHighlightIds((s) => {
              const n = new Set(s);
              n.add(card.decision_card_id);
              return n;
            });
            window.setTimeout(() => {
              setHighlightIds((s) => {
                const n = new Set(s);
                n.delete(card.decision_card_id);
                return n;
              });
            }, 2000);
          } else if (evt === "override") {
            const rec = data as OverrideRecord;
            setOverrides((prev) => [rec, ...prev].slice(0, 500));
          }
        },
      },
    );
    return unsub;
  }, []);

  const overrideMap = useMemo(() => {
    const m = new Map<string, OverrideRecord>();
    for (const o of overrides) {
      // last one wins (most recent)
      if (!m.has(o.decision_card_id)) m.set(o.decision_card_id, o);
    }
    return m;
  }, [overrides]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return cards.filter((c) => {
      if (action !== "all" && c.permitted_action !== action) return false;
      if (source.trim() && c.source !== source.trim()) return false;
      if (eventType.trim() && c.event_type !== eventType.trim()) return false;
      if (policyRule.trim() && c.policy_rule_id !== policyRule.trim()) return false;
      if (scenario.trim() && (c.scenario_id ?? "") !== scenario.trim()) return false;
      if (language.trim() && (c.language ?? "") !== language.trim()) return false;
      if (osintVerdict.trim()) {
        const v = String(c.osint_verdict ?? "").toLowerCase();
        if (v !== osintVerdict.trim().toLowerCase()) return false;
      }
      if (sinceMs > 0) {
        const t = Date.parse(c.timestamp);
        if (!Number.isNaN(t) && t < sinceMs) return false;
      }
      if (!q) return true;
      return [
        c.event_id,
        c.decision_card_id,
        c.source,
        c.event_type,
        c.label,
        c.policy_rule_id,
        c.scenario_id ?? "",
      ]
        .join(" ")
        .toLowerCase()
        .includes(q);
    });
  }, [cards, query, action]);

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text">Alerts</h1>
          <p className="mt-1 text-sm text-subtle">
            Decision cards from the orchestrator-backed audit ledger.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={
              "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs " +
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
            {live ? "live" : "offline"}
          </span>
          <button onClick={load} className="btn" disabled={loading}>
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>
      </header>

      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[240px]">
            <SearchIcon
              size={14}
              className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-dim"
            />
            <input
              className="input pl-8"
              placeholder="Filter by event id, source, rule, label…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <div className="flex items-center gap-1 text-xs text-subtle">
            <Filter size={14} />
            Action
          </div>
          <div className="flex flex-wrap gap-1">
            {ACTIONS.map((a) => (
              <button
                key={a}
                onClick={() => setAction(a)}
                className={
                  "rounded-md border px-2.5 py-1 text-xs transition-colors " +
                  (action === a
                    ? "border-accent/50 bg-accent/10 text-accent"
                    : "border-border bg-muted text-subtle hover:text-text")
                }
              >
                {a.replace(/_/g, " ")}
              </button>
            ))}
          </div>
          <div className="ml-auto text-xs text-dim">
            <span className="mono">{filtered.length}</span> / {cards.length}
          </div>
        </div>

        <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-3 lg:grid-cols-6">
          <Field label="Source" value={source} onChange={setSource} placeholder="email_gateway" />
          <Field label="Event type" value={eventType} onChange={setEventType} placeholder="suspicious_email" />
          <Field label="Policy rule" value={policyRule} onChange={setPolicyRule} placeholder="EMAIL-HIGH-001" />
          <Field label="Scenario" value={scenario} onChange={setScenario} placeholder="phishing_burst" />
          <Field label="Language" value={language} onChange={setLanguage} placeholder="en" />
          <Field label="OSINT verdict" value={osintVerdict} onChange={setOsintVerdict} placeholder="malicious" />
        </div>

        {err && (
          <div className="mt-3 rounded-md border border-sev-critical/40 bg-sev-critical/10 p-3 text-sm text-sev-critical">
            {err}
          </div>
        )}

        <div className="mt-3 overflow-hidden rounded-lg border border-border">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60 text-left text-[11px] uppercase tracking-wider text-dim">
              <tr>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Label / Event</th>
                <th className="px-3 py-2">Source</th>
                <th className="px-3 py-2">Rule</th>
                <th className="px-3 py-2">Score</th>
                <th className="px-3 py-2">OSINT</th>
                <th className="px-3 py-2">LLM</th>
                <th className="px-3 py-2">When</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-3 py-8 text-center text-sm text-dim">
                    {loading ? "Loading…" : "No alerts match your filters."}
                  </td>
                </tr>
              )}
              {filtered.map((c) => {
                const sev = actionSeverity(c.permitted_action);
                const scoreSev = severityFromScore(c.risk_score_final);
                const overridden = overrideMap.get(c.decision_card_id);
                return (
                  <tr
                    key={c.decision_card_id}
                    className={cn(
                      "border-t border-border/80 hover:bg-muted/50 transition-colors",
                      highlightIds.has(c.decision_card_id) && "bg-accent/5",
                    )}
                  >
                    <td className="whitespace-nowrap px-3 py-2">
                      <SeverityBadge severity={sev}>
                        {c.permitted_action.replace(/_/g, " ")}
                      </SeverityBadge>
                      {overridden && (
                        <div className="mt-1 inline-flex items-center gap-1 text-[10px] text-sev-medium">
                          <ShieldAlert size={11} /> overridden →{" "}
                          {overridden.overridden_action.replace(/_/g, " ")}
                        </div>
                      )}
                    </td>
                    <td className="min-w-0 px-3 py-2">
                      <Link
                        to={`/alerts/${encodeURIComponent(c.decision_card_id)}`}
                        className="block"
                      >
                        <div className="truncate text-text">
                          {c.label || c.event_type}
                        </div>
                        <div className="mono truncate text-[11px] text-dim">
                          {truncateMiddle(c.event_id, 28)}
                        </div>
                      </Link>
                    </td>
                    <td className="px-3 py-2 text-subtle">{c.source}</td>
                    <td className="px-3 py-2">
                      <Chip>{c.policy_rule_id}</Chip>
                    </td>
                    <td className="px-3 py-2">
                      <span className={`mono font-semibold ${sevTextClass[scoreSev]}`}>
                        {formatScore(c.risk_score_final)}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-subtle">
                      {c.osint_enabled && !c.osint_skipped ? (
                        <Chip>{c.osint_verdict ?? "unknown"}</Chip>
                      ) : (
                        <span className="text-dim">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-subtle">
                      {c.llm_used ? (
                        <Chip>{c.llm_provider ?? "used"}</Chip>
                      ) : (
                        <span className="text-dim">fallback</span>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-xs text-subtle">
                      {relativeTime(c.timestamp)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function Field({
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
    <label className="block">
      <div className="label mb-1">{label}</div>
      <input
        className="input"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}
