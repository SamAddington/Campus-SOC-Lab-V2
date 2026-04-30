import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Card, EmptyState } from "@/components/ui/Card";
import {
  api,
  type CorrelationAlert,
  type CorrelationDryRunResult,
  type CorrelationRule,
  type SavedSearch,
} from "@/lib/api";
import { relativeTime } from "@/lib/format";

export function Hunts() {
  const [searches, setSearches] = useState<SavedSearch[]>([]);
  const [rules, setRules] = useState<CorrelationRule[]>([]);
  const [alerts, setAlerts] = useState<CorrelationAlert[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [newName, setNewName] = useState("");
  const [newQ, setNewQ] = useState("");
  const [newSource, setNewSource] = useState("");
  const [newEventType, setNewEventType] = useState("");
  const [newLang, setNewLang] = useState("");

  const [ruleName, setRuleName] = useState("");
  const [ruleSearchId, setRuleSearchId] = useState("");
  const [ruleSchedule, setRuleSchedule] = useState(60);
  const [ruleDedup, setRuleDedup] = useState(300);
  const [ruleSeverity, setRuleSeverity] = useState("medium");
  const [ruleMode, setRuleMode] = useState<"search" | "sequence">("search");
  const [dryBusyId, setDryBusyId] = useState<string | null>(null);
  const [dryResult, setDryResult] = useState<CorrelationDryRunResult | null>(null);
  const [seqWithin, setSeqWithin] = useState(600);
  const [seqByField, setSeqByField] = useState("anon_record.user_id_hash");
  const [seqStepsJson, setSeqStepsJson] = useState(
    '[\n  {"search_id":"","source":"email_gateway","event_type":"","q":""},\n  {"search_id":"","source":"","event_type":"","q":"password"}\n]',
  );

  async function load() {
    setLoading(true);
    try {
      const [s, r, a] = await Promise.all([api.savedSearches(400), api.correlationRules(800), api.correlationAlerts(400)]);
      setSearches((s.items ?? []).slice().reverse());
      setRules((r.items ?? []).slice().reverse());
      setAlerts((a.items ?? []).slice().reverse());
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const searchIndex = useMemo(() => {
    const m = new Map<string, SavedSearch>();
    for (const s of searches) {
      const id = String(s.search_id || "");
      if (id) m.set(id, s);
    }
    return m;
  }, [searches]);

  const canCreateSearch = newName.trim().length >= 3;
  const parsedSteps = useMemo(() => {
    if (ruleMode !== "sequence") return null;
    try {
      const v = JSON.parse(seqStepsJson) as unknown;
      return Array.isArray(v) ? v : null;
    } catch {
      return null;
    }
  }, [ruleMode, seqStepsJson]);
  const canCreateRule =
    ruleName.trim().length >= 3 &&
    (ruleMode === "search"
      ? ruleSearchId.trim().length > 0
      : Boolean(parsedSteps && parsedSteps.length >= 2));

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold text-text">Hunts</h1>
        <p className="mt-1 text-sm text-subtle">
          Saved searches + scheduled correlation rules (runs against OpenSearch) + Notables (correlation alerts).
        </p>
      </header>

      {err && (
        <Card title="Error">
          <div className="text-sm text-sev-critical">{err}</div>
        </Card>
      )}

      <Card
        title="Saved searches"
        subtitle="Create reusable queries for hunting (stored in audit ledger)."
        action={
          <button className="btn" type="button" onClick={load} disabled={loading}>
            Refresh
          </button>
        }
      >
        <div className="grid gap-3 md:grid-cols-2">
          <label className="block">
            <div className="label mb-1">Name</div>
            <input className="input" value={newName} onChange={(e) => setNewName(e.target.value)} />
          </label>
          <label className="block">
            <div className="label mb-1">Query (q)</div>
            <input className="input mono" value={newQ} onChange={(e) => setNewQ(e.target.value)} placeholder="reset password urgent" />
          </label>
          <label className="block">
            <div className="label mb-1">Source</div>
            <input className="input mono" value={newSource} onChange={(e) => setNewSource(e.target.value)} placeholder="email_gateway" />
          </label>
          <label className="block">
            <div className="label mb-1">Event type</div>
            <input className="input mono" value={newEventType} onChange={(e) => setNewEventType(e.target.value)} placeholder="suspicious_email" />
          </label>
          <label className="block">
            <div className="label mb-1">Language</div>
            <input className="input mono" value={newLang} onChange={(e) => setNewLang(e.target.value)} placeholder="en" />
          </label>
          <div className="flex items-end">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!canCreateSearch}
              onClick={async () => {
                try {
                  await api.savedSearchCreate({
                    name: newName.trim(),
                    q: newQ.trim(),
                    source: newSource.trim(),
                    event_type: newEventType.trim(),
                    language: newLang.trim(),
                    include_message: false,
                  });
                  setNewName("");
                  setNewQ("");
                  setNewSource("");
                  setNewEventType("");
                  setNewLang("");
                  await load();
                } catch (e) {
                  setErr((e as Error).message);
                }
              }}
            >
              Create
            </button>
          </div>
        </div>

        <div className="mt-4">
          {searches.length === 0 ? (
            <EmptyState title="No saved searches" description="Create your first saved search above." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-xs text-dim">
                  <tr className="border-b border-border">
                    <th className="py-2 text-left">Name</th>
                    <th className="py-2 text-left">Query</th>
                    <th className="py-2 text-left">Updated</th>
                    <th className="py-2 text-left">Run</th>
                  </tr>
                </thead>
                <tbody>
                  {searches.map((s) => (
                    <tr key={String(s.search_id)} className="border-b border-border/60">
                      <td className="py-2">
                        <div className="font-medium text-text">{s.name}</div>
                        <div className="mono text-xs text-dim">{s.search_id}</div>
                      </td>
                      <td className="py-2 mono text-xs text-subtle">
                        {JSON.stringify({ q: s.q, source: s.source, event_type: s.event_type, language: s.language })}
                      </td>
                      <td className="py-2 text-dim">{relativeTime(String(s.updated_at || s.created_at || ""))}</td>
                      <td className="py-2">
                        <button
                          className="btn"
                          type="button"
                          onClick={async () => {
                            try {
                              const r = await api.collectorSearch({
                                q: String(s.q || ""),
                                source: String(s.source || ""),
                                event_type: String(s.event_type || ""),
                                language: String(s.language || ""),
                                limit: 50,
                                cursor: 0,
                                include_message: 0,
                              });
                              alert(`Matched ${r.count} event(s). Source: ${r.source ?? "unknown"}`);
                            } catch (e) {
                              setErr((e as Error).message);
                            }
                          }}
                        >
                          Run
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Card>

      <Card
        title="Correlation rules"
        subtitle="Search mode: one saved search on a schedule. Sequence mode: ordered steps joined by a field within a time window (collector scheduler)."
      >
        <div className="grid gap-3 md:grid-cols-2">
          <label className="block">
            <div className="label mb-1">Rule name</div>
            <input className="input" value={ruleName} onChange={(e) => setRuleName(e.target.value)} />
          </label>
          <label className="block">
            <div className="label mb-1">Mode</div>
            <select className="input" value={ruleMode} onChange={(e) => setRuleMode(e.target.value as "search" | "sequence")}>
              <option value="search">search (saved search)</option>
              <option value="sequence">sequence (EQL-ish)</option>
            </select>
          </label>
          {ruleMode === "search" ? (
            <label className="block md:col-span-2">
              <div className="label mb-1">Saved search</div>
              <select className="input" value={ruleSearchId} onChange={(e) => setRuleSearchId(e.target.value)}>
                <option value="">Select…</option>
                {searches.map((s) => (
                  <option key={String(s.search_id)} value={String(s.search_id)}>
                    {s.name}
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <>
              <label className="block">
                <div className="label mb-1">within_seconds</div>
                <input className="input mono" value={seqWithin} onChange={(e) => setSeqWithin(Number(e.target.value))} />
              </label>
              <label className="block">
                <div className="label mb-1">by_field (join key)</div>
                <input className="input mono" value={seqByField} onChange={(e) => setSeqByField(e.target.value)} />
              </label>
              <label className="block md:col-span-2">
                <div className="label mb-1">Steps (JSON array)</div>
                <textarea className="input mono min-h-[140px]" spellCheck={false} value={seqStepsJson} onChange={(e) => setSeqStepsJson(e.target.value)} />
                <div className="mt-1 text-xs text-dim">
                  Each step may use <span className="mono">search_id</span> (saved search) or inline{" "}
                  <span className="mono">q</span>/<span className="mono">source</span>/<span className="mono">event_type</span>.
                </div>
              </label>
            </>
          )}
          <label className="block">
            <div className="label mb-1">Schedule seconds</div>
            <input className="input mono" value={ruleSchedule} onChange={(e) => setRuleSchedule(Number(e.target.value))} />
          </label>
          <label className="block">
            <div className="label mb-1">Dedup seconds</div>
            <input className="input mono" value={ruleDedup} onChange={(e) => setRuleDedup(Number(e.target.value))} />
          </label>
          <label className="block">
            <div className="label mb-1">Severity</div>
            <select className="input" value={ruleSeverity} onChange={(e) => setRuleSeverity(e.target.value)}>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </label>
          <div className="flex items-end">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!canCreateRule}
              onClick={async () => {
                try {
                  if (ruleMode === "search") {
                    await api.correlationRuleCreate({
                      name: ruleName.trim(),
                      mode: "search",
                      search_id: ruleSearchId,
                      schedule_seconds: Math.max(10, Number(ruleSchedule || 60)),
                      dedup_seconds: Math.max(0, Number(ruleDedup || 0)),
                      severity: ruleSeverity,
                      enabled: true,
                    });
                  } else {
                    const steps = parsedSteps as Array<Record<string, unknown>>;
                    await api.correlationRuleCreate({
                      name: ruleName.trim(),
                      mode: "sequence",
                      search_id: "",
                      steps,
                      within_seconds: Math.max(30, Number(seqWithin || 600)),
                      by_field: seqByField.trim() || "anon_record.user_id_hash",
                      schedule_seconds: Math.max(10, Number(ruleSchedule || 60)),
                      dedup_seconds: Math.max(0, Number(ruleDedup || 0)),
                      severity: ruleSeverity,
                      enabled: true,
                    });
                  }
                  setRuleName("");
                  setRuleSearchId("");
                  await load();
                } catch (e) {
                  setErr((e as Error).message);
                }
              }}
            >
              Create rule
            </button>
          </div>
        </div>

        <div className="mt-4">
          {rules.length === 0 ? (
            <EmptyState title="No correlation rules" description="Create a rule above to start emitting notables." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-xs text-dim">
                  <tr className="border-b border-border">
                    <th className="py-2 text-left">Rule</th>
                    <th className="py-2 text-left">Mode</th>
                    <th className="py-2 text-left">Search / sequence</th>
                    <th className="py-2 text-left">Schedule</th>
                    <th className="py-2 text-left">Dedup</th>
                    <th className="py-2 text-left">Severity</th>
                    <th className="py-2 text-left">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((r) => (
                    <tr key={String(r.rule_id)} className="border-b border-border/60">
                      <td className="py-2">
                        <div className="font-medium text-text">{r.name}</div>
                        <div className="mono text-xs text-dim">{r.rule_id}</div>
                      </td>
                      <td className="py-2 mono text-xs">{String(r.mode ?? "search")}</td>
                      <td className="py-2 text-subtle">
                        {String(r.mode ?? "search") === "sequence"
                          ? `${(r.steps ?? []).length} step(s), ${String(r.within_seconds ?? 600)}s window`
                          : searchIndex.get(String(r.search_id))?.name ?? r.search_id}
                      </td>
                      <td className="py-2 mono">{String(r.schedule_seconds ?? 60)}s</td>
                      <td className="py-2 mono">{String(r.dedup_seconds ?? 300)}s</td>
                      <td className="py-2">
                        <span className="chip">{String(r.severity ?? "medium")}</span>
                      </td>
                      <td className="py-2">
                        <button
                          type="button"
                          className="btn"
                          disabled={!r.rule_id || dryBusyId === String(r.rule_id)}
                          onClick={async () => {
                            setDryBusyId(String(r.rule_id));
                            setDryResult(null);
                            try {
                              const out = await api.correlationDryRun(String(r.rule_id));
                              setDryResult(out);
                            } catch (e) {
                              setErr((e as Error).message);
                            } finally {
                              setDryBusyId(null);
                            }
                          }}
                        >
                          {dryBusyId === String(r.rule_id) ? "Running…" : "Dry run"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {dryResult ? (
            <div className="mt-4 rounded-lg border border-border bg-muted/20 p-3">
              <div className="text-xs font-semibold text-text">Last dry run</div>
              <pre className="mt-2 max-h-64 overflow-auto text-[11px] leading-relaxed text-subtle mono">
                {JSON.stringify(dryResult, null, 2)}
              </pre>
            </div>
          ) : null}
        </div>
      </Card>

      <Card title="Notables (correlation alerts)" subtitle="Emitted by scheduled rules when matches are found.">
        {alerts.length === 0 ? (
          <EmptyState title="No notables yet" description="Once rules run and match events, notables will appear here." />
        ) : (
          <div className="space-y-2">
            {alerts.slice(0, 30).map((a) => (
              <div key={String(a.alert_id)} className="rounded-lg border border-border bg-muted/20 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-text">{a.rule_name}</div>
                    <div className="mt-0.5 text-xs text-dim">{a.summary}</div>
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    <span className="chip">{String(a.severity ?? "medium")}</span>
                    <span className="mono text-dim">{relativeTime(String(a.created_at || ""))}</span>
                  </div>
                </div>
                {a.sample_event_ids?.length ? (
                  <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-subtle">
                    <span>
                      sample_event_ids: <span className="mono">{a.sample_event_ids.join(", ")}</span>
                    </span>
                    <Link
                      className="btn"
                      to={`/timeline?${new URLSearchParams({ event_ids: (a.sample_event_ids ?? []).join(",") }).toString()}`}
                    >
                      Open in timeline
                    </Link>
                  </div>
                ) : null}
              </div>
            ))}
            {alerts.length > 30 ? <div className="text-xs text-dim">Showing newest 30 notables.</div> : null}
          </div>
        )}
      </Card>
    </div>
  );
}

