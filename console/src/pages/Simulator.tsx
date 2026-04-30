import { useEffect, useState } from "react";
import { Play, RefreshCw } from "lucide-react";
import { Card, EmptyState } from "@/components/ui/Card";
import { Chip, SeverityBadge } from "@/components/ui/Badge";
import { JsonView } from "@/components/ui/JsonView";
import { api, type ScenarioMeta } from "@/lib/api";

type RunRow = {
  index: number;
  event_id: string;
  ok: boolean;
  status_code: number;
  response?: any;
  detail?: string;
};

export function Simulator() {
  const [scenarios, setScenarios] = useState<ScenarioMeta[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [pace, setPace] = useState(500);
  const [running, setRunning] = useState(false);
  const [summary, setSummary] = useState<any | null>(null);
  const [results, setResults] = useState<RunRow[]>([]);
  const [raw, setRaw] = useState<any | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const loadScenarios = async () => {
    try {
      const r = await api.scenarios();
      setScenarios(r.items ?? []);
      if (r.items?.length && !selected) setSelected(r.items[0].scenario_id);
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  useEffect(() => {
    loadScenarios();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const run = async () => {
    if (!selected) return;
    setRunning(true);
    setErr(null);
    try {
      const r = await api.runScenario({ scenario_id: selected, pace_ms: pace });
      setSummary(r.summary);
      setResults((r.results ?? []) as RunRow[]);
      setRaw(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  const current = scenarios.find((s) => s.scenario_id === selected);

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text">Simulator</h1>
          <p className="mt-1 text-sm text-subtle">
            Replay a campus security scenario through the orchestrator and watch the
            audit ledger populate.
          </p>
        </div>
        <button onClick={loadScenarios} className="btn">
          <RefreshCw size={14} />
          Refresh
        </button>
      </header>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Scenario" className="xl:col-span-1">
          <label className="label block">Scenario</label>
          <select
            className="input mt-1"
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
          >
            {scenarios.map((s) => (
              <option key={s.scenario_id} value={s.scenario_id}>
                {s.scenario_id}
              </option>
            ))}
            {scenarios.length === 0 && <option value="">(no scenarios)</option>}
          </select>

          <label className="label mt-4 block">Replay pace (ms)</label>
          <input
            type="number"
            min={0}
            step={100}
            value={pace}
            onChange={(e) => setPace(Number(e.target.value || 0))}
            className="input mt-1"
          />

          <button
            disabled={!selected || running}
            onClick={run}
            className="btn btn-primary mt-4 w-full justify-center"
          >
            <Play size={14} />
            {running ? "Running…" : "Run scenario"}
          </button>

          {err && (
            <div className="mt-3 rounded-md border border-sev-critical/40 bg-sev-critical/10 p-2 text-xs text-sev-critical">
              {err}
            </div>
          )}
        </Card>

        <Card title="Description" className="xl:col-span-2">
          {current ? (
            <div className="space-y-2 text-sm text-text">
              <div>
                <span className="label">ID </span>
                <span className="mono">{current.scenario_id}</span>
              </div>
              <div>
                <span className="label">File </span>
                <span className="mono">{current.file}</span>
              </div>
              <div>
                <span className="label">Event count </span>
                <span className="mono">{current.event_count}</span>
              </div>
              <p className="pt-2 text-subtle">
                {current.description || "No description provided."}
              </p>
            </div>
          ) : (
            <EmptyState title="No scenario selected" />
          )}
        </Card>
      </div>

      {summary && (
        <Card title="Run summary">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat label="Scenario" value={summary.scenario_id} mono />
            <Stat label="Total events" value={summary.total_events} />
            <Stat
              label="Success / Errors"
              value={`${summary.success_count ?? 0} / ${summary.error_count ?? 0}`}
            />
            <Stat label="Pace" value={`${summary.pace_ms} ms`} />
          </div>
          <div className="mt-3 grid grid-cols-1 gap-2 text-xs text-subtle sm:grid-cols-2">
            <div>
              <span className="label">Started </span>
              <span className="mono">{summary.started_at}</span>
            </div>
            <div>
              <span className="label">Ended </span>
              <span className="mono">{summary.ended_at}</span>
            </div>
            <div className="sm:col-span-2">
              <span className="label">Target </span>
              <span className="mono">{summary.target_url}</span>
            </div>
          </div>
        </Card>
      )}

      {results.length > 0 && (
        <Card title="Event results">
          <div className="overflow-hidden rounded-lg border border-border">
            <table className="w-full border-collapse text-sm">
              <thead className="bg-muted/60 text-left text-[11px] uppercase tracking-wider text-dim">
                <tr>
                  <th className="px-3 py-2">#</th>
                  <th className="px-3 py-2">Event ID</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">HTTP</th>
                  <th className="px-3 py-2">Detail</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r) => (
                  <tr key={r.index} className="border-t border-border/80">
                    <td className="px-3 py-2 mono text-dim">{r.index}</td>
                    <td className="px-3 py-2 mono">{r.event_id}</td>
                    <td className="px-3 py-2">
                      <SeverityBadge severity={r.ok ? "low" : "critical"}>
                        {r.ok ? "ok" : "error"}
                      </SeverityBadge>
                    </td>
                    <td className="px-3 py-2 mono text-subtle">{r.status_code}</td>
                    <td className="px-3 py-2 text-subtle">
                      {r.ok ? (
                        <Chip>
                          {r.response?.decision_card_id ??
                            r.response?.status ??
                            "processed"}
                        </Chip>
                      ) : (
                        <span className="text-sev-critical">
                          {typeof r.response === "string"
                            ? r.response
                            : r.detail ?? JSON.stringify(r.response ?? {})}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {raw && (
        <Card title="Raw response">
          <JsonView value={raw} />
        </Card>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="card-muted p-3">
      <div className="label">{label}</div>
      <div className={"mt-1 text-lg font-semibold " + (mono ? "mono" : "")}>{value}</div>
    </div>
  );
}
