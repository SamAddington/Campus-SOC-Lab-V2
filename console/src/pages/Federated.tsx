import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { Card, KeyValueGrid } from "@/components/ui/Card";
import { Chip, SeverityBadge } from "@/components/ui/Badge";
import { JsonView } from "@/components/ui/JsonView";
import { api, type FederatedStatus, type GlobalModel } from "@/lib/api";
import { absoluteTime, relativeTime } from "@/lib/format";

export function Federated() {
  const [status, setStatus] = useState<FederatedStatus | null>(null);
  const [model, setModel] = useState<GlobalModel | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [modelErr, setModelErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const s = await api.federatedStatus();
      setStatus(s);
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    }
    try {
      const m = await api.globalModel();
      setModel(m);
      setModelErr(null);
    } catch (e) {
      setModelErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const id = window.setInterval(load, 8000);
    return () => window.clearInterval(id);
  }, []);

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text">Federated ML</h1>
          <p className="mt-1 text-sm text-subtle">
            Round state from the aggregator and the currently deployed global model.
          </p>
        </div>
        <button onClick={load} className="btn" disabled={loading}>
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </header>

      {err && (
        <div className="rounded-md border border-sev-critical/40 bg-sev-critical/10 p-3 text-sm text-sev-critical">
          Aggregator unreachable: {err}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Round state" className="xl:col-span-1">
          {status ? (
            <KeyValueGrid
              rows={[
                { k: "Round", v: <span className="mono">{status.round}</span> },
                {
                  k: "Status",
                  v: (
                    <SeverityBadge
                      severity={status.status === "aggregated" ? "low" : "medium"}
                    >
                      {status.status}
                    </SeverityBadge>
                  ),
                },
                {
                  k: "Updated",
                  v: (
                    <span>
                      {relativeTime(status.updated_at)}
                      <span className="ml-2 text-dim">{absoluteTime(status.updated_at)}</span>
                    </span>
                  ),
                },
              ]}
            />
          ) : (
            <div className="text-xs text-dim">Loading…</div>
          )}
        </Card>

        <Card title="Clients" className="xl:col-span-2">
          {status ? (
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              {status.expected_clients.map((c) => {
                const received = status.received_updates.includes(c);
                return (
                  <div
                    key={c}
                    className="flex items-center justify-between rounded-lg border border-border bg-muted px-3 py-2"
                  >
                    <div>
                      <div className="mono text-sm text-text">{c}</div>
                      <div className="text-[11px] text-dim">
                        {received ? "update submitted" : "awaiting update"}
                      </div>
                    </div>
                    <SeverityBadge severity={received ? "low" : "medium"}>
                      {received ? "ready" : "pending"}
                    </SeverityBadge>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-xs text-dim">Loading…</div>
          )}
        </Card>

        <Card title="Global model" className="xl:col-span-3">
          {modelErr && (
            <div className="mb-3 rounded-md border border-border bg-muted px-3 py-2 text-xs text-subtle">
              No global model yet. Trigger <span className="mono">POST /aggregate</span> on the aggregator once clients have submitted updates.
            </div>
          )}
          {model && (
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
              <KeyValueGrid
                rows={[
                  { k: "Round", v: <span className="mono">{model.round}</span> },
                  { k: "Num clients", v: <span className="mono">{model.num_clients}</span> },
                  { k: "Total samples", v: <span className="mono">{model.total_samples}</span> },
                  {
                    k: "Intercept",
                    v: <span className="mono">{model.intercept?.toFixed?.(4) ?? model.intercept}</span>,
                  },
                  { k: "Updated", v: relativeTime(model.updated_at) },
                ]}
              />
              <div className="xl:col-span-2">
                <div className="label mb-2">Coefficients</div>
                <div className="overflow-hidden rounded-lg border border-border">
                  <table className="w-full border-collapse text-sm">
                    <thead className="bg-muted/60 text-left text-[11px] uppercase tracking-wider text-dim">
                      <tr>
                        <th className="px-3 py-2">Feature</th>
                        <th className="px-3 py-2">Weight</th>
                        <th className="px-3 py-2">Magnitude</th>
                      </tr>
                    </thead>
                    <tbody>
                      {model.feature_order.map((f, i) => {
                        const w = model.coef[i];
                        const max =
                          model.coef.reduce((m, c) => Math.max(m, Math.abs(c)), 0) || 1;
                        const pct = (Math.abs(w) / max) * 100;
                        const neg = w < 0;
                        return (
                          <tr key={f} className="border-t border-border/80">
                            <td className="px-3 py-2 mono">{f}</td>
                            <td className="px-3 py-2 mono">{w?.toFixed?.(3) ?? w}</td>
                            <td className="px-3 py-2">
                              <div className="h-1.5 w-full overflow-hidden rounded-full bg-elev">
                                <div
                                  className={
                                    "h-full rounded-full " +
                                    (neg ? "bg-sev-info" : "bg-accent/80")
                                  }
                                  style={{ width: `${pct}%` }}
                                />
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <div className="mt-2 flex gap-2 text-[11px] text-dim">
                  <Chip>positive → raises risk</Chip>
                  <Chip>negative → lowers risk</Chip>
                </div>
              </div>
            </div>
          )}
        </Card>

        {model && (
          <Card className="xl:col-span-3" title="Model (raw)">
            <JsonView value={model} />
          </Card>
        )}
      </div>
    </div>
  );
}
