import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { SeverityBadge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import { relativeTime } from "@/lib/format";

type ServiceKey =
  | "audit"
  | "orchestrator"
  | "simulator"
  | "collector"
  | "detector"
  | "policy"
  | "osint"
  | "llm"
  | "federated"
  | "traffic";

type ServiceRow = {
  key: ServiceKey;
  label: string;
  port: number;
  status: "up" | "down" | "unknown";
  latencyMs: number | null;
  checkedAt: string;
  error?: string;
};

const SERVICES: Array<{ key: ServiceKey; label: string; port: number }> = [
  { key: "orchestrator", label: "Orchestrator", port: 8021 },
  { key: "collector", label: "Collector", port: 8001 },
  { key: "detector", label: "Detector", port: 8000 },
  { key: "policy", label: "Policy Engine", port: 8020 },
  { key: "audit", label: "Audit", port: 8022 },
  { key: "simulator", label: "Simulator", port: 8023 },
  { key: "llm", label: "LLM Assistant", port: 8024 },
  { key: "osint", label: "OSINT", port: 8028 },
  { key: "federated", label: "Federated Aggregator", port: 8010 },
  { key: "traffic", label: "Traffic Ingestor", port: 8027 },
];

export function Services() {
  const [rows, setRows] = useState<ServiceRow[]>(() =>
    SERVICES.map((s) => ({
      key: s.key,
      label: s.label,
      port: s.port,
      status: "unknown",
      latencyMs: null,
      checkedAt: new Date().toISOString(),
    })),
  );
  const [loading, setLoading] = useState(false);

  const check = async () => {
    setLoading(true);
    const next = await Promise.all(
      SERVICES.map(async (s): Promise<ServiceRow> => {
        const t0 = performance.now();
        try {
          await api.health(s.key);
          return {
            key: s.key,
            label: s.label,
            port: s.port,
            status: "up",
            latencyMs: Math.round(performance.now() - t0),
            checkedAt: new Date().toISOString(),
          };
        } catch (e) {
          return {
            key: s.key,
            label: s.label,
            port: s.port,
            status: "down",
            latencyMs: null,
            checkedAt: new Date().toISOString(),
            error: (e as Error).message,
          };
        }
      }),
    );
    setRows(next);
    setLoading(false);
  };

  useEffect(() => {
    check();
    const id = window.setInterval(check, 15_000);
    return () => window.clearInterval(id);
  }, []);

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text">Services</h1>
          <p className="mt-1 text-sm text-subtle">Health of every backend in the stack.</p>
        </div>
        <button onClick={check} className="btn" disabled={loading}>
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          Check now
        </button>
      </header>

      <Card>
        <div className="overflow-hidden rounded-lg border border-border">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60 text-left text-[11px] uppercase tracking-wider text-dim">
              <tr>
                <th className="px-3 py-2">Service</th>
                <th className="px-3 py-2">Port</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Latency</th>
                <th className="px-3 py-2">Last checked</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.key} className="border-t border-border/80">
                  <td className="px-3 py-2 text-text">{r.label}</td>
                  <td className="px-3 py-2 mono text-subtle">{r.port}</td>
                  <td className="px-3 py-2">
                    <SeverityBadge
                      severity={
                        r.status === "up"
                          ? "low"
                          : r.status === "down"
                          ? "critical"
                          : "info"
                      }
                    >
                      {r.status}
                    </SeverityBadge>
                  </td>
                  <td className="px-3 py-2 mono text-subtle">
                    {r.latencyMs === null ? "—" : `${r.latencyMs} ms`}
                  </td>
                  <td className="px-3 py-2 text-xs text-subtle">
                    {relativeTime(r.checkedAt)}
                    {r.error && (
                      <span className="ml-2 text-sev-critical">{r.error}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
