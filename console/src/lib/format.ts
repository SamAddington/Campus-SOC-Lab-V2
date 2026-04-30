export type Severity = "info" | "low" | "medium" | "high" | "critical";

export function severityFromScore(score: number | null | undefined): Severity {
  if (score === null || score === undefined || Number.isNaN(Number(score))) return "info";
  const s = Number(score);
  if (s >= 0.85) return "critical";
  if (s >= 0.7) return "high";
  if (s >= 0.4) return "medium";
  if (s >= 0.2) return "low";
  return "info";
}

export function actionSeverity(action?: string | null): Severity {
  switch ((action || "").toLowerCase()) {
    case "escalate":
      return "critical";
    case "queue_for_review":
      return "medium";
    case "allow":
      return "low";
    default:
      return "info";
  }
}

export function formatScore(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  const n = Number(value);
  if (Number.isNaN(n)) return "—";
  return n.toFixed(2);
}

export function relativeTime(iso?: string | null): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const diffMs = Date.now() - t;
  const s = Math.round(diffMs / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  return `${d}d ago`;
}

export function absoluteTime(iso?: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

export const sevTextClass: Record<Severity, string> = {
  info: "text-sev-info",
  low: "text-sev-low",
  medium: "text-sev-medium",
  high: "text-sev-high",
  critical: "text-sev-critical",
};

export function truncateMiddle(value: string, max = 18): string {
  if (!value) return "";
  if (value.length <= max) return value;
  const keep = Math.max(4, Math.floor((max - 1) / 2));
  return `${value.slice(0, keep)}…${value.slice(-keep)}`;
}
