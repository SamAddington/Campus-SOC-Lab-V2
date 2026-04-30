import { cn } from "@/lib/cn";
import { formatScore, severityFromScore } from "@/lib/format";

export function ScoreBar({
  label,
  value,
  hint,
  className,
}: {
  label: string;
  value: number | null | undefined;
  hint?: string;
  className?: string;
}) {
  const sev = severityFromScore(value);
  const pct =
    value === null || value === undefined || Number.isNaN(Number(value))
      ? 0
      : Math.max(0, Math.min(1, Number(value))) * 100;

  const barColor = {
    info: "bg-sev-info",
    low: "bg-sev-low",
    medium: "bg-sev-medium",
    high: "bg-sev-high",
    critical: "bg-sev-critical",
  }[sev];

  return (
    <div className={cn("rounded-lg border border-border bg-muted p-3", className)}>
      <div className="flex items-center justify-between">
        <div className="label">{label}</div>
        <div className="mono text-lg font-semibold text-text">{formatScore(value)}</div>
      </div>
      <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-elev">
        <div
          className={cn("h-full rounded-full transition-all", barColor)}
          style={{ width: `${pct}%` }}
        />
      </div>
      {hint && <div className="mt-1 text-[11px] text-dim">{hint}</div>}
    </div>
  );
}
