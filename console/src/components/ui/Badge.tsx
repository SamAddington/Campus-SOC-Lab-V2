import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import type { Severity } from "@/lib/format";

const sevClass: Record<Severity, string> = {
  info:     "bg-sev-info/10 text-sev-info border-sev-info/30",
  low:      "bg-sev-low/10 text-sev-low border-sev-low/30",
  medium:   "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
  high:     "bg-sev-high/10 text-sev-high border-sev-high/30",
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
};

export function SeverityBadge({
  severity,
  children,
  dot = true,
  className,
}: {
  severity: Severity;
  children: ReactNode;
  dot?: boolean;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider",
        sevClass[severity],
        className,
      )}
    >
      {dot && (
        <span
          className={cn(
            "inline-block h-1.5 w-1.5 rounded-full animate-pulseDot",
            severity === "critical" && "bg-sev-critical",
            severity === "high" && "bg-sev-high",
            severity === "medium" && "bg-sev-medium",
            severity === "low" && "bg-sev-low",
            severity === "info" && "bg-sev-info",
          )}
        />
      )}
      {children}
    </span>
  );
}

export function Chip({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("chip", className)}>{children}</span>;
}
