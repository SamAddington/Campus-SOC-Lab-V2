import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export function Card({
  children,
  className,
  title,
  subtitle,
  action,
}: {
  children: ReactNode;
  className?: string;
  title?: ReactNode;
  subtitle?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <section className={cn("card", className)}>
      {(title || action) && (
        <header className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
          <div>
            {title && <h3 className="text-sm font-semibold text-text">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs text-subtle">{subtitle}</p>}
          </div>
          {action && <div className="shrink-0">{action}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function KeyValueGrid({ rows }: { rows: Array<{ k: ReactNode; v: ReactNode }> }) {
  return (
    <dl className="grid grid-cols-[minmax(120px,200px)_1fr] gap-x-6 gap-y-2 text-sm">
      {rows.map((r, i) => (
        <div key={i} className="contents">
          <dt className="label self-center">{r.k}</dt>
          <dd className="min-w-0 break-words text-text">{r.v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function EmptyState({
  title,
  description,
  icon,
  action,
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-muted/40 px-6 py-10 text-center">
      {icon && <div className="mb-3 text-dim">{icon}</div>}
      <div className="text-sm font-medium text-text">{title}</div>
      {description && <div className="mt-1 max-w-md text-xs text-subtle">{description}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
