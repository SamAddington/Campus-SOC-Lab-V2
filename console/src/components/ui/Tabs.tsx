import { type ReactNode, createContext, useContext, useId, useState } from "react";
import { cn } from "@/lib/cn";

type Ctx = {
  value: string;
  setValue: (v: string) => void;
  idBase: string;
};

const TabsCtx = createContext<Ctx | null>(null);

export function Tabs({
  defaultValue,
  value,
  onValueChange,
  children,
  className,
}: {
  defaultValue: string;
  value?: string;
  onValueChange?: (v: string) => void;
  children: ReactNode;
  className?: string;
}) {
  const [internal, setInternal] = useState(defaultValue);
  const idBase = useId();
  const current = value ?? internal;
  const setValue = (v: string) => {
    if (value === undefined) setInternal(v);
    onValueChange?.(v);
  };
  return (
    <TabsCtx.Provider value={{ value: current, setValue, idBase }}>
      <div className={className}>{children}</div>
    </TabsCtx.Provider>
  );
}

export function TabsList({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      role="tablist"
      className={cn(
        "flex flex-wrap items-center gap-1 border-b border-border px-1",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function TabsTrigger({
  value,
  children,
  count,
}: {
  value: string;
  children: ReactNode;
  count?: number;
}) {
  const ctx = useContext(TabsCtx)!;
  const active = ctx.value === value;
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={() => ctx.setValue(value)}
      className={cn(
        "group relative -mb-px inline-flex items-center gap-2 rounded-t-md px-3 py-2 text-sm transition-colors",
        active
          ? "text-text"
          : "text-subtle hover:text-text",
      )}
    >
      <span>{children}</span>
      {typeof count === "number" && (
        <span
          className={cn(
            "rounded-full px-1.5 py-0.5 text-[10px] font-mono",
            active ? "bg-accent/15 text-accent" : "bg-muted text-subtle",
          )}
        >
          {count}
        </span>
      )}
      <span
        className={cn(
          "absolute inset-x-2 bottom-0 h-[2px] rounded-t-full transition-opacity",
          active ? "bg-accent opacity-100" : "opacity-0",
        )}
      />
    </button>
  );
}

export function TabsContent({
  value,
  children,
  className,
}: {
  value: string;
  children: ReactNode;
  className?: string;
}) {
  const ctx = useContext(TabsCtx)!;
  if (ctx.value !== value) return null;
  return (
    <div role="tabpanel" className={cn("pt-4", className)}>
      {children}
    </div>
  );
}
