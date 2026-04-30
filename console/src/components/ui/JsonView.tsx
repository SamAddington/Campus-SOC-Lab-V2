import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { cn } from "@/lib/cn";

export function JsonView({ value, className }: { value: unknown; className?: string }) {
  const [copied, setCopied] = useState(false);
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* noop */
    }
  };
  return (
    <div className={cn("relative rounded-lg border border-border bg-muted", className)}>
      <button
        type="button"
        onClick={copy}
        className="absolute right-2 top-2 inline-flex items-center gap-1 rounded border border-border bg-elev px-2 py-1 text-[11px] text-subtle hover:text-text"
      >
        {copied ? <Check size={12} /> : <Copy size={12} />}
        {copied ? "Copied" : "Copy"}
      </button>
      <pre className="mono max-h-[420px] overflow-auto whitespace-pre-wrap break-words p-3 pr-16 text-[12px] leading-relaxed text-subtle">
        {text}
      </pre>
    </div>
  );
}
