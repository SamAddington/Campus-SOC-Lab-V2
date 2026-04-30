import { useEffect, type ReactNode } from "react";
import { X } from "lucide-react";

export function Modal({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
  size = "md",
}: {
  open: boolean;
  onClose: () => void;
  title?: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  size?: "sm" | "md" | "lg";
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [open, onClose]);

  if (!open) return null;

  const widths = {
    sm: "max-w-sm",
    md: "max-w-lg",
    lg: "max-w-3xl",
  }[size];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden
      />
      <div
        role="dialog"
        aria-modal="true"
        className={`relative w-full ${widths} rounded-xl border border-border bg-surface shadow-card`}
      >
        <header className="flex items-start justify-between gap-4 border-b border-border px-4 py-3">
          <div>
            {title && <h3 className="text-sm font-semibold text-text">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs text-subtle">{subtitle}</p>}
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded-md p-1 text-subtle hover:bg-muted hover:text-text"
          >
            <X size={16} />
          </button>
        </header>
        <div className="px-4 py-3">{children}</div>
        {footer && (
          <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
            {footer}
          </footer>
        )}
      </div>
    </div>
  );
}
