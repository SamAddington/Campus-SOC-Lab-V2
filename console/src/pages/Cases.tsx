import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Plus, RefreshCw, FolderKanban } from "lucide-react";
import { Card, EmptyState } from "@/components/ui/Card";
import { api, type CaseRecord } from "@/lib/api";
import { relativeTime } from "@/lib/format";

export function Cases() {
  const [items, setItems] = useState<CaseRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [assignedTo, setAssignedTo] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      const r = await api.cases(300);
      setItems((r.items ?? []).slice().reverse());
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const canCreate = title.trim().length >= 4;

  async function onCreate() {
    if (!canCreate) return;
    try {
      await api.caseCreate({
        title: title.trim(),
        description: description.trim(),
        severity,
        assigned_to: assignedTo.trim() || null,
        status: "open",
      });
      setTitle("");
      setDescription("");
      setAssignedTo("");
      await load();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  const sorted = useMemo(() => {
    return items.slice().sort((a, b) => String(b.updated_at || "").localeCompare(String(a.updated_at || "")));
  }, [items]);

  return (
    <div className="space-y-4">
      <header className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-text">Cases</h1>
          <p className="mt-1 text-sm text-subtle">
            Lightweight case management (assignments, status, notes) — a stepping stone toward SIEM/SOC workflows.
          </p>
        </div>
        <button type="button" className="btn" onClick={load} disabled={loading}>
          <RefreshCw size={14} /> Refresh
        </button>
      </header>

      {err && (
        <Card title="Error">
          <div className="text-sm text-sev-critical">{err}</div>
        </Card>
      )}

      <Card
        title="Create case"
        subtitle="Requires analyst/admin role if JWT RBAC is enabled."
        action={
          <button type="button" className="btn btn-primary" onClick={onCreate} disabled={!canCreate}>
            <Plus size={14} /> Create
          </button>
        }
      >
        <div className="grid gap-3 md:grid-cols-2">
          <label className="block">
            <div className="label mb-1">Title</div>
            <input className="input" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Suspicious burst of reset emails" />
          </label>
          <label className="block">
            <div className="label mb-1">Assigned to (optional)</div>
            <input className="input mono" value={assignedTo} onChange={(e) => setAssignedTo(e.target.value)} placeholder="analyst-1" />
          </label>
          <label className="block md:col-span-2">
            <div className="label mb-1">Description</div>
            <textarea className="input min-h-[92px]" value={description} onChange={(e) => setDescription(e.target.value)} />
          </label>
          <label className="block">
            <div className="label mb-1">Severity</div>
            <select className="input" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </label>
          <div className="text-xs text-dim md:col-span-1">
            Tip: link related decision cards from Alert Detail in the next iteration.
          </div>
        </div>
      </Card>

      <Card title="Queue" subtitle={`${sorted.length} case(s)`}>
        {(() => {
          if (loading) return <div className="text-sm text-dim">Loading…</div>;
          if (sorted.length === 0) {
            return (
              <EmptyState
                title="No cases yet"
                description="Create a case to start tracking investigation workflow."
                icon={<FolderKanban size={18} />}
              />
            );
          }
          return (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-xs text-dim">
                  <tr className="border-b border-border">
                    <th className="py-2 text-left">Case</th>
                    <th className="py-2 text-left">Status</th>
                    <th className="py-2 text-left">Severity</th>
                    <th className="py-2 text-left">Assignee</th>
                    <th className="py-2 text-left">Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((c) => (
                    <tr key={String(c.case_id)} className="border-b border-border/60">
                      <td className="py-2">
                        <div className="font-medium text-text">
                          <Link
                            className="hover:underline"
                            to={`/cases/${encodeURIComponent(String(c.case_id || ""))}`}
                          >
                            {c.title}
                          </Link>
                        </div>
                        <div className="mono text-xs text-dim">{c.case_id}</div>
                      </td>
                      <td className="py-2">
                        <span className="chip">{String(c.status || "open")}</span>
                      </td>
                      <td className="py-2">
                        <span className="chip">{String(c.severity || "medium")}</span>
                      </td>
                      <td className="py-2 mono">{String(c.assigned_to || "—")}</td>
                      <td className="py-2 text-dim">{relativeTime(String(c.updated_at || c.created_at || ""))}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        })()}
      </Card>
    </div>
  );
}

