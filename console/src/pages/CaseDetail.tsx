import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Send, UserPlus, CheckCircle2 } from "lucide-react";
import { Card, EmptyState } from "@/components/ui/Card";
import { api, type CaseNote, type CaseRecord } from "@/lib/api";
import { relativeTime } from "@/lib/format";

export function CaseDetail() {
  const { caseId } = useParams();
  const [item, setItem] = useState<CaseRecord | null>(null);
  const [notes, setNotes] = useState<CaseNote[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const [noteBody, setNoteBody] = useState("");
  const [assignee, setAssignee] = useState("");
  const [status, setStatus] = useState("open");
  const [events, setEvents] = useState<Array<Record<string, unknown>>>([]);
  const [eventsErr, setEventsErr] = useState<string | null>(null);

  const load = async () => {
    if (!caseId) return;
    setLoading(true);
    try {
      const r = await api.caseGet(caseId);
      setItem(r.case ?? null);
      setNotes(r.notes ?? []);
      setStatus(String(r.case?.status ?? "open"));
      setAssignee(String(r.case?.assigned_to ?? ""));
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
  }, [caseId]);

  async function onAddNote() {
    if (!caseId) return;
    const body = noteBody.trim();
    if (!body) return;
    try {
      await api.caseNote(caseId, body);
      setNoteBody("");
      await load();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  async function onAssign() {
    if (!caseId) return;
    try {
      await api.caseAssign(caseId, assignee.trim());
      await load();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  async function onSetStatus(next: string) {
    if (!caseId) return;
    try {
      await api.caseStatus(caseId, next);
      await load();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  if (loading) {
    return <div className="text-sm text-dim">Loading…</div>;
  }

  if (err) {
    return (
      <Card title="Error">
        <div className="text-sm text-sev-critical">{err}</div>
      </Card>
    );
  }

  if (!item) {
    return <EmptyState title="Case not found" description="The case may have been deleted or the ID is wrong." />;
  }

  const relatedEventIds = (item.related_event_ids ?? []).filter(Boolean).map(String);
  const timelineHref =
    relatedEventIds.length > 0
      ? `/timeline?${new URLSearchParams({ event_ids: relatedEventIds.join(",") }).toString()}`
      : "/timeline";

  return (
    <div className="space-y-4">
      <header className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <Link to="/cases" className="inline-flex items-center gap-2 text-xs text-subtle hover:text-text">
            <ArrowLeft size={14} /> Back to cases
          </Link>
          <h1 className="mt-2 truncate text-xl font-semibold text-text">{item.title}</h1>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-dim">
            <span className="chip">{String(item.status || "open")}</span>
            <span className="chip">{String(item.severity || "medium")}</span>
            <span className="mono">{String(item.case_id)}</span>
            <span>· updated {relativeTime(String(item.updated_at || item.created_at || ""))}</span>
          </div>
        </div>
      </header>

      <Card title="Workflow">
        {item.sla_response_due_at ? (
          <div className="mb-3 rounded-lg border border-border bg-muted/20 p-3 text-xs text-subtle">
            <div>
              <span className="label">First-response SLA due</span>{" "}
              <span className="mono text-text">{String(item.sla_response_due_at)}</span>
            </div>
            {item.first_acknowledged_at ? (
              <div className="mt-1">
                Acknowledged <span className="mono text-text">{String(item.first_acknowledged_at)}</span>
              </div>
            ) : (
              <div className="mt-1 text-sev-medium">Not yet acknowledged / triaged.</div>
            )}
            {item.resolved_at ? (
              <div className="mt-1">
                Resolved <span className="mono text-text">{String(item.resolved_at)}</span>
              </div>
            ) : null}
          </div>
        ) : null}
        <div className="grid gap-3 md:grid-cols-3">
          <label className="block">
            <div className="label mb-1">Status</div>
            <select className="input" value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="open">open</option>
              <option value="triaged">triaged</option>
              <option value="in_progress">in_progress</option>
              <option value="pending_customer">pending_customer</option>
              <option value="resolved">resolved</option>
              <option value="closed">closed</option>
            </select>
            <button type="button" className="btn mt-2 w-full" onClick={() => onSetStatus(status)}>
              <CheckCircle2 size={14} /> Update status
            </button>
          </label>

          <label className="block md:col-span-2">
            <div className="label mb-1">Assignee</div>
            <div className="flex gap-2">
              <input className="input mono flex-1" value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="analyst-1" />
              <button type="button" className="btn" onClick={onAssign}>
                <UserPlus size={14} /> Assign
              </button>
            </div>
            <div className="mt-1 text-xs text-dim">
              Mutations require analyst/admin role if JWT RBAC is enabled.
            </div>
          </label>
        </div>
      </Card>

      <Card title="Description">
        <div className="whitespace-pre-wrap text-sm text-subtle">{String(item.description || "—")}</div>
      </Card>

      <Card title="Notes" subtitle={`${notes.length} note(s)`}>
        <div className="space-y-3">
          <div className="grid gap-2">
            <textarea className="input min-h-[88px]" value={noteBody} onChange={(e) => setNoteBody(e.target.value)} placeholder="Add investigation notes, decisions, and evidence pointers…" />
            <button type="button" className="btn btn-primary justify-center" onClick={onAddNote} disabled={!noteBody.trim()}>
              <Send size={14} /> Add note
            </button>
          </div>
          {notes.length === 0 ? (
            <EmptyState title="No notes yet" description="Add the first note to start documenting investigation work." />
          ) : (
            <ul className="space-y-2">
              {notes
                .slice()
                .reverse()
                .map((n) => (
                  <li key={String(n.note_id)} className="rounded-lg border border-border bg-muted/20 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-dim">
                      <span className="mono">{String(n.author || "unknown")}</span>
                      <span>{relativeTime(String(n.created_at || ""))}</span>
                    </div>
                    <div className="mt-2 whitespace-pre-wrap text-sm text-text">{String(n.body || "")}</div>
                  </li>
                ))}
            </ul>
          )}
        </div>
      </Card>

      <Card
        title="Related events (pivot)"
        subtitle={
          relatedEventIds.length
            ? `Searches collector events by event_id (${relatedEventIds.join(", ")})`
            : "Add related_event_ids to pivot into raw events."
        }
        action={
          <div className="flex items-center gap-2">
            <Link to={timelineHref} className="btn">
              Open timeline
            </Link>
            <button
              type="button"
              className="btn"
              disabled={!relatedEventIds.length}
              onClick={async () => {
                try {
                  setEventsErr(null);
                  const all: Array<Record<string, unknown>> = [];
                  for (const id of relatedEventIds) {
                    const r = await api.collectorSearch({ event_id: id, limit: 50, cursor: 0, include_message: 0 });
                    all.push(...(r.items ?? []));
                  }
                  setEvents(all);
                } catch (e) {
                  setEventsErr((e as Error).message);
                }
              }}
            >
              Search events
            </button>
          </div>
        }
      >
        {eventsErr && <div className="text-sm text-sev-critical">{eventsErr}</div>}
        {events.length === 0 ? (
          <div className="text-sm text-dim">No events loaded.</div>
        ) : (
          <div className="space-y-2">
            {events.slice(0, 20).map((ev, i) => (
              <pre
                key={`${String((ev as any).event_id ?? "ev")}-${i}`}
                className="overflow-auto rounded-md border border-border bg-muted/20 p-3 text-xs"
              >
                {JSON.stringify(ev, null, 2)}
              </pre>
            ))}
            {events.length > 20 && <div className="text-xs text-dim">Showing first 20 events.</div>}
          </div>
        )}
      </Card>
    </div>
  );
}

