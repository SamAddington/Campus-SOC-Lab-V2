import { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Card, EmptyState } from "@/components/ui/Card";
import { api } from "@/lib/api";
import { absoluteTime, relativeTime } from "@/lib/format";

function parseNum(v: string | null): number | null {
  if (!v) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function readFilters(search: string) {
  const qp = new URLSearchParams(search);
  return {
    since_ms: parseNum(qp.get("since_ms")),
    until_ms: parseNum(qp.get("until_ms")),
    event_id: qp.get("event_id") || "",
    event_ids: qp.get("event_ids") || "",
    source: qp.get("source") || "",
    event_type: qp.get("event_type") || "",
    language: qp.get("language") || "",
    user_id_hash: qp.get("user_id_hash") || "",
    email_domain: qp.get("email_domain") || "",
    q: qp.get("q") || "",
  };
}

export function Timeline() {
  const { search } = useLocation();
  const nav = useNavigate();

  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [items, setItems] = useState<Array<Record<string, unknown>>>([]);
  const [facets, setFacets] = useState<Record<string, Array<{ key: string; count: number }>> | null>(null);

  const [sinceMs, setSinceMs] = useState<number | null>(null);
  const [untilMs, setUntilMs] = useState<number | null>(null);
  const [eventId, setEventId] = useState("");
  const [eventIds, setEventIds] = useState("");
  const [source, setSource] = useState("");
  const [eventType, setEventType] = useState("");
  const [language, setLanguage] = useState("");
  const [userIdHash, setUserIdHash] = useState("");
  const [emailDomain, setEmailDomain] = useState("");
  const [textQ, setTextQ] = useState("");

  useEffect(() => {
    const f = readFilters(search);
    setSinceMs(f.since_ms);
    setUntilMs(f.until_ms);
    setEventId(f.event_id);
    setEventIds(f.event_ids);
    setSource(f.source);
    setEventType(f.event_type);
    setLanguage(f.language);
    setUserIdHash(f.user_id_hash);
    setEmailDomain(f.email_domain);
    setTextQ(f.q);
  }, [search]);

  const searchParams = useMemo(() => {
    const p: Record<string, string | number | undefined> = {
      since_ms: sinceMs ?? undefined,
      until_ms: untilMs ?? undefined,
      event_id: eventId.trim() || undefined,
      event_ids: eventIds.trim() || undefined,
      source: source.trim() || undefined,
      event_type: eventType.trim() || undefined,
      language: language.trim() || undefined,
      user_id_hash: userIdHash.trim() || undefined,
      email_domain: emailDomain.trim() || undefined,
      q: textQ.trim() || undefined,
      limit: 200,
      cursor: 0,
      include_message: 0,
    };
    return p;
  }, [sinceMs, untilMs, eventId, eventIds, source, eventType, language, userIdHash, emailDomain, textQ]);

  const facetParams = useMemo(() => {
    const { limit: _l, cursor: _c, include_message: _i, ...rest } = searchParams;
    return { ...rest, size: 10 };
  }, [searchParams]);

  function pushUrl() {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(searchParams)) {
      if (v === undefined || v === null || v === "") continue;
      if (k === "limit" || k === "cursor" || k === "include_message") continue;
      qs.set(k, String(v));
    }
    const s = qs.toString();
    nav(s ? `/timeline?${s}` : "/timeline");
  }

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const [r, f] = await Promise.all([
          api.collectorSearch(
            searchParams as {
              since_ms?: number;
              until_ms?: number;
              event_id?: string;
              event_ids?: string;
              source?: string;
              event_type?: string;
              language?: string;
              user_id_hash?: string;
              email_domain?: string;
              q?: string;
              limit?: number;
              cursor?: number;
              include_message?: number;
            },
          ),
          api.collectorFacets(
            facetParams as {
              since_ms?: number;
              until_ms?: number;
              event_id?: string;
              event_ids?: string;
              source?: string;
              event_type?: string;
              language?: string;
              user_id_hash?: string;
              email_domain?: string;
              q?: string;
              size?: number;
            },
          ),
        ]);
        if (cancelled) return;
        setItems((r.items ?? []) as Array<Record<string, unknown>>);
        setFacets(f.facets ?? null);
        setErr(null);
      } catch (e) {
        if (cancelled) return;
        setErr((e as Error).message);
        setItems([]);
        setFacets(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [searchParams, facetParams]);

  return (
    <div className="space-y-4">
      <header>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-semibold text-text">Timeline</h1>
            <p className="mt-1 text-sm text-subtle">
              Time-ordered events with facets and pivots (SIEM-style hunt view). Filters sync to the URL on Apply.
            </p>
          </div>
          <Link to="/hunts" className="btn">
            Back to hunts
          </Link>
        </div>
      </header>

      <Card title="Filters" subtitle="Maps to collector `/search` and `/search/facets`.">
        <div className="grid gap-3 md:grid-cols-3">
          <label className="block">
            <div className="label mb-1">since_ms</div>
            <input
              className="input mono"
              value={sinceMs === null ? "" : String(sinceMs)}
              onChange={(e) => setSinceMs(e.target.value.trim() ? Number(e.target.value) : null)}
              placeholder="(ms since epoch)"
            />
          </label>
          <label className="block">
            <div className="label mb-1">until_ms</div>
            <input
              className="input mono"
              value={untilMs === null ? "" : String(untilMs)}
              onChange={(e) => setUntilMs(e.target.value.trim() ? Number(e.target.value) : null)}
              placeholder="(ms since epoch)"
            />
          </label>
          <label className="block">
            <div className="label mb-1">q</div>
            <input className="input mono" value={textQ} onChange={(e) => setTextQ(e.target.value)} placeholder="reset password urgent" />
          </label>
          <label className="block">
            <div className="label mb-1">event_id</div>
            <input className="input mono" value={eventId} onChange={(e) => setEventId(e.target.value)} placeholder="single id" />
          </label>
          <label className="block md:col-span-2">
            <div className="label mb-1">event_ids (comma-separated)</div>
            <input className="input mono" value={eventIds} onChange={(e) => setEventIds(e.target.value)} placeholder="id1,id2" />
          </label>
          <label className="block">
            <div className="label mb-1">source</div>
            <input className="input mono" value={source} onChange={(e) => setSource(e.target.value)} placeholder="email_gateway" />
          </label>
          <label className="block">
            <div className="label mb-1">event_type</div>
            <input className="input mono" value={eventType} onChange={(e) => setEventType(e.target.value)} placeholder="suspicious_email" />
          </label>
          <label className="block">
            <div className="label mb-1">language</div>
            <input className="input mono" value={language} onChange={(e) => setLanguage(e.target.value)} placeholder="en" />
          </label>
          <label className="block">
            <div className="label mb-1">user_id_hash</div>
            <input className="input mono" value={userIdHash} onChange={(e) => setUserIdHash(e.target.value)} placeholder="(anon)" />
          </label>
          <label className="block">
            <div className="label mb-1">email_domain</div>
            <input className="input mono" value={emailDomain} onChange={(e) => setEmailDomain(e.target.value)} placeholder="example.edu" />
          </label>
          <div className="flex items-end gap-2">
            <button className="btn btn-primary" type="button" onClick={pushUrl}>
              Apply
            </button>
            <button
              className="btn"
              type="button"
              onClick={() => {
                nav("/timeline");
              }}
            >
              Reset
            </button>
          </div>
        </div>
      </Card>

      {err && (
        <Card title="Error">
          <div className="text-sm text-sev-critical">{err}</div>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-[1fr_340px]">
        <Card title="Events" subtitle={loading ? "Loading…" : `${items.length} event(s) loaded (top 200).`}>
          {items.length === 0 ? (
            <EmptyState title="No events" description="Adjust filters, time window, or query." />
          ) : (
            <div className="space-y-2">
              {items.map((ev, i) => {
                const row = ev;
                const ingestedAt = typeof row.ingested_at === "string" ? row.ingested_at : "";
                const anonRaw = row.anon_record;
                const anon = isRecord(anonRaw) ? anonRaw : {};
                const eid = typeof row.event_id === "string" ? row.event_id : "";
                const dom = typeof anon.email_domain === "string" ? anon.email_domain : "";
                const uid = typeof anon.user_id_hash === "string" ? anon.user_id_hash : "";
                const src = typeof anon.source === "string" ? anon.source : "";
                const et = typeof anon.event_type === "string" ? anon.event_type : "";
                const pivotQs = new URLSearchParams();
                if (dom) pivotQs.set("email_domain", dom);
                if (uid) pivotQs.set("user_id_hash", uid);
                const pivotHref = `/timeline?${pivotQs.toString()}`;
                return (
                  <div key={`${eid || "ev"}-${i}`} className="rounded-lg border border-border bg-muted/10 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-dim">
                      <div className="mono">{eid || "—"}</div>
                      <div>
                        {relativeTime(ingestedAt)} · {absoluteTime(ingestedAt)}
                      </div>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                      <span className="chip">source: {src || "—"}</span>
                      <span className="chip">type: {et || "—"}</span>
                      {dom ? <span className="chip">domain: {dom}</span> : null}
                      {uid ? <span className="chip">user: {uid.slice(0, 10)}…</span> : null}
                      {dom || uid ? (
                        <Link className="btn" to={pivotHref}>
                          Pivot domain/user
                        </Link>
                      ) : null}
                    </div>
                    <pre className="mt-2 overflow-auto rounded-md border border-border bg-muted/20 p-3 text-xs">
                      {JSON.stringify(ev, null, 2)}
                    </pre>
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        <Card title="Facets" subtitle="Top values in the current filter window.">
          {facets ? (
            <div className="space-y-4 text-sm">
              {Object.entries(facets).map(([k, buckets]) => (
                <div key={k}>
                  <div className="label mb-2">{k}</div>
                  {buckets.length === 0 ? (
                    <div className="text-xs text-dim">—</div>
                  ) : (
                    <ul className="space-y-1">
                      {buckets.map((b) => (
                        <li key={`${k}:${b.key}`} className="flex items-center justify-between gap-2">
                          <button
                            type="button"
                            className="text-left text-xs text-text hover:underline"
                            onClick={() => {
                              if (k === "source") setSource(String(b.key));
                              if (k === "event_type") setEventType(String(b.key));
                              if (k === "email_domain") setEmailDomain(String(b.key));
                            }}
                          >
                            <span className="mono">{String(b.key)}</span>
                          </button>
                          <span className="mono text-xs text-dim">{b.count}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-sm text-dim">No facets loaded.</div>
          )}
        </Card>
      </div>
    </div>
  );
}
