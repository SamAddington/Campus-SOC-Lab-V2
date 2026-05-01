import { useEffect, useMemo, useRef, useState } from "react";
import { Card, EmptyState } from "@/components/ui/Card";
import { Modal } from "@/components/ui/Modal";
import { api, type TrainingChallenge, type TrainingRun } from "@/lib/api";
import { useSettings } from "@/lib/settings";

type StepId = "open_case" | "document_indicators" | "scope_campaign" | "response_steps";
type Host = { ip: string; name: string };

export function Training() {
  const { settings } = useSettings();
  const [challenges, setChallenges] = useState<TrainingChallenge[]>([]);
  const [activeChallenge, setActiveChallenge] = useState<TrainingChallenge | null>(null);
  const [run, setRun] = useState<TrainingRun | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [caseTitle, setCaseTitle] = useState("Late-night phishing campaign investigation");
  const [caseSeverity, setCaseSeverity] = useState("high");
  const [noteBody, setNoteBody] = useState("");
  const [scopeBody, setScopeBody] = useState("");
  const [planBody, setPlanBody] = useState("");
  const [showEmail, setShowEmail] = useState(false);

  const [ddosHot, setDdosHot] = useState<Record<string, boolean>>({});
  const ddosTickRef = useRef(0);

  const steps = useMemo(() => {
    const objs = activeChallenge?.objectives ?? [];
    return objs
      .map((o) => ({ id: String(o.id || ""), title: String(o.title || ""), required: Boolean(o.required) }))
      .filter((o) => o.id);
  }, [activeChallenge]);

  async function load() {
    setLoading(true);
    try {
      const c = await api.trainingChallenges();
      setChallenges(c.items ?? []);
      const first = (c.items ?? [])[0] ?? null;
      setActiveChallenge(first);
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function start() {
    if (!activeChallenge?.challenge_id) return;
    try {
      const r = await api.trainingRunStart(String(activeChallenge.challenge_id));
      setRun(r.run);
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  async function log(action_type: string, payload: Record<string, unknown>) {
    if (!run?.run_id) return;
    await api.trainingAction(run.run_id, action_type, payload);
  }

  async function complete() {
    if (!run?.run_id) return;
    try {
      const out = await api.trainingComplete(run.run_id);
      setRun(out.run);
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  const runDone = run?.status === "completed";
  const score = typeof run?.score === "number" ? run.score : null;
  const letter = (run?.report as any)?.grade?.letter as string | undefined;
  const challengeId = String(activeChallenge?.challenge_id ?? "");

  const ddosHosts: Host[] = useMemo(
    () => [
      { name: "student-portal", ip: "203.0.113.10" },
      { name: "auth-gateway", ip: "203.0.113.11" },
      { name: "vpn", ip: "203.0.113.12" },
      { name: "dns", ip: "203.0.113.53" },
      { name: "email", ip: "203.0.113.25" },
      { name: "lms", ip: "203.0.113.40" },
      { name: "api", ip: "203.0.113.60" },
      { name: "edge-waf", ip: "203.0.113.80" },
    ],
    [],
  );

  function computeDdosHot(hosts: Host[], tick: number) {
    const next: Record<string, boolean> = {};
    for (const h of hosts) next[h.ip] = false;
    const k = Math.max(1, Math.min(4, 1 + (tick % 4)));
    const shuffled = hosts.slice().sort(() => (Math.random() < 0.5 ? -1 : 1));
    for (const h of shuffled.slice(0, k)) next[h.ip] = true;
    return next;
  }

  useEffect(() => {
    if (!(challengeId === "full-scale-ddos" && run && !runDone)) return;
    ddosTickRef.current = 0;
    const id = globalThis.setInterval(() => {
      ddosTickRef.current += 1;
      setDdosHot(computeDdosHot(ddosHosts, ddosTickRef.current));
    }, 750);
    return () => globalThis.clearInterval(id);
  }, [challengeId, ddosHosts, run, runDone]);

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold text-text">Training</h1>
        <p className="mt-1 text-sm text-subtle">
          Interactive analyst tutoring (MVP). Your actions are logged to the audit ledger and scored deterministically.
        </p>
      </header>

      {err ? (
        <div className="rounded-lg border border-sev-critical/40 bg-sev-critical/10 p-3 text-sm text-sev-critical">
          {err}
        </div>
      ) : null}

      <Card
        title="Challenge"
        subtitle="Pick a lab and start a run."
        action={
          <div className="flex gap-2">
            <button className="btn" type="button" onClick={load} disabled={loading}>
              Refresh
            </button>
            <button className="btn btn-primary" type="button" onClick={start} disabled={!activeChallenge || Boolean(run && !runDone)}>
              {run && !runDone ? "Run in progress" : "Start run"}
            </button>
          </div>
        }
      >
        {challenges.length === 0 ? (
          <EmptyState title="No challenges" description="Training challenges are served by the audit service." />
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            <label className="block">
              <div className="label mb-1">Challenge</div>
              <select
                className="input"
                value={activeChallenge?.challenge_id ?? ""}
                onChange={(e) => setActiveChallenge(challenges.find((x) => x.challenge_id === e.target.value) ?? null)}
                disabled={Boolean(run && !runDone)}
              >
                {challenges.map((c) => (
                  <option key={c.challenge_id} value={c.challenge_id}>
                    {c.name}
                  </option>
                ))}
              </select>
            </label>
            <div className="rounded-lg border border-border bg-muted/20 p-3 text-sm text-subtle">
              <div className="text-xs font-semibold text-text">Briefing</div>
              <pre className="mt-2 whitespace-pre-wrap text-sm text-subtle">
                {activeChallenge?.briefing ?? "—"}
              </pre>
              {challengeId === "late-night-phishing" ? (
                <div className="mt-3">
                  <button type="button" className="btn" onClick={() => setShowEmail(true)}>
                    View sample phishing email
                  </button>
                </div>
              ) : null}
            </div>
          </div>
        )}
      </Card>

      {challengeId === "full-scale-ddos" ? (
        <Card
          title="Network view (simulated)"
          subtitle="Animated map of connected hosts under stress (training-only; RFC 5737 documentation IPs)."
        >
          <div className="grid gap-2 md:grid-cols-2">
            <div className="rounded-lg border border-border bg-muted/10 p-3">
              <div className="text-xs font-semibold text-text">Connected hosts</div>
              <div className="mt-2 space-y-1">
                {ddosHosts.map((h) => {
                  const hot = Boolean(ddosHot[h.ip]);
                  return (
                    <div
                      key={h.ip}
                      className={`flex items-center justify-between rounded-md border px-2 py-1 text-xs ${
                        hot
                          ? "border-sev-critical/50 bg-sev-critical/10 text-sev-critical animate-pulse"
                          : "border-border bg-muted/20 text-subtle"
                      }`}
                    >
                      <span className="mono">{h.ip}</span>
                      <span className="mono text-dim">{h.name}</span>
                      <span className="chip">{hot ? "under attack" : "stable"}</span>
                    </div>
                  );
                })}
              </div>
            </div>
            <div className="rounded-lg border border-border bg-muted/10 p-3">
              <div className="text-xs font-semibold text-text">Attack animation</div>
              <div className="mt-2 text-sm text-subtle">
                <div className="mono text-xs text-dim">
                  under_attack={Object.values(ddosHot).filter(Boolean).length} / {ddosHosts.length}
                </div>
                <div className="mt-3 grid place-items-center rounded-lg border border-border bg-base/40 p-4">
                  <svg viewBox="0 0 360 220" className="h-[180px] w-full max-w-[520px]">
                    <defs>
                      <linearGradient id="line" x1="0" y1="0" x2="1" y2="0">
                        <stop offset="0%" stopColor="rgba(148,163,184,0.25)" />
                        <stop offset="50%" stopColor="rgba(148,163,184,0.5)" />
                        <stop offset="100%" stopColor="rgba(148,163,184,0.25)" />
                      </linearGradient>
                    </defs>
                    {/* edge node */}
                    <circle cx="180" cy="30" r="10" fill="rgba(34,211,238,0.25)" stroke="rgba(34,211,238,0.7)" />
                    <text x="180" y="18" textAnchor="middle" fontSize="10" fill="rgba(226,232,240,0.75)">
                      edge
                    </text>
                    {/* spokes */}
                    {ddosHosts.map((h, i) => {
                      const angle = (i / ddosHosts.length) * Math.PI * 2;
                      const x = 180 + Math.cos(angle) * 140;
                      const y = 120 + Math.sin(angle) * 70;
                      const hot = Boolean(ddosHot[h.ip]);
                      return (
                        <g key={h.ip}>
                          <line x1="180" y1="30" x2={x} y2={y} stroke="url(#line)" strokeWidth="2" />
                          <circle
                            cx={x}
                            cy={y}
                            r={hot ? 9 : 7}
                            fill={hot ? "rgba(239,68,68,0.25)" : "rgba(148,163,184,0.18)"}
                            stroke={hot ? "rgba(239,68,68,0.9)" : "rgba(148,163,184,0.45)"}
                          />
                          {hot ? (
                            <circle cx={x} cy={y} r="14" fill="rgba(239,68,68,0.10)" stroke="rgba(239,68,68,0.25)" />
                          ) : null}
                        </g>
                      );
                    })}
                  </svg>
                </div>
              </div>
            </div>
          </div>
        </Card>
      ) : null}

      <Card title="Objectives" subtitle="Complete these steps. Use the buttons below to record actions.">
        <ul className="list-disc space-y-1.5 pl-5 text-sm text-subtle">
          {steps.map((s) => (
            <li key={s.id}>
              <span className="font-medium text-text">{s.title}</span>{" "}
              {s.required ? <span className="chip ml-1">required</span> : null}
            </li>
          ))}
        </ul>
      </Card>

      <Card title="Actions" subtitle={`Trainee: ${settings.analystId} · run_id: ${run?.run_id ?? "—"}`}>
        {run == null ? (
          <div className="text-sm text-dim">Start a run to begin recording actions.</div>
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            <div className="rounded-lg border border-border bg-muted/10 p-3">
              <div className="text-xs font-semibold text-text">1) Open case</div>
              <div className="mt-2 grid gap-2">
                <input className="input" value={caseTitle} onChange={(e) => setCaseTitle(e.target.value)} disabled={runDone} />
                <select className="input" value={caseSeverity} onChange={(e) => setCaseSeverity(e.target.value)} disabled={runDone}>
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </select>
                <button
                  type="button"
                  className="btn"
                  disabled={runDone}
                  onClick={async () => {
                    await log("case_create", { title: caseTitle.trim(), severity: caseSeverity, trainee: settings.analystId });
                  }}
                >
                  Record case creation
                </button>
              </div>
            </div>

            <div className="rounded-lg border border-border bg-muted/10 p-3">
              <div className="text-xs font-semibold text-text">2) Indicators / notes</div>
              <textarea
                className="input mono min-h-[120px]"
                spellCheck={false}
                value={noteBody}
                onChange={(e) => setNoteBody(e.target.value)}
                disabled={runDone}
                placeholder="Examples: suspicious sender pattern, URL/domain, subject theme, impacted users, etc."
              />
              <div className="mt-2 flex gap-2">
                <button
                  type="button"
                  className="btn"
                  disabled={runDone || noteBody.trim().length < 10}
                  onClick={async () => {
                    await log("case_note", { body: noteBody.trim() });
                    setNoteBody("");
                  }}
                >
                  Record note
                </button>
              </div>
            </div>

            <div className="rounded-lg border border-border bg-muted/10 p-3">
              <div className="text-xs font-semibold text-text">3) Scope statement</div>
              <textarea
                className="input mono min-h-[120px]"
                spellCheck={false}
                value={scopeBody}
                onChange={(e) => setScopeBody(e.target.value)}
                disabled={runDone}
                placeholder="Who/what/when/how; what you would pivot on next."
              />
              <div className="mt-2 flex gap-2">
                <button
                  type="button"
                  className="btn"
                  disabled={runDone || scopeBody.trim().length < 10}
                  onClick={async () => {
                    await log("campaign_scope", { body: scopeBody.trim() });
                    setScopeBody("");
                  }}
                >
                  Record scope
                </button>
              </div>
            </div>

            <div className="rounded-lg border border-border bg-muted/10 p-3">
              <div className="text-xs font-semibold text-text">4) Response plan</div>
              <textarea
                className="input mono min-h-[120px]"
                spellCheck={false}
                value={planBody}
                onChange={(e) => setPlanBody(e.target.value)}
                disabled={runDone}
                placeholder="Safe response steps (comms, monitoring, containment)."
              />
              <div className="mt-2 flex gap-2">
                <button
                  type="button"
                  className="btn"
                  disabled={runDone || planBody.trim().length < 10}
                  onClick={async () => {
                    await log("response_plan", { body: planBody.trim() });
                    setPlanBody("");
                  }}
                >
                  Record plan
                </button>
                <button type="button" className="btn btn-primary" disabled={runDone} onClick={complete}>
                  Complete run
                </button>
              </div>
            </div>
          </div>
        )}
      </Card>

      {runDone ? (
        <Card
          title="After Action Report"
          subtitle={`status=${run?.status} · grade=${letter || "—"} · score=${score == null ? "—" : score.toFixed(2)} · passed=${String(run?.passed ?? false)}`}
        >
          <pre className="mono max-h-[520px] overflow-auto text-[11px] leading-relaxed text-subtle">
            {JSON.stringify(run?.report ?? {}, null, 2)}
          </pre>
        </Card>
      ) : null}

      <Modal
        open={showEmail}
        onClose={() => setShowEmail(false)}
        title="Sample phishing email (training)"
        subtitle="Use this to practice extracting concrete indicators."
        size="lg"
        footer={
          <button type="button" className="btn btn-primary" onClick={() => setShowEmail(false)}>
            Close
          </button>
        }
      >
        <div className="space-y-3 text-sm text-subtle">
          <div className="rounded-lg border border-border bg-muted/20 p-3">
            <div className="grid gap-1">
              <div>
                <span className="label">From</span>{" "}
                <span className="mono">Campus IT Helpdesk &lt;support@campus-it-security.example&gt;</span>
              </div>
              <div>
                <span className="label">To</span> <span className="mono">student123@example.edu</span>
              </div>
              <div>
                <span className="label">Subject</span>{" "}
                <span className="mono">URGENT: Account verification required to avoid suspension</span>
              </div>
            </div>
          </div>
          <div className="rounded-lg border border-border bg-base/40 p-3">
            <div className="mono whitespace-pre-wrap text-[12px] leading-relaxed">
              {`Hello,\n\nWe detected unusual sign-in activity on your campus account.\nTo keep access to your student aid documents, you must verify your account within 30 minutes.\n\nVerify now: http://campus-security-login.example/verify\n\nIf you do not verify, your account will be suspended until you contact the helpdesk.\n\n— Campus IT Security`}
            </div>
          </div>
          <div className="text-xs text-dim">
            Training note: this example uses non-routable documentation domains. In real incidents, record the exact sender,
            reply-to, visible links, and any user-reported context.
          </div>
        </div>
      </Modal>
    </div>
  );
}

