import { useEffect, useMemo, useRef, useState } from "react";
import { Card, EmptyState } from "@/components/ui/Card";
import { Modal } from "@/components/ui/Modal";
import { api, type TrainingChallenge, type TrainingRun } from "@/lib/api";
import { useSettings } from "@/lib/settings";

type StepId = "open_case" | "document_indicators" | "scope_campaign" | "response_steps";
type Host = { ip: string; name: string };

function AccountCompromiseViz() {
  return (
    <Card title="Example (training): sign-in timeline" subtitle="Illustrative timeline + impossible travel badge (documentation IPs).">
      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-muted/10 p-3 text-sm text-subtle">
          <div className="text-xs font-semibold text-text">Timeline</div>
          <div className="mt-2 space-y-2 text-xs">
            {[
              { t: "08:01", loc: "New York, US", ip: "203.0.113.44", dev: "Windows · Chrome" },
              { t: "08:06", loc: "Warsaw, PL", ip: "203.0.113.201", dev: "Linux · Unknown UA" },
              { t: "08:08", loc: "Warsaw, PL", ip: "203.0.113.201", dev: "Linux · Unknown UA" },
            ].map((e) => (
              <div key={`${e.t}-${e.ip}`} className="rounded-md border border-border bg-base/40 p-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="mono text-dim">{e.t}</span>
                  <span className="chip">sign-in</span>
                </div>
                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
                  <span className="mono">{e.ip}</span>
                  <span className="text-dim">{e.loc}</span>
                  <span className="text-dim">{e.dev}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-muted/10 p-3">
          <div className="text-xs font-semibold text-text">Risk flags</div>
          <div className="mt-2 flex flex-wrap gap-2 text-xs">
            <span className="chip border border-sev-critical/40 bg-sev-critical/10 text-sev-critical">Impossible travel</span>
            <span className="chip">New device</span>
            <span className="chip">MFA fatigue reports</span>
          </div>
          <div className="mt-3 text-xs text-dim">
            What to note: timestamps, geo mismatch, device/user-agent drift, and any risky follow-on actions (mailbox rules, OAuth grants).
          </div>
        </div>
      </div>
    </Card>
  );
}

function BecRuleChainViz() {
  const rules = [
    { name: "Hide vendor thread", when: 'Subject contains "invoice" OR "remittance"', action: "Move to RSS Subscriptions" },
    { name: "Forward finance mail", when: "From contains finance@", action: "Forward to external address" },
    { name: "Delete alerts", when: "From contains security@", action: "Delete" },
  ];
  return (
    <Card title="Example (training): mailbox rule chain" subtitle="How a compromised mailbox can hide and forward messages.">
      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-muted/10 p-3 text-sm text-subtle">
          <div className="text-xs font-semibold text-text">Rule chain</div>
          <div className="mt-2 space-y-2 text-xs">
            {rules.map((r) => (
              <div key={r.name} className="rounded-md border border-border bg-base/40 p-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium text-text">{r.name}</span>
                  <span className="chip">rule</span>
                </div>
                <div className="mt-1">
                  <span className="label">when</span> <span className="mono">{r.when}</span>
                </div>
                <div className="mt-1">
                  <span className="label">then</span> <span className="mono">{r.action}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-muted/10 p-3 text-sm text-subtle">
          <div className="text-xs font-semibold text-text">Indicators to capture</div>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-subtle">
            <li>Forwarding target domain and any reply-to mismatches</li>
            <li>New/modified rules (created_at), OAuth grants, sign-in anomalies</li>
            <li>Victim thread context (vendor change request, urgency, secrecy cues)</li>
          </ul>
        </div>
      </div>
    </Card>
  );
}

function RansomwareViz({ reduceMotion, visualTick }: Readonly<{ reduceMotion: boolean; visualTick: number }>) {
  const hosts = useMemo(
    () => Array.from({ length: 16 }).map((_, i) => `WS-${String(i + 1).padStart(2, "0")}`),
    [],
  );
  const pct = reduceMotion ? 62 : 10 + ((visualTick * 9) % 85);
  return (
    <Card title="Example (training): blast radius + encryption meter" subtitle="Illustrative host impact view.">
      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-muted/10 p-3">
          <div className="text-xs font-semibold text-text">Blast radius</div>
          <div className="mt-2 grid grid-cols-4 gap-2 text-[11px]">
            {hosts.map((h, i) => {
              const hot = (i + visualTick) % 7 === 0;
              return (
                <div
                  key={h}
                  className={`rounded-md border px-2 py-1 text-center mono ${
                    hot ? "border-sev-critical/50 bg-sev-critical/10 text-sev-critical" : "border-border bg-base/40 text-dim"
                  }`}
                >
                  {h}
                </div>
              );
            })}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-muted/10 p-3">
          <div className="text-xs font-semibold text-text">Encryption progress</div>
          <div className="mt-3">
            <div className="flex items-center justify-between text-xs text-subtle">
              <span className="mono">shares_encrypted</span>
              <span className="mono">{pct}%</span>
            </div>
            <div className="mt-2 h-2 w-full overflow-hidden rounded bg-base/40">
              <div className="h-2 bg-sev-critical/60" style={{ width: `${pct}%` }} />
            </div>
            <div className="mt-3 text-xs text-dim">
              Practice: isolate affected hosts, preserve evidence, identify patient zero, validate backups before restore.
            </div>
          </div>
        </div>
      </div>
    </Card>
  );
}

function EndpointMalwareViz({ reduceMotion, visualTick }: Readonly<{ reduceMotion: boolean; visualTick: number }>) {
  const beacons = useMemo(() => Array.from({ length: 5 }).map((_, i) => `b${i + 1}`), []);
  return (
    <Card title="Example (training): process tree + C2 beacon ticker" subtitle="Illustrative EDR view (synthetic).">
      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-muted/10 p-3 text-xs text-subtle">
          <div className="text-xs font-semibold text-text">Process tree</div>
          <pre className="mono mt-2 whitespace-pre-wrap leading-relaxed text-dim">{String.raw`explorer.exe
-- chrome.exe  (user browsing)
-- invoice_viewer.exe  (new install)
    +-- powershell.exe  -enc ...
        +-- rundll32.exe  C:\Users\...\AppData\Roaming\upd.dll,Entry`}</pre>
        </div>
        <div className="rounded-lg border border-border bg-muted/10 p-3 text-xs text-subtle">
          <div className="text-xs font-semibold text-text">Outbound beacons</div>
          <div className="mt-2 space-y-1">
            {beacons.map((id, i) => {
              const s = reduceMotion ? 30 + i * 7 : 8 + ((visualTick + i) % 40);
              const cls = reduceMotion ? "text-dim" : "animate-pulse text-sev-warn";
              return (
                <div key={id} className="flex items-center justify-between rounded-md border border-border bg-base/40 px-2 py-1">
                  <span className="mono">c2.example</span>
                  <span className={`mono ${cls}`}>last_seen={s}s</span>
                </div>
              );
            })}
          </div>
          <div className="mt-3 text-xs text-dim">
            Practice: isolate endpoint, collect triage artifacts, rotate exposed credentials, hunt for same hash/domain.
          </div>
        </div>
      </div>
    </Card>
  );
}

function CredStuffingViz({ reduceMotion, visualTick }: Readonly<{ reduceMotion: boolean; visualTick: number }>) {
  const cells = useMemo(() => Array.from({ length: 72 }).map((_, i) => `c${i}`), []);
  const locked = reduceMotion ? 14 : 8 + (visualTick % 19);
  const lockedCls = reduceMotion ? "text-text" : "animate-pulse text-sev-warn";
  return (
    <Card title="Example (training): auth heatmap + lockouts" subtitle="Illustrative auth failures by minute (synthetic).">
      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-muted/10 p-3">
          <div className="text-xs font-semibold text-text">Failure heatmap</div>
          <div className="mt-3 grid grid-cols-12 gap-1">
            {cells.map((k, i) => {
              const v = (i * 17 + visualTick * 13) % 100;
              const hot = v > 78;
              const mid = v > 55 && v <= 78;
              let cls = "bg-base/40";
              if (mid) cls = "bg-sev-warn/30";
              if (hot) cls = "bg-sev-critical/40";
              return <div key={k} className={`h-3 w-full rounded-sm border border-border ${cls}`} />;
            })}
          </div>
          <div className="mt-2 text-xs text-dim">Tip: correlate with app, username, and MFA outcomes (fail vs success).</div>
        </div>
        <div className="rounded-lg border border-border bg-muted/10 p-3">
          <div className="text-xs font-semibold text-text">Lockouts</div>
          <div className="mt-3 flex items-end justify-between">
            <div className="text-xs text-subtle">
              <div className="label">locked_accounts</div>
              <div className={`mono text-2xl ${lockedCls}`}>{locked}</div>
            </div>
            <div className="text-xs text-dim">Mitigate with rate limits, MFA, and user guidance (avoid broad lockout harm).</div>
          </div>
        </div>
      </div>
    </Card>
  );
}

function WebAppViz({ visualTick }: Readonly<{ visualTick: number }>) {
  return (
    <Card title="Example (training): WAF spikes + affected endpoints" subtitle="Illustrative WAF/app symptoms (synthetic).">
      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-muted/10 p-3">
          <div className="text-xs font-semibold text-text">WAF events</div>
          <svg viewBox="0 0 240 80" className="mt-3 h-[90px] w-full">
            {Array.from({ length: 24 }).map((_, i) => {
              const h = 10 + ((i * 9 + visualTick * 7) % 55);
              const hot = h > 50;
              return (
                <rect
                  key={`bar-${i * 10}`}
                  x={i * 10}
                  y={80 - h}
                  width="7"
                  height={h}
                  fill={hot ? "rgba(239,68,68,0.55)" : "rgba(148,163,184,0.35)"}
                />
              );
            })}
          </svg>
          <div className="mt-1 text-xs text-dim">Spike correlates with 500s on login endpoint.</div>
        </div>
        <div className="rounded-lg border border-border bg-muted/10 p-3 text-xs text-subtle">
          <div className="text-xs font-semibold text-text">Affected endpoints</div>
          <div className="mt-2 space-y-1">
            {["POST /auth/login", "GET /api/v1/users?search=", "POST /comments", "GET /admin"].map((e) => (
              <div key={e} className="flex items-center justify-between rounded-md border border-border bg-base/40 px-2 py-1">
                <span className="mono">{e}</span>
                <span className="chip">targeted</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Card>
  );
}

function VulnExploitViz() {
  const patched = 6;
  const total = 14;
  const pct = Math.round((patched / total) * 100);
  return (
    <Card title="Example (training): patch gap + exploit chain" subtitle="Illustrative exposure view (synthetic).">
      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-muted/10 p-3">
          <div className="text-xs font-semibold text-text">Patch gap meter</div>
          <div className="mt-3">
            <div className="flex items-center justify-between text-xs text-subtle">
              <span className="mono">patched_assets</span>
              <span className="mono">
                {patched}/{total} ({pct}%)
              </span>
            </div>
            <div className="mt-2 h-2 w-full overflow-hidden rounded bg-base/40">
              <div className="h-2 bg-sev-warn/60" style={{ width: `${pct}%` }} />
            </div>
            <div className="mt-2 text-xs text-dim">Practice: prioritize internet-exposed systems first; add compensating controls.</div>
          </div>
        </div>
        <div className="rounded-lg border border-border bg-muted/10 p-3 text-xs text-subtle">
          <div className="text-xs font-semibold text-text">Exploitation chain (example)</div>
          <ol className="mt-2 list-decimal space-y-1 pl-5 text-xs text-subtle">
            <li>Scan / enumerate version</li>
            <li>Exploit attempt payload (pattern match)</li>
            <li>Webshell or command execution (if successful)</li>
            <li>Credential access / lateral movement (follow-on)</li>
          </ol>
        </div>
      </div>
    </Card>
  );
}

function ExfilViz({ reduceMotion, visualTick }: Readonly<{ reduceMotion: boolean; visualTick: number }>) {
  const pct = reduceMotion ? 74 : 35 + ((visualTick * 11) % 60);
  return (
    <Card title="Example (training): exfil gauge + destinations" subtitle="Illustrative bytes-out view (synthetic).">
      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-muted/10 p-3">
          <div className="text-xs font-semibold text-text">Bytes out</div>
          <div className="mt-3">
            <div className="flex items-center justify-between text-xs text-subtle">
              <span className="mono">egress_saturation</span>
              <span className="mono">{pct}%</span>
            </div>
            <div className="mt-2 h-2 w-full overflow-hidden rounded bg-base/40">
              <div className="h-2 bg-sev-warn/60" style={{ width: `${pct}%` }} />
            </div>
            <div className="mt-2 text-xs text-dim">Practice: identify source host/account and confirm business justification.</div>
          </div>
        </div>
        <div className="rounded-lg border border-border bg-muted/10 p-3 text-xs text-subtle">
          <div className="text-xs font-semibold text-text">Top destinations</div>
          <div className="mt-2 space-y-1">
            {["files-sync.example", "cdn-cache.example", "paste-drop.example"].map((d) => (
              <div key={d} className="flex items-center justify-between rounded-md border border-border bg-base/40 px-2 py-1">
                <span className="mono">{d}</span>
                <span className="chip">rare</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Card>
  );
}

function InsiderViz({ reduceMotion, visualTick }: Readonly<{ reduceMotion: boolean; visualTick: number }>) {
  const nodes = [
    { x: 150, y: 25, label: "HR" },
    { x: 190, y: 60, label: "FIN" },
    { x: 150, y: 95, label: "ADM" },
  ];
  return (
    <Card title="Example (training): access graph + anomaly trend" subtitle="Illustrative access relationships (synthetic).">
      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-muted/10 p-3">
          <div className="text-xs font-semibold text-text">Access graph</div>
          <svg viewBox="0 0 240 120" className="mt-3 h-[110px] w-full">
            <circle cx="40" cy="60" r="14" fill="rgba(34,211,238,0.18)" stroke="rgba(34,211,238,0.75)" />
            <text x="40" y="64" textAnchor="middle" fontSize="8" fill="rgba(226,232,240,0.75)">
              user
            </text>
            {nodes.map((n, i) => {
              const hot = !reduceMotion && (visualTick + i) % 3 === 0;
              return (
                <g key={n.label}>
                  <line x1="54" y1="60" x2={n.x - 12} y2={n.y} stroke="rgba(148,163,184,0.35)" strokeWidth="2" />
                  <circle
                    cx={n.x}
                    cy={n.y}
                    r={hot ? 13 : 11}
                    fill={hot ? "rgba(239,68,68,0.18)" : "rgba(148,163,184,0.15)"}
                    stroke={hot ? "rgba(239,68,68,0.8)" : "rgba(148,163,184,0.45)"}
                  />
                  <text x={n.x} y={n.y + 3} textAnchor="middle" fontSize="8" fill="rgba(226,232,240,0.75)">
                    {n.label}
                  </text>
                </g>
              );
            })}
          </svg>
          <div className="mt-1 text-xs text-dim">Practice: document facts, avoid assumptions; coordinate with HR/legal as required.</div>
        </div>
        <div className="rounded-lg border border-border bg-muted/10 p-3">
          <div className="text-xs font-semibold text-text">Anomaly trend</div>
          <svg viewBox="0 0 240 80" className="mt-3 h-[90px] w-full">
            <polyline
              fill="none"
              stroke="rgba(239,68,68,0.8)"
              strokeWidth="2"
              points={Array.from({ length: 16 })
                .map((_, i) => {
                  const v = 20 + ((i * 7 + visualTick * 9) % 50);
                  return `${i * 16},${80 - v}`;
                })
                .join(" ")}
            />
          </svg>
        </div>
      </div>
    </Card>
  );
}

function TrainingVisuals(
  props: Readonly<{
    challengeId: string;
    reduceMotion: boolean;
    visualTick: number;
    ddosHosts: Host[];
    ddosHot: Record<string, boolean>;
  }>,
) {
  const { challengeId, reduceMotion, visualTick, ddosHosts, ddosHot } = props;

  if (challengeId === "account-compromise-o365-google") return <AccountCompromiseViz />;
  if (challengeId === "bec-mailbox-rules") return <BecRuleChainViz />;
  if (challengeId === "ransomware-outbreak") return <RansomwareViz reduceMotion={reduceMotion} visualTick={visualTick} />;
  if (challengeId === "endpoint-malware-infostealer") return <EndpointMalwareViz reduceMotion={reduceMotion} visualTick={visualTick} />;
  if (challengeId === "credential-stuffing-bruteforce") return <CredStuffingViz reduceMotion={reduceMotion} visualTick={visualTick} />;
  if (challengeId === "web-app-attack") return <WebAppViz visualTick={visualTick} />;
  if (challengeId === "vulnerability-exploitation") return <VulnExploitViz />;
  if (challengeId === "data-exfiltration") return <ExfilViz reduceMotion={reduceMotion} visualTick={visualTick} />;
  if (challengeId === "insider-misuse") return <InsiderViz reduceMotion={reduceMotion} visualTick={visualTick} />;

  if (challengeId === "full-scale-ddos") {
    return (
      <Card title="Network view (simulated)" subtitle="Animated map of connected hosts under stress (training-only; RFC 5737 documentation IPs).">
        <div className="grid gap-2 md:grid-cols-2">
          <div className="rounded-lg border border-border bg-muted/10 p-3">
            <div className="text-xs font-semibold text-text">Connected hosts</div>
            <div className="mt-2 space-y-1">
              {ddosHosts.map((h) => {
                const hot = Boolean(ddosHot[h.ip]);
                const cls = hot
                  ? "border-sev-critical/50 bg-sev-critical/10 text-sev-critical"
                  : "border-border bg-muted/20 text-subtle";
                const pulse = !reduceMotion && hot ? " animate-pulse" : "";
                return (
                  <div key={h.ip} className={`flex items-center justify-between rounded-md border px-2 py-1 text-xs ${cls}${pulse}`}>
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
                  <circle cx="180" cy="30" r="10" fill="rgba(34,211,238,0.25)" stroke="rgba(34,211,238,0.7)" />
                  <text x="180" y="18" textAnchor="middle" fontSize="10" fill="rgba(226,232,240,0.75)">
                    edge
                  </text>
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
    );
  }

  return null;
}

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

  const reduceMotion = Boolean(settings.reduceMotion);
  const [visualTick, setVisualTick] = useState(0);

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
    if (reduceMotion) {
      setDdosHot(computeDdosHot(ddosHosts, 1));
      return;
    }
    ddosTickRef.current = 0;
    const id = globalThis.setInterval(() => {
      ddosTickRef.current += 1;
      setDdosHot(computeDdosHot(ddosHosts, ddosTickRef.current));
    }, 750);
    return () => globalThis.clearInterval(id);
  }, [challengeId, ddosHosts, reduceMotion, run, runDone]);

  useEffect(() => {
    if (!run || runDone) return;
    if (reduceMotion) return;
    const animatedIds = new Set([
      "ransomware-outbreak",
      "endpoint-malware-infostealer",
      "credential-stuffing-bruteforce",
      "web-app-attack",
      "data-exfiltration",
      "insider-misuse",
    ]);
    if (!animatedIds.has(challengeId)) return;
    const id = globalThis.setInterval(() => setVisualTick((t) => t + 1), 900);
    return () => globalThis.clearInterval(id);
  }, [challengeId, reduceMotion, run, runDone]);

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

      <TrainingVisuals
        challengeId={challengeId}
        reduceMotion={reduceMotion}
        visualTick={visualTick}
        ddosHosts={ddosHosts}
        ddosHot={ddosHot}
      />

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

