import { useEffect, useMemo, useState } from "react";
import { Download, ShieldCheck, Trash2 } from "lucide-react";
import { Card, EmptyState } from "@/components/ui/Card";
import { api, type AuditIntegrityVerify, type AuditSummary, type DecisionCard, type OverrideRecord } from "@/lib/api";
import { useSettings } from "@/lib/settings";
import { DECISION_RIGHTS_MATRIX, type DecisionRight } from "@/lib/decision_rights";

function downloadText(filename: string, content: string, mime = "text/plain") {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function toMarkdown(summary: AuditSummary | null, cards: DecisionCard[], overrides: OverrideRecord[]) {
  const lines: string[] = [];
  lines.push("# SOC Audit Export");
  lines.push("");
  lines.push(`Exported at: ${new Date().toISOString()}`);
  lines.push("");
  if (summary) {
    lines.push("## Summary");
    lines.push("");
    lines.push(`- total_decisions: ${summary.total_decisions}`);
    lines.push(`- total_overrides: ${summary.total_overrides}`);
    lines.push(`- osint_enriched_count: ${summary.osint_enriched_count}`);
    lines.push("");
  }
  lines.push("## Decision cards");
  lines.push("");
  lines.push(`Count: ${cards.length}`);
  lines.push("");
  lines.push("```json");
  lines.push(JSON.stringify(cards, null, 2));
  lines.push("```");
  lines.push("");
  lines.push("## Overrides");
  lines.push("");
  lines.push(`Count: ${overrides.length}`);
  lines.push("");
  lines.push("```json");
  lines.push(JSON.stringify(overrides, null, 2));
  lines.push("```");
  lines.push("");
  return lines.join("\n");
}

function escapeHtml(s: string) {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

type CheckStatus = "pass" | "warn" | "fail";
type ComplianceCheck = { framework: string; control: string; status: CheckStatus; evidence: string };

function statusLabel(s: CheckStatus) {
  return s === "pass" ? "PASS" : s === "warn" ? "WARN" : "FAIL";
}

function statusClass(s: CheckStatus) {
  return s === "pass" ? "pill pass" : s === "warn" ? "pill warn" : "pill fail";
}

function overallFromChecks(checks: ComplianceCheck[]) {
  const hasFail = checks.some((c) => c.status === "fail");
  const hasWarn = checks.some((c) => c.status === "warn");
  if (hasFail) return { label: "Does not meet expectations", status: "fail" as const };
  if (hasWarn) return { label: "Partially meets expectations", status: "warn" as const };
  return { label: "Meets or exceeds expectations", status: "pass" as const };
}

function caseSummary(card: DecisionCard, override?: OverrideRecord) {
  const effective = override?.overridden_action ?? card.permitted_action;
  return {
    id: card.decision_card_id,
    when: card.timestamp,
    source: card.source,
    event_type: card.event_type,
    action: effective,
    score: card.risk_score_final,
    policy_rule_id: card.policy_rule_id,
    osint: card.osint_enabled && !card.osint_skipped ? (card.osint_verdict ?? "unknown") : "—",
    llm: card.llm_used ? `${card.llm_tier ?? "?"}/${card.llm_provider ?? "?"}` : "fallback",
    requires_human_review: card.requires_human_review,
    override: override ? "yes" : "no",
  };
}

function buildComplianceChecks(params: {
  integrity: AuditIntegrityVerify | null;
  llmProvider: { teacherProvider?: string; studentProvider?: string };
  settings: ReturnType<typeof useSettings>["settings"];
}) {
  const { integrity, llmProvider, settings } = params;
  const integrityOk =
    Boolean(integrity?.decision_cards.ok) &&
    Boolean(integrity?.overrides.ok) &&
    Boolean(integrity?.simulation_runs.ok);

  const teacherProvider = (llmProvider.teacherProvider || "unknown").toLowerCase();
  const isHostedTeacher = teacherProvider === "openai" || teacherProvider === "anthropic";

  const checks: ComplianceCheck[] = [
    {
      framework: "Zero Trust",
      control: "API access control for sensitive endpoints",
      status: integrity?.auth_enabled ? "pass" : "warn",
      evidence: integrity?.auth_enabled
        ? "Audit service reports auth_enabled=true (API key required)."
        : "Audit service reports auth_enabled=false or unknown; verify SOC_API_KEY is set and enforced.",
    },
    {
      framework: "Auditability",
      control: "Tamper-evident ledger integrity",
      status: integrity ? (integrityOk ? "pass" : "fail") : "warn",
      evidence: integrity
        ? `integrity_verify: decision_cards=${integrity.decision_cards.ok}, overrides=${integrity.overrides.ok}, simulation_runs=${integrity.simulation_runs.ok}`
        : "Integrity verification not captured in report (call /integrity/verify).",
    },
    {
      framework: "Privacy by Design",
      control: "Hosted AI egress risk managed",
      status: isHostedTeacher ? (settings.allowHostedTeacher ? "warn" : "fail") : "pass",
      evidence: isHostedTeacher
        ? `Teacher provider is hosted (${teacherProvider}); allow_hosted_teacher=${String(settings.allowHostedTeacher)}`
        : "Teacher provider is local/disabled; hosted egress minimized.",
    },
    {
      framework: "NIST CSF 2.0",
      control: "Protect: bounded AI role + human-in-loop",
      status: "pass",
      evidence: "LLM is explainer-only by design; human approvals required for impactful actions (see decision rights matrix).",
    },
    {
      framework: "NIST CSF 2.0",
      control: "Detect/Respond: auditable decision records",
      status: "pass",
      evidence: "Decision cards and overrides are logged; exports provide case-by-case evidence.",
    },
  ];

  return checks;
}

function buildPdfReportHtml(params: {
  programName: string;
  generatedAt: string;
  settingsSummary: Array<[string, string]>;
  llmSummary: Array<[string, string]>;
  integritySummary: Array<[string, string]>;
  checks: ComplianceCheck[];
  decisionRights: DecisionRight[];
  cases: Array<ReturnType<typeof caseSummary>>;
  appendixJson: unknown;
}) {
  const overall = overallFromChecks(params.checks);
  const checkRows = params.checks
    .map(
      (c) =>
        `<tr>
          <td>${escapeHtml(c.framework)}</td>
          <td>${escapeHtml(c.control)}</td>
          <td><span class="${statusClass(c.status)}">${statusLabel(c.status)}</span></td>
          <td>${escapeHtml(c.evidence)}</td>
        </tr>`,
    )
    .join("");

  const kvTable = (rows: Array<[string, string]>) =>
    `<table class="kv">
      <tbody>
        ${rows
          .map(
            ([k, v]) =>
              `<tr><td class="k">${escapeHtml(k)}</td><td class="v">${escapeHtml(v)}</td></tr>`,
          )
          .join("")}
      </tbody>
    </table>`;

  const rightsRows = params.decisionRights
    .map((r) => {
      const pb = `<ul>${r.privacyBoundary.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>`;
      const ae = `<ul>${r.auditEvidence.map((x) => `<li><span class="mono">${escapeHtml(x)}</span></li>`).join("")}</ul>`;
      return `<tr>
        <td><b>${escapeHtml(r.socAction)}</b></td>
        <td><span class="mono">${escapeHtml(r.aiRole)}</span></td>
        <td><span class="mono">${escapeHtml(r.humanApproval)}</span></td>
        <td>${pb}</td>
        <td>${ae}</td>
      </tr>`;
    })
    .join("");

  const caseSections = params.cases
    .map(
      (c) => `<section class="case">
        <div class="case-head">
          <div class="case-title">Case: <span class="mono">${escapeHtml(c.id)}</span></div>
          <div class="case-meta">when=${escapeHtml(c.when)} · action=${escapeHtml(c.action)} · score=${escapeHtml(String(c.score))}</div>
        </div>
        <table class="kv">
          <tbody>
            <tr><td class="k">source</td><td class="v">${escapeHtml(c.source)}</td></tr>
            <tr><td class="k">event_type</td><td class="v">${escapeHtml(c.event_type)}</td></tr>
            <tr><td class="k">policy_rule_id</td><td class="v"><span class="mono">${escapeHtml(c.policy_rule_id)}</span></td></tr>
            <tr><td class="k">osint_verdict</td><td class="v">${escapeHtml(c.osint)}</td></tr>
            <tr><td class="k">llm</td><td class="v">${escapeHtml(c.llm)}</td></tr>
            <tr><td class="k">requires_human_review</td><td class="v">${escapeHtml(String(c.requires_human_review))}</td></tr>
            <tr><td class="k">override_recorded</td><td class="v">${escapeHtml(c.override)}</td></tr>
          </tbody>
        </table>
      </section>`,
    )
    .join("");

  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>SOC Privacy & Compliance Audit</title>
    <style>
      :root{
        --text:#111827;
        --muted:#4b5563;
        --border:#e5e7eb;
        --bg:#ffffff;
        --soft:#f9fafb;
        --pass:#16a34a;
        --warn:#d97706;
        --fail:#dc2626;
      }
      @page { margin: 14mm; }
      html, body { background: var(--bg); color: var(--text); }
      body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
      .header { display:flex; justify-content:space-between; gap:16px; border-bottom:1px solid var(--border); padding-bottom:12px; margin-bottom:14px; }
      .title { font-size: 18px; font-weight: 700; margin: 0; }
      .subtitle { margin: 4px 0 0; color: var(--muted); font-size: 12px; }
      .meta { text-align:right; font-size: 11px; color: var(--muted); }
      h2 { font-size: 14px; margin: 18px 0 10px; }
      h3 { font-size: 12px; margin: 14px 0 8px; }
      .callout { border:1px solid var(--border); background: var(--soft); padding: 10px 12px; border-radius: 8px; }
      .pill { display:inline-block; padding:2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; border:1px solid var(--border); }
      .pill.pass { color: var(--pass); border-color: rgba(22,163,74,.35); background: rgba(22,163,74,.06); }
      .pill.warn { color: var(--warn); border-color: rgba(217,119,6,.35); background: rgba(217,119,6,.06); }
      .pill.fail { color: var(--fail); border-color: rgba(220,38,38,.35); background: rgba(220,38,38,.06); }
      table { width: 100%; border-collapse: collapse; }
      th, td { border:1px solid var(--border); padding: 8px; vertical-align: top; }
      th { background: var(--soft); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
      td { font-size: 12px; }
      .kv td { border-left: none; border-right:none; border-top: 1px solid var(--border); border-bottom:none; padding:6px 0; }
      .kv tr:first-child td { border-top:none; }
      .kv .k { width: 210px; color: var(--muted); font-size: 11px; text-transform: lowercase; letter-spacing:.02em; }
      .kv .v { font-size: 12px; }
      ul { margin: 0; padding-left: 18px; }
      .grid2 { display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }
      .case { border:1px solid var(--border); border-radius: 10px; padding: 10px 12px; margin: 10px 0; break-inside: avoid; }
      .case-head { display:flex; justify-content:space-between; gap:12px; align-items:flex-start; margin-bottom:8px; }
      .case-title { font-weight: 700; font-size: 12px; }
      .case-meta { font-size: 11px; color: var(--muted); text-align:right; }
      pre { white-space: pre-wrap; word-break: break-word; background: var(--soft); border:1px solid var(--border); border-radius: 8px; padding: 10px 12px; font-size: 11px; }
    </style>
  </head>
  <body>
    <div class="header">
      <div>
        <div class="title">SOC Privacy & Compliance Audit Report</div>
        <div class="subtitle">${escapeHtml(params.programName)} · Zero Trust · NIST CSF 2.0 · Privacy by Design · Auditability</div>
      </div>
      <div class="meta">
        <div>Generated: <span class="mono">${escapeHtml(params.generatedAt)}</span></div>
        <div>Report type: case-by-case audit export</div>
      </div>
    </div>

    <div class="callout">
      <div><b>Overall assessment</b>: <span class="${statusClass(overall.status)}">${escapeHtml(overall.label)}</span></div>
      <div style="margin-top:6px;color:var(--muted);font-size:12px">
        This assessment is based on captured runtime evidence (LLM provider status + audit integrity verification), configured operator posture (settings), and the program's decision rights matrix.
      </div>
    </div>

    <h2>1. System posture (captured)</h2>
    <div class="grid2">
      <div class="callout">
        <h3>Operator posture (Settings)</h3>
        ${kvTable(params.settingsSummary)}
      </div>
      <div class="callout">
        <h3>Runtime evidence</h3>
        ${kvTable(params.llmSummary)}
        <div style="height:10px"></div>
        ${kvTable(params.integritySummary)}
      </div>
    </div>

    <h2>2. Framework compliance checks</h2>
    <table>
      <thead>
        <tr>
          <th style="width:140px">Framework</th>
          <th>Control / expectation</th>
          <th style="width:90px">Status</th>
          <th>Evidence</th>
        </tr>
      </thead>
      <tbody>
        ${checkRows}
      </tbody>
    </table>

    <h2>3. Decision rights matrix (AI + privacy + audit)</h2>
    <table>
      <thead>
        <tr>
          <th style="width:140px">SOC action</th>
          <th style="width:90px">AI role</th>
          <th style="width:100px">Human approval</th>
          <th>Privacy boundary</th>
          <th>Audit evidence</th>
        </tr>
      </thead>
      <tbody>
        ${rightsRows}
      </tbody>
    </table>

    <h2>4. Case-by-case audit (most recent)</h2>
    <div style="color:var(--muted);font-size:12px;margin-bottom:8px">
      Included cases: ${escapeHtml(String(params.cases.length))}. For full raw exports, use JSON/Markdown export.
    </div>
    ${caseSections}

    <h2>5. Appendix (export payload)</h2>
    <pre>${escapeHtml(JSON.stringify(params.appendixJson, null, 2))}</pre>
  </body>
</html>`;
}

function openPrintWindow(title: string, content: string) {
  const w = window.open("", "_blank", "noopener,noreferrer");
  if (!w) {
    alert("Popup blocked. Allow popups for this site to export PDF (Print → Save as PDF).");
    return;
  }
  w.document.open();
  w.document.write(content);
  w.document.close();
  w.focus();
  w.print();
}

export function Audit() {
  const { settings } = useSettings();
  const [summary, setSummary] = useState<AuditSummary | null>(null);
  const [cards, setCards] = useState<DecisionCard[]>([]);
  const [overrides, setOverrides] = useState<OverrideRecord[]>([]);
  const [integrity, setIntegrity] = useState<AuditIntegrityVerify | null>(null);
  const [llmProvider, setLlmProvider] = useState<{ teacherProvider?: string; studentProvider?: string }>({});
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const exportJson = useMemo(
    () => ({
      exported_at: new Date().toISOString(),
      summary,
      decision_cards: cards,
      overrides,
      decision_rights_matrix: DECISION_RIGHTS_MATRIX,
    }),
    [summary, cards, overrides],
  );

  async function load() {
    setBusy(true);
    try {
      const [s, c, o, p] = await Promise.all([
        api.summary(),
        api.decisionCards(2000),
        api.overrides(2000),
        api.llmProviders(),
      ]);
      setSummary(s);
      setCards(c.items ?? []);
      setOverrides((o.items ?? []) as OverrideRecord[]);
      setLlmProvider({ teacherProvider: p.teacher?.provider, studentProvider: p.student?.provider });
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function verifyIntegrity() {
    setBusy(true);
    try {
      const v = await api.integrityVerify();
      setIntegrity(v);
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function purgeRetention() {
    if (!confirm("Purge audit ledger records beyond retention window?")) return;
    setBusy(true);
    try {
      await api.purgeRetention();
      await load();
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const integrityOk =
    integrity?.decision_cards.ok && integrity?.overrides.ok && integrity?.simulation_runs.ok;

  const overrideMap = useMemo(() => {
    const m = new Map<string, OverrideRecord>();
    for (const o of overrides) {
      if (!m.has(o.decision_card_id)) m.set(o.decision_card_id, o);
    }
    return m;
  }, [overrides]);

  async function exportPdf() {
    setBusy(true);
    try {
      const v = integrity ?? (await api.integrityVerify());
      setIntegrity(v);
      const checks = buildComplianceChecks({ integrity: v, llmProvider, settings });
      const cases = cards.slice(0, 25).map((c) => caseSummary(c, overrideMap.get(c.decision_card_id)));
      const html = buildPdfReportHtml({
        programName: settings.programName,
        generatedAt: new Date().toISOString(),
        settingsSummary: [
          ["tenant", settings.tenant],
          ["env", settings.env],
          ["deployment_profile", settings.deploymentProfile],
          ["guardrails_strict", String(settings.guardrailsStrict)],
          ["allow_hosted_teacher", String(settings.allowHostedTeacher)],
          ["gpu_enabled_for_local_llm", String(settings.gpuEnabledForLocalLlm)],
        ],
        llmSummary: [
          ["student_provider", llmProvider.studentProvider ?? "unknown"],
          ["teacher_provider", llmProvider.teacherProvider ?? "unknown"],
        ],
        integritySummary: [
          ["audit_auth_enabled", String(Boolean(v.auth_enabled))],
          ["hash_chain_ok", String(Boolean(v.decision_cards.ok && v.overrides.ok && v.simulation_runs.ok))],
          ["decision_cards_checked", String(v.decision_cards.checked)],
          ["overrides_checked", String(v.overrides.checked)],
          ["simulation_runs_checked", String(v.simulation_runs.checked)],
        ],
        checks,
        decisionRights: DECISION_RIGHTS_MATRIX,
        cases,
        appendixJson: exportJson,
      });
      openPrintWindow("SOC Privacy & Compliance Audit", html);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-text">Audit</h1>
          <p className="mt-1 text-sm text-subtle">
            Ledger visibility, integrity checks, retention operations, and exports for evidence packs.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button className="btn" onClick={() => downloadText("soc-audit.json", JSON.stringify(exportJson, null, 2), "application/json")}>
            <Download size={14} /> Export JSON
          </button>
          <button className="btn" onClick={() => downloadText("soc-audit.md", toMarkdown(summary, cards, overrides), "text/markdown")}>
            <Download size={14} /> Export Markdown
          </button>
          <button
            className="btn"
            onClick={exportPdf}
            title="Uses browser Print → Save as PDF"
            disabled={busy}
          >
            <Download size={14} /> Export PDF
          </button>
        </div>
      </header>

      {err && (
        <div className="rounded-lg border border-sev-critical/40 bg-sev-critical/10 p-3 text-sm text-sev-critical">
          {err}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card
          className="xl:col-span-2"
          title="Ledger status"
          subtitle="Counts come from the audit summary endpoint."
          action={
            <div className="flex gap-2">
              <button className="btn" onClick={verifyIntegrity} disabled={busy}>
                <ShieldCheck size={14} /> Verify integrity
              </button>
              <button className="btn" onClick={purgeRetention} disabled={busy}>
                <Trash2 size={14} /> Purge retention
              </button>
            </div>
          }
        >
          {!summary ? (
            <EmptyState title="No summary yet" description="Ensure SOC API key is set and the audit service is healthy." />
          ) : (
            <div className="grid gap-3 md:grid-cols-3">
              <div className="card px-4 py-3">
                <div className="label">Decision cards</div>
                <div className="mt-2 font-mono text-2xl font-semibold text-text">{summary.total_decisions}</div>
              </div>
              <div className="card px-4 py-3">
                <div className="label">Overrides</div>
                <div className="mt-2 font-mono text-2xl font-semibold text-text">{summary.total_overrides}</div>
              </div>
              <div className="card px-4 py-3">
                <div className="label">OSINT enriched</div>
                <div className="mt-2 font-mono text-2xl font-semibold text-text">{summary.osint_enriched_count}</div>
              </div>
            </div>
          )}

          {integrity && (
            <div className="mt-4 rounded-lg border border-border bg-muted/40 p-3 text-sm">
              <div className="flex items-center justify-between">
                <div className="font-medium text-text">Integrity</div>
                <div className={integrityOk ? "text-sev-low" : "text-sev-critical"}>
                  {integrityOk ? "ok" : "failed"}
                </div>
              </div>
              <div className="mt-2 grid gap-2 md:grid-cols-3">
                <div className="mono text-[12px] text-subtle">
                  decision_cards: {String(integrity.decision_cards.ok)} (checked {integrity.decision_cards.checked})
                </div>
                <div className="mono text-[12px] text-subtle">
                  overrides: {String(integrity.overrides.ok)} (checked {integrity.overrides.checked})
                </div>
                <div className="mono text-[12px] text-subtle">
                  simulation_runs: {String(integrity.simulation_runs.ok)} (checked {integrity.simulation_runs.checked})
                </div>
              </div>
            </div>
          )}
        </Card>

        <Card title="Export guidance" subtitle="How to use exports for compliance evidence.">
          <ul className="list-disc space-y-1.5 pl-5 text-sm text-subtle">
            <li>
              <b>JSON</b> is best for machine processing and long-term evidence packs.
            </li>
            <li>
              <b>Markdown</b> is best for tickets, runbooks, and review notes.
            </li>
            <li>
              <b>PDF</b> export uses browser print-to-PDF; it does not require extra dependencies.
            </li>
          </ul>
        </Card>
      </div>

      <Card
        title="Decision rights matrix (AI + privacy + audit)"
        subtitle="Defines what the AI may do, when human approval is required, privacy boundaries, and what evidence must be logged."
      >
        <div className="overflow-hidden rounded-lg border border-border">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60 text-left text-[11px] uppercase tracking-wider text-dim">
              <tr>
                <th className="px-3 py-2">SOC action</th>
                <th className="px-3 py-2">AI role</th>
                <th className="px-3 py-2">Human approval</th>
                <th className="px-3 py-2">Privacy boundary</th>
                <th className="px-3 py-2">Audit evidence</th>
              </tr>
            </thead>
            <tbody>
              {DECISION_RIGHTS_MATRIX.map((row) => (
                <tr key={row.socAction} className="border-t border-border/80 align-top">
                  <td className="px-3 py-2 font-medium text-text">{row.socAction}</td>
                  <td className="px-3 py-2">
                    <span className="mono text-[12px] text-subtle">{row.aiRole}</span>
                  </td>
                  <td className="px-3 py-2">
                    <span className="mono text-[12px] text-subtle">{row.humanApproval}</span>
                  </td>
                  <td className="px-3 py-2">
                    <ul className="list-disc space-y-1 pl-4 text-[12px] text-subtle">
                      {row.privacyBoundary.map((x) => (
                        <li key={x}>{x}</li>
                      ))}
                    </ul>
                  </td>
                  <td className="px-3 py-2">
                    <ul className="list-disc space-y-1 pl-4 text-[12px] text-subtle">
                      {row.auditEvidence.map((x) => (
                        <li key={x} className="mono">
                          {x}
                        </li>
                      ))}
                    </ul>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

