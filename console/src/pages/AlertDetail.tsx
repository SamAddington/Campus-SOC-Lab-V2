import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  BrainCircuit,
  CircleCheck,
  FileText,
  Gavel,
  Globe2,
  Network,
  ShieldAlert,
  ShieldCheck,
  Pencil,
  History,
  PlayCircle,
  AlertTriangle,
  GraduationCap,
  Cpu,
} from "lucide-react";
import {
  api,
  type DecisionCard,
  type LLMAssistRequest,
  type LLMAssistResponse,
  type OverrideRecord,
} from "@/lib/api";
import { AssistResponseView } from "@/pages/LLM";
import { Card, EmptyState, KeyValueGrid } from "@/components/ui/Card";
import { Chip, SeverityBadge } from "@/components/ui/Badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/Tabs";
import { ScoreBar } from "@/components/ui/ScoreBar";
import { JsonView } from "@/components/ui/JsonView";
import { Modal } from "@/components/ui/Modal";
import {
  absoluteTime,
  actionSeverity,
  relativeTime,
} from "@/lib/format";
import { useSettings } from "@/lib/settings";
import { decisionRightsForAction } from "@/lib/decision_rights";

const ACTION_OPTIONS = ["allow", "queue_for_review", "escalate"] as const;

type PrivacyFinding = {
  status: "pass" | "warn" | "fail";
  title: string;
  details: string;
};

function detectPossiblePII(text: string): string[] {
  const hits: string[] = [];
  const email = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
  const studentId = /\b(student|sid|s\d{5,})\b/gi;
  const ssnLike = /\b\d{3}-\d{2}-\d{4}\b/g;
  if (email.test(text)) hits.push("Looks like an email address appears in a narrative field.");
  if (studentId.test(text)) hits.push("Looks like an identity token appears in a narrative field.");
  if (ssnLike.test(text)) hits.push("Looks like an SSN-like pattern appears in a narrative field.");
  return hits;
}

function privacyAssessment(params: {
  card: DecisionCard;
  overrides: OverrideRecord[];
  allowHostedTeacher: boolean;
}) {
  const { card, overrides, allowHostedTeacher } = params;
  const findings: PrivacyFinding[] = [];

  // Purpose limitation (best-effort: this stack is for SOC triage only)
  findings.push({
    status: "pass",
    title: "Purpose limitation",
    details: "Decision card is used for SOC triage (allow / queue_for_review / escalate) and reviewer overrides; no autonomous enforcement is performed by the LLM.",
  });

  // Data minimization
  const narratives = [card.explanation, card.analyst_summary, card.helpdesk_explanation]
    .filter(Boolean)
    .join("\n");
  const piiHits = detectPossiblePII(narratives);
  if (piiHits.length) {
    findings.push({
      status: "warn",
      title: "Data minimization",
      details: `Potential PII detected in narrative fields. ${piiHits.join(" ")}`,
    });
  } else {
    findings.push({
      status: "pass",
      title: "Data minimization",
      details: "No obvious PII patterns detected in explanation / analyst summary / helpdesk explanation.",
    });
  }

  // Hosted teacher privacy boundary
  const hosted = (card.llm_provider || "").toLowerCase() === "openai" || (card.llm_provider || "").toLowerCase() === "anthropic";
  if (hosted && !allowHostedTeacher) {
    findings.push({
      status: "fail",
      title: "Hosted AI boundary (privacy)",
      details: `Decision shows llm_provider=${card.llm_provider}, but Settings disallow hosted teacher usage. Treat as a privacy policy violation and require review.`,
    });
  } else if (hosted) {
    findings.push({
      status: "warn",
      title: "Hosted AI boundary (privacy)",
      details: `Decision used hosted provider (${card.llm_provider}). Ensure prompts are compliant with policy and vendor terms; provenance is logged for audit.`,
    });
  } else {
    findings.push({
      status: "pass",
      title: "Hosted AI boundary (privacy)",
      details: "No hosted LLM provider detected on this decision card.",
    });
  }

  // Retention control (best-effort: we can only assert that ledger retention exists, not that purge ran)
  findings.push({
    status: "warn",
    title: "Retention control",
    details: "Ledger retention is enforced by the audit service (AUDIT_RETENTION_DAYS + purge endpoint). This UI cannot confirm purge cadence for this specific record.",
  });

  // Human approval / audit trail
  if (card.requires_human_review && overrides.length === 0) {
    findings.push({
      status: "warn",
      title: "Human approval",
      details: "Human review is required but no override record exists yet. Ensure a reviewer logs an approval/override decision.",
    });
  } else {
    findings.push({
      status: "pass",
      title: "Human approval",
      details: overrides.length ? "Override/approval records exist for this decision card." : "No human approval required by policy for this decision.",
    });
  }

  return findings;
}

export function AlertDetail() {
  const { decisionCardId } = useParams();
  const [card, setCard] = useState<DecisionCard | null>(null);
  const [overrides, setOverrides] = useState<OverrideRecord[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [creatingCase, setCreatingCase] = useState(false);

  const load = async () => {
    try {
      const [cardsRes, overridesRes] = await Promise.all([
        api.decisionCards(1000),
        api.overrides(200),
      ]);
      const found = cardsRes.items.find((c) => c.decision_card_id === decisionCardId);
      setCard(found ?? null);
      setOverrides(
        (overridesRes.items ?? []).filter(
          (o: OverrideRecord) => o.decision_card_id === decisionCardId,
        ),
      );
      setErr(found ? null : "Decision card not found in audit ledger.");
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [decisionCardId]);

  const sev = useMemo(() => actionSeverity(card?.permitted_action), [card]);

  const latestOverride = overrides[0] ?? null;
  const effectiveAction = card?.final_human_action ?? latestOverride?.overridden_action ?? null;

  if (err && !card) {
    return (
      <div className="space-y-4">
        <BackLink />
        <Card>
          <div className="text-sm text-sev-critical">{err}</div>
        </Card>
      </div>
    );
  }
  if (!card) {
    return (
      <div className="space-y-4">
        <BackLink />
        <Card>
          <div className="text-sm text-subtle">Loading…</div>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <BackLink />

      <header className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={sev}>
              {card.permitted_action.replace(/_/g, " ")}
            </SeverityBadge>
            {effectiveAction && effectiveAction !== card.permitted_action && (
              <SeverityBadge severity={actionSeverity(effectiveAction)}>
                overridden → {effectiveAction.replace(/_/g, " ")}
              </SeverityBadge>
            )}
            {card.requires_human_review && (
              <Chip>
                <ShieldAlert size={12} className="text-sev-medium" />
                human review
              </Chip>
            )}
            {card.scenario_id && <Chip>scenario: {card.scenario_id}</Chip>}
            {card.osint_enabled && !card.osint_skipped && (
              <Chip>osint: {card.osint_verdict ?? "unknown"}</Chip>
            )}
            {card.llm_used && (
              <Chip>
                llm: {card.llm_tier ?? "?"} · {card.llm_provider ?? "?"}
              </Chip>
            )}
          </div>
          <h1 className="mt-2 text-xl font-semibold text-text">
            {card.label || card.event_type}
          </h1>
          <div className="mt-1 mono text-[12px] text-subtle">
            {card.decision_card_id}
          </div>
          <div className="mt-1 text-xs text-dim">
            {relativeTime(card.timestamp)} · {absoluteTime(card.timestamp)}
          </div>
        </div>

        <div className="flex flex-col items-end gap-3">
          <button className="btn btn-primary" onClick={() => setModalOpen(true)}>
            <Pencil size={14} />
            Override action
          </button>
          <div className="grid grid-cols-3 gap-3">
            <ScoreBar label="Rule" value={card.risk_score_rule} />
            <ScoreBar label="Federated" value={card.risk_score_fl} />
            <ScoreBar label="Final" value={card.risk_score_final} />
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            className="btn"
            disabled={creatingCase}
            onClick={async () => {
              try {
                setCreatingCase(true);
                const title = `Investigation: ${card.permitted_action} · ${card.source}/${card.event_type}`;
                const r = await api.caseCreate({
                  title,
                  description: `Created from decision card ${card.decision_card_id} (event_id ${card.event_id}).`,
                  severity: actionSeverity(card.permitted_action),
                  status: "open",
                  related_decision_cards: [card.decision_card_id],
                  related_event_ids: [card.event_id],
                });
                globalThis.location.assign(`/cases/${encodeURIComponent(r.case_id)}`);
              } catch (e) {
                setErr((e as Error).message);
              } finally {
                setCreatingCase(false);
              }
            }}
            title="Create a case from this alert"
          >
            Create case
          </button>
        </div>
      </header>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">
            <FileText size={14} className="mr-1 inline" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="detector">Detector</TabsTrigger>
          <TabsTrigger value="policy">
            <Gavel size={14} className="mr-1 inline" />
            Policy
          </TabsTrigger>
          <TabsTrigger value="osint">
            <Globe2 size={14} className="mr-1 inline" />
            OSINT
          </TabsTrigger>
          <TabsTrigger value="llm">
            <BrainCircuit size={14} className="mr-1 inline" />
            LLM
          </TabsTrigger>
          <TabsTrigger value="privacy">
            <ShieldCheck size={14} className="mr-1 inline" />
            Privacy
          </TabsTrigger>
          <TabsTrigger value="federated">
            <Network size={14} className="mr-1 inline" />
            Federated
          </TabsTrigger>
          <TabsTrigger value="history" count={overrides.length}>
            <History size={14} className="mr-1 inline" />
            History
          </TabsTrigger>
          <TabsTrigger value="raw">Raw</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <Card title="Event" className="xl:col-span-2">
              <KeyValueGrid
                rows={[
                  { k: "Event ID", v: <span className="mono">{card.event_id}</span> },
                  { k: "Source", v: card.source },
                  { k: "Type", v: card.event_type },
                  { k: "Language", v: card.language },
                  { k: "Scenario", v: card.scenario_id ?? "—" },
                  { k: "Threshold", v: card.threshold_version ?? "default" },
                  {
                    k: "Consent (distill)",
                    v: card.consent_use_for_distillation ? "granted" : "not granted",
                  },
                ]}
              />
              <div className="mt-3">
                <Link
                  className="btn"
                  to={`/timeline?${new URLSearchParams({ event_id: card.event_id }).toString()}`}
                >
                  Open event in timeline
                </Link>
              </div>
            </Card>

            <Card title="Triage">
              <KeyValueGrid
                rows={[
                  {
                    k: "Action",
                    v: (
                      <SeverityBadge severity={sev}>
                        {card.permitted_action.replace(/_/g, " ")}
                      </SeverityBadge>
                    ),
                  },
                  {
                    k: "Human review",
                    v: card.requires_human_review ? (
                      <span className="inline-flex items-center gap-1 text-sev-medium">
                        <ShieldAlert size={14} /> required
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-sev-low">
                        <CircleCheck size={14} /> not required
                      </span>
                    ),
                  },
                  {
                    k: "Final human action",
                    v: effectiveAction ? (
                      <SeverityBadge severity={actionSeverity(effectiveAction)}>
                        {effectiveAction.replace(/_/g, " ")}
                      </SeverityBadge>
                    ) : (
                      "—"
                    ),
                  },
                  { k: "Policy rule", v: <Chip>{card.policy_rule_id}</Chip> },
                ]}
              />
            </Card>

            <Card className="xl:col-span-3" title="Explanation">
              <p className="text-sm leading-relaxed text-text">
                {card.explanation || "No explanation returned."}
              </p>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="detector">
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <ScoreBar label="Rule-based" value={card.risk_score_rule} hint="Interpretable rule core" />
            <ScoreBar label="Federated (FL)" value={card.risk_score_fl} hint="Aggregated cross-client model" />
            <ScoreBar label="Final (policy input)" value={card.risk_score_final} hint="Fed into policy engine" />
          </div>
          <Card className="mt-4" title="Detector explanation">
            <p className="text-sm text-text">{card.explanation || "—"}</p>
          </Card>
        </TabsContent>

        <TabsContent value="policy">
          <Card title="Policy engine result">
            <KeyValueGrid
              rows={[
                { k: "Rule ID", v: <Chip>{card.policy_rule_id}</Chip> },
                {
                  k: "Permitted action",
                  v: (
                    <SeverityBadge severity={sev}>
                      {card.permitted_action.replace(/_/g, " ")}
                    </SeverityBadge>
                  ),
                },
                {
                  k: "Requires human review",
                  v: card.requires_human_review ? "yes" : "no",
                },
                {
                  k: "Scores seen by policy",
                  v: (
                    <span className="mono text-subtle">
                      rule={card.risk_score_rule?.toFixed?.(2) ?? card.risk_score_rule} · fl=
                      {card.risk_score_fl?.toFixed?.(2) ?? "n/a"} · final=
                      {card.risk_score_final?.toFixed?.(2) ?? card.risk_score_final}
                    </span>
                  ),
                },
              ]}
            />
          </Card>
        </TabsContent>

        <TabsContent value="osint">
          {card.osint_enabled && !card.osint_skipped ? (
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
              <Card title="Summary">
                <KeyValueGrid
                  rows={[
                    { k: "Verdict", v: <Chip>{card.osint_verdict ?? "unknown"}</Chip> },
                    {
                      k: "Score",
                      v: (
                        <span className="mono">
                          {card.osint_score?.toFixed?.(2) ?? card.osint_score ?? "—"}
                        </span>
                      ),
                    },
                    { k: "Indicators", v: card.osint_indicator_count ?? 0 },
                    {
                      k: "Providers",
                      v:
                        (card.osint_providers_used ?? []).length === 0 ? (
                          <span className="text-dim">—</span>
                        ) : (
                          <div className="flex flex-wrap gap-1">
                            {(card.osint_providers_used ?? []).map((p) => (
                              <Chip key={p}>{p}</Chip>
                            ))}
                          </div>
                        ),
                    },
                  ]}
                />
              </Card>
              <Card className="xl:col-span-2" title="Short explanation">
                <p className="text-sm text-text">
                  {card.osint_short_explanation || "No OSINT explanation available."}
                </p>
              </Card>
            </div>
          ) : (
            <Card>
              <div className="text-sm text-subtle">
                OSINT enrichment was{" "}
                {card.osint_enabled === false ? "disabled" : "skipped"} for this event.
              </div>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="llm">
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <Card title="Provenance">
              <KeyValueGrid
                rows={[
                  {
                    k: "Used",
                    v: card.llm_used ? (
                      <span className="inline-flex items-center gap-1 text-sev-low">
                        <CircleCheck size={14} /> yes
                      </span>
                    ) : (
                      <span className="text-dim">fallback</span>
                    ),
                  },
                  { k: "Tier", v: card.llm_tier ?? "—" },
                  { k: "Provider", v: card.llm_provider ?? "—" },
                  { k: "Model", v: <span className="mono">{card.llm_model ?? "—"}</span> },
                  { k: "Reason", v: card.llm_reason ?? "—" },
                ]}
              />
            </Card>
            <Card title="Analyst summary" className="xl:col-span-2">
              <p className="whitespace-pre-wrap text-sm leading-relaxed text-text">
                {card.analyst_summary || "No analyst summary returned."}
              </p>
            </Card>
            <Card title="Helpdesk explanation" className="xl:col-span-2">
              <p className="whitespace-pre-wrap text-sm leading-relaxed text-text">
                {card.helpdesk_explanation || "No helpdesk explanation returned."}
              </p>
            </Card>
            <Card title="Next steps">
              <ol className="list-decimal space-y-1.5 pl-4 text-sm text-text">
                {(card.next_steps ?? []).length === 0 && (
                  <li className="list-none text-dim">No next steps returned.</li>
                )}
                {(card.next_steps ?? []).map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            </Card>

            <div className="xl:col-span-3">
              <ReAskPanel card={card} />
            </div>
          </div>
        </TabsContent>

        <TabsContent value="privacy">
          <PrivacyTab card={card} overrides={overrides} />
        </TabsContent>

        <TabsContent value="federated">
          <Card title="Federated contribution">
            <KeyValueGrid
              rows={[
                {
                  k: "FL score",
                  v: (
                    <span className="mono">
                      {card.risk_score_fl?.toFixed?.(2) ?? card.risk_score_fl ?? "n/a"}
                    </span>
                  ),
                },
                { k: "Model round", v: card.model_round ?? "n/a" },
                { k: "Threshold", v: card.threshold_version ?? "default" },
              ]}
            />
            <p className="mt-3 text-xs text-subtle">
              The FL score comes from the aggregator’s global model. See{" "}
              <Link to="/federated" className="text-accent hover:underline">
                Federated ML
              </Link>{" "}
              for round state and client participation.
            </p>
          </Card>
        </TabsContent>

        <TabsContent value="history">
          <Card
            title="Override history"
            subtitle="All human overrides recorded for this decision card."
          >
            {overrides.length === 0 ? (
              <EmptyState
                title="No overrides yet"
                description="Use the Override action button to record a reviewer decision."
                icon={<History size={22} />}
              />
            ) : (
              <ul className="divide-y divide-border">
                {overrides.map((o, i) => (
                  <li key={`${o.timestamp}-${i}`} className="py-3">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={actionSeverity(o.original_action)}>
                        {o.original_action.replace(/_/g, " ")}
                      </SeverityBadge>
                      <span className="text-dim">→</span>
                      <SeverityBadge severity={actionSeverity(o.overridden_action)}>
                        {o.overridden_action.replace(/_/g, " ")}
                      </SeverityBadge>
                      <span className="ml-auto text-[11px] text-dim">
                        {relativeTime(o.timestamp)}
                      </span>
                    </div>
                    <div className="mt-2 text-sm text-text">{o.reason}</div>
                    <div className="mt-1 text-[11px] text-dim">
                      reviewer <span className="mono">{o.reviewer_id}</span> ·{" "}
                      <span className="mono">{absoluteTime(o.timestamp)}</span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </TabsContent>

        <TabsContent value="raw">
          <Card title="Decision card (raw)">
            <JsonView value={card} />
          </Card>
        </TabsContent>
      </Tabs>

      <OverrideModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        card={card}
        onSubmitted={(rec) => {
          setOverrides((prev) => [rec, ...prev]);
          setModalOpen(false);
          // Kick a background refresh so other tabs stay consistent.
          load();
        }}
      />
    </div>
  );
}

function PrivacyTab({ card, overrides }: { card: DecisionCard; overrides: OverrideRecord[] }) {
  const { settings } = useSettings();
  const [integrity, setIntegrity] = useState<{ ok: boolean; detail: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const allowHostedTeacher = Boolean(settings.allowHostedTeacher);

  const findings = useMemo(
    () => privacyAssessment({ card, overrides, allowHostedTeacher }),
    [card, overrides, allowHostedTeacher],
  );

  const hasFail = findings.some((f) => f.status === "fail");
  const hasWarn = findings.some((f) => f.status === "warn");
  const verdict = hasFail ? "fail" : hasWarn ? "warn" : "pass";

  // Best-effort: map triage outcome to a rights-matrix row (ticketing is the default control plane here)
  const mappedSocAction =
    card.permitted_action === "allow"
      ? "Open ticket"
      : card.permitted_action === "queue_for_review"
      ? "Open ticket"
      : "Open ticket";
  const rights = decisionRightsForAction(mappedSocAction);

  const verifyIntegrity = async () => {
    try {
      const v = await api.integrityVerify();
      const ok = Boolean(v.decision_cards.ok && v.overrides.ok && v.simulation_runs.ok);
      setIntegrity({
        ok,
        detail: `decision_cards=${String(v.decision_cards.ok)} overrides=${String(v.overrides.ok)} simulation_runs=${String(v.simulation_runs.ok)}`,
      });
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  return (
    <div className="space-y-4">
      {(verdict === "fail" || verdict === "warn") && (
        <Card
          title={verdict === "fail" ? "Privacy compliance alert" : "Privacy review recommended"}
          subtitle="This section checks privacy principles and AI boundaries using the Decision Rights Matrix and runtime evidence."
        >
          <div className={verdict === "fail" ? "text-sm text-sev-critical" : "text-sm text-sev-medium"}>
            {verdict === "fail"
              ? "This decision appears to violate at least one privacy boundary or program rule. Request audit review and record a human approval/override."
              : "This decision warrants a human privacy review. Verify audit integrity and ensure approval/override logs are captured if required."}
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <Link to="/audit" className="btn btn-primary">
              Open Audit page
            </Link>
            <button className="btn" onClick={verifyIntegrity}>
              Verify ledger integrity
            </button>
            <button
              className="btn"
              onClick={() =>
                globalThis.window?.scrollTo?.({
                  top: globalThis.document?.body?.scrollHeight ?? 0,
                  behavior: "smooth",
                })
              }
            >
              Jump to override review
            </button>
          </div>
          {err && <div className="mt-2 text-xs text-sev-critical">{err}</div>}
          {integrity && (
            <div className="mt-2 text-xs text-subtle">
              integrity: <span className="mono">{integrity.detail}</span> →{" "}
              <span className={integrity.ok ? "text-sev-low" : "text-sev-critical"}>
                {integrity.ok ? "ok" : "failed"}
              </span>
            </div>
          )}
        </Card>
      )}

      <Card title="Decision Rights Matrix (applied)">
        <KeyValueGrid
          rows={[
            { k: "Mapped SOC action", v: mappedSocAction },
            { k: "AI role", v: rights ? <span className="mono">{rights.aiRole}</span> : "—" },
            { k: "Human approval", v: rights ? <span className="mono">{rights.humanApproval}</span> : "—" },
            { k: "Requires human review (policy)", v: card.requires_human_review ? "yes" : "no" },
            { k: "Overrides recorded", v: overrides.length ? `${overrides.length}` : "0" },
          ]}
        />
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <div className="rounded-lg border border-border bg-muted/40 p-3">
            <div className="label mb-1">Privacy boundary</div>
            <ul className="list-disc space-y-1 pl-5 text-sm text-subtle">
              {(rights?.privacyBoundary ?? ["(no matrix row matched)"]).map((x) => (
                <li key={x}>{x}</li>
              ))}
            </ul>
          </div>
          <div className="rounded-lg border border-border bg-muted/40 p-3">
            <div className="label mb-1">Audit evidence required</div>
            <ul className="list-disc space-y-1 pl-5 text-sm text-subtle">
              {(rights?.auditEvidence ?? ["(no matrix row matched)"]).map((x) => (
                <li key={x} className="mono">
                  {x}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </Card>

      <Card title="Privacy principle checks">
        <ul className="space-y-2">
          {findings.map((f) => (
            <li key={f.title} className="rounded-lg border border-border bg-muted/30 p-3">
              <div className="flex items-center justify-between">
                <div className="text-sm font-medium text-text">{f.title}</div>
                <span
                  className={
                    "mono text-[11px] " +
                    (f.status === "pass"
                      ? "text-sev-low"
                      : f.status === "warn"
                      ? "text-sev-medium"
                      : "text-sev-critical")
                  }
                >
                  {f.status.toUpperCase()}
                </span>
              </div>
              <div className="mt-1 text-[13px] leading-relaxed text-subtle">{f.details}</div>
            </li>
          ))}
        </ul>
      </Card>

      <Card
        title="Approval logs & override review"
        subtitle="If human approval is required, record an override (even if confirming the same action) with rationale."
      >
        {overrides.length === 0 ? (
          <EmptyState
            title="No approval / override records"
            description="Use Override action to log an approval/override decision and rationale."
            icon={<History size={22} />}
          />
        ) : (
          <ul className="divide-y divide-border">
            {overrides.map((o, i) => (
              <li key={`${o.timestamp}-${i}`} className="py-3">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={actionSeverity(o.original_action)}>
                    {o.original_action.replace(/_/g, " ")}
                  </SeverityBadge>
                  <span className="text-dim">→</span>
                  <SeverityBadge severity={actionSeverity(o.overridden_action)}>
                    {o.overridden_action.replace(/_/g, " ")}
                  </SeverityBadge>
                  <span className="ml-auto text-[11px] text-dim">{relativeTime(o.timestamp)}</span>
                </div>
                <div className="mt-2 text-sm text-text">{o.reason}</div>
                <div className="mt-1 text-[11px] text-dim">
                  approver <span className="mono">{o.reviewer_id}</span> ·{" "}
                  <span className="mono">{absoluteTime(o.timestamp)}</span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function BackLink() {
  return (
    <Link
      to="/alerts"
      className="inline-flex items-center gap-1 text-xs text-subtle hover:text-text"
    >
      <ArrowLeft size={14} />
      Back to alerts
    </Link>
  );
}

function OverrideModal({
  open,
  onClose,
  card,
  onSubmitted,
}: {
  open: boolean;
  onClose: () => void;
  card: DecisionCard;
  onSubmitted: (rec: OverrideRecord) => void;
}) {
  const { settings } = useSettings();
  const [reviewer, setReviewer] = useState(settings.analystId);
  const [newAction, setNewAction] = useState<string>(() =>
    card.permitted_action === "escalate" ? "queue_for_review" : "escalate",
  );

  // Keep the reviewer field in sync if the analyst updates their ID in Settings
  // while the modal is closed (when open, let the user keep their edits).
  useEffect(() => {
    if (!open) setReviewer(settings.analystId);
  }, [settings.analystId, open]);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const disabled =
    submitting ||
    !reviewer.trim() ||
    !reason.trim() ||
    newAction === card.permitted_action;

  const submit = async () => {
    setSubmitting(true);
    setErr(null);
    const payload = {
      decision_card_id: card.decision_card_id,
      event_id: card.event_id,
      reviewer_id: reviewer.trim(),
      original_action: card.permitted_action,
      overridden_action: newAction,
      reason: reason.trim(),
    };
    try {
      await api.logOverride(payload);
      const optimistic: OverrideRecord = {
        ...payload,
        timestamp: new Date().toISOString(),
      };
      onSubmitted(optimistic);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Override decision"
      subtitle={
        <>
          Recording a human override for{" "}
          <span className="mono">{card.decision_card_id}</span>. The original
          detector/policy result stays intact in the audit ledger; this is added
          as an immutable override record.
        </>
      }
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={submitting}>
            Cancel
          </button>
          <button className="btn btn-primary" onClick={submit} disabled={disabled}>
            {submitting ? "Submitting…" : "Record override"}
          </button>
        </>
      }
    >
      <div className="space-y-3">
        <div>
          <label className="label">Reviewer ID</label>
          <input
            className="input mt-1"
            value={reviewer}
            onChange={(e) => setReviewer(e.target.value)}
            placeholder="e.g. analyst-1"
          />
        </div>

        <div>
          <label className="label">New action</label>
          <div className="mt-1 grid grid-cols-3 gap-2">
            {ACTION_OPTIONS.map((a) => {
              const active = newAction === a;
              return (
                <button
                  key={a}
                  type="button"
                  onClick={() => setNewAction(a)}
                  className={
                    "rounded-md border px-2 py-1.5 text-xs transition-colors " +
                    (active
                      ? "border-accent/60 bg-accent/10 text-accent"
                      : "border-border bg-muted text-subtle hover:text-text")
                  }
                >
                  {a.replace(/_/g, " ")}
                </button>
              );
            })}
          </div>
          {newAction === card.permitted_action && (
            <div className="mt-1 text-[11px] text-sev-medium">
              Pick an action different from the current one.
            </div>
          )}
        </div>

        <div>
          <label className="label">Reason</label>
          <textarea
            className="input mt-1 min-h-[90px] resize-y"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Why are you overriding this decision? (e.g. legitimate course reminder flagged due to password-reset phrasing)"
          />
        </div>

        {err && (
          <div className="rounded-md border border-sev-critical/40 bg-sev-critical/10 p-2 text-xs text-sev-critical">
            {err}
          </div>
        )}
      </div>
    </Modal>
  );
}

function ReAskPanel({ card }: { card: DecisionCard }) {
  const [mode, setMode] = useState<LLMAssistRequest["mode"]>(null);
  const [running, setRunning] = useState(false);
  const [resp, setResp] = useState<LLMAssistResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const run = async () => {
    setRunning(true);
    setErr(null);
    try {
      const body: LLMAssistRequest = {
        event_id: card.event_id,
        source: card.source,
        event_type: card.event_type,
        language: card.language || "en",
        risk_score_rule: card.risk_score_rule,
        risk_score_fl: card.risk_score_fl,
        risk_score_final: card.risk_score_final,
        label: card.label,
        action: card.permitted_action,
        explanation: card.explanation,
        policy_rule_id: card.policy_rule_id,
        policy_reason: card.explanation || "",
        requires_human_review: card.requires_human_review,
        features: {},
        scenario_id: card.scenario_id ?? null,
        mode: mode ?? null,
      };
      const res = await api.llmAssist(body);
      setResp(res);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <BrainCircuit size={14} className="text-accent" /> Re-ask LLM
        </span>
      }
      subtitle={
        <>
          Call <span className="mono">POST /assist</span> again with this
          card's context. The response shown here is <i>not</i> written to the
          audit ledger — it's for comparison only.
        </>
      }
      action={
        <div className="flex items-center gap-2">
          <select
            aria-label="Routing mode"
            className="input h-8 w-[220px] font-mono text-[12px]"
            value={mode ?? ""}
            onChange={(e) =>
              setMode(
                e.target.value === ""
                  ? null
                  : (e.target.value as LLMAssistRequest["mode"]),
              )
            }
          >
            <option value="">— server default —</option>
            <option value="student_only">student_only</option>
            <option value="teacher_only">teacher_only</option>
            <option value="teacher_shadow">teacher_shadow</option>
            <option value="teacher_then_student_refine">
              teacher_then_student_refine
            </option>
          </select>
          <button className="btn btn-primary" onClick={run} disabled={running}>
            <PlayCircle size={14} /> {running ? "Asking…" : "Re-ask"}
          </button>
        </div>
      }
    >
      {err && (
        <div className="mb-3 inline-flex items-center gap-1 rounded-md border border-sev-critical/40 bg-sev-critical/10 px-2 py-1 text-xs text-sev-critical">
          <AlertTriangle size={12} /> {err}
        </div>
      )}
      <div className="grid gap-4 xl:grid-cols-2">
        <div>
          <div className="label mb-2 flex items-center gap-2">
            <Cpu size={12} /> Stored in audit
          </div>
          <StoredAssistBlock card={card} />
        </div>
        <div>
          <div className="label mb-2 flex items-center gap-2">
            <GraduationCap size={12} /> Fresh response
          </div>
          {!resp ? (
            <div className="rounded-lg border border-dashed border-border bg-muted/30 p-4 text-center text-xs text-dim">
              Press <b>Re-ask</b> to call the LLM again. Useful for comparing
              student vs teacher on the same input.
            </div>
          ) : (
            <AssistResponseView resp={resp} />
          )}
        </div>
      </div>
    </Card>
  );
}

function StoredAssistBlock({ card }: { card: DecisionCard }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {card.llm_used ? (
          <span className="inline-flex items-center gap-1 rounded-md border border-sev-low/40 bg-sev-low/10 px-2 py-0.5 text-[11px] text-sev-low">
            <CircleCheck size={12} /> llm_used
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 rounded-md border border-border bg-muted px-2 py-0.5 text-[11px] text-dim">
            fallback
          </span>
        )}
        <Chip>tier: {card.llm_tier ?? "—"}</Chip>
        {card.llm_provider && <Chip>provider: {card.llm_provider}</Chip>}
        {card.llm_model && <Chip>model: {card.llm_model}</Chip>}
      </div>
      <div className="rounded-lg border border-border bg-muted/40 p-3">
        <div className="label mb-1">Analyst summary</div>
        <p className="whitespace-pre-wrap text-sm leading-relaxed text-text">
          {card.analyst_summary || "—"}
        </p>
      </div>
      <div className="rounded-lg border border-border bg-muted/40 p-3">
        <div className="label mb-1">Helpdesk explanation</div>
        <p className="whitespace-pre-wrap text-sm leading-relaxed text-text">
          {card.helpdesk_explanation || "—"}
        </p>
      </div>
      <div className="rounded-lg border border-border bg-muted/40 p-3">
        <div className="label mb-1">Next steps</div>
        <ol className="list-decimal space-y-1 pl-5 text-sm text-text">
          {(card.next_steps ?? []).length === 0 && (
            <li className="list-none text-dim">—</li>
          )}
          {(card.next_steps ?? []).map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ol>
      </div>
    </div>
  );
}
