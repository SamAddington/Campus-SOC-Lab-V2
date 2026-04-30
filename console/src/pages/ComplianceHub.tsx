import { useEffect, useState } from "react";
import { BookCheck, ShieldAlert } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { useSettings } from "@/lib/settings";
import { api, type AuditIntegrityVerify, type LLMProvidersStatus } from "@/lib/api";

export function ComplianceHub() {
  const { settings } = useSettings();
  const [llm, setLlm] = useState<LLMProvidersStatus | null>(null);
  const [integrity, setIntegrity] = useState<AuditIntegrityVerify | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [p, v] = await Promise.all([api.llmProviders(), api.integrityVerify()]);
        if (cancelled) return;
        setLlm(p);
        setIntegrity(v);
        setErr(null);
      } catch (e) {
        if (!cancelled) setErr((e as Error).message);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, []);

  const integrityOk =
    integrity?.decision_cards.ok && integrity?.overrides.ok && integrity?.simulation_runs.ok;

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text">Compliance Hub</h1>
          <p className="mt-1 text-sm text-subtle">
            How AI-assisted SOC operations are monitored and constrained under Zero Trust, NIST CSF 2.0, Privacy by Design, and auditability.
          </p>
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
          title="Zero Trust controls (in this stack)"
          subtitle="Identity and access enforcement for sensitive endpoints."
        >
          <ul className="list-disc space-y-1.5 pl-5 text-sm text-subtle">
            <li>
              Sensitive API routes require <span className="mono">X-API-Key</span> (configured as{" "}
              <span className="mono">SOC_API_KEY</span>).
            </li>
            <li>
              The console sends <span className="mono">X-API-Key</span> from{" "}
              <span className="mono">localStorage.soc_api_key</span> (Settings → API access).
            </li>
            <li>
              Human action is bounded: policy + audit are the enforcement points; LLM is not.
            </li>
          </ul>
        </Card>

        <Card title="Current posture (from Settings)" subtitle="Local operator intent (not auto-enforced).">
          <div className="space-y-2 text-sm text-subtle">
            <div>
              <span className="label">deployment_profile</span>{" "}
              <span className="mono">{settings.deploymentProfile}</span>
            </div>
            <div>
              <span className="label">guardrails_strict</span>{" "}
              <span className="mono">{String(settings.guardrailsStrict)}</span>
            </div>
            <div>
              <span className="label">allow_hosted_teacher</span>{" "}
              <span className="mono">{String(settings.allowHostedTeacher)}</span>
            </div>
            <div>
              <span className="label">gpu_local_llm</span>{" "}
              <span className="mono">{String(settings.gpuEnabledForLocalLlm)}</span>
            </div>
          </div>
        </Card>

        <Card
          className="xl:col-span-2"
          title="NIST CSF 2.0 alignment (high level)"
          subtitle="This is a practical mapping for this prototype; formal control testing is deployment-specific."
        >
          <div className="grid gap-3 md:grid-cols-2 text-sm text-subtle">
            <div className="rounded-lg border border-border bg-muted/40 p-3">
              <div className="flex items-center gap-2 text-text font-medium">
                <BookCheck size={16} className="text-accent" /> Govern / Identify
              </div>
              <div className="mt-1">
                Documented governance checklist, privacy model, and in-app settings that record operator intent.
              </div>
            </div>
            <div className="rounded-lg border border-border bg-muted/40 p-3">
              <div className="flex items-center gap-2 text-text font-medium">
                <BookCheck size={16} className="text-accent" /> Protect
              </div>
              <div className="mt-1">
                API key access control, minimization/pseudonymization at ingest, scoped OSINT egress, bounded AI behavior.
              </div>
            </div>
            <div className="rounded-lg border border-border bg-muted/40 p-3">
              <div className="flex items-center gap-2 text-text font-medium">
                <BookCheck size={16} className="text-accent" /> Detect
              </div>
              <div className="mt-1">
                Detector scoring + policy engine triage; traffic anomalies are aggregate-only by design.
              </div>
            </div>
            <div className="rounded-lg border border-border bg-muted/40 p-3">
              <div className="flex items-center gap-2 text-text font-medium">
                <BookCheck size={16} className="text-accent" /> Respond / Recover
              </div>
              <div className="mt-1">
                Human-in-the-loop overrides logged to ledger; exportable evidence packs from the Audit page.
              </div>
            </div>
          </div>
        </Card>

        <Card title="AI privacy & auditability" subtitle="How AI use is monitored to prevent privacy invasion.">
          <ul className="list-disc space-y-1.5 pl-5 text-sm text-subtle">
            <li>
              The LLM assistant is a <b>bounded explainer</b>: it does not change scores/actions.
            </li>
            <li>
              Decision cards include <span className="mono">llm_tier</span>, <span className="mono">llm_provider</span>,{" "}
              and <span className="mono">llm_model</span> for audit trails.
            </li>
            <li>
              Hosted teacher use is explicit and should be treated as an egress event; prefer local student (Ollama) for privacy-first operation.
            </li>
          </ul>
        </Card>

        <Card
          className="xl:col-span-3"
          title="Runtime signals"
          subtitle="Live configuration evidence from backend services."
        >
          <div className="grid gap-3 md:grid-cols-3 text-sm text-subtle">
            <div className="rounded-lg border border-border bg-muted/40 p-3">
              <div className="flex items-center gap-2 text-text font-medium">
                <ShieldAlert size={16} className="text-accent" /> LLM providers
              </div>
              <div className="mt-1 mono text-[12px]">
                student={llm?.student?.provider ?? "unknown"} / {llm?.student?.model ?? ""}
                <br />
                teacher={llm?.teacher?.provider ?? "unknown"} / {llm?.teacher?.model ?? ""}
                <br />
                mode={llm?.default_mode ?? "?"} (review {llm?.human_review_mode ?? "?"})
              </div>
            </div>
            <div className="rounded-lg border border-border bg-muted/40 p-3">
              <div className="flex items-center gap-2 text-text font-medium">
                <ShieldAlert size={16} className="text-accent" /> Audit integrity
              </div>
              <div className="mt-1 mono text-[12px]">
                ok={String(Boolean(integrityOk))}
                <br />
                decision_cards={String(Boolean(integrity?.decision_cards.ok))}
                <br />
                overrides={String(Boolean(integrity?.overrides.ok))}
              </div>
            </div>
            <div className="rounded-lg border border-border bg-muted/40 p-3">
              <div className="flex items-center gap-2 text-text font-medium">
                <ShieldAlert size={16} className="text-accent" /> Exports
              </div>
              <div className="mt-1">
                Use the <b>Audit</b> page to export JSON/Markdown/PDF evidence packs.
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}

