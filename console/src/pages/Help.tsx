import { Link } from "react-router-dom";
import type { ReactNode } from "react";
import {
  LayoutDashboard,
  Bell,
  Radio,
  Network,
  Play,
  Boxes,
  Settings as Cog,
  LifeBuoy,
  ShieldAlert,
  Activity,
  Zap,
  BookOpen,
  Info,
  BrainCircuit,
} from "lucide-react";
import { Card, KeyValueGrid } from "@/components/ui/Card";
import { SeverityBadge, Chip } from "@/components/ui/Badge";

export function Help() {
  return (
    <div className="space-y-4">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-text flex items-center gap-2">
            <LifeBuoy size={18} className="text-accent" /> Help &amp; reference
          </h1>
          <p className="mt-1 max-w-3xl text-sm text-subtle">
            Everything this console can do, grouped by page. Each section lists the
            available options, the actions you can take, and which backend service
            is responsible for the data you see.
          </p>
        </div>
        <Link to="/settings" className="btn">
          <Cog size={14} /> Open Settings
        </Link>
      </header>

      {/* Quick navigation */}
      <Card title="Quick navigation">
        <ul className="grid grid-cols-1 gap-2 text-sm md:grid-cols-2 lg:grid-cols-3">
          <QuickLink to="#dashboard" icon={<LayoutDashboard size={14} />}>Dashboard</QuickLink>
          <QuickLink to="#alerts" icon={<Bell size={14} />}>Alerts &amp; Alert detail</QuickLink>
          <QuickLink to="#traffic" icon={<Radio size={14} />}>Traffic</QuickLink>
          <QuickLink to="#llm" icon={<BrainCircuit size={14} />}>LLM Assistant</QuickLink>
          <QuickLink to="#federated" icon={<Network size={14} />}>Federated ML</QuickLink>
          <QuickLink to="#simulator" icon={<Play size={14} />}>Simulator</QuickLink>
          <QuickLink to="#services" icon={<Boxes size={14} />}>Services</QuickLink>
          <QuickLink to="#settings" icon={<Cog size={14} />}>Settings</QuickLink>
          <QuickLink to="#compliance" icon={<ShieldAlert size={14} />}>Compliance Hub</QuickLink>
          <QuickLink to="#audit" icon={<Activity size={14} />}>Audit</QuickLink>
          <QuickLink to="#glossary" icon={<BookOpen size={14} />}>Glossary</QuickLink>
          <QuickLink to="#severity" icon={<ShieldAlert size={14} />}>Severity scale</QuickLink>
        </ul>
      </Card>

      {/* Getting started */}
      <Card title="Getting started" subtitle="A good first ten minutes with the console.">
        <ol className="list-decimal space-y-1.5 pl-5 text-sm text-subtle">
          <li>
            Open <Link to="/settings" className="link">Settings</Link> and set your{" "}
            <b>program name</b>, <b>analyst name</b> and <b>analyst ID</b>. These are
            saved in your browser and used throughout the UI.
          </li>
          <li>
            In <Link to="/settings" className="link">Settings</Link>, paste your{" "}
            <b>SOC API key</b>. The console stores it as{" "}
            <span className="mono">localStorage.soc_api_key</span> and sends it
            to protected API routes.
          </li>
          <li>
            If you enable a hosted LLM teacher (OpenAI-compatible or Anthropic),
            review <span className="mono">docs/privacy_model.md</span> and{" "}
            <span className="mono">docs/llm_teacher_student.md</span> first. The
            LLM is a <b>bounded explainer</b> (no automated actions) and every
            decision card records LLM provenance for audit.
          </li>
          <li>
            Visit the <Link to="/simulator" className="link">Simulator</Link> and run
            a scenario (for example <span className="mono">phish_wave</span>). It
            injects events through the full pipeline.
          </li>
          <li>
            Open the <Link to="/alerts" className="link">Alerts</Link> queue — new
            decision cards stream in live. Click one to open the detail view.
          </li>
          <li>
            On the alert detail page, review the detector / policy / OSINT / LLM tabs
            and, if needed, click <b>Override action</b> to record a reviewed
            outcome.
          </li>
          <li>
            Check <Link to="/services" className="link">Services</Link> to confirm
            every backend is healthy.
          </li>
        </ol>
      </Card>

      {/* Dashboard */}
      <Section
        id="dashboard"
        icon={<LayoutDashboard size={16} />}
        title="Dashboard"
        source="audit"
        blurb="At-a-glance view of recent detections and reviewer activity."
      >
        <FeatureList>
          <Feature title="KPI tiles">
            Counts of total decisions, escalations, auto-blocks, and manual reviews.
            Update live as new decisions and overrides arrive.
          </Feature>
          <Feature title="Live indicator">
            The dot in the header shows whether the console is receiving the audit
            SSE stream. Green = connected, amber = reconnecting.
          </Feature>
          <Feature title="Action mix over time">
            Stacked bar chart of recommended actions per time bucket. Use the window
            picker to switch between <Chip>1h</Chip> <Chip>6h</Chip> <Chip>24h</Chip>{" "}
            <Chip>7d</Chip>.
          </Feature>
          <Feature title="Recent alerts">
            The ten most recent decision cards. Click a row to open the detail page.
          </Feature>
        </FeatureList>
      </Section>

      {/* Alerts */}
      <Section
        id="alerts"
        icon={<Bell size={16} />}
        title="Alerts &amp; Alert detail"
        source="audit · detector · policy_engine · osint · llm_assistant · aggregator"
        blurb="The main triage surface. Every decision card from the orchestrator appears here."
      >
        <FeatureList>
          <Feature title="Live queue">
            New cards arrive over SSE and are prepended with a brief highlight.
          </Feature>
          <Feature title="Filters">
            Filter by <b>severity</b> (score-based) and <b>recommended action</b>.
            A text search matches decision-card IDs, event IDs, detector IDs and
            rationale text.
          </Feature>
          <Feature title="Override badge">
            Rows show a badge when any override has been recorded against the card.
          </Feature>
          <Feature title="Detail tabs">
            Open a card to see tabs for{" "}
            <Chip>Summary</Chip> <Chip>Detector</Chip> <Chip>Policy</Chip>{" "}
            <Chip>OSINT</Chip> <Chip>LLM</Chip> <Chip>Federated</Chip>{" "}
            <Chip>History</Chip>. The header shows the <i>effective</i> action
            (after any overrides).
          </Feature>
          <Feature title="Override action">
            The <b>Override action</b> button opens a dialog that POSTs to{" "}
            <span className="mono">/log_override</span>. The reviewer field is
            prefilled with your <Link to="/settings" className="link">analyst ID</Link>.
            The UI updates optimistically and the record shows up in the{" "}
            <b>History</b> tab.
          </Feature>
          <Feature title="JSON inspection">
            Every structured block has a copy-to-clipboard JSON view for deeper
            forensic work.
          </Feature>
        </FeatureList>
      </Section>

      {/* Traffic */}
      <Section
        id="traffic"
        icon={<Radio size={16} />}
        title="Traffic"
        source="traffic_ingestor"
        blurb="Rolling-window flow telemetry and anomaly windows."
      >
        <FeatureList>
          <Feature title="Status">
            Current window configuration, detector model, last ingest time, and
            anomaly counts.
          </Feature>
          <Feature title="Traffic volume chart">
            Area chart of recent traffic windows. Hover for per-window totals.
          </Feature>
          <Feature title="Anomalies table">
            Recent anomaly windows with severity badges, source, target, and score.
          </Feature>
          <Feature title="Synthetic generator">
            Controls to <Chip>start</Chip> <Chip>stop</Chip> and emit a{" "}
            <Chip>burst</Chip> of synthetic traffic for demos. Useful for seeding
            the queue before a walkthrough.
          </Feature>
          <Feature title="Manual detect">
            Trigger a detection sweep on demand without waiting for the scheduler.
          </Feature>
        </FeatureList>
      </Section>

      {/* LLM Assistant */}
      <Section
        id="llm"
        icon={<BrainCircuit size={16} />}
        title="LLM Assistant"
        source="llm_assistant · audit"
        blurb="Observability for the teacher / student router and a live playground."
      >
        <FeatureList>
          <Feature title="Provider cards">
            Live status of the configured <b>teacher</b> and <b>student</b> providers
            from <span className="mono">GET /providers</span> — model name and
            whether each is enabled (API key wired or local model present).
          </Feature>
          <Feature title="Routing modes">
            Shows the default mode and the human-review mode:
            <Chip>student_only</Chip> <Chip>teacher_only</Chip>{" "}
            <Chip>teacher_shadow</Chip> <Chip>teacher_then_student_refine</Chip>.
          </Feature>
          <Feature title="Routing over time">
            Stacked bar chart of tier mix (teacher / student / fallback) per
            time bucket, with a <b>window</b> picker
            (<Chip>1h</Chip> <Chip>6h</Chip> <Chip>24h</Chip> <Chip>7d</Chip>).
            Also shows total cards, how many actually used the LLM, and the top
            providers, models, and routing reasons.
          </Feature>
          <Feature title="Playground">
            A form that POSTs to <span className="mono">/assist</span>. You can
            prefill from any recent decision card or edit the sample by hand.
            Choose a <b>mode</b> to force student vs teacher for the call. The
            response is shown formatted (summary, helpdesk explanation, next
            steps) plus the raw JSON, and is <i>not</i> written to the audit
            ledger.
          </Feature>
          <Feature title="Re-ask LLM (on alert detail)">
            The <b>LLM</b> tab on any alert has a <b>Re-ask</b> panel that calls
            {" "}
            <span className="mono">/assist</span> again with the card's context,
            displaying the fresh response side-by-side with what was stored in
            audit — great for comparing tiers or modes.
          </Feature>
          <Feature title="Per-alert provenance">
            The alert detail LLM tab always shows tier, provider, model, and
            routing reason, plus the analyst summary, helpdesk explanation and
            next-steps that were stored when the decision was made.
          </Feature>
        </FeatureList>
      </Section>

      {/* Federated ML */}
      <Section
        id="federated"
        icon={<Network size={16} />}
        title="Federated ML"
        source="aggregator"
        blurb="Inspect the federated-learning round that backs the detector."
      >
        <FeatureList>
          <Feature title="Round status">
            Current round number, participant count, and aggregation status.
          </Feature>
          <Feature title="Global model">
            Summary of the latest global model (version, metrics, last update).
          </Feature>
          <Feature title="Participants">
            Per-client contribution metadata as reported by the aggregator.
          </Feature>
        </FeatureList>
      </Section>

      {/* Simulator */}
      <Section
        id="simulator"
        icon={<Play size={16} />}
        title="Simulator"
        source="simulator"
        blurb="Inject scripted scenarios end-to-end through the pipeline."
      >
        <FeatureList>
          <Feature title="Scenario picker">
            Choose a built-in scenario and press <b>Run</b>. The simulator emits
            events which flow through collector → detector → orchestrator → audit.
          </Feature>
          <Feature title="Run log">
            Shows the events that were produced, their IDs, and timestamps.
          </Feature>
          <Feature title="Tip">
            Run a scenario, then switch to the <Link to="/alerts" className="link">Alerts</Link>{" "}
            page — new cards will stream in live.
          </Feature>
        </FeatureList>
      </Section>

      {/* Services */}
      <Section
        id="services"
        icon={<Boxes size={16} />}
        title="Services"
        source="all backends · /healthz"
        blurb="Health dashboard for every container in the stack."
      >
        <FeatureList>
          <Feature title="Live probes">
            Each row calls the service's <span className="mono">/healthz</span>{" "}
            endpoint and reports latency, version, and error text if any.
          </Feature>
          <Feature title="What to check first">
            If Alerts or Dashboard look empty, confirm the <b>audit</b>,{" "}
            <b>orchestrator</b> and <b>detector</b> are green here.
          </Feature>
        </FeatureList>
      </Section>

      <Section
        id="compliance"
        icon={<ShieldAlert size={16} />}
        title="Compliance Hub"
        source="console · audit · llm_assistant"
        blurb="Framework-aligned view of Zero Trust controls, AI guardrails, and audit integrity signals."
      >
        <FeatureList>
          <Feature title="Runtime evidence">
            Shows live signals for LLM provider status and audit integrity verification so reviewers can confirm configuration matches policy.
          </Feature>
          <Feature title="AI privacy posture">
            Summarizes how the teacher/student assistant is constrained (explainer-only) and how provenance is logged for auditability.
          </Feature>
        </FeatureList>
      </Section>

      <Section
        id="audit"
        icon={<Activity size={16} />}
        title="Audit"
        source="audit"
        blurb="Ledger integrity checks, retention operations, and evidence exports."
      >
        <FeatureList>
          <Feature title="Integrity verification">
            Calls <span className="mono">/integrity/verify</span> to confirm the ledger hash chain is consistent.
          </Feature>
          <Feature title="Retention purge">
            Calls <span className="mono">/retention/purge</span> to enforce the configured retention horizon.
          </Feature>
          <Feature title="Export evidence pack">
            Export audit data as <b>JSON</b>, <b>Markdown</b>, or <b>PDF</b> (via browser print-to-PDF).
          </Feature>
        </FeatureList>
      </Section>

      {/* Settings */}
      <Section
        id="settings"
        icon={<Cog size={16} />}
        title="Settings"
        source="browser localStorage"
        blurb="Personalize labels, store local API credentials, and document deployment posture."
      >
        <FeatureList>
          <Feature title="Program">
            <b>Program name</b> (sidebar + browser tab) and <b>subtitle</b>.
          </Feature>
          <Feature title="Analyst profile">
            <b>Analyst name</b> and <b>analyst ID</b>. The ID is used as the default
            reviewer when you open an override dialog.
          </Feature>
          <Feature title="Workspace labels">
            Cosmetic <b>tenant</b> and <b>environment</b> chips in the top bar.
          </Feature>
          <Feature title="SOC API key">
            Set the local API key used for backend auth. It is saved in{" "}
            <span className="mono">localStorage.soc_api_key</span> and added to
            requests as <span className="mono">X-API-Key</span>.
          </Feature>
          <Feature title="LLM providers (Teacher / Student)">
            Record your intended <b>student</b> and <b>teacher</b> provider/model and routing modes.
            Backend configuration is still done via env vars; these settings help keep operations auditable.
          </Feature>
          <Feature title="Threat intel &amp; OSINT keys">
            Optional local reference fields for NVD, MalwareBazaar, and Tavily keys. Prefer env/secret stores for real deployments.
          </Feature>
          <Feature title="Federated learning, orchestration, and guardrails">
            Document your posture for enrichment and guardrails (strictness, hosted-teacher allowance) and demo toggles.
          </Feature>
          <Feature title="Connectors & SIEM (deployment)">
            Live connectors are configured in <span className="mono">.env</span> /{" "}
            <span className="mono">docker-compose.yml</span> (not in the console). See{" "}
            <span className="mono">docs/integrations/README.md</span> for Canvas/Blackboard/Moodle/Brightspace and
            network connectors (Meraki/Duo/Umbrella/ISE/Firepower), plus device polling (SNMP/NETCONF/SSH) gated by{" "}
            <span className="mono">DEVICE_ALLOWLIST</span>. Optional SIEM egress is configured on the collector via{" "}
            <span className="mono">SIEM_*</span> env vars.
          </Feature>
          <Feature title="Deployment profile / GPU notes">
            Record how you are running orchestration at runtime and whether local LLM inference is using GPU.
          </Feature>
          <Feature title="Reset">
            <b>Reset to defaults</b> clears stored profile values, clears the local
            SOC API key, and restores the original &ldquo;Campus SOC&rdquo; branding.
          </Feature>
        </FeatureList>
      </Section>

      {/* Glossary */}
      <Card
        title={
          <span id="glossary" className="flex items-center gap-2">
            <BookOpen size={14} className="text-subtle" /> Glossary
          </span>
        }
      >
        <KeyValueGrid
          rows={[
            { k: "Decision card", v: "The orchestrator's aggregated verdict combining detector, policy, OSINT and LLM evidence." },
            { k: "Override", v: "A reviewer-logged correction to the recommended action. Stored alongside the decision." },
            { k: "Effective action", v: "The most recent override's action if any exist, otherwise the recommended action." },
            { k: "SSE", v: "Server-sent events stream from the audit service used for live updates to Dashboard and Alerts." },
            { k: "Anomaly window", v: "A fixed-duration bucket of flow telemetry the traffic ingestor has flagged as unusual." },
            { k: "Federated round", v: "One coordination cycle where clients share model updates with the aggregator." },
            { k: "Teacher / Student", v: "Two LLM tiers: teacher = large/high-quality model, student = small/fast on-device model. The router picks one per request." },
            { k: "Fallback", v: "When no provider is reachable, the LLM assistant returns a safe deterministic response labeled tier=fallback." },
            { k: "SOC API key", v: "Shared API credential required by protected endpoints. The console sends it as X-API-Key from localStorage.soc_api_key." },
            { k: "Audit hash chain", v: "Tamper-evident record linkage in the audit ledger using previous_hash and record_hash." },
            { k: "LLM provenance", v: "Per-decision metadata (llm_tier, llm_provider, llm_model) so AI usage is always auditable." },
            { k: "Teacher / Student routing", v: "How the LLM assistant chooses between tiers (student_only, teacher_shadow, etc.), recorded in decision cards for audit." },
          ]}
        />
      </Card>

      <Card
        title={
          <span className="flex items-center gap-2">
            <ShieldAlert size={14} className="text-subtle" /> Security, privacy, and AI guardrails
          </span>
        }
        subtitle="Operational notes for Zero Trust, NIST-aligned controls, and privacy-preserving AI usage."
      >
        <KeyValueGrid
          rows={[
            {
              k: "Zero Trust baseline",
              v: (
                <span>
                  Sensitive API routes require <span className="mono">X-API-Key</span>. Set{" "}
                  <span className="mono">SOC_API_KEY</span> in the deployment and store the same value in{" "}
                  <span className="mono">localStorage.soc_api_key</span> (Settings → API access).
                </span>
              ),
            },
            {
              k: "LLM safety boundary",
              v: "The LLM assistant is an explainer only. It cannot change detector scores, policy outcomes, or review flags.",
            },
            {
              k: "AI privacy posture",
              v: "Decision-card prompts are designed to avoid raw identifiers; cards always record llm_tier/provider/model to audit any external AI usage.",
            },
            {
              k: "Hosted teacher caution",
              v: "If TEACHER_PROVIDER is a hosted API, prompts and outputs are sent to that vendor. Keep teacher disabled (TEACHER_PROVIDER=none) for fully local operation.",
            },
            {
              k: "OSINT minimization",
              v: "Only extracted indicators are queried; private/reserved IPs are rejected; outbound endpoints are allowlisted via scopes.yaml.",
            },
            {
              k: "Audit integrity & retention",
              v: "Audit records are hash-chained (previous_hash/record_hash). Retention is controlled by AUDIT_RETENTION_DAYS and can be purged via POST /retention/purge.",
            },
          ]}
        />
      </Card>

      {/* Severity */}
      <Card
        title={
          <span id="severity" className="flex items-center gap-2">
            <ShieldAlert size={14} className="text-subtle" /> Severity scale
          </span>
        }
        subtitle="Score → severity mapping used across all views."
      >
        <div className="flex flex-wrap gap-3 text-sm">
          <SevRow sev="info" range="0.00 – 0.19" meaning="Informational; usually auto-allowed." />
          <SevRow sev="low" range="0.20 – 0.49" meaning="Low risk; monitored." />
          <SevRow sev="medium" range="0.50 – 0.74" meaning="Elevated; may trigger policy review." />
          <SevRow sev="high" range="0.75 – 0.89" meaning="High risk; typically escalated." />
          <SevRow sev="critical" range="0.90 – 1.00" meaning="Critical; candidate for auto-block." />
        </div>
      </Card>

      {/* Data flow */}
      <Card
        title={
          <span className="flex items-center gap-2">
            <Activity size={14} className="text-subtle" /> Data flow
          </span>
        }
      >
        <pre className="mono overflow-x-auto rounded-md border border-border bg-muted p-3 text-[12px] leading-relaxed text-subtle">
{`simulator ──▶ collector ──▶ detector ──▶ orchestrator ──▶ audit ──▶ console
                               ▲    policy_engine ┘    │
                               │    osint ─────────────┤
                               │    llm_assistant ─────┤
             aggregator ◀──────┘                        ▼
                                              /log_override (reviewer)`}
        </pre>
      </Card>

      {/* Shortcuts / tips */}
      <Card
        title={
          <span className="flex items-center gap-2">
            <Zap size={14} className="text-subtle" /> Tips
          </span>
        }
      >
        <ul className="list-disc space-y-1.5 pl-5 text-sm text-subtle">
          <li>
            Use the <Link to="/alerts" className="link">Alerts</Link> filters to narrow
            by severity or action; the queue stays live while filtered.
          </li>
          <li>
            Clicking your name in the top-right takes you to <Link to="/settings" className="link">Settings</Link>.
          </li>
          <li>
            All JSON panels on the detail view have a copy button so you can paste
            into an incident ticket.
          </li>
          <li>
            Settings are per-browser. Clear site data to reset, or use the{" "}
            <b>Reset to defaults</b> button in Settings.
          </li>
        </ul>
      </Card>

      <div className="text-center text-[11px] text-dim">
        <Info size={12} className="inline -mt-0.5 mr-1" />
        This console is a workshop tool. It is not hardened for production SOC use.
      </div>
    </div>
  );
}

function Section({
  id,
  icon,
  title,
  source,
  blurb,
  children,
}: Readonly<{
  id: string;
  icon: ReactNode;
  title: ReactNode;
  source?: string;
  blurb?: string;
  children: ReactNode;
}>) {
  return (
    <Card
      title={
        <span id={id} className="flex items-center gap-2">
          <span className="text-subtle">{icon}</span>
          {title}
        </span>
      }
      subtitle={blurb}
      action={source ? <Chip>source: {source}</Chip> : undefined}
    >
      {children}
    </Card>
  );
}

function FeatureList({ children }: Readonly<{ children: ReactNode }>) {
  return <div className="grid gap-3 md:grid-cols-2">{children}</div>;
}

function Feature({ title, children }: Readonly<{ title: ReactNode; children: ReactNode }>) {
  return (
    <div className="rounded-lg border border-border bg-muted/40 p-3">
      <div className="text-sm font-medium text-text">{title}</div>
      <div className="mt-1 text-[13px] leading-relaxed text-subtle">{children}</div>
    </div>
  );
}

function QuickLink({
  to,
  icon,
  children,
}: Readonly<{
  to: string;
  icon: ReactNode;
  children: ReactNode;
}>) {
  return (
    <li>
      <a
        href={to}
        className="flex items-center gap-2 rounded-md border border-border bg-muted/40 px-3 py-2 text-subtle hover:bg-muted hover:text-text"
      >
        <span className="text-dim">{icon}</span>
        {children}
      </a>
    </li>
  );
}

function SevRow({
  sev,
  range,
  meaning,
}: Readonly<{
  sev: "info" | "low" | "medium" | "high" | "critical";
  range: string;
  meaning: string;
}>) {
  return (
    <div className="flex w-full items-center gap-3 rounded-md border border-border bg-muted/40 px-3 py-2 md:w-auto">
      <SeverityBadge severity={sev}>{sev}</SeverityBadge>
      <span className="mono text-[12px] text-subtle">{range}</span>
      <span className="text-subtle">— {meaning}</span>
    </div>
  );
}
