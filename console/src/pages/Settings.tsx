import { useEffect, useState } from "react";
import { Save, RotateCcw, CheckCircle2 } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { useSettings, DEFAULT_SETTINGS, type Settings as S } from "@/lib/settings";

const SOC_API_KEY_STORAGE_KEY = "soc_api_key";

export function Settings() {
  const { settings, update, reset } = useSettings();
  const [draft, setDraft] = useState<S>(settings);
  const [socApiKey, setSocApiKey] = useState<string>("");
  const [storedSocApiKey, setStoredSocApiKey] = useState<string>("");
  const [savedAt, setSavedAt] = useState<number | null>(null);

  useEffect(() => {
    setDraft(settings);
  }, [settings]);

  useEffect(() => {
    const stored = globalThis.localStorage?.getItem(SOC_API_KEY_STORAGE_KEY) || "";
    setSocApiKey(stored);
    setStoredSocApiKey(stored);
  }, []);

  const dirty =
    JSON.stringify(draft) !== JSON.stringify(settings) ||
    socApiKey !== storedSocApiKey;

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const sanitized: S = {
      programName: draft.programName.trim() || DEFAULT_SETTINGS.programName,
      programSubtitle: draft.programSubtitle.trim() || DEFAULT_SETTINGS.programSubtitle,
      analystName: draft.analystName.trim() || DEFAULT_SETTINGS.analystName,
      analystId: draft.analystId.trim() || DEFAULT_SETTINGS.analystId,
      tenant: draft.tenant.trim() || DEFAULT_SETTINGS.tenant,
      env: draft.env.trim() || DEFAULT_SETTINGS.env,

      theme: draft.theme,
      density: draft.density,
      reduceMotion: Boolean(draft.reduceMotion),

      currentRole: draft.currentRole,
      userDirectoryJson: draft.userDirectoryJson || "[]",

      studentProvider: draft.studentProvider,
      studentModel: draft.studentModel.trim(),
      teacherProvider: draft.teacherProvider,
      teacherModel: draft.teacherModel.trim(),
      llmDefaultMode: draft.llmDefaultMode,
      llmHumanReviewMode: draft.llmHumanReviewMode,

      nvdApiKey: draft.nvdApiKey.trim(),
      malwareBazaarApiKey: draft.malwareBazaarApiKey.trim(),
      tavilyApiKey: draft.tavilyApiKey.trim(),

      preferFederatedSignals: Boolean(draft.preferFederatedSignals),

      enableOsintEnrichment: Boolean(draft.enableOsintEnrichment),
      osintMinRuleScore: draft.osintMinRuleScore.trim() || DEFAULT_SETTINGS.osintMinRuleScore,

      guardrailsStrict: Boolean(draft.guardrailsStrict),
      allowHostedTeacher: Boolean(draft.allowHostedTeacher),

      deploymentProfile: draft.deploymentProfile,
      gpuEnabledForLocalLlm: Boolean(draft.gpuEnabledForLocalLlm),
    };
    update(sanitized);
    if (socApiKey.trim()) {
      const trimmed = socApiKey.trim();
      globalThis.localStorage?.setItem(SOC_API_KEY_STORAGE_KEY, trimmed);
      setSocApiKey(trimmed);
      setStoredSocApiKey(trimmed);
    } else {
      globalThis.localStorage?.removeItem(SOC_API_KEY_STORAGE_KEY);
      setStoredSocApiKey("");
    }
    setDraft(sanitized);
    setSavedAt(Date.now());
    globalThis.setTimeout(() => setSavedAt((t) => (t && Date.now() - t > 2000 ? null : t)), 2200);
  }

  function onReset() {
    reset();
    setDraft(DEFAULT_SETTINGS);
    setSocApiKey("");
    setStoredSocApiKey("");
    globalThis.localStorage?.removeItem(SOC_API_KEY_STORAGE_KEY);
    setSavedAt(Date.now());
  }

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold text-text">Settings</h1>
        <p className="mt-1 text-sm text-subtle">
          Personalize the console. These values are stored in your browser only
          (<span className="mono">localStorage</span>) — they never leave your machine.
        </p>
      </header>

      <form onSubmit={onSubmit} className="space-y-4">
        <Card
          title="Program"
          subtitle="Rename the workshop to match your organization, course, or team."
        >
          <div className="grid gap-4 md:grid-cols-2">
            <Field
              label="Program name"
              hint="Appears in the sidebar header and browser tab."
              value={draft.programName}
              onChange={(v) => setDraft({ ...draft, programName: v })}
              placeholder="Campus SOC"
              maxLength={60}
            />
            <Field
              label="Subtitle"
              hint="Small text under the program name."
              value={draft.programSubtitle}
              onChange={(v) => setDraft({ ...draft, programSubtitle: v })}
              placeholder="Workshop Console"
              maxLength={60}
            />
          </div>
        </Card>

        <Card
          title="Analyst profile"
          subtitle="Used in the top bar and prefilled when you log overrides on alerts."
        >
          <div className="grid gap-4 md:grid-cols-2">
            <Field
              label="Analyst name"
              hint="Display name shown in the top-right user area."
              value={draft.analystName}
              onChange={(v) => setDraft({ ...draft, analystName: v })}
              placeholder="Jane Doe"
              maxLength={60}
            />
            <Field
              label="Analyst ID"
              hint="Default reviewer ID written to audit override records."
              value={draft.analystId}
              onChange={(v) => setDraft({ ...draft, analystId: v })}
              placeholder="analyst-1"
              maxLength={60}
              mono
            />
          </div>
        </Card>

        <Card
          title="Workspace labels"
          subtitle="Cosmetic tags shown in the top bar. They do not affect backend routing."
        >
          <div className="grid gap-4 md:grid-cols-2">
            <Field
              label="Tenant"
              value={draft.tenant}
              onChange={(v) => setDraft({ ...draft, tenant: v })}
              placeholder="campus-demo"
              mono
            />
            <Field
              label="Environment"
              value={draft.env}
              onChange={(v) => setDraft({ ...draft, env: v })}
              placeholder="workshop"
              mono
            />
          </div>
        </Card>

        <Card
          title="Appearance"
          subtitle="Console-only preferences. These do not change backend behavior."
        >
          <div className="grid gap-4 md:grid-cols-2">
            <SelectField
              label="Theme"
              hint="Controls console theme preference."
              value={draft.theme}
              onChange={(v) => setDraft({ ...draft, theme: v as S["theme"] })}
              options={[
                { value: "dark", label: "Dark" },
                { value: "light", label: "Light" },
                { value: "system", label: "System" },
              ]}
            />
            <SelectField
              label="Density"
              hint="Compact reduces whitespace on tables and cards."
              value={draft.density}
              onChange={(v) => setDraft({ ...draft, density: v as S["density"] })}
              options={[
                { value: "comfortable", label: "Comfortable" },
                { value: "compact", label: "Compact" },
              ]}
            />
            <ToggleField
              label="Reduce motion"
              hint="Minimizes animations for accessibility (also affects training visuals like the DDoS network pulse)."
              checked={draft.reduceMotion}
              onChange={(v) => setDraft({ ...draft, reduceMotion: v })}
            />
          </div>
        </Card>

        <Card
          title="User management (local)"
          subtitle="Local role and directory metadata for demos. This does not change backend authorization."
        >
          <div className="grid gap-4 md:grid-cols-2">
            <SelectField
              label="Current role"
              hint="Used for local UI conventions only."
              value={draft.currentRole}
              onChange={(v) => setDraft({ ...draft, currentRole: v as S["currentRole"] })}
              options={[
                { value: "viewer", label: "Viewer" },
                { value: "analyst", label: "Analyst" },
                { value: "admin", label: "Admin" },
              ]}
            />
            <TextAreaField
              label="User directory (JSON)"
              hint='Optional. Example: [{"id":"analyst-1","name":"A. One","role":"analyst"}]'
              value={draft.userDirectoryJson}
              onChange={(v) => setDraft({ ...draft, userDirectoryJson: v })}
              rows={5}
              mono
            />
          </div>
        </Card>

        <Card
          title="API access"
          subtitle="Used by the console when calling protected backend endpoints."
        >
          <div className="grid gap-4 md:grid-cols-1">
            <Field
              label="SOC API key"
              hint="Stored in this browser as localStorage key soc_api_key. Must match SOC_API_KEY in your deployment."
              value={socApiKey}
              onChange={setSocApiKey}
              placeholder="paste-your-soc-api-key"
              maxLength={200}
              mono
            />
          </div>
        </Card>

        <Card
          title="OIDC sign-in (build-time)"
          subtitle="Set these as Docker build-args / Vite env when building the console image. The callback path must be registered with your IdP."
        >
          <div className="grid gap-2 text-xs text-subtle md:grid-cols-2">
            <div>
              <div className="label mb-0.5">VITE_OIDC_ISSUER</div>
              <div className="mono break-all text-dim">{String(import.meta.env.VITE_OIDC_ISSUER || "") || "—"}</div>
            </div>
            <div>
              <div className="label mb-0.5">VITE_OIDC_CLIENT_ID</div>
              <div className="mono break-all text-dim">{String(import.meta.env.VITE_OIDC_CLIENT_ID || "") || "—"}</div>
            </div>
            <div className="md:col-span-2">
              <div className="label mb-0.5">VITE_OIDC_REDIRECT_URI</div>
              <div className="mono break-all text-dim">{String(import.meta.env.VITE_OIDC_REDIRECT_URI || "") || "(defaults to {origin}/auth/callback)"}</div>
            </div>
            <div className="md:col-span-2">
              <div className="label mb-0.5">VITE_OIDC_SCOPES</div>
              <div className="mono break-all text-dim">{String(import.meta.env.VITE_OIDC_SCOPES || "") || "openid profile email"}</div>
            </div>
          </div>
        </Card>

        <Card
          title="LLM providers (Teacher / Student)"
          subtitle="These settings are notes for operators; backend provider selection is set via environment variables."
        >
          <div className="grid gap-4 md:grid-cols-2">
            <SelectField
              label="Student provider"
              hint="Maps to STUDENT_PROVIDER (recommended: ollama for fully local)."
              value={draft.studentProvider}
              onChange={(v) => setDraft({ ...draft, studentProvider: v as S["studentProvider"] })}
              options={[
                { value: "ollama", label: "ollama (local)" },
                { value: "openai", label: "openai-compatible (API)" },
                { value: "anthropic", label: "anthropic (API)" },
                { value: "none", label: "none (disabled)" },
              ]}
            />
            <Field
              label="Student model"
              hint="Maps to STUDENT_MODEL / OLLAMA_MODEL."
              value={draft.studentModel}
              onChange={(v) => setDraft({ ...draft, studentModel: v })}
              placeholder="llama3.2"
              maxLength={80}
              mono
            />
            <SelectField
              label="Teacher provider"
              hint="Maps to TEACHER_PROVIDER. Hosted teachers send prompts externally."
              value={draft.teacherProvider}
              onChange={(v) => setDraft({ ...draft, teacherProvider: v as S["teacherProvider"] })}
              options={[
                { value: "none", label: "none (disabled)" },
                { value: "ollama", label: "ollama (local)" },
                { value: "openai", label: "openai-compatible (API)" },
                { value: "anthropic", label: "anthropic (API)" },
              ]}
            />
            <Field
              label="Teacher model"
              hint="Maps to TEACHER_MODEL."
              value={draft.teacherModel}
              onChange={(v) => setDraft({ ...draft, teacherModel: v })}
              placeholder=""
              maxLength={80}
              mono
            />
            <SelectField
              label="Default routing mode"
              hint="Maps to LLM_DEFAULT_MODE."
              value={draft.llmDefaultMode}
              onChange={(v) => setDraft({ ...draft, llmDefaultMode: v as S["llmDefaultMode"] })}
              options={[
                { value: "student_only", label: "student_only" },
                { value: "teacher_only", label: "teacher_only" },
                { value: "teacher_shadow", label: "teacher_shadow" },
                { value: "teacher_then_student_refine", label: "teacher_then_student_refine" },
              ]}
            />
            <SelectField
              label="Human-review routing mode"
              hint="Maps to LLM_HUMAN_REVIEW_MODE."
              value={draft.llmHumanReviewMode}
              onChange={(v) => setDraft({ ...draft, llmHumanReviewMode: v as S["llmHumanReviewMode"] })}
              options={[
                { value: "student_only", label: "student_only" },
                { value: "teacher_only", label: "teacher_only" },
                { value: "teacher_shadow", label: "teacher_shadow" },
                { value: "teacher_then_student_refine", label: "teacher_then_student_refine" },
              ]}
            />
          </div>
        </Card>

        <Card
          title="Threat intel & OSINT keys (local reference)"
          subtitle="Recommended to store as env vars / secret store in deployment. These fields are local-only."
        >
          <div className="grid gap-4 md:grid-cols-2">
            <Field
              label="NVD API key"
              hint="Intended for NVD enrichment (future integration)."
              value={draft.nvdApiKey}
              onChange={(v) => setDraft({ ...draft, nvdApiKey: v })}
              placeholder=""
              maxLength={200}
              mono
            />
            <Field
              label="MalwareBazaar API key"
              hint="Intended for MalwareBazaar lookups (future integration)."
              value={draft.malwareBazaarApiKey}
              onChange={(v) => setDraft({ ...draft, malwareBazaarApiKey: v })}
              placeholder=""
              maxLength={200}
              mono
            />
            <Field
              label="Tavily API key"
              hint="Intended for controlled web research (future integration)."
              value={draft.tavilyApiKey}
              onChange={(v) => setDraft({ ...draft, tavilyApiKey: v })}
              placeholder=""
              maxLength={200}
              mono
            />
          </div>
        </Card>

        <Card
          title="Federated learning & orchestration (notes)"
          subtitle="Local toggles for how you want to run demos; backend behavior is controlled by service env vars."
        >
          <div className="grid gap-4 md:grid-cols-2">
            <ToggleField
              label="Prefer federated signals"
              hint="Conservative posture: only allow FL/ML to raise risk (backend behavior)."
              checked={draft.preferFederatedSignals}
              onChange={(v) => setDraft({ ...draft, preferFederatedSignals: v })}
            />
            <ToggleField
              label="Enable OSINT enrichment"
              hint="Maps to ENABLE_OSINT_ENRICHMENT in orchestrator."
              checked={draft.enableOsintEnrichment}
              onChange={(v) => setDraft({ ...draft, enableOsintEnrichment: v })}
            />
            <Field
              label="OSINT min rule score"
              hint="Maps to OSINT_MIN_RULE_SCORE (string for easy copy/paste)."
              value={draft.osintMinRuleScore}
              onChange={(v) => setDraft({ ...draft, osintMinRuleScore: v })}
              placeholder="0.40"
              maxLength={10}
              mono
            />
          </div>
        </Card>

        <Card
          title="Neurosymbolic guardrails"
          subtitle="Console-only posture flags; intended to document how you want AI and rules to interact."
        >
          <div className="grid gap-4 md:grid-cols-2">
            <ToggleField
              label="Strict guardrails"
              hint="Prefer deterministic policy/rules over generative suggestions when there is conflict."
              checked={draft.guardrailsStrict}
              onChange={(v) => setDraft({ ...draft, guardrailsStrict: v })}
            />
            <ToggleField
              label="Allow hosted teacher"
              hint="If off, treat hosted teacher usage as disallowed by policy (operator guidance)."
              checked={draft.allowHostedTeacher}
              onChange={(v) => setDraft({ ...draft, allowHostedTeacher: v })}
            />
          </div>
        </Card>

        <Card
          title="Deployment profile"
          subtitle="Console-only notes. Actual runtime behavior is set via Docker Compose env vars and how you run Ollama/GPU on the host."
        >
          <div className="grid gap-4 md:grid-cols-2">
            <SelectField
              label="Profile"
              value={draft.deploymentProfile}
              onChange={(v) => setDraft({ ...draft, deploymentProfile: v as S["deploymentProfile"] })}
              options={[
                { value: "workshop", label: "Workshop" },
                { value: "local", label: "Local (single laptop)" },
                { value: "prod_like", label: "Prod-like (segmented)" },
              ]}
            />
            <ToggleField
              label="GPU for local LLM inference"
              hint="If using Ollama locally, enable GPU on the host; containers call Ollama at OLLAMA_BASE_URL."
              checked={draft.gpuEnabledForLocalLlm}
              onChange={(v) => setDraft({ ...draft, gpuEnabledForLocalLlm: v })}
            />
          </div>
        </Card>

        <div className="flex items-center gap-3">
          <button type="submit" className="btn btn-primary" disabled={!dirty}>
            <Save size={14} /> Save changes
          </button>
          <button type="button" className="btn" onClick={onReset}>
            <RotateCcw size={14} /> Reset to defaults
          </button>
          {savedAt && (
            <span className="inline-flex items-center gap-1.5 text-xs text-sev-low">
              <CheckCircle2 size={14} /> Saved
            </span>
          )}
          {dirty && !savedAt && (
            <span className="text-xs text-dim">Unsaved changes</span>
          )}
        </div>
      </form>

      <Card title="Backend configuration (read-only)">
        <ul className="list-disc space-y-1 pl-5 text-sm text-subtle">
          <li>
            Protected APIs require a shared key via <span className="mono">SOC_API_KEY</span>.
            The console sends it from <span className="mono">localStorage.soc_api_key</span>.
          </li>
          <li>
            HMAC anonymization secret is set via <span className="mono">HMAC_SECRET</span>.
          </li>
          <li>
            Audit record signatures use <span className="mono">AUDIT_SIGNING_KEY</span>,
            and retention purge horizon uses <span className="mono">AUDIT_RETENTION_DAYS</span>.
          </li>
          <li>
            Service wiring can be overridden with URLs like{" "}
            <span className="mono">COLLECTOR_URL</span>, <span className="mono">ORCHESTRATOR_URL</span>,{" "}
            <span className="mono">DETECTOR_URL</span>, <span className="mono">POLICY_URL</span>,{" "}
            <span className="mono">AUDIT_URL</span>, <span className="mono">OSINT_URL</span>, and{" "}
            <span className="mono">LLM_ASSISTANT_URL</span> (defaults assume docker-compose service names).
          </li>
          <li>
            LLM routing is configured via <span className="mono">LLM_DEFAULT_MODE</span> /{" "}
            <span className="mono">LLM_HUMAN_REVIEW_MODE</span> and providers{" "}
            (<span className="mono">STUDENT_PROVIDER</span>/<span className="mono">STUDENT_MODEL</span>,{" "}
            <span className="mono">TEACHER_PROVIDER</span>/<span className="mono">TEACHER_MODEL</span>). Teacher shadow
            outputs persist to <span className="mono">LLM_SHADOW_LOG</span>.
          </li>
          <li>
            For privacy-preserving AI usage, keep <span className="mono">TEACHER_PROVIDER=none</span>{" "}
            to stay fully local, or review <span className="mono">docs/privacy_model.md</span>{" "}
            before enabling any hosted teacher provider.
          </li>
          <li>
            OSINT enrichment toggles via <span className="mono">ENABLE_OSINT_ENRICHMENT</span> and threshold{" "}
            <span className="mono">OSINT_MIN_RULE_SCORE</span>. Provider allowlists are controlled by{" "}
            <span className="mono">OSINT_SCOPES_PATH</span> (plus per-provider RPM and key env vars).
          </li>
          <li>
            External connectors run in <span className="mono">integrations</span> (port 8025) and are configured via env vars
            like <span className="mono">CANVAS_*</span>, <span className="mono">MERAKI_*</span>, <span className="mono">DUO_*</span>,{" "}
            <span className="mono">UMBRELLA_*</span>, <span className="mono">ISE_*</span>, <span className="mono">FMC_*</span>, and device polling{" "}
            targets (<span className="mono">SNMP_TARGETS</span>/<span className="mono">NETCONF_TARGETS</span>/<span className="mono">SSH_TARGETS</span>)
            gated by <span className="mono">DEVICE_ALLOWLIST</span>. Integrations uses{" "}
            <span className="mono">SCOPES_PATH</span> and persists cursors under{" "}
            <span className="mono">INTEGRATION_STATE_DIR</span>.
          </li>
          <li>
            Optional SIEM egress is configured on the collector via{" "}
            <span className="mono">SIEM_SPLUNK_HEC_*</span>, <span className="mono">SIEM_ELASTIC_*</span>,{" "}
            <span className="mono">SIEM_SENTINEL_*</span>, and <span className="mono">SIEM_SYSLOG_*</span>.
          </li>
          <li>
            If SIEM egress is enabled, durability/spooling is configured via{" "}
            <span className="mono">SIEM_SPOOL_*</span> (directory, limits, flush interval, batch size, max attempts).
          </li>
          <li>
            Detector scoring layers can be toggled via <span className="mono">USE_ML</span> /{" "}
            <span className="mono">USE_FEDERATED</span>.
          </li>
          <li>
            Service URLs, ports, and volumes live in{" "}
            <span className="mono">docker-compose.yml</span>.
          </li>
        </ul>
      </Card>
    </div>
  );
}

function SelectField({
  label,
  hint,
  value,
  onChange,
  options,
}: Readonly<{
  label: string;
  hint?: string;
  value: string;
  onChange: (v: string) => void;
  options: Array<{ value: string; label: string }>;
}>) {
  return (
    <label className="block">
      <div className="label mb-1">{label}</div>
      <select
        className="input"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      {hint && <div className="mt-1 text-[11px] text-dim">{hint}</div>}
    </label>
  );
}

function ToggleField({
  label,
  hint,
  checked,
  onChange,
}: Readonly<{
  label: string;
  hint?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}>) {
  return (
    <label className="flex items-center justify-between gap-3 rounded-lg border border-border bg-muted/40 px-3 py-2">
      <div>
        <div className="text-sm font-medium text-text">{label}</div>
        {hint && <div className="mt-0.5 text-[11px] text-dim">{hint}</div>}
      </div>
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
    </label>
  );
}

function TextAreaField({
  label,
  hint,
  value,
  onChange,
  rows = 4,
  mono,
}: Readonly<{
  label: string;
  hint?: string;
  value: string;
  onChange: (v: string) => void;
  rows?: number;
  mono?: boolean;
}>) {
  return (
    <label className="block">
      <div className="label mb-1">{label}</div>
      <textarea
        className={`input ${mono ? "font-mono text-[13px]" : ""}`}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        rows={rows}
      />
      {hint && <div className="mt-1 text-[11px] text-dim">{hint}</div>}
    </label>
  );
}

function Field({
  label,
  hint,
  value,
  onChange,
  placeholder,
  maxLength,
  mono,
}: Readonly<{
  label: string;
  hint?: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  maxLength?: number;
  mono?: boolean;
}>) {
  return (
    <label className="block">
      <div className="label mb-1">{label}</div>
      <input
        className={`input ${mono ? "font-mono text-[13px]" : ""}`}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        maxLength={maxLength}
      />
      {hint && <div className="mt-1 text-[11px] text-dim">{hint}</div>}
    </label>
  );
}
