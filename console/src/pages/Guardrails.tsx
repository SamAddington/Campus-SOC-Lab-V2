import { useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { api } from "@/lib/api";

type EvalOut = {
  permitted_action: string;
  requires_human_review: boolean;
  policy_rule_id: string;
  policy_reason: string;
  policy_version: number;
  [k: string]: unknown;
};

export function Guardrails() {
  const [yamlText, setYamlText] = useState("");
  const [loadedYaml, setLoadedYaml] = useState("");
  const [path, setPath] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [okMsg, setOkMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const [tEventId, setTEventId] = useState("evt-test-1");
  const [tSource, setTSource] = useState("email_gateway");
  const [tEventType, setTEventType] = useState("suspicious_email");
  const [tLang, setTLang] = useState("en");
  const [tRuleScore, setTRuleScore] = useState(0.3);
  const [tFlScore, setTFlScore] = useState<number | null>(null);
  const [tFinalScore, setTFinalScore] = useState(0.55);
  const [tLabel, setTLabel] = useState("suspicious");
  const [tFeaturesJson, setTFeaturesJson] = useState(`{"osint_verdict":"suspicious"}`);
  const [evalOut, setEvalOut] = useState<EvalOut | null>(null);

  async function load() {
    setLoading(true);
    try {
      const r = await api.policyRulesRaw();
      setYamlText(String(r.yaml_text || ""));
      setLoadedYaml(String(r.yaml_text || ""));
      setPath(String(r.path || ""));
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

  const dirty = useMemo(() => yamlText !== loadedYaml, [yamlText, loadedYaml]);

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold text-text">Guardrails</h1>
        <p className="mt-1 text-sm text-subtle">
          Neurosymbolic policy guardrails (symbolic rules over ML/FL signals + features). Edit YAML safely with
          validation + version bumps, and test evaluation outputs.
        </p>
      </header>

      {err && (
        <Card title="Error">
          <div className="text-sm text-sev-critical">{err}</div>
        </Card>
      )}

      {okMsg && (
        <Card title="Saved">
          <div className="text-sm text-sev-low">{okMsg}</div>
        </Card>
      )}

      <Card
        title="Policy rules YAML"
        subtitle={path ? `Backed by ${path} (admin-only update).` : "Admin-only update."}
        action={
          <div className="flex items-center gap-2">
            <button className="btn" type="button" onClick={load} disabled={loading || saving}>
              Reload
            </button>
            <button
              className="btn"
              type="button"
              disabled={!dirty || saving}
              onClick={() => {
                setYamlText(loadedYaml);
                setOkMsg(null);
                setErr(null);
              }}
              title="Revert unsaved edits"
            >
              Revert
            </button>
            <button
              className="btn btn-primary"
              type="button"
              disabled={saving || !dirty || loading}
              onClick={async () => {
                setSaving(true);
                try {
                  const r = await api.policyRulesUpdate({ yaml_text: yamlText });
                  setOkMsg(`Updated rules to version ${r.version} (${r.rules_count} rules).`);
                  setErr(null);
                  await load();
                } catch (e) {
                  setErr((e as Error).message);
                  setOkMsg(null);
                } finally {
                  setSaving(false);
                }
              }}
            >
              Save (bump version)
            </button>
          </div>
        }
      >
        <div className="grid gap-3">
          <textarea
            className="input mono min-h-[360px]"
            spellCheck={false}
            value={yamlText}
            onChange={(e) => setYamlText(e.target.value)}
            placeholder="version: 1\nrules:\n  - id: ..."
          />
          <div className="text-xs text-dim">
            Tips: use `when.min_final_score` / `when.max_final_score`, and `when.feature_flags` for enriched signals (e.g.
            `osint_verdict`). Valid actions: <span className="mono">allow</span>,{" "}
            <span className="mono">queue_for_review</span>, <span className="mono">escalate</span>.
          </div>
        </div>
      </Card>

      <Card title="Test rule evaluation" subtitle="Runs Policy Engine evaluate() with your sample input.">
        <div className="grid gap-3 md:grid-cols-2">
          <label className="block">
            <div className="label mb-1">event_id</div>
            <input className="input mono" value={tEventId} onChange={(e) => setTEventId(e.target.value)} />
          </label>
          <label className="block">
            <div className="label mb-1">source</div>
            <input className="input mono" value={tSource} onChange={(e) => setTSource(e.target.value)} />
          </label>
          <label className="block">
            <div className="label mb-1">event_type</div>
            <input className="input mono" value={tEventType} onChange={(e) => setTEventType(e.target.value)} />
          </label>
          <label className="block">
            <div className="label mb-1">language</div>
            <input className="input mono" value={tLang} onChange={(e) => setTLang(e.target.value)} />
          </label>
          <label className="block">
            <div className="label mb-1">risk_score_rule</div>
            <input
              className="input mono"
              value={String(tRuleScore)}
              onChange={(e) => setTRuleScore(Number(e.target.value))}
            />
          </label>
          <label className="block">
            <div className="label mb-1">risk_score_final</div>
            <input
              className="input mono"
              value={String(tFinalScore)}
              onChange={(e) => setTFinalScore(Number(e.target.value))}
            />
          </label>
          <label className="block">
            <div className="label mb-1">risk_score_fl (optional)</div>
            <input
              className="input mono"
              value={tFlScore === null ? "" : String(tFlScore)}
              onChange={(e) => {
                const v = e.target.value.trim();
                setTFlScore(v ? Number(v) : null);
              }}
              placeholder="(blank)"
            />
          </label>
          <label className="block">
            <div className="label mb-1">label</div>
            <input className="input mono" value={tLabel} onChange={(e) => setTLabel(e.target.value)} />
          </label>
          <label className="block md:col-span-2">
            <div className="label mb-1">features (JSON)</div>
            <textarea
              className="input mono min-h-[96px]"
              spellCheck={false}
              value={tFeaturesJson}
              onChange={(e) => setTFeaturesJson(e.target.value)}
            />
          </label>
          <div className="flex items-end gap-2 md:col-span-2">
            <button
              className="btn btn-primary"
              type="button"
              onClick={async () => {
                setErr(null);
                setOkMsg(null);
                setEvalOut(null);
                let features: Record<string, unknown> = {};
                try {
                  const txt = tFeaturesJson.trim();
                  features = txt ? (JSON.parse(txt) as Record<string, unknown>) : {};
                } catch (e) {
                  setErr(`features JSON invalid: ${(e as Error).message}`);
                  return;
                }
                try {
                  const out = await api.policyEvaluate({
                    event_id: tEventId || "evt-test-1",
                    source: tSource,
                    event_type: tEventType,
                    language: tLang,
                    risk_score_rule: Number(tRuleScore),
                    risk_score_fl: tFlScore === null ? null : Number(tFlScore),
                    risk_score_final: Number(tFinalScore),
                    label: tLabel,
                    features,
                  });
                  setEvalOut(out as EvalOut);
                } catch (e) {
                  setErr((e as Error).message);
                }
              }}
            >
              Run evaluate
            </button>
            <button
              className="btn"
              type="button"
              onClick={() => {
                setEvalOut(null);
                setErr(null);
                setOkMsg(null);
              }}
            >
              Clear
            </button>
          </div>
        </div>

        {evalOut && (
          <div className="mt-4 rounded-lg border border-border bg-muted/30 p-4">
            <div className="grid gap-2 text-sm md:grid-cols-2">
              <div>
                <div className="label">permitted_action</div>
                <div className="mono text-text">{String(evalOut.permitted_action)}</div>
              </div>
              <div>
                <div className="label">requires_human_review</div>
                <div className="mono text-text">{String(evalOut.requires_human_review)}</div>
              </div>
              <div>
                <div className="label">policy_rule_id</div>
                <div className="mono text-text">{String(evalOut.policy_rule_id)}</div>
              </div>
              <div>
                <div className="label">policy_version</div>
                <div className="mono text-text">{String(evalOut.policy_version)}</div>
              </div>
              <div className="md:col-span-2">
                <div className="label">policy_reason</div>
                <div className="text-text">{String(evalOut.policy_reason)}</div>
              </div>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

