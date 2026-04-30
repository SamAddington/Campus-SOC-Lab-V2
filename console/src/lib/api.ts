// Thin fetch layer. All calls go through Vite/nginx proxy prefixes
// (/api/<service>/...) so the frontend never needs to know host names.

export type DecisionCard = {
  schema_version?: string;
  decision_card_id: string;
  event_id: string;
  timestamp: string;
  source: string;
  event_type: string;
  language: string;
  risk_score_rule: number;
  risk_score_fl: number | null;
  risk_score_final: number;
  label: string;
  explanation: string;
  policy_rule_id: string;
  permitted_action: string;
  requires_human_review: boolean;
  final_human_action: string | null;
  scenario_id: string | null;
  model_round: number | null;
  threshold_version: string | null;
  analyst_summary: string | null;
  helpdesk_explanation: string | null;
  next_steps: string[] | null;
  llm_used: boolean | null;
  llm_reason: string | null;
  llm_tier: string | null;
  llm_provider: string | null;
  llm_model: string | null;
  consent_use_for_distillation: boolean | null;
  osint_enabled: boolean | null;
  osint_skipped: boolean | null;
  osint_verdict: string | null;
  osint_score: number | null;
  osint_indicator_count: number | null;
  osint_providers_used: string[] | null;
  osint_short_explanation: string | null;
};

export type AuditSummary = {
  total_decisions: number;
  total_overrides: number;
  action_counts: Record<string, number>;
  policy_rule_counts: Record<string, number>;
  scenario_counts: Record<string, number>;
  llm_tier_counts: Record<string, number>;
  llm_provider_counts: Record<string, number>;
  osint_verdict_counts: Record<string, number>;
  osint_enriched_count: number;
};

export type AuditIntegrityCheck = {
  ok: boolean;
  checked: number;
  path: string;
};

export type AuditIntegrityVerify = {
  auth_enabled: boolean;
  decision_cards: AuditIntegrityCheck;
  overrides: AuditIntegrityCheck;
  simulation_runs: AuditIntegrityCheck;
};

export type FederatedStatus = {
  round: number;
  expected_clients: string[];
  received_updates: string[];
  status: string;
  updated_at: string;
};

export type GlobalModel = {
  round: number;
  feature_order: string[];
  coef: number[];
  intercept: number;
  num_clients: number;
  total_samples: number;
  updated_at: string;
};

export type ScenarioMeta = {
  scenario_id: string;
  description: string;
  event_count: number;
  file: string;
};

export type OverrideRecord = {
  decision_card_id: string;
  event_id: string;
  reviewer_id: string;
  original_action: string;
  overridden_action: string;
  reason: string;
  timestamp?: string;
};

export type TrafficStatus = {
  config: {
    window_seconds: number;
    max_windows_retained: number;
    ipv4_bucket_prefix: number;
    ipv6_bucket_prefix: number;
    k_anonymity_min: number;
    warmup_windows: number;
    collector_url: string;
    emit_to_collector: boolean;
    hmac_keyed: boolean;
  };
  detectors: Array<Record<string, unknown>>;
  emitter: Record<string, unknown>;
  synthetic: { running: boolean };
  current_window_start: number | null;
};

export type TrafficAnomaly = {
  detector: string;
  severity: "low" | "medium" | "high" | string;
  window_start: number;
  group_key?: string;
  features?: Record<string, number>;
  reason?: string;
  z?: number;
  score?: number;
  [k: string]: unknown;
};

export type LLMProviderInfo = {
  provider: string;
  model: string;
  enabled: boolean;
  [k: string]: unknown;
};

export type LLMProvidersStatus = {
  teacher: LLMProviderInfo;
  student: LLMProviderInfo;
  default_mode: string;
  human_review_mode: string;
  [k: string]: unknown;
};

export type LLMAssistRequest = {
  event_id: string;
  source: string;
  event_type: string;
  language?: string;
  risk_score_rule: number;
  risk_score_fl?: number | null;
  risk_score_final: number;
  label: string;
  action: string;
  explanation: string;
  policy_rule_id: string;
  policy_reason: string;
  requires_human_review?: boolean;
  features?: Record<string, unknown>;
  scenario_id?: string | null;
  mode?:
    | "student_only"
    | "teacher_only"
    | "teacher_shadow"
    | "teacher_then_student_refine"
    | null;
};

export type LLMAssistResponse = {
  schema_version?: string;
  analyst_summary: string;
  helpdesk_explanation: string;
  next_steps: string[];
  llm_used: boolean;
  llm_reason: string;
  llm_tier: string;
  llm_provider?: string | null;
  llm_model?: string | null;
};

export type TrafficWindowsSnapshot = {
  window_seconds: number;
  max_windows_retained: number;
  current_window_start: number | null;
  windows: Array<{
    window_start: number;
    group_count: number;
    totals: Record<string, number>;
  }>;
};

export type CollectorSiemSpoolStatus = {
  siem: Record<string, { enabled?: boolean; configured?: boolean }>;
  spool: Record<string, unknown>;
};

export type CollectorSearchResult<T = Record<string, unknown>> = {
  count: number;
  items: T[];
  next_cursor: number | null;
  source?: string;
};

export type CollectorEntitySearchResult<T = Record<string, unknown>> = {
  count: number;
  items: T[];
  next_cursor: number | null;
  source?: string;
};

export type CollectorFacetsResponse = {
  size: number;
  facets: Record<string, Array<{ key: string; count: number }>>;
};

export type CaseRecord = {
  case_id?: string | null;
  title: string;
  description?: string;
  status?: string;
  severity?: string;
  created_at?: string | null;
  updated_at?: string | null;
  created_by?: string | null;
  assigned_to?: string | null;
  tags?: string[];
  related_decision_cards?: string[];
  related_event_ids?: string[];
  sla_response_due_at?: string | null;
  first_acknowledged_at?: string | null;
  resolved_at?: string | null;
  [k: string]: unknown;
};

export type CaseNote = {
  case_id: string;
  note_id?: string | null;
  author?: string | null;
  body: string;
  created_at?: string | null;
  [k: string]: unknown;
};

export type SavedSearch = {
  search_id?: string | null;
  name: string;
  description?: string;
  q?: string;
  source?: string;
  event_type?: string;
  language?: string;
  include_message?: boolean;
  created_at?: string | null;
  updated_at?: string | null;
  created_by?: string | null;
  [k: string]: unknown;
};

export type CorrelationRule = {
  rule_id?: string | null;
  name: string;
  description?: string;
  enabled?: boolean;
  severity?: string;
  search_id?: string;
  mode?: string;
  within_seconds?: number;
  by_field?: string;
  steps?: Array<Record<string, unknown>>;
  schedule_seconds?: number;
  dedup_seconds?: number;
  created_at?: string | null;
  updated_at?: string | null;
  created_by?: string | null;
  [k: string]: unknown;
};

export type CorrelationAlert = {
  alert_id?: string | null;
  rule_id: string;
  rule_name: string;
  severity?: string;
  summary: string;
  match_count?: number;
  sample_event_ids?: string[];
  created_at?: string | null;
  query?: Record<string, unknown>;
  [k: string]: unknown;
};

export type CorrelationDryRunResult = {
  dry_run?: boolean;
  rule_id?: string;
  would_alert?: boolean;
  match_count?: number;
  sample_event_ids?: string[];
  window?: { since_ms?: number; until_ms?: number };
  query?: Record<string, unknown>;
  detail?: string;
  [k: string]: unknown;
};

export type PolicyRulesRaw = {
  path: string;
  yaml_text: string;
};

export type PolicyRulesUpdateResponse = {
  status: string;
  version: number;
  rules_count: number;
};

export type PolicyEvaluateInput = {
  event_id: string;
  source: string;
  event_type: string;
  language: string;
  risk_score_rule: number;
  risk_score_fl?: number | null;
  risk_score_final: number;
  label: string;
  features?: Record<string, unknown>;
};

export type PolicyEvaluateOutput = {
  permitted_action: string;
  requires_human_review: boolean;
  policy_rule_id: string;
  policy_reason: string;
  policy_version: number;
  [k: string]: unknown;
};

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const apiKey =
    globalThis.localStorage?.getItem("soc_api_key") ||
    (globalThis as any).__SOC_API_KEY__ ||
    "";
  const jwt =
    globalThis.localStorage?.getItem("soc_jwt") ||
    (globalThis as any).__SOC_JWT__ ||
    "";
  const authHeaders: Record<string, string> = {
    ...(apiKey ? { "X-API-Key": apiKey } : {}),
    ...(jwt ? { Authorization: `Bearer ${jwt}` } : {}),
  };
  const extraHeaders = init?.headers;
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders,
      ...(extraHeaders ?? undefined),
    },
  });
  const ct = res.headers.get("content-type") || "";
  const body = ct.includes("application/json") ? await res.json() : await res.text();
  if (!res.ok) {
    const detail =
      typeof body === "string"
        ? body
        : body?.detail
        ? typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail)
        : `HTTP ${res.status}`;
    throw new Error(detail);
  }
  return body as T;
}

export const api = {
  // Audit / ledger
  decisionCards: (limit = 200) =>
    request<{ count: number; items: DecisionCard[] }>(`/api/audit/decision_cards?limit=${limit}`),
  overrides: (limit = 50) =>
    request<{ count: number; items: any[] }>(`/api/audit/overrides?limit=${limit}`),
  summary: () => request<AuditSummary>(`/api/audit/summary`),
  integrityVerify: () => request<AuditIntegrityVerify>(`/api/audit/integrity/verify`),
  purgeRetention: () =>
    request<{ status: string; retention_days: number; removed: Record<string, number> }>(
      `/api/audit/retention/purge`,
      { method: "POST" },
    ),
  logOverride: (body: {
    decision_card_id: string;
    event_id: string;
    reviewer_id: string;
    original_action: string;
    overridden_action: string;
    reason: string;
  }) =>
    request<{ status: string }>(`/api/audit/log_override`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // Orchestrator
  processEvent: (body: { event_id: string; payload: Record<string, unknown>; scenario_id?: string }) =>
    request<Record<string, unknown>>(`/api/orchestrator/process_event`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // Simulator
  scenarios: () => request<{ count: number; items: ScenarioMeta[] }>(`/api/simulator/scenarios`),
  runScenario: (body: { scenario_id: string; pace_ms?: number; stop_on_error?: boolean }) =>
    request<{ status: string; summary: any; results: any[] }>(`/api/simulator/run_scenario`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // Federated
  federatedStatus: () => request<FederatedStatus>(`/api/federated/status`),
  globalModel: () => request<GlobalModel>(`/api/federated/global_model`),

  // Traffic ingestor
  trafficStatus: () => request<TrafficStatus>(`/api/traffic/status`),
  trafficAnomalies: (limit = 50) =>
    request<{ recent: TrafficAnomaly[]; emitter: Record<string, unknown> }>(
      `/api/traffic/anomalies?limit=${limit}`,
    ),
  trafficWindows: () => request<TrafficWindowsSnapshot>(`/api/traffic/windows`),
  trafficDetect: () => request<Record<string, unknown>>(`/api/traffic/detect`, { method: "POST" }),
  syntheticStart: (body: { flows_per_second: number }) =>
    request<Record<string, unknown>>(`/api/traffic/synthetic/start`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  syntheticStop: () =>
    request<Record<string, unknown>>(`/api/traffic/synthetic/stop`, { method: "POST" }),
  syntheticBurst: (body: {
    duration_seconds: number;
    subnet?: string;
    service?: string;
  }) =>
    request<Record<string, unknown>>(`/api/traffic/synthetic/burst`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // LLM assistant
  llmProviders: () => request<LLMProvidersStatus>(`/api/llm/providers`),
  llmAssist: (body: LLMAssistRequest) =>
    request<LLMAssistResponse>(`/api/llm/assist`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // Policy engine guardrails
  policyRulesRaw: () => request<PolicyRulesRaw>(`/api/policy_engine/rules/raw`),
  policyRulesUpdate: (body: { yaml_text: string }) =>
    request<PolicyRulesUpdateResponse>(`/api/policy_engine/rules/update`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  policyEvaluate: (body: PolicyEvaluateInput) =>
    request<PolicyEvaluateOutput>(`/api/policy_engine/evaluate`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // SSE URL (EventSource, not fetch)
  auditStreamUrl: () => `/api/audit/stream`,

  // Collector SIEM spool
  collectorSiemSpoolStatus: (dest?: string) =>
    request<CollectorSiemSpoolStatus>(
      `/api/collector/siem/spool/status${dest ? `?dest=${encodeURIComponent(dest)}` : ""}`,
    ),

  collectorSearch: (params: {
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
    tenant?: string;
    limit?: number;
    cursor?: number;
    include_message?: number;
  }) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null) continue;
      q.set(k, String(v));
    }
    return request<CollectorSearchResult>(`/api/collector/search?${q.toString()}`);
  },

  collectorEntities: (params: {
    q?: string;
    entity_type?: string;
    tenant?: string;
    limit?: number;
    cursor?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params.q) qs.set("q", params.q);
    if (params.entity_type) qs.set("entity_type", params.entity_type);
    if (params.tenant) qs.set("tenant", params.tenant);
    if (params.limit != null) qs.set("limit", String(params.limit));
    if (params.cursor != null) qs.set("cursor", String(params.cursor));
    const s = qs.toString();
    return request<CollectorEntitySearchResult>(`/api/collector/entities${s ? `?${s}` : ""}`);
  },

  collectorFacets: (params: {
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
    tenant?: string;
    size?: number;
  }) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null) continue;
      qs.set(k, String(v));
    }
    const s = qs.toString();
    return request<CollectorFacetsResponse>(`/api/collector/search/facets${s ? `?${s}` : ""}`);
  },

  // Audit cases (workflow)
  cases: (limit = 100) => request<{ count: number; items: CaseRecord[] }>(`/api/audit/cases?limit=${limit}`),
  caseCreate: (payload: CaseRecord) =>
    request<{ status: string; case_id: string }>(`/api/audit/cases`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  caseGet: (caseId: string) =>
    request<{ case: CaseRecord; notes: CaseNote[] }>(`/api/audit/cases/${encodeURIComponent(caseId)}`),
  caseAssign: (caseId: string, assignedTo: string) =>
    request<{ status: string; case_id: string; assigned_to: string | null }>(
      `/api/audit/cases/${encodeURIComponent(caseId)}/assign?assigned_to=${encodeURIComponent(assignedTo)}`,
      { method: "POST" },
    ),
  caseStatus: (caseId: string, status: string) =>
    request<{ status: string; case_id: string; case_status: string }>(
      `/api/audit/cases/${encodeURIComponent(caseId)}/status?status=${encodeURIComponent(status)}`,
      { method: "POST" },
    ),
  caseNote: (caseId: string, body: string) =>
    request<{ status: string; case_id: string; note_id: string }>(
      `/api/audit/cases/${encodeURIComponent(caseId)}/notes`,
      { method: "POST", body: JSON.stringify({ case_id: caseId, body }) },
    ),

  // Saved searches + correlation
  savedSearches: (limit = 200) =>
    request<{ count: number; items: SavedSearch[] }>(`/api/audit/saved_searches?limit=${limit}`),
  savedSearchCreate: (payload: SavedSearch) =>
    request<{ status: string; search_id: string }>(`/api/audit/saved_searches`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  correlationRules: (limit = 500) =>
    request<{ count: number; items: CorrelationRule[] }>(`/api/audit/correlation/rules?limit=${limit}`),
  correlationRuleCreate: (payload: CorrelationRule) =>
    request<{ status: string; rule_id: string }>(`/api/audit/correlation/rules`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  correlationAlerts: (limit = 200) =>
    request<{ count: number; items: CorrelationAlert[] }>(`/api/audit/correlation/alerts?limit=${limit}`),
  correlationDryRun: (rule_id: string) =>
    request<CorrelationDryRunResult>(`/api/collector/correlation/dry_run`, {
      method: "POST",
      body: JSON.stringify({ rule_id }),
    }),

  // Health checks
  health: (
    service:
      | "audit"
      | "orchestrator"
      | "simulator"
      | "collector"
      | "detector"
      | "policy"
      | "osint"
      | "llm"
      | "federated"
      | "traffic",
  ) => request<{ status: string }>(`/api/${service}/health`),
};
