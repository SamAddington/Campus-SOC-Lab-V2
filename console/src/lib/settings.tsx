import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type Settings = {
  programName: string;
  programSubtitle: string;
  analystName: string;
  analystId: string;
  tenant: string;
  env: string;

  // Appearance (console-only)
  theme: "dark" | "light" | "system";
  density: "comfortable" | "compact";
  reduceMotion: boolean;

  // User management (console-only; does not affect API authorization)
  currentRole: "viewer" | "analyst" | "admin";
  userDirectoryJson: string;

  // LLM providers (console guidance + local notes; backend is configured via env)
  studentProvider: "ollama" | "openai" | "anthropic" | "none";
  studentModel: string;
  teacherProvider: "ollama" | "openai" | "anthropic" | "none";
  teacherModel: string;
  llmDefaultMode:
    | "student_only"
    | "teacher_only"
    | "teacher_shadow"
    | "teacher_then_student_refine";
  llmHumanReviewMode:
    | "student_only"
    | "teacher_only"
    | "teacher_shadow"
    | "teacher_then_student_refine";

  // Threat intel & OSINT keys (stored locally; recommended to set via env/secret store)
  nvdApiKey: string;
  malwareBazaarApiKey: string;
  tavilyApiKey: string;

  // Federated learning (console-only preference)
  preferFederatedSignals: boolean;

  // Orchestration controls (console-only notes; backend is configured via env)
  enableOsintEnrichment: boolean;
  osintMinRuleScore: string;

  // Neurosymbolic guardrails (console-only posture flags)
  guardrailsStrict: boolean;
  allowHostedTeacher: boolean;

  // Deployment profile (console-only notes for runtime posture)
  deploymentProfile: "workshop" | "local" | "prod_like";
  gpuEnabledForLocalLlm: boolean;
};

export const DEFAULT_SETTINGS: Settings = {
  programName: "Campus SOC",
  programSubtitle: "Workshop Console",
  analystName: "analyst",
  analystId: "analyst-1",
  tenant: "campus-demo",
  env: "workshop",

  theme: "dark",
  density: "comfortable",
  reduceMotion: false,

  currentRole: "analyst",
  userDirectoryJson: "[]",

  studentProvider: "ollama",
  studentModel: "llama3.2",
  teacherProvider: "none",
  teacherModel: "",
  llmDefaultMode: "student_only",
  llmHumanReviewMode: "teacher_shadow",

  nvdApiKey: "",
  malwareBazaarApiKey: "",
  tavilyApiKey: "",

  preferFederatedSignals: true,

  enableOsintEnrichment: true,
  osintMinRuleScore: "0.40",

  guardrailsStrict: true,
  allowHostedTeacher: false,

  deploymentProfile: "workshop",
  gpuEnabledForLocalLlm: false,
};

const STORAGE_KEY = "wicys-soc-console.settings.v2";

function loadFromStorage(): Settings {
  if (globalThis.window === undefined) return DEFAULT_SETTINGS;
  try {
    const raw = globalThis.localStorage?.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_SETTINGS;
    const parsed = JSON.parse(raw) as Partial<Settings>;
    return { ...DEFAULT_SETTINGS, ...parsed };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

function saveToStorage(value: Settings) {
  try {
    globalThis.localStorage?.setItem(STORAGE_KEY, JSON.stringify(value));
  } catch {
    /* ignore quota / disabled storage */
  }
}

type Ctx = {
  settings: Settings;
  update: (patch: Partial<Settings>) => void;
  reset: () => void;
};

const SettingsCtx = createContext<Ctx | null>(null);

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<Settings>(loadFromStorage);

  // Sync across tabs.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key !== STORAGE_KEY) return;
      if (!e.newValue) {
        setSettings(DEFAULT_SETTINGS);
        return;
      }
      try {
        const parsed = JSON.parse(e.newValue) as Partial<Settings>;
        setSettings({ ...DEFAULT_SETTINGS, ...parsed });
      } catch {
        /* ignore */
      }
    };
    globalThis.window?.addEventListener("storage", onStorage);
    return () => globalThis.window?.removeEventListener("storage", onStorage);
  }, []);

  // Reflect program name into the document title.
  useEffect(() => {
    const title = `${settings.programName} Console`;
    if (document.title !== title) document.title = title;
  }, [settings.programName]);

  const update = useCallback((patch: Partial<Settings>) => {
    setSettings((prev) => {
      const next = { ...prev, ...patch };
      saveToStorage(next);
      return next;
    });
  }, []);

  const reset = useCallback(() => {
    saveToStorage(DEFAULT_SETTINGS);
    setSettings(DEFAULT_SETTINGS);
  }, []);

  const value = useMemo(() => ({ settings, update, reset }), [settings, update, reset]);

  return <SettingsCtx.Provider value={value}>{children}</SettingsCtx.Provider>;
}

export function useSettings(): Ctx {
  const ctx = useContext(SettingsCtx);
  if (!ctx) {
    throw new Error("useSettings must be used within <SettingsProvider>");
  }
  return ctx;
}
