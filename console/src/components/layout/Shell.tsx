import type { ReactNode } from "react";
import { useEffect, useState } from "react";
import { Link, NavLink } from "react-router-dom";
import {
  Shield,
  LayoutDashboard,
  Bell,
  BrainCircuit,
  Network,
  Play,
  Boxes,
  Radio,
  Settings as Cog,
  Activity,
  Search,
  CircleUser,
  HelpCircle,
  LifeBuoy,
  ClipboardCheck,
  FileCheck2,
  FolderKanban,
  Radar,
  GraduationCap,
  ShieldCheck,
  History,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { parseJwtPayload } from "@/lib/jwt";
import { clearConsoleAuth, oidcConfigured, startOidcLogin } from "@/lib/oidc";
import { useSettings } from "@/lib/settings";

type NavItem = { to: string; label: string; icon: ReactNode; end?: boolean };

const NAV: NavItem[] = [
  { to: "/", label: "Dashboard", icon: <LayoutDashboard size={16} />, end: true },
  { to: "/alerts", label: "Alerts", icon: <Bell size={16} /> },
  { to: "/hunts", label: "Hunts", icon: <Radar size={16} /> },
  { to: "/timeline", label: "Timeline", icon: <History size={16} /> },
  { to: "/traffic", label: "Traffic", icon: <Radio size={16} /> },
  { to: "/llm", label: "LLM Assistant", icon: <BrainCircuit size={16} /> },
  { to: "/federated", label: "Federated ML", icon: <Network size={16} /> },
  { to: "/simulator", label: "Simulator", icon: <Play size={16} /> },
  { to: "/services", label: "Services", icon: <Boxes size={16} /> },
];

const SYSTEM_NAV: NavItem[] = [
  { to: "/compliance", label: "Compliance Hub", icon: <ClipboardCheck size={16} /> },
  { to: "/audit", label: "Audit", icon: <FileCheck2 size={16} /> },
  { to: "/training", label: "Training", icon: <GraduationCap size={16} /> },
  { to: "/cases", label: "Cases", icon: <FolderKanban size={16} /> },
  { to: "/guardrails", label: "Guardrails", icon: <ShieldCheck size={16} /> },
  { to: "/help", label: "Help", icon: <LifeBuoy size={16} /> },
  { to: "/settings", label: "Settings", icon: <Cog size={16} /> },
];

export function Shell({ children }: Readonly<{ children: ReactNode }>) {
  const { settings } = useSettings();

  return (
    <div className="flex h-full min-h-screen">
      <aside className="flex w-[232px] shrink-0 flex-col border-r border-border bg-surface/60 backdrop-blur">
        <Link
          to="/"
          className="flex items-center gap-2 border-b border-border px-4 py-3 hover:bg-muted/40"
        >
          <div className="grid h-7 w-7 place-items-center rounded-md bg-accent/15 text-accent">
            <Shield size={16} />
          </div>
          <div className="min-w-0 leading-tight">
            <div className="truncate text-sm font-semibold text-text">
              {settings.programName}
            </div>
            <div className="truncate text-[11px] text-dim">
              {settings.programSubtitle}
            </div>
          </div>
        </Link>

        <nav className="flex-1 overflow-y-auto px-2 py-3">
          <div className="mb-1 px-2 text-[10px] font-semibold uppercase tracking-wider text-dim">
            Operations
          </div>
          <ul className="space-y-0.5">
            {NAV.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    cn("nav-link", isActive && "nav-link-active")
                  }
                >
                  <span className="text-subtle">{item.icon}</span>
                  <span>{item.label}</span>
                </NavLink>
              </li>
            ))}
          </ul>

          <div className="mb-1 mt-4 px-2 text-[10px] font-semibold uppercase tracking-wider text-dim">
            System
          </div>
          <ul className="space-y-0.5">
            {SYSTEM_NAV.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  className={({ isActive }) =>
                    cn("nav-link", isActive && "nav-link-active")
                  }
                >
                  <span className="text-subtle">{item.icon}</span>
                  <span>{item.label}</span>
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>

        <div className="border-t border-border p-3 text-[11px] text-dim">
          <div className="flex items-center gap-2">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-sev-low animate-pulseDot" />
            <span>Stack online</span>
          </div>
          <div className="mt-1 mono">v0.1.0 · workshop</div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="flex-1 overflow-auto">
          <div className="mx-auto max-w-[1480px] p-6">{children}</div>
        </main>
      </div>
    </div>
  );
}

function TopBar() {
  const { settings } = useSettings();
  const [authTick, setAuthTick] = useState(0);
  useEffect(() => {
    const bump = () => setAuthTick((n) => n + 1);
    window.addEventListener("soc-auth-changed", bump);
    return () => window.removeEventListener("soc-auth-changed", bump);
  }, []);
  const jwt = globalThis.localStorage?.getItem("soc_jwt") || "";
  const claims = jwt ? parseJwtPayload(jwt) : null;
  const jwtTenantRaw = claims?.tenant ?? claims?.tid ?? claims?.org_id;
  const jwtTenant =
    typeof jwtTenantRaw === "string" || typeof jwtTenantRaw === "number"
      ? String(jwtTenantRaw).trim()
      : "";
  const sub = claims && typeof claims.sub === "string" ? claims.sub : "";

  return (
    <header
      key={authTick}
      className="sticky top-0 z-10 flex h-12 items-center gap-3 border-b border-border bg-base/80 px-4 backdrop-blur"
    >
      <div className="flex min-w-0 max-w-[40%] flex-wrap items-center gap-2 text-xs text-subtle">
        <Activity size={14} className="text-sev-low shrink-0" />
        <span className="mono truncate">tenant: {jwtTenant || settings.tenant}</span>
        <span className="text-dim">·</span>
        <span className="mono">env: {settings.env}</span>
        {sub ? (
          <>
            <span className="text-dim">·</span>
            <span className="mono truncate" title={sub}>
              sub: {sub}
            </span>
          </>
        ) : null}
      </div>

      <div className="relative mx-auto min-w-0 w-full max-w-md flex-1">
        <Search
          size={14}
          className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-dim"
        />
        <input
          className="input pl-8 pr-14"
          placeholder="Search events, decision cards, rules…"
          disabled
        />
        <span className="kbd pointer-events-none absolute right-2 top-1/2 -translate-y-1/2">/</span>
      </div>

      <div className="ml-auto flex shrink-0 items-center gap-2 text-xs text-subtle">
        {oidcConfigured() ? (
          jwt ? (
            <button type="button" className="btn" onClick={() => clearConsoleAuth()}>
              Sign out
            </button>
          ) : (
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void startOidcLogin().catch((e) => window.alert((e as Error).message))}
            >
              Sign in
            </button>
          )
        ) : null}
        <span className="chip">UTC</span>
        <Link
          to="/help"
          className="inline-flex items-center gap-1 rounded-md border border-border bg-muted px-2 py-1 text-subtle hover:text-text"
          title="Help"
        >
          <HelpCircle size={14} />
          <span>Help</span>
        </Link>
        <Link
          to="/settings"
          className="inline-flex items-center gap-1.5 rounded-md px-1 py-0.5 text-subtle hover:text-text"
          title="Edit profile"
        >
          <CircleUser size={16} />
          <span className="hidden sm:inline">
            <span className="font-medium text-text">{settings.analystName}</span>
            <span className="ml-1 mono text-dim">· {settings.analystId}</span>
          </span>
        </Link>
      </div>
    </header>
  );
}
