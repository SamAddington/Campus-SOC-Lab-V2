import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card } from "@/components/ui/Card";
import { clearPkceSession, exchangeCodeForTokens, readPkceState, redirectUri } from "@/lib/oidc";

export function AuthCallback() {
  const navigate = useNavigate();
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function run() {
      const params = new URLSearchParams(window.location.search);
      const code = params.get("code");
      const state = params.get("state");
      const oauthErr = params.get("error");
      if (oauthErr) {
        setErr(`${oauthErr}: ${params.get("error_description") || ""}`);
        return;
      }
      if (!code || !state) {
        setErr("Missing code or state in callback URL.");
        return;
      }
      const expected = readPkceState();
      if (!expected || state !== expected) {
        setErr("Invalid OAuth state. Clear site data and sign in again.");
        clearPkceSession();
        return;
      }
      try {
        const tokens = await exchangeCodeForTokens(code);
        clearPkceSession();
        const bearer = tokens.id_token || tokens.access_token;
        if (!bearer) {
          throw new Error("Token response missing id_token and access_token.");
        }
        globalThis.localStorage?.setItem("soc_jwt", bearer);
        window.dispatchEvent(new Event("soc-auth-changed"));
        if (!cancelled) navigate("/", { replace: true });
      } catch (e) {
        if (!cancelled) setErr((e as Error).message);
      }
    }
    void run();
    return () => {
      cancelled = true;
    };
  }, [navigate]);

  if (err) {
    return (
      <div className="mx-auto max-w-lg space-y-4 p-6">
        <Card title="Sign-in failed">
          <p className="text-sm text-sev-critical">{err}</p>
          <p className="mt-3 text-xs text-dim">
            Callback URL in use: <span className="mono">{redirectUri()}</span>
          </p>
          <button type="button" className="btn mt-4" onClick={() => navigate("/settings", { replace: true })}>
            Back to settings
          </button>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-[40vh] items-center justify-center p-6 text-sm text-subtle">
      Completing sign-in…
    </div>
  );
}
