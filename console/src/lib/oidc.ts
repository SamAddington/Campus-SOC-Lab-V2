const PKCE_VERIFIER_KEY = "oidc_pkce_verifier";
const PKCE_STATE_KEY = "oidc_state";

function issuerBase(): string {
  return String(import.meta.env.VITE_OIDC_ISSUER || "")
    .trim()
    .replace(/\/$/, "");
}

export function oidcConfigured(): boolean {
  const iss = issuerBase();
  const cid = String(import.meta.env.VITE_OIDC_CLIENT_ID || "").trim();
  return Boolean(iss && cid);
}

function b64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(input: string): Promise<ArrayBuffer> {
  const data = new TextEncoder().encode(input);
  return crypto.subtle.digest("SHA-256", data);
}

type OidcDiscovery = {
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint?: string;
};

export async function fetchOidcDiscovery(): Promise<OidcDiscovery> {
  const iss = issuerBase();
  const res = await fetch(`${iss}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`);
  const meta = (await res.json()) as OidcDiscovery;
  if (!meta.authorization_endpoint || !meta.token_endpoint) {
    throw new Error("OIDC discovery missing authorization_endpoint or token_endpoint");
  }
  return meta;
}

export function redirectUri(): string {
  const fromEnv = String(import.meta.env.VITE_OIDC_REDIRECT_URI || "").trim();
  if (fromEnv) return fromEnv;
  return `${window.location.origin}/auth/callback`;
}

/** Start Authorization Code + PKCE flow (navigates away). */
export async function startOidcLogin(): Promise<void> {
  if (!oidcConfigured()) throw new Error("OIDC is not configured (set VITE_OIDC_ISSUER and VITE_OIDC_CLIENT_ID at build time).");
  const meta = await fetchOidcDiscovery();
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)).buffer);
  const challenge = b64url(await sha256(verifier));
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)).buffer);
  sessionStorage.setItem(PKCE_VERIFIER_KEY, verifier);
  sessionStorage.setItem(PKCE_STATE_KEY, state);
  const clientId = String(import.meta.env.VITE_OIDC_CLIENT_ID || "").trim();
  const scope = String(import.meta.env.VITE_OIDC_SCOPES || "openid profile email").trim();
  const url = new URL(meta.authorization_endpoint);
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", redirectUri());
  url.searchParams.set("scope", scope);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("state", state);
  window.location.assign(url.toString());
}

export function readPkceVerifier(): string | null {
  return sessionStorage.getItem(PKCE_VERIFIER_KEY);
}

export function readPkceState(): string | null {
  return sessionStorage.getItem(PKCE_STATE_KEY);
}

export function clearPkceSession(): void {
  sessionStorage.removeItem(PKCE_VERIFIER_KEY);
  sessionStorage.removeItem(PKCE_STATE_KEY);
}

export async function exchangeCodeForTokens(code: string): Promise<{ access_token?: string; id_token?: string }> {
  const meta = await fetchOidcDiscovery();
  const verifier = readPkceVerifier();
  if (!verifier) throw new Error("Missing PKCE verifier (session expired). Retry login.");
  const clientId = String(import.meta.env.VITE_OIDC_CLIENT_ID || "").trim();
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri(),
    client_id: clientId,
    code_verifier: verifier,
  });
  const res = await fetch(meta.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    const detail = typeof data.error_description === "string" ? data.error_description : JSON.stringify(data);
    throw new Error(detail || `Token exchange failed (${res.status})`);
  }
  return {
    access_token: typeof data.access_token === "string" ? data.access_token : undefined,
    id_token: typeof data.id_token === "string" ? data.id_token : undefined,
  };
}

export function clearConsoleAuth(): void {
  globalThis.localStorage?.removeItem("soc_jwt");
  clearPkceSession();
  window.dispatchEvent(new Event("soc-auth-changed"));
}
