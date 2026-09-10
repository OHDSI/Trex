// Provider configuration and small request helpers. No database, no express:
// everything here is a pure function of its input so it can be tested directly.

/** Off unless explicitly enabled, like the native IdP. */
export function oidcProviderEnabled(
  raw: string | undefined = Deno.env.get("TREX_OIDC_PROVIDER_ENABLED"),
): boolean {
  return raw === "true" || raw === "1";
}

/**
 * The issuer every token carries and every relying party validates, so it comes
 * from configuration rather than from the request: a proxied Host header would
 * otherwise vary the `iss` claim between callers and break validation.
 */
export function issuerUrl(
  base: string | undefined = Deno.env.get("TREX_OIDC_ISSUER"),
  basePath = "",
): string {
  return (base ?? "http://localhost:33001").replace(/\/+$/, "") + basePath;
}

/** Where an unauthenticated /authorize sends the browser; trex hosts no login UI. */
export function loginUrl(
  raw: string | undefined = Deno.env.get("TREX_OIDC_LOGIN_URL"),
): string | null {
  return raw && raw.length > 0 ? raw : null;
}

/**
 * Reads one cookie off the raw header: the server mounts no cookie parser, and
 * this is the only route that needs one. Matches the whole name, so a cookie
 * merely ending in the wanted name is not mistaken for it.
 */
export function readCookie(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}

export interface SeedClientSpec {
  clientId: string;
  clientSecret?: string;
  name: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  /** Roles the client itself carries, for the client credentials grant. */
  clientRoles: string[];
  /**
   * Scopes this client may be granted. Undefined means "not configured": the
   * row keeps whatever it has (or the column default on a first insert), so a
   * deployment that set them by hand does not have them reset on every boot.
   *
   * It exists because a scope is grantable only when the client lists it —
   * grantedScopes() narrows every request to allowed_scopes — and the column
   * default is openid/profile/email. Without this, the `idp_groups` scope that
   * carries federated group membership could never reach the client trex seeds
   * itself, and the whole claims contract would be inert for it.
   */
  allowedScopes?: string[];
}

const splitList = (raw: string | undefined): string[] =>
  (raw ?? "").split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);

/**
 * Reads one client from the environment. Returns null when no client id is set,
 * which is the ordinary case for a deployment that registers clients another way.
 */
export function parseSeedClient(
  env: Record<string, string | undefined>,
): SeedClientSpec | null {
  const clientId = env.TREX_OIDC_CLIENT_ID?.trim();
  if (!clientId) return null;

  const redirectUris = splitList(env.TREX_OIDC_CLIENT_REDIRECT_URIS);
  // A client with no redirect URI can never complete a flow, and registering it
  // would only produce a confusing invalid_request later.
  if (redirectUris.length === 0) return null;

  return {
    clientId,
    clientSecret: env.TREX_OIDC_CLIENT_SECRET?.trim() || undefined,
    name: env.TREX_OIDC_CLIENT_NAME?.trim() || clientId,
    redirectUris,
    postLogoutRedirectUris: splitList(env.TREX_OIDC_CLIENT_POST_LOGOUT_URIS),
    clientRoles: splitList(env.TREX_OIDC_CLIENT_ROLES),
    allowedScopes: parseScopes(env.TREX_OIDC_CLIENT_SCOPES),
  };
}

/**
 * `openid` is added when it is missing: without it /authorize refuses the
 * request outright with invalid_scope, so a scope list that omits it can only
 * ever be a configuration mistake, and one whose symptom points nowhere near
 * the setting that caused it.
 */
function parseScopes(raw: string | undefined): string[] | undefined {
  const scopes = splitList(raw);
  if (scopes.length === 0) return undefined;
  return scopes.includes("openid") ? scopes : ["openid", ...scopes];
}
