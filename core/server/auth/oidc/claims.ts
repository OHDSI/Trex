// id_token claim construction.
//
// Split from the signing code so the claim rules — what each scope adds, what
// the role looks like, how long a token lives — can be tested without a signing
// key or a database.

export interface IdTokenUser {
  id: string;
  email: string;
  name?: string | null;
  /** trex's own admin/user role. Gates trex features; not application access. */
  role: string;
  /** Named application roles. This is what a relying party authorizes against. */
  appRoles: string[];
  emailVerified?: boolean;
  /** Raw upstream group identifiers. Unmapped: meaning belongs to the relying party. */
  idpGroups?: string[];
  /** sso_provider.id the session was federated from; absent for native logins. */
  idpProvider?: string;
}

/**
 * Where a federated sign-in records the upstream identity it came from, inside
 * trexdb."user".app_metadata. One nested object rather than two top-level keys,
 * so it cannot collide with GoTrue's own `provider`/`providers` entries and so
 * a native sign-in can drop the whole thing with a single `- 'idp'`.
 *
 * The name lives here, next to the claims it feeds, because the producer
 * (federation/router.ts) and the consumer (oidc/router.ts's fetchUser) must
 * agree on it and neither owns it.
 */
export const IDP_METADATA_KEY = "idp";

export interface IdpMetadata {
  /** sso_provider.id. */
  provider: string;
  /** Raw upstream group identifiers, exactly as resolved at sign-in. */
  groups: string[];
}

/**
 * Reads the federation block back out of a user's app_metadata.
 *
 * Tolerant by design: app_metadata is a free-form JSONB column that predates
 * this and can hold anything. Anything that is not the shape written by the
 * federation callback yields no federation fields at all, so a malformed or
 * hand-edited value degrades to "this is a native session" rather than
 * asserting a provider that cannot be substantiated.
 */
export function federationFromAppMetadata(
  appMetadata: unknown,
): { idpProvider?: string; idpGroups?: string[] } {
  if (typeof appMetadata !== "object" || appMetadata === null) return {};
  const block = (appMetadata as Record<string, unknown>)[IDP_METADATA_KEY];
  if (typeof block !== "object" || block === null) return {};

  const { provider, groups } = block as Record<string, unknown>;
  if (typeof provider !== "string" || provider.length === 0) return {};
  const list = Array.isArray(groups) && groups.every((g) => typeof g === "string")
    ? groups as string[]
    : [];
  return { idpProvider: provider, idpGroups: list };
}

export interface IdTokenOptions {
  issuer: string;
  audience: string;
  nonce?: string | null;
  scopes: string[];
  ttlSeconds?: number;
  authTime?: number;
}

export const DEFAULT_ID_TOKEN_TTL_SECONDS = 3600;

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  auth_time: number;
  nonce?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  trex_role: string;
  // Named application roles, not the system role: what a relying party
  // authorizes against.
  roles: string[];
  app_metadata: { trex_role: string };
  idp_groups?: string[];
  idp_provider?: string;
}

/**
 * Claims are scope-gated: `profile` and `email` add nothing unless requested.
 * The role is not gated — it is the reason a relying party asks for a token at
 * all — and is emitted both top-level and under app_metadata so a consumer
 * reads it the same way it reads the native access token.
 */
export function buildIdTokenClaims(user: IdTokenUser, opts: IdTokenOptions): IdTokenClaims {
  const now = Math.floor(Date.now() / 1000);
  const claims: IdTokenClaims = {
    iss: opts.issuer,
    sub: user.id,
    aud: opts.audience,
    iat: now,
    exp: now + (opts.ttlSeconds ?? DEFAULT_ID_TOKEN_TTL_SECONDS),
    auth_time: opts.authTime ?? now,
    trex_role: user.role,
    // Application roles, never the system role: they are different concepts and
    // conflating them would grant application access on a trex admin flag.
    roles: user.appRoles,
    app_metadata: { trex_role: user.role },
  };

  if (opts.nonce) claims.nonce = opts.nonce;
  if (opts.scopes.includes("email")) {
    claims.email = user.email;
    claims.email_verified = Boolean(user.emailVerified);
  }
  if (opts.scopes.includes("profile") && user.name) {
    claims.name = user.name;
  }
  // Behind its own scope: group lists are large and only usermgmt needs them,
  // so relying parties that do not ask are not made to carry them. Gated also
  // on idpProvider so a native (password) login never emits either claim,
  // scope request notwithstanding — there is no upstream identity to report.
  if (opts.scopes.includes("idp_groups") && user.idpProvider) {
    claims.idp_groups = user.idpGroups ?? [];
    claims.idp_provider = user.idpProvider;
  }

  return claims;
}
