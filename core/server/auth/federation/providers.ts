// The only module in federation/ that talks to the database.
import type { ProviderConfig, UpstreamIdentity } from "./types.ts";

// deno-lint-ignore no-explicit-any
type PgClient = any;

/**
 * Enabled providers that are actually federatable. A row with no issuer is
 * configuration in progress, not a provider — returning it would produce a
 * sign-in button that 500s.
 */
export async function loadProviders(client: PgClient): Promise<Map<string, ProviderConfig>> {
  const { rows } = await client.query(
    `SELECT id, "displayName", "clientId", "clientSecret", issuer, discovery_url,
            scopes, claim_map, groups_source, groups_claim, link_policy, auto_provision
       FROM trexdb.sso_provider
      WHERE enabled = true AND issuer IS NOT NULL`,
  );
  const out = new Map<string, ProviderConfig>();
  for (const r of rows) {
    out.set(r.id, {
      id: r.id,
      displayName: r.displayName,
      clientId: r.clientId,
      clientSecret: r.clientSecret,
      issuer: r.issuer,
      // Most providers publish discovery at the standard well-known path; only
      // the odd one out needs discovery_url set explicitly.
      discoveryUrl: r.discovery_url ??
        r.issuer.replace(/\/+$/, "") + "/.well-known/openid-configuration",
      scopes: r.scopes,
      claimMap: r.claim_map ?? {},
      groupsSource: r.groups_source,
      groupsClaim: r.groups_claim,
      linkPolicy: r.link_policy,
      autoProvision: r.auto_provision,
    });
  }
  return out;
}

export async function findUserIdByEmail(client: PgClient, email: string): Promise<string | null> {
  const { rows } = await client.query(
    `SELECT id FROM trexdb."user" WHERE lower(email) = lower($1) LIMIT 1`,
    [email],
  );
  return rows[0]?.id ?? null;
}

/** A federated user has no password: no row in account with providerId 'credential'. */
export async function provisionUser(client: PgClient, identity: UpstreamIdentity): Promise<string> {
  const id = crypto.randomUUID();
  await client.query(
    `INSERT INTO trexdb."user" (id, name, email, "emailVerified", email_confirmed_at, role)
     VALUES ($1, $2, $3, true, NOW(), 'user')`,
    [id, identity.name ?? identity.email, identity.email],
  );
  return id;
}

export async function upsertAccount(client: PgClient, args: {
  userId: string;
  providerId: string;
  accountId: string;
  accessToken?: string;
  refreshToken?: string;
  accessTokenExpiresAt?: Date;
  scope?: string;
  idToken?: string;
}): Promise<void> {
  await client.query(
    `INSERT INTO trexdb.account
       (id, "userId", "accountId", "providerId", "accessToken", "refreshToken",
        "accessTokenExpiresAt", scope, "idToken")
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     ON CONFLICT ("providerId", "accountId") DO UPDATE SET
       "accessToken" = EXCLUDED."accessToken",
       -- Providers commonly return a refresh token only on first authorization;
       -- overwriting a stored one with NULL on a later sign-in would strand
       -- whatever depends on it (see phase 5's refresh-token use).
       "refreshToken" = COALESCE(EXCLUDED."refreshToken", trexdb.account."refreshToken"),
       "accessTokenExpiresAt" = EXCLUDED."accessTokenExpiresAt",
       scope = EXCLUDED.scope,
       "idToken" = EXCLUDED."idToken",
       "updatedAt" = NOW()`,
    [
      crypto.randomUUID(), args.userId, args.accountId, args.providerId,
      args.accessToken ?? null, args.refreshToken ?? null,
      args.accessTokenExpiresAt ?? null, args.scope ?? null, args.idToken ?? null,
    ],
  );
}
