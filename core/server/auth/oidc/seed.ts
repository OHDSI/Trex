// Client registration from the environment.
//
// A relying party's client_id, secret and redirect URIs are deployment
// configuration, and the deployment that runs trex is the one that knows them.
// Without this a fresh database has no clients at all and every /authorize
// returns invalid_client, which would leave the provider unusable until someone
// wrote rows by hand.
//
// Re-running is safe and is the point: the row is upserted on every boot, so
// changing a redirect URI is an env change and a restart rather than a manual
// UPDATE.

import { pool } from "../../db.ts";
import { hashPassword } from "../password.ts";
import { parseSeedClient, type SeedClientSpec } from "./config.ts";

export { parseSeedClient };
export type { SeedClientSpec };

export async function upsertClient(spec: SeedClientSpec): Promise<void> {
  // A confidential client keeps its secret hashed; a public one stores null and
  // is held to PKCE instead.
  const secretHash = spec.clientSecret ? await hashPassword(spec.clientSecret) : null;

  await pool.query(
    // allowed_scopes is the one field that is only written when configured:
    // COALESCE leaves an unset TREX_OIDC_CLIENT_SCOPES meaning "whatever the
    // row already has", so a deployment that granted a scope by hand does not
    // lose it on the next restart, and a first insert still lands on the
    // column's own default.
    `INSERT INTO trexdb.oidc_client
       (client_id, client_secret_hash, name, redirect_uris,
        post_logout_redirect_uris, require_pkce, client_roles, allowed_scopes)
     VALUES ($1, $2, $3, $4, $5, $6, $7,
             COALESCE($8::text[], ARRAY['openid', 'profile', 'email']))
     ON CONFLICT (client_id) DO UPDATE
        SET client_secret_hash = EXCLUDED.client_secret_hash,
            name = EXCLUDED.name,
            redirect_uris = EXCLUDED.redirect_uris,
            post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
            require_pkce = EXCLUDED.require_pkce,
            client_roles = EXCLUDED.client_roles,
            allowed_scopes = COALESCE($8::text[], trexdb.oidc_client.allowed_scopes),
            updated_at = now()`,
    [
      spec.clientId,
      secretHash,
      spec.name,
      spec.redirectUris,
      spec.postLogoutRedirectUris,
      // A confidential client authenticates with its secret; PKCE stays required
      // for public ones, which have nothing else to prove who they are.
      secretHash === null,
      spec.clientRoles,
      spec.allowedScopes ?? null,
    ],
  );
}

/** Called at boot; never fatal, since a provider with no seeded client still serves. */
export async function seedClientFromEnv(
  env: Record<string, string | undefined> = Deno.env.toObject(),
): Promise<boolean> {
  const spec = parseSeedClient(env);
  if (!spec) return false;
  try {
    await upsertClient(spec);
    console.log(`[oidc] registered client ${spec.clientId}`);
    return true;
  } catch (e) {
    console.error("[oidc] client registration failed (continuing):", (e as Error)?.message ?? e);
    return false;
  }
}
