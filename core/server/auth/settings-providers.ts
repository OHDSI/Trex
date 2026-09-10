// Provider discovery for GET /settings.
//
// Split out of auth-router.ts so the "no external providers" fallback can be
// unit tested against an injected client, without pulling in the express
// router or the database connection auth-router.ts (via ../db.ts) requires
// at import time.
import { federationEnabled } from "./federation/config.ts";
import { loadProviders } from "./federation/providers.ts";

// deno-lint-ignore no-explicit-any
type PgClient = any;

/**
 * External providers advertised by /settings, the GoTrue-compatible endpoint
 * a sign-in page hits unconditionally at boot to decide which buttons to
 * render. A missing sso_provider table (a fresh database ahead of its
 * migration) or any other transient query failure here must degrade to "no
 * external providers" rather than fail the whole discovery response — that
 * would take native password sign-in down with it, not just federation. The
 * same defensive pattern (tolerate this table's absence, don't propagate)
 * already exists for sso_provider in index.ts, auth.ts and
 * d2e-compat/boot.ts.
 *
 * Gated on the same flag as the routes themselves (federation/router.ts only
 * mounts /authorize and /callback when federationEnabled()). Advertising a
 * provider whose endpoints are not mounted puts a sign-in button on the page
 * whose /authorize 404s — or, worse, is swallowed by the native IdP's
 * catch-all and comes back 403 — so the advertisement and the routes have to
 * be decided by one and the same condition.
 *
 * `enabled` is a parameter rather than an inline env read so a test can pin
 * it; a test that let the default fire would pass or fail with the developer's
 * environment.
 */
export async function loadExternalProviders(
  client: PgClient,
  enabled: boolean = federationEnabled(),
): Promise<Record<string, boolean>> {
  const external: Record<string, boolean> = { email: true };
  if (!enabled) return external;
  try {
    for (const id of (await loadProviders(client)).keys()) {
      external[id] = true;
    }
  } catch (err) {
    console.error("[auth] Failed to load SSO providers for /settings:", err);
  }
  return external;
}
