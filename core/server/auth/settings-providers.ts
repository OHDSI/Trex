// Provider discovery for GET /settings.
//
// Split out of auth-router.ts so the "no external providers" fallback can be
// unit tested against an injected client, without pulling in the express
// router or the database connection auth-router.ts (via ../db.ts) requires
// at import time.
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
 */
export async function loadExternalProviders(client: PgClient): Promise<Record<string, boolean>> {
  const external: Record<string, boolean> = { email: true };
  try {
    for (const id of (await loadProviders(client)).keys()) {
      external[id] = true;
    }
  } catch (err) {
    console.error("[auth] Failed to load SSO providers for /settings:", err);
  }
  return external;
}
