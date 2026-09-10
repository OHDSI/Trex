import type { Express } from "express";

export const D2E_COMPAT = Deno.env.get("D2E_COMPAT") === "true";

/** d2e base path that the front-end/caddy prefix onto every request. */
const D2E_BASE = (Deno.env.get("D2E_BASE_PATH") || "/d2e").replace(/\/+$/, "");

/**
 * Early middleware: strip the d2e base prefix (`/d2e/...` -> `/...`) so trex's
 * routes and the root-mounted d2e plugin routes (/portal, /WebAPI, /analytics-svc)
 * match. The d2e Hono fork did this in its Hono `getPath`; trex's Express main
 * needs it as the FIRST middleware (before any route is registered). No-op unless
 * D2E_COMPAT. Rewrites both `url` and `originalUrl` so downstream proxies that read
 * either see the unprefixed path.
 */
export function applyD2eCompatEarly(app: Express): void {
  if (!D2E_COMPAT) return;
  const strip = (u: string): string => {
    if (u === D2E_BASE || u === `${D2E_BASE}/`) return "/";
    if (u.startsWith(`${D2E_BASE}/`)) return u.slice(D2E_BASE.length);
    return u;
  };
  app.use((req, res, next) => {
    const hadPrefix = req.url === D2E_BASE || req.url.startsWith(`${D2E_BASE}/`);
    req.url = strip(req.url);
    if (req.originalUrl) (req as { originalUrl: string }).originalUrl = strip(req.originalUrl);
    if (hadPrefix) {
      // A redirect issued against the stripped path (e.g. express.static's
      // trailing-slash 301: /portal -> /portal/) would drop the /d2e prefix and
      // bounce the client out of the base path, looping with the caddy front door
      // (ERR_TOO_MANY_REDIRECTS). Re-add /d2e to root-relative Location targets.
      const reprefix = (v: unknown): unknown =>
        typeof v === "string" && v.startsWith("/") && v !== D2E_BASE &&
          !v.startsWith(`${D2E_BASE}/`)
          ? `${D2E_BASE}${v}`
          : v;
      const origSetHeader = res.setHeader.bind(res);
      (res as { setHeader: (n: string, v: unknown) => unknown }).setHeader = (
        name: string,
        value: unknown,
      ) => {
        if (String(name).toLowerCase() === "location") value = reprefix(value);
        return origSetHeader(name, value as never);
      };
    }
    next();
  });
}

/** Boot-time DuckDB/native side-effects (webapi, fhir, attaches). No-op unless D2E_COMPAT.
 *  A boot failure (e.g. a missing DuckDB extension on a given arch) must NEVER take
 *  down trex's main worker — the server must still come up and serve. So the whole
 *  boot is guarded here in addition to each block's own try/catch. */
export async function runD2eBoot(): Promise<void> {
  if (!D2E_COMPAT) return;
  try {
    const { d2eBoot } = await import("./boot.ts");
    await d2eBoot();
  } catch (e) {
    console.error("[d2e-compat] boot failed (continuing without it):", (e as Error)?.message ?? e);
  }
}

/** WebAPI security seeding (atlas-db-init). No-op unless D2E_COMPAT.
 *  Split out of runD2eBoot() because it must run AFTER startNativeWebApi():
 *  it waits on tables WebAPI's Flyway creates, and index.ts starts WebAPI
 *  only once the listener is up (see the boot-order contract in boot.ts).
 *  Guarded like runD2eBoot — seeding must never take the node down. */
export async function runD2eAtlasDbInit(): Promise<void> {
  if (!D2E_COMPAT) return;
  try {
    const { d2eAtlasDbInit } = await import("./boot.ts");
    await d2eAtlasDbInit();
  } catch (e) {
    console.error("[d2e-compat] atlas-db-init failed (continuing without it):", (e as Error)?.message ?? e);
  }
}

/** Mounts d2e-only Express routes. No-op unless D2E_COMPAT. */
// Awaited so routes are registered before the server starts listening.
export async function applyD2eCompat(app: Express): Promise<void> {
  if (!D2E_COMPAT) return;
  const m = await import("./routes.ts");
  m.mountD2eRoutes(app);
}

/**
 * Guard the handoff to the `trex.provision` plugin kind.
 *
 * The provisioning itself (login users, supabase roles, schemas, grants) now
 * lives in d2e as @data2evidence/d2e-bootstrap, so the policy ships with the
 * services that depend on it. What cannot move here is the failure mode: if the
 * plugin is not mounted, trex would boot healthy onto an unprovisioned database
 * and every consumer would fail much later with a confusing error (alp-logto
 * crash-looping on a missing role, say). So when d2e's bootstrap config is
 * present, a provision plugin having run is mandatory.
 */
export function assertD2eProvisioned(appliedTargets: number): void {
  // Env read at call time, not via the module-level D2E_COMPAT const, so the
  // guard is exercisable without re-importing this module (which drags in
  // routes.ts). It runs once at boot, so there is no hot path to protect.
  if (Deno.env.get("D2E_COMPAT") !== "true") return;
  const configured = Deno.env.get("POSTGRES_MANAGE_CONFIG") &&
    Deno.env.get("POSTGRES_MANAGE_USERS");
  if (!configured) {
    console.log("[d2e-compat] provisioning skipped — POSTGRES_MANAGE_CONFIG/USERS not set");
    return;
  }
  if (appliedTargets === 0) {
    throw new Error(
      "POSTGRES_MANAGE_CONFIG/USERS are set but no trex.provision plugin was found. " +
        "Mount @data2evidence/d2e-bootstrap under a PLUGINS_DEV_PATH entry.",
    );
  }
}

/**
 * Mirror the active plugin registry into the legacy `trex.plugins` table that
 * d2e's job plugins read. No-op unless D2E_COMPAT. Call AFTER plugin init (and
 * any dynamic re-registration) so every active plugin is captured. A failure
 * must never take down boot. */
export async function syncD2ePlugins(
  activeRegistry: Map<string, { version: string; trexConfig?: unknown }>,
): Promise<void> {
  if (!D2E_COMPAT) return;
  try {
    const { syncTrexPluginsTable } = await import("./plugins-sync.ts");
    await syncTrexPluginsTable(activeRegistry);
  } catch (e) {
    console.error("[d2e-compat] plugins sync failed (continuing):", (e as Error)?.message ?? e);
  }
}
