import { STATUS_CODE } from "jsr:@std/http@^1.0/status";
import { join } from "jsr:@std/path@^1.0";
import express from "express";
import { createServer, request as httpRequest } from "node:http";
import { grafserv } from "postgraphile/grafserv/express/v4";
import cors from "cors";
import { BASE_PATH } from "./config.ts";
import { pool } from "./db.ts";
import { authRouter } from "./auth/auth-router.ts";
import { ensureAuthKeys } from "./auth/api-keys.ts";
import {
  ensureSbKeys,
  resolveApiCredential,
  type SbKeyRecord,
  translateSbHeaders,
} from "./auth/sb-keys.ts";
import { verifyAccessToken } from "./auth/jwt.ts";
import { initDek } from "./auth/dek.ts";
import { getJwtSecret } from "./auth/jwt.ts";
import { createPostGraphile } from "./postgraphile.ts";
import { authContext } from "./middleware/auth-context.ts";
import { Plugins } from "./plugin/plugin.ts";
import { addPluginRoutes } from "./routes/plugin.ts";
import { functionsRouter } from "./routes/functions.ts";
import { cliLoginRouter } from "./routes/cli-login.ts";
import { nativeIdpEnabled } from "./auth/native-idp.ts";
import { rolesRouter } from "./auth/roles-api.ts";
import { oidcProviderEnabled, registerOidcRoutes } from "./auth/oidc/router.ts";
import { seedClientFromEnv } from "./auth/oidc/seed.ts";
import { registerFederationRoutes } from "./auth/federation/router.ts";
import { getActiveSigningKey } from "./auth/oidc/keys.ts";
import { fnmap } from "./plugin/function.ts";
import { apiLimiter } from "./middleware/rate-limit.ts";
import { applyD2eCompat, applyD2eCompatEarly, assertD2eProvisioned, D2E_COMPAT, runD2eAtlasDbInit, runD2eBoot, syncD2ePlugins } from "./d2e-compat/index.ts";
import { parseReadyPort, startBootstrapReadySignal } from "./d2e-compat/bootstrap-ready.ts";
import { collectProvisionTargets, runProvisionTargets } from "./plugin/provision.ts";
import { collectNavEntries, mergeNav } from "./plugin/nav.ts";
import { startNativeWebApi } from "./webapi-native.ts";
import { handleRealtimeUpgrade, mountRealtime, startRealtimeService, stopRealtimeService } from "./realtime/index.ts";

console.log("main function started");
console.log(Deno.version);

addEventListener("beforeunload", () => {
  console.log("main worker exiting");
  void stopRealtimeService();
});

addEventListener("unhandledrejection", (ev) => {
  console.log(ev);
  ev.preventDefault();
});

// Trust only the configured number of reverse-proxy hops (default 1). Setting
// "trust proxy" to true derives req.ip from the client-supplied X-Forwarded-For
// chain, which lets callers spoof it to mint unlimited buckets against the
// IP-keyed rate limiters (including the auth brute-force limiter). Override via
// TREX_TRUST_PROXY (hop count, "true"/"false", or a CIDR/IP list) to match the
// deployment's proxy topology.
function parseTrustProxy(raw: string | undefined): boolean | number | string {
  if (raw === undefined || raw.trim() === "") return 1;
  const v = raw.trim();
  if (v.toLowerCase() === "true") return true;
  if (v.toLowerCase() === "false") return false;
  const n = Number(v);
  if (Number.isInteger(n) && n >= 0) return n;
  return v; // CIDR / IP list — passed through to express verbatim
}

const app = express();
app.set("trust proxy", parseTrustProxy(Deno.env.get("TREX_TRUST_PROXY")));
// D2E_COMPAT: strip the /d2e base prefix before ANY route is registered.
applyD2eCompatEarly(app);
const server = createServer(app);

const trustedOrigins = (Deno.env.get("BETTER_AUTH_TRUSTED_ORIGINS") || "").split(",").filter(Boolean);
app.use(cors({
  origin: trustedOrigins.length > 0 ? trustedOrigins : false,
  credentials: true,
}));

const _TREX_DEBUG = (Deno.env.get("TREX_DEBUG") || "").toLowerCase().split(",").map((s) => s.trim());
const DEBUG_STUDIO = _TREX_DEBUG.includes("studio") || _TREX_DEBUG.includes("all");
const DEBUG_GRAPHQL = _TREX_DEBUG.includes("graphql") || _TREX_DEBUG.includes("all");

// Buffer the body so downstream cliLoginRouter's express.json() can't 500 with "stream not readable".
const STUDIO_BODY_MAX_JSON = 5 * 1024 * 1024;
const STUDIO_BODY_MAX_MULTIPART = 50 * 1024 * 1024;
app.use(["/plugins/trex/studio/api", "/plugins/trex/studio/api/*"], async (req, res, next) => {
  if (req.method === "GET" || req.method === "HEAD") return next();
  if (Buffer.isBuffer((req as any).body) && (req as any).body.length > 0) return next();
  const ct = String(req.headers["content-type"] ?? "").toLowerCase();
  const isMultipart = ct.startsWith("multipart/");
  const limit = isMultipart ? STUDIO_BODY_MAX_MULTIPART : STUDIO_BODY_MAX_JSON;
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for await (const chunk of req as any) {
      const c = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += c.length;
      if (total > limit) {
        try { (req as any).destroy?.(); } catch { /* ignore */ }
        res.status(413).json({
          error: "payload_too_large",
          error_description: `Body exceeds ${limit} bytes`,
        });
        return;
      }
      chunks.push(c);
    }
  } catch (e) {
    console.error("[studio-body-buffer] read error:", e);
    return next();
  }
  (req as any).body = Buffer.concat(chunks, total);
  (req as any)._body = true;
  if (DEBUG_STUDIO) {
    console.log(`[studio-body-buffer] ${req.method} ${req.originalUrl} read=${total}`);
  }
  next();
});

// Public settings endpoint — no auth required, only whitelisted keys
const PUBLIC_SETTING_KEYS = ["auth.selfRegistration", "auth.anonKey"];

app.get(`${BASE_PATH}/api/settings/public`, apiLimiter, async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT key, value FROM trexdb.setting WHERE key = ANY($1)`,
      [PUBLIC_SETTING_KEYS]
    );
    const settings: Record<string, any> = {};
    for (const row of result.rows) {
      settings[row.key] = row.value;
    }
    res.json(settings);
  } catch {
    // Table may not exist yet — return safe defaults
    res.json({ "auth.selfRegistration": false });
  }
});

// Web shell extension config — top-nav items as { path, label, plugin }.
// Each entry adds a top-nav link in the web shell that routes to a single-spa
// mount of the named plugin (loaded from /plugins/trex/<plugin>/<plugin>-spa.js).
// Entries come from the registered plugins' own `trex.ui.nav` declarations;
// TREX_WEB_NAV_EXTRA (a JSON array of the same shape) adds to them and wins on
// a path collision, so a deployment can still relabel or replace one.
app.get(`${BASE_PATH}/api/web-config`, apiLimiter, (_req, res) => {
  let envExtra: unknown[] = [];
  const raw = Deno.env.get("TREX_WEB_NAV_EXTRA");
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) envExtra = parsed;
    } catch (err) {
      console.warn("[web-config] invalid TREX_WEB_NAV_EXTRA:", err);
    }
  }
  const navExtra = mergeNav(collectNavEntries(Plugins.activeRegistry), envExtra);
  res.json({ navExtra });
});

// Federation relying-party endpoints (/auth/v1/authorize, /auth/v1/callback).
// Off unless TREX_FEDERATION_ENABLED is set, and mounted BEFORE the native IdP
// block below on purpose: when the native IdP is disabled that block installs a
// catch-all 403 across the whole of `${BASE_PATH}/auth/v1`, which would swallow
// these two routes — and a deployment that federates is exactly the one that
// turns the native IdP off.
registerFederationRoutes(app, BASE_PATH, pool);

// Mount the GoTrue-compatible native auth router — but only when the native IDP
// is explicitly enabled. Disabled by default so a deployment fronted by an
// external IdP (d2e + Logto) ships no native login for ANY user and no usable
// seeded admin@trex.local credential. When disabled, every native login endpoint
// returns 403. Enable with TREX_IDP_ENABLED=true (see docker-compose.dev.yml /
// docker-compose-local.yml for local/standalone use).
if (nativeIdpEnabled()) {
  app.use(`${BASE_PATH}/auth/v1`, authRouter);
} else {
  app.use(
    `${BASE_PATH}/auth/v1`,
    (_req: express.Request, res: express.Response) => {
      res.status(403).json({
        error: "idp_disabled",
        error_description:
          "Native login is disabled. Set TREX_IDP_ENABLED=true to enable it.",
      });
    },
  );
}

// Application-role administration. Always mounted: it is an admin API guarded by
// the caller's own token, not part of the login surface the native IdP switch
// turns off.
app.use(`${BASE_PATH}/admin/roles`, rolesRouter);

// OIDC provider. Separate switch from the native IdP: a deployment may want the
// protocol surface for its relying parties without exposing email/password
// login, or the reverse. Off by default, so nothing changes for a stack that
// does not ask for it.
if (oidcProviderEnabled()) {
  app.use(`${BASE_PATH}/oidc`, registerOidcRoutes(BASE_PATH));
  console.log(`OIDC provider mounted on ${BASE_PATH}/oidc`);
  // Registers the client named in the environment, if any. Not awaited: a
  // client is only needed once a browser arrives at /authorize, and boot must
  // not wait on the database for it.
  void seedClientFromEnv();
}

// Deno doesn't have `global` — polyfill for npm packages that expect Node.js
if (typeof (globalThis as any).global === "undefined") {
  (globalThis as any).global = globalThis;
}

// MCP server (before authContext — uses its own API key auth)
try {
  const { mountMcpServer } = await import("./mcp/index.ts");
  mountMcpServer(app);
  console.log(`MCP server mounted on ${BASE_PATH}/mcp`);
} catch (err) {
  console.error("MCP server failed to initialize:", err);
}

// Helper: extract user from Bearer token (for session-based admin endpoints)
async function getAuthUser(req: any): Promise<{ id: string; role: string } | null> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);
  const claims = await verifyAccessToken(token);
  if (!claims) return null;
  return { id: claims.sub, role: claims.app_metadata?.trex_role || "user" };
}

// API key management endpoint (Bearer-token authenticated)
app.post(`${BASE_PATH}/api/api-keys`, apiLimiter, express.json(), async (req, res) => {
  try {
    const user = await getAuthUser(req);
    if (!user || user.role !== "admin") {
      res.status(401).json({ error: "Admin authentication required" });
      return;
    }
    const { generateApiKey } = await import("./mcp/auth.ts");
    const { name, expiresAt } = req.body || {};
    if (!name) {
      res.status(400).json({ error: "name is required" });
      return;
    }
    let expiresDate: Date | undefined;
    if (expiresAt) {
      expiresDate = new Date(expiresAt);
      if (isNaN(expiresDate.getTime())) {
        res.status(400).json({ error: "Invalid expiresAt date" });
        return;
      }
    }
    const result = await generateApiKey(
      user.id,
      name,
      expiresDate,
    );
    res.json(result);
  } catch (err) {
    console.error("API key creation error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get(`${BASE_PATH}/api/api-keys`, apiLimiter, async (req, res) => {
  try {
    const user = await getAuthUser(req);
    if (!user || user.role !== "admin") {
      res.status(401).json({ error: "Admin authentication required" });
      return;
    }
    const result = await pool.query(
      `SELECT id, name, key_prefix, "lastUsedAt", "expiresAt", "revokedAt", "createdAt" FROM trexdb.api_key WHERE "userId" = $1 ORDER BY "createdAt" DESC`,
      [user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("API key list error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete(`${BASE_PATH}/api/api-keys/:id`, apiLimiter, async (req, res) => {
  try {
    const user = await getAuthUser(req);
    if (!user || user.role !== "admin") {
      res.status(401).json({ error: "Admin authentication required" });
      return;
    }
    const result = await pool.query(
      `UPDATE trexdb.api_key SET "revokedAt" = NOW() WHERE id = $1 AND "userId" = $2 AND "revokedAt" IS NULL RETURNING id`,
      [req.params.id, user.id]
    );
    if (result.rows.length === 0) {
      res.status(404).json({ error: "Key not found or already revoked" });
      return;
    }
    res.json({ ok: true });
  } catch (err) {
    console.error("API key revoke error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Generate Supabase CLI compatible access token (sbp_ format)
app.post(`${BASE_PATH}/api/cli-token`, apiLimiter, express.json(), async (req, res) => {
  try {
    const user = await getAuthUser(req);
    if (!user || user.role !== "admin") {
      res.status(401).json({ error: "Admin authentication required" });
      return;
    }
    const { generateApiKey } = await import("./mcp/auth.ts");
    const name = req.body?.name || "supabase-cli";
    const result = await generateApiKey(user.id, name, undefined, "sbp_");
    res.json({ access_token: result.key });
  } catch (err) {
    console.error("CLI token creation error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Dynamic plugin registration — register functions from a given directory.
// Loads code from disk and spawns workers, so it must require admin auth and
// strict containment within an allow-listed workspace directory (resolved via
// Deno.realPath to defeat `..` traversal and symlink escape).
app.post(`${BASE_PATH}/api/plugins/register`, apiLimiter, express.json(), async (req, res) => {
  try {
    const user = await getAuthUser(req);
    if (!user || user.role !== "admin") {
      res.status(401).json({ error: "Admin authentication required" });
      return;
    }
    const { path: dirPath } = req.body || {};
    if (!dirPath || typeof dirPath !== "string") {
      res.status(400).json({ error: "path is required" });
      return;
    }
    const allowedPrefixes = [
      Deno.env.get("DEVX_WORKSPACE_DIR") || "/tmp/devx-workspaces",
      "/var/devx-workspaces",
    ];
    let canonical: string;
    try {
      canonical = await Deno.realPath(dirPath);
    } catch {
      res.status(400).json({ error: "Invalid path" });
      return;
    }
    const resolvedPrefixes = (
      await Promise.all(
        allowedPrefixes.map(async (p) => {
          try {
            return await Deno.realPath(p);
          } catch {
            return null;
          }
        }),
      )
    ).filter((p): p is string => p !== null);
    const contained = resolvedPrefixes.some(
      (p) => canonical === p || canonical.startsWith(p + "/"),
    );
    if (!contained) {
      res.status(403).json({ error: "Path not in allowed workspace directory" });
      return;
    }
    const result = await Plugins.registerFromPath(app, canonical);
    if (result.ok) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (err) {
    console.error("Plugin registration error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Readiness probe: 200 only after ensureAuthKeys has populated supabaseEnvVars
// (which itself happens after the auth.anonKey + auth.serviceRoleKey rows land
// in trexdb.setting). Used by the container healthcheck so studio's depends_on
// waits until keys are actually fetchable, not just until the HTTP server is up.
app.get(`${BASE_PATH}/api/ready`, (_req, res) => {
  if (supabaseEnvVars.length > 0) {
    res.status(200).json({ ready: true });
  } else {
    res.status(503).json({ ready: false, reason: "auth keys not yet initialized" });
  }
});

// Admin-only: get auth keys
app.get(`${BASE_PATH}/api/settings/auth-keys`, apiLimiter, async (req, res) => {
  try {
    const user = await getAuthUser(req);
    if (!user || user.role !== "admin") {
      res.status(401).json({ error: "Admin authentication required" });
      return;
    }
    const result = await pool.query(
      `SELECT key, value FROM trexdb.setting WHERE key IN ('auth.anonKey', 'auth.serviceRoleKey', 'auth.publishableKey', 'auth.secretKey')`,
    );
    const keys: Record<string, string> = {};
    for (const row of result.rows) {
      // pg pre-parses JSONB: legacy rows arrive as bare strings, sb rows as objects.
      const value = row.value;
      keys[row.key] = typeof value === "object" && value !== null ? (value as SbKeyRecord).key : value;
    }
    res.json(keys);
  } catch (err) {
    console.error("Auth keys error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Streams a worker Response into an express response — CSV/binary bodies must
// not be text()-mangled. Defined BEFORE the routes that call it: in the
// unbundled dev-mode module evaluation, later top-level function declarations
// are not hoisted into earlier route closures (calling one throws
// ReferenceError at request time).
async function pipeWorkerResponse(workerResponse: globalThis.Response, res: any) {
  res.status(workerResponse.status);
  workerResponse.headers.forEach((value: string, key: string) => {
    const lower = key.toLowerCase();
    if (lower === "content-encoding" || lower === "content-length" || lower === "transfer-encoding") return;
    res.setHeader(key, value);
  });
  if (!workerResponse.body) { res.end(); return; }
  const reader = workerResponse.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) res.write(value);
    }
  } finally {
    try { reader.releaseLock(); } catch { /* ignore */ }
    try { res.end(); } catch { /* ignore */ }
  }
}

// PostgREST — before authContext since PostgREST handles its own JWT verification.
// Served in-process by the @trex/postgrest plugin worker.
// Use express.raw() to capture the raw body before any middleware consumes it
// (same caveat as the /storage/v1 route below).
app.all(
  [`${BASE_PATH}/rest/v1`, `${BASE_PATH}/rest/v1/*`],
  express.raw({ type: "*/*", limit: "50mb" }),
  async (req, res) => {
    const handler = fnmap["@trex/postgrest/functions"];
    if (!handler) {
      res.status(503).json({ error: "postgrest plugin not loaded" });
      return;
    }
    try {
      const host = req.get("host") || "localhost";
      const protocol = req.protocol || "http";
      // Rewrite /trex/rest/v1/... to the plugin's /postgrest/... mount.
      const pluginPath = req.originalUrl.replace(`${BASE_PATH}/rest/v1`, "/postgrest") || "/postgrest/";
      const requestUrl = `${protocol}://${host}${pluginPath}`;

      const headers = new Headers();
      for (const [key, val] of Object.entries(req.headers)) {
        if (val) {
          const lower = key.toLowerCase();
          if (lower === "accept-encoding" || lower === "content-length") continue;
          headers.set(key, Array.isArray(val) ? val.join(", ") : String(val));
        }
      }
      // New-format sb keys → legacy JWT of the same role; the vendored PostgREST
      // plugin only validates legacy JWTs.
      await translateSbHeaders(headers);
      // supabase-js sends apikey header + Authorization header.
      // If no Authorization header, use apikey as Bearer token so the plugin can determine the role.
      const apikey = headers.get("apikey");
      if (!headers.has("authorization") && apikey) {
        headers.set("authorization", `Bearer ${apikey}`);
      }

      let body: Blob | undefined;
      if (req.method !== "GET" && req.method !== "HEAD") {
        // req.body may already be a parsed object: cliLoginRouter's express.json() short-circuits express.raw().
        if (Buffer.isBuffer(req.body) && req.body.length > 0) {
          body = new Blob([req.body]);
        } else if (req.body && typeof req.body === "object" && Object.keys(req.body).length > 0) {
          body = new Blob([JSON.stringify(req.body)], { type: "application/json" });
        }
      }

      const webReq = new globalThis.Request(requestUrl, { method: req.method, headers, body });
      const workerResponse = await handler(webReq);
      // Stream the response — CSV/binary bodies must not be text()-mangled.
      await pipeWorkerResponse(workerResponse, res);
    } catch (err) {
      console.error("[postgrest-plugin] Error:", err);
      if (!res.headersSent) {
        res.status(500).json({ error: "Internal server error" });
      }
    }
  },
);

// Realtime is served natively (Phoenix-channels protocol over WS + the
// /realtime/v1/api/broadcast HTTP endpoint) — no external realtime container.
// mountRealtime registers the HTTP routes; the WS upgrade is handled in the
// server.on("upgrade") block below, and the replication service is started
// after server.listen.
mountRealtime(app);

// Supabase CLI subdomain routing — the CLI hits https://{ref}.trex.local/storage/v1/...
// without the BASE_PATH prefix. Rewrite to include the prefix so routes match.
if (BASE_PATH && BASE_PATH !== "/") {
  const supabasePaths = ["/storage/v1/", "/auth/v1/", "/rest/v1/", "/functions/v1/"];
  app.use((req, _res, next) => {
    if (!req.url.startsWith(BASE_PATH) && supabasePaths.some((p) => req.url.startsWith(p))) {
      req.url = `${BASE_PATH}${req.url}`;
      req.originalUrl = req.url;
    }
    next();
  });
}

// CLI login polling endpoint — no auth required (before authContext)
app.use(cliLoginRouter);

app.use(apiLimiter);
app.use(authContext);

// Admin-only gate: the sidecar forwarder uses its own service key, so without
// this any unauthenticated caller would get admin data. Static assets pass through.
app.use("/plugins/trex/studio/api", (req, res, next) => {
  const role = (req as any).pgSettings?.["app.user_role"];
  if (role === "admin") return next();
  res.status(role ? 403 : 401).json({
    error: role ? "forbidden" : "not_authenticated",
    error_description: "Studio API is admin-only",
  });
});

// Run every plugin-declared `trex.provision` module before plugins load —
// plugin init functions and plugin migrations both connect using the roles these
// create. Collected by a filesystem pre-pass so the modules can run ahead of the
// scan that would otherwise register them.
// Deliberately OUTSIDE the plugin-init try/catch below: that catch logs and
// carries on to server.listen, which would leave trex reporting healthy on an
// unprovisioned database. A provisioning failure is fatal, same abort idiom as
// the DEK init further down.
try {
  const provisionTargets = await collectProvisionTargets([
    Deno.env.get("PLUGINS_DEV_PATH") || "./plugins-dev",
    Deno.env.get("PLUGINS_PATH") || "./plugins",
  ]);
  assertD2eProvisioned(provisionTargets.length);
  if (provisionTargets.length > 0) {
    const applied = await runProvisionTargets(provisionTargets, {
      exec: (sql) => pool.query(sql),
      env: Deno.env.toObject(),
    });
    console.log(`provision: ${provisionTargets.length} plugin(s), ${applied} statement(s) applied`);
  }
} catch (err) {
  console.error("[boot] FATAL: database provisioning failed:", err);
  if (typeof Deno.exit === "function") Deno.exit(1);
  throw err;
}

// Signal downstream d2e services (e.g. alp-logto) that the roles/schemas/grants
// above now exist. They cannot `depends_on: trex` for this — that edge would be
// circular with trex -> alp-logto-post-init -> alp-logto, and compose allows
// only one healthcheck condition on trex anyway — so they poll this instead.
// Opt-in only: no-op unless both D2E_COMPAT and D2E_BOOTSTRAP_READY_PORT are set.
if (D2E_COMPAT) {
  const readyPort = parseReadyPort(Deno.env.get("D2E_BOOTSTRAP_READY_PORT"));
  if (readyPort !== null) startBootstrapReadySignal(readyPort);
}

try {
// The studio SPA is served entirely by the Studio Node sidecar via the
// @trex/studio function plugin (the studio catch-all route below). The sidecar's
// Next.js build embeds NEXT_PUBLIC_BASE_PATH=/plugins/trex/studio, so its HTML
// references assets under that base and they resolve. The old static build_static
// export shipped root-relative asset refs (blank page) and lacked studio's server
// API routes, so it is no longer served.
function buildWorkerRequest(req: any, rewrittenPath?: string): globalThis.Request {
  const host = req.get("host") || "localhost";
  const protocol = req.protocol || "http";
  const path = rewrittenPath ?? req.originalUrl;
  const requestUrl = `${protocol}://${host}${path}`;
  const headers = new Headers();
  for (const [key, val] of Object.entries(req.headers)) {
    if (!val) continue;
    const lower = key.toLowerCase();
    if (lower === "accept-encoding" || lower === "content-length") continue;
    headers.set(key, Array.isArray(val) ? val.join(", ") : String(val));
  }
  let body: Blob | undefined;
  if (req.method !== "GET" && req.method !== "HEAD" && req.body && (req.body as Buffer).length > 0) {
    // Copy so a retried forward sees the body — passing the Buffer directly can mark it transferred.
    body = new Blob([new Uint8Array(req.body as Buffer)]);
  }
  return new globalThis.Request(requestUrl, { method: req.method, headers, body });
}

// Best-effort JSON-body redaction — secrets must not hit stdout.
function redactForLog(s: string): string {
  return s
    .replace(/("(?:password|currentPassword|newPassword|access_token|refresh_token|apikey|api_key|service_role_key|anon_key|client_secret|token|otp|magiclink|secret)"\s*:\s*")[^"]*(")/gi, '$1***$2')
    .replace(/("authorization"\s*:\s*"Bearer\s+)[^"]*(")/gi, '$1***$2');
}

async function forwardToStudioSidecar(req: any, res: any) {
  const handler = fnmap["@trex/studio/functions"];
  if (!handler) {
    res.status(503).json({ error: "Studio plugin not loaded" });
    return;
  }
  const sidecarPath = req.originalUrl.replace("/plugins/trex/studio", "/studio-proxy");
  // req.body's type depends on which body-parser middleware ran (Buffer, parsed object,
  // array, undefined). Treat it as unknown and only trust it after a Buffer check.
  const rawBody: unknown = req.body;
  const bodyBuffer = rawBody instanceof Uint8Array ? Buffer.from(rawBody) : null;
  if (DEBUG_STUDIO) {
    const bodyLen = bodyBuffer ? bodyBuffer.length : 0;
    console.log(`[studio-sidecar-fwd] ${req.method} ${sidecarPath} bodyLen=${bodyLen} ct=${req.headers["content-type"] ?? ""}`);
  }
  const webReq = buildWorkerRequest(req, sidecarPath);
  const workerResponse = await handler(webReq);
  if (DEBUG_STUDIO && workerResponse.status >= 400 && sidecarPath.startsWith("/studio-proxy/api/")) {
    const cloned = workerResponse.clone();
    try {
      const reqBody = bodyBuffer ? redactForLog(bodyBuffer.toString("utf8").slice(0, 800)) : "";
      const resBody = redactForLog((await cloned.text()).slice(0, 800));
      console.log(`[studio-sidecar-${workerResponse.status >= 500 ? "5xx" : "4xx"}] ${req.method} ${sidecarPath} status=${workerResponse.status}\n  reqBody=${reqBody}\n  resBody=${resBody}`);
    } catch { /* ignore */ }
  }
  await pipeWorkerResponse(workerResponse, res);
}

// Cloud-only endpoints stubbed so self-hosted Studio's polling stays quiet.
app.get("/plugins/trex/studio/api/platform/notifications", (_req, res) => {
  res.status(200).json([]);
});
app.get("/plugins/trex/studio/api/platform/notifications/summary", (_req, res) => {
  res.status(200).json({ has_new: false, has_warning: false, has_critical: false });
});
app.post("/plugins/trex/studio/api/platform/notifications/archive-all", (_req, res) => {
  res.status(200).json([]);
});

// Serve the whole studio app (pages, /_next assets, and API) from the sidecar.
// The admin-only gate above still protects /plugins/trex/studio/api.
app.all(
  ["/plugins/trex/studio", "/plugins/trex/studio/*"],
  async (req, res) => {
    try {
      await forwardToStudioSidecar(req, res);
    } catch (err) {
      console.error("[studio] Error:", err);
      res.status(500).json({ error: "Internal server error", message: String(err) });
    }
  },
);

  // D2E_COMPAT routes BEFORE plugins: specific d2e routes (/portal/env.js,
  // /portal/plugin.json, /WebAPI, /logto, ...) must win over the d2e-ui plugin's
  // /portal static + SPA fallback, which would otherwise shadow the dynamic
  // /portal/env.js the portal needs (its absence crashes the portal app).
  await applyD2eCompat(app);
  await Plugins.initPlugins(app);
  addPluginRoutes(app);
  console.log("Plugin system initialized");

  // Re-register devx app functions (dynamic plugins don't survive restarts)
  const WORKSPACE_DIR = Deno.env.get("DEVX_WORKSPACE_DIR") || "/tmp/devx-workspaces";
  try {
    const appsResult = await pool.query(
      `SELECT path FROM devx.apps WHERE path IS NOT NULL AND path != ''`,
    );
    let count = 0;
    for (const row of appsResult.rows) {
      const appPath = `${WORKSPACE_DIR}/${row.path}`;
      try {
        await Deno.stat(`${appPath}/package.json`);
        await Plugins.registerFromPath(app, appPath);
        count++;
      } catch { /* skip apps without package.json */ }
    }
    if (count > 0) console.log(`Re-registered ${count} devx app functions`);
  } catch { /* devx schema may not exist yet */ }

  // D2E_COMPAT: mirror the active registry into the legacy `trex.plugins` table
  // that d2e's job plugins read for flow/data-model discovery. No-op otherwise.
  await syncD2ePlugins(Plugins.getActivePlugins());
} catch (err) {
  console.error("Plugin system failed to initialize:", err);
}

// Supabase-compatible /storage/v1/* route — calls storage worker directly.
// Bypasses pluginAuthz because Supabase Storage handles its own JWT auth
// (required for public bucket access without a Bearer token).
// Use express.raw() to capture the raw body before any middleware consumes it.
app.all(`${BASE_PATH}/storage/v1/*`, express.raw({ type: "*/*", limit: "50mb" }), async (req, res) => {
  const handler = fnmap["@trex/storage/supabase-storage/functions"];
  if (!handler) {
    res.status(503).json({ error: "Storage plugin not loaded" });
    return;
  }
  try {
    const host = req.get("host") || "localhost";
    const protocol = req.protocol || "http";
    // Rewrite /trex/storage/v1/... to /storage-api/...
    const storagePath = req.originalUrl.replace(`${BASE_PATH}/storage/v1`, "/storage-api");
    const requestUrl = `${protocol}://${host}${storagePath}`;

    const headers = new Headers();
    for (const [key, val] of Object.entries(req.headers)) {
      if (val) {
        const lower = key.toLowerCase();
        if (lower === "accept-encoding" || lower === "content-length") continue;
        headers.set(key, Array.isArray(val) ? val.join(", ") : String(val));
      }
    }
    // Same sb→legacy swap as the PostgREST proxy — supabase-storage validates
    // legacy JWTs itself.
    await translateSbHeaders(headers);

    let body: Blob | undefined;
    if (req.method !== "GET" && req.method !== "HEAD") {
      // req.body may already be a parsed object: cliLoginRouter's express.json() short-circuits express.raw().
      if (Buffer.isBuffer(req.body) && req.body.length > 0) {
        body = new Blob([req.body]);
      } else if (req.body && typeof req.body === "object" && Object.keys(req.body).length > 0) {
        body = new Blob([JSON.stringify(req.body)], { type: "application/json" });
        headers.set("content-type", "application/json");
      } else if (storagePath.startsWith("/storage-api/object/list/")) {
        // Supabase CLI sends POST to /object/list/ with empty body — inject defaults
        body = new Blob([JSON.stringify({ prefix: "", limit: 100, offset: 0 })], { type: "application/json" });
        headers.set("content-type", "application/json");
      } else if (headers.get("content-type")?.includes("application/json")) {
        body = new Blob(["{}"], { type: "application/json" });
      }
    }

    const webReq = new globalThis.Request(requestUrl, { method: req.method, headers, body });
    const workerResponse = await handler(webReq);

    res.status(workerResponse.status);
    workerResponse.headers.forEach((value: string, key: string) => {
      const lower = key.toLowerCase();
      if (lower === "content-encoding" || lower === "content-length" || lower === "transfer-encoding") return;
      res.setHeader(key, value);
    });
    const responseBody = await workerResponse.text();
    res.send(responseBody);
  } catch (err) {
    console.error("[storage-proxy] Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


// Supabase-compatible /pg/v1/* route — calls postgres-meta worker directly.
app.all(`${BASE_PATH}/pg/v1/*`, express.json({ limit: "5mb" }), async (req, res) => {
  // Admin-only: pg-meta runs privileged schema introspection/DDL against the
  // database and does NOT authenticate the caller itself (unlike PostgREST on
  // /rest/v1 and the storage worker on /storage/v1, which verify the JWT). Gate
  // it here the same way the Studio API is gated, so an authenticated non-admin
  // (or anon) can't reach it. authContext has already populated pgSettings.
  const role = (req as any).pgSettings?.["app.user_role"];
  if (role !== "admin") {
    res.status(role ? 403 : 401).json({
      error: role ? "forbidden" : "not_authenticated",
      error_description: "pg-meta (/pg/v1) is admin-only",
    });
    return;
  }
  const handler = fnmap["@trex/pg-meta/postgres-meta/functions"];
  if (!handler) {
    res.status(503).json({ error: "pg-meta plugin not loaded" });
    return;
  }
  try {
    const host = req.get("host") || "localhost";
    const protocol = req.protocol || "http";
    // Rewrite /trex/pg/v1/... to /pg-meta-api/...
    const metaPath = req.originalUrl.replace(`${BASE_PATH}/pg/v1`, "/pg-meta-api");
    const requestUrl = `${protocol}://${host}${metaPath}`;

    const headers = new Headers();
    for (const [key, val] of Object.entries(req.headers)) {
      if (val) {
        const lower = key.toLowerCase();
        if (lower === "accept-encoding" || lower === "content-length") continue;
        headers.set(key, Array.isArray(val) ? val.join(", ") : String(val));
      }
    }

    let body: Blob | undefined;
    if (req.method !== "GET" && req.method !== "HEAD") {
      const rawBody = JSON.stringify(req.body);
      if (rawBody && rawBody !== "undefined") {
        body = new Blob([rawBody], { type: "application/json" });
        headers.set("content-type", "application/json");
      }
    }

    const webReq = new globalThis.Request(requestUrl, { method: req.method, headers, body });
    const workerResponse = await handler(webReq);

    res.status(workerResponse.status);
    workerResponse.headers.forEach((value: string, key: string) => {
      const lower = key.toLowerCase();
      if (lower === "content-encoding" || lower === "content-length" || lower === "transfer-encoding") return;
      res.setHeader(key, value);
    });
    const responseBody = await workerResponse.text();
    res.send(responseBody);
  } catch (err) {
    console.error("[pg-meta-proxy] Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Initialize the wrapped DEK before anything that may encrypt/decrypt secrets.
// First-boot: generates a fresh DEK, wraps it with the KEK derived from
// TREX_ROOT_KEY, persists it in trexdb.kek_wrapped_dek. Subsequent boots:
// reads + unwraps the active row.
try {
  await initDek(pool);
  console.log("[boot] DEK initialized");
  // Mint the OIDC signing key now rather than on the first token. Relying
  // parties fetch jwks_uri as soon as they discover the provider, and a JWKS
  // served empty can be cached that way, leaving every id_token unverifiable
  // until the client happens to refresh. It has to come after initDek: the
  // private key is stored encrypted, so minting it any earlier fails with
  // "DEK not initialized". Fire-and-forget, like the client seed.
  if (oidcProviderEnabled()) {
    void getActiveSigningKey().catch((err) =>
      console.error("[oidc] could not prepare the signing key:", err)
    );
  }
} catch (err) {
  console.error("[boot] FATAL: DEK init failed:", err);
  // This service runs inside the trex host's embedded edge runtime, which does
  // not implement Deno.exit — calling it threw "Deno.exit is not a function",
  // masking the real DEK error above. A worker can't kill the host process
  // anyway, so re-throw to abort the rest of boot: every top-level statement
  // below (including the final server.listen) is skipped, leaving the node down
  // and its /trex/api/ready healthcheck failing loudly rather than serving with
  // an uninitialized DEK. Still honour a real Deno.exit where the runtime has one.
  if (typeof Deno.exit === "function") Deno.exit(1);
  throw err;
}

// One-shot: d2e registers an Admin and a Read credential under the same username,
// and the native source-attach selects the Admin one — so the table must allow one
// credential per (databaseId, username, userScope), not per (databaseId, username).
// Replace the legacy unique constraint with a (db, username, userScope) index so the
// /trex/db upserts (ON CONFLICT on those columns) keep both scopes. Guarded by cheap
// catalog lookups so a restart, once migrated, takes no ACCESS EXCLUSIVE lock on the
// table (which could otherwise block boot behind an active connection).
try {
  const oldCon = await pool.query(
    `SELECT 1 FROM pg_constraint
      WHERE conname = 'database_credential_databaseId_username_key' LIMIT 1`,
  );
  if (oldCon.rows.length > 0) {
    await pool.query(
      `ALTER TABLE trexdb.database_credential
         DROP CONSTRAINT IF EXISTS "database_credential_databaseId_username_key"`,
    );
  }
  const newIdx = await pool.query(
    `SELECT 1 FROM pg_class
      WHERE relname = 'database_credential_db_user_scope_key' LIMIT 1`,
  );
  if (newIdx.rows.length === 0) {
    await pool.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS database_credential_db_user_scope_key
         ON trexdb.database_credential ("databaseId", username, "userScope")`,
    );
  }
} catch (err) {
  console.error("[bootstrap] database_credential scope-constraint migration failed:", err);
}

// One-shot bootstrap: encrypt any database_credential rows that still hold a
// plaintext password. Runs after core migrations so password_encrypted exists.
try {
  const tableCheck = await pool.query(
    `SELECT column_name FROM information_schema.columns
     WHERE table_schema = 'trexdb' AND table_name = 'database_credential'
       AND column_name = 'password_encrypted'`,
  );
  if (tableCheck.rows.length > 0) {
    const stale = await pool.query(
      `SELECT id, password FROM trexdb.database_credential
       WHERE password_encrypted IS NULL AND password IS NOT NULL`,
    );
    if (stale.rows.length > 0) {
      const { encryptSecret } = await import("./auth/crypto.ts");
      let migrated = 0;
      for (const row of stale.rows) {
        try {
          const ct = await encryptSecret(row.password);
          await pool.query(
            `UPDATE trexdb.database_credential
             SET password_encrypted = $1, password = NULL, "updatedAt" = NOW()
             WHERE id = $2`,
            [ct, row.id],
          );
          migrated++;
        } catch (rowErr) {
          console.error(`[bootstrap] failed to encrypt credential ${row.id}:`, rowErr);
        }
      }
      console.log(`[bootstrap] Encrypted ${migrated}/${stale.rows.length} legacy database_credential password(s)`);
    }
  }
} catch (err) {
  console.error("[bootstrap] database_credential encryption migration failed:", err);
}

// Admin bootstrap banner — warn if no admin user and no ADMIN_EMAIL is set.
try {
  const adminCount = await pool.query(
    `SELECT COUNT(*)::INTEGER AS n FROM trexdb."user" WHERE role = 'admin' AND ("deletedAt" IS NULL)`,
  );
  const hasAdmin = (adminCount.rows[0]?.n ?? 0) > 0;
  const adminEmail = Deno.env.get("ADMIN_EMAIL");
  if (!hasAdmin && !adminEmail) {
    const banner = [
      "",
      "================================================================================",
      "  TREX BOOTSTRAP NOTICE: no admin user is configured.",
      "  Either set ADMIN_EMAIL=<your@email> in the environment so the next sign-up",
      "  is promoted to admin, or sign up the first account to bootstrap admin",
      "  via the first-user-promotion hook.",
      "================================================================================",
      "",
    ].join("\n");
    console.warn(banner);
  }
} catch (err) {
  console.error("[bootstrap] admin presence check failed:", err);
}

// Auto-create roles declared by plugins in the PostgreSQL role table
try {
  const { ensureRolesExist } = await import("./plugin/function.ts");
  await ensureRolesExist();
} catch (err) {
  console.error("Role auto-creation failed:", err);
}

if (DEBUG_GRAPHQL) {
  app.use(`${BASE_PATH}/graphql`, express.json({ limit: "1mb" }), (req, res, next) => {
    if (req.method !== "POST") return next();
    const origJson = res.json.bind(res);
    const origSend = res.send.bind(res);
    const log = (body: any) => {
      if (res.statusCode >= 400) {
        try {
          const q = (req.body as any)?.query;
          const r = typeof body === "string" ? body.slice(0, 400) : JSON.stringify(body).slice(0, 400);
          console.log(`[graphql-4xx] status=${res.statusCode} query=${String(q).slice(0,200)} resp=${r}`);
        } catch { /* ignore */ }
      }
    };
    res.json = ((body: any) => { log(body); return origJson(body); }) as any;
    res.send = ((body: any) => { log(body); return origSend(body); }) as any;
    next();
  });
}

const databaseUrl = Deno.env.get("DATABASE_URL");
if (databaseUrl) {
  try {
    const schemas = (Deno.env.get("PG_SCHEMA") || "trexdb").split(",");
    const pgl = createPostGraphile(databaseUrl, schemas);
    const serv = pgl.createServ(grafserv);
    await serv.addTo(app, server);
    console.log(`PostGraphile mounted on ${BASE_PATH}/graphql and ${BASE_PATH}/graphiql`);
  } catch (err) {
    console.error("PostGraphile failed to initialize:", err);
  }
} else {
  console.warn("DATABASE_URL not set — PostGraphile disabled");
}

// WebSocket upgrade handler — handles the native realtime channel socket and the
// devx Vite HMR tunnel.
// Reaches user code because trexas's runtime patches `internals.upgradeHttpRaw`
// in ext/runtime/js/http.js to use op_http_upgrade_raw2 instead of upstream's
// Deno.serve-only path.
server.on("upgrade", (req, socket, head) => {
  // Realtime websocket (native Phoenix-channels handler) gets first refusal.
  if (handleRealtimeUpgrade(req, socket, head)) return;

  const urlPath = req.url || "";

  const proxyMatch = urlPath.match(/\/plugins\/\w+\/devx-api\/apps\/([^/]+)\/proxy(\/.*)?$/);
  if (!proxyMatch) return; // Not a devx proxy path — let other handlers (e.g. PostGraphile) handle it

  const appId = proxyMatch[1];
  const statusUrl = `http://localhost:8000/plugins/trex/devx-api/apps/${appId}/server/status`;

  const statusReq = httpRequest(statusUrl, {
    headers: { cookie: req.headers.cookie || "" },
  }, (statusRes) => {
    let data = "";
    statusRes.on("data", (chunk: string) => { data += chunk; });
    statusRes.on("end", () => {
      try {
        const status = JSON.parse(data);
        if (status.status !== "running") { socket.destroy(); return; }
        const port = status.url ? new URL(status.url).port : String(status.port);

        const proxyReq = httpRequest(`http://localhost:${port}${urlPath}`, {
          method: "GET",
          headers: { ...req.headers, host: `localhost:${port}` },
        });
        proxyReq.on("upgrade", (_proxyRes, proxySocket, proxyHead) => {
          socket.write(
            "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            `Sec-WebSocket-Accept: ${_proxyRes.headers["sec-websocket-accept"]}\r\n` +
            ((_proxyRes.headers["sec-websocket-protocol"]) ? `Sec-WebSocket-Protocol: ${_proxyRes.headers["sec-websocket-protocol"]}\r\n` : "") +
            "\r\n"
          );
          if (proxyHead.length > 0) socket.write(proxyHead);
          proxySocket.pipe(socket);
          socket.pipe(proxySocket);
          proxySocket.on("error", () => socket.destroy());
          socket.on("error", () => proxySocket.destroy());
        });
        proxyReq.on("error", () => socket.destroy());
        proxyReq.end();
      } catch { socket.destroy(); }
    });
  });
  statusReq.on("error", () => socket.destroy());
  statusReq.end();
});

app.get(`${BASE_PATH}/_internal/health`, (_req, res) => {
  res.status(STATUS_CODE.OK).json({ message: "ok" });
});

app.get(`${BASE_PATH}/_internal/metric`, async (req, res) => {
  const user = await getAuthUser(req);
  if (!user || user.role !== "admin") {
    res.status(401).json({ error: "Admin authentication required" });
    return;
  }
  const metric = await EdgeRuntime.getRuntimeMetrics();
  res.json(metric);
});

app.put(`${BASE_PATH}/_internal/upload`, async (req, res) => {
  try {
    const user = await getAuthUser(req);
    if (!user || user.role !== "admin") {
      res.status(401).json({ error: "Admin authentication required" });
      return;
    }
    let body = "";
    for await (const chunk of req) {
      body += chunk;
    }
    const dir = await Deno.makeTempDir();
    const path = join(dir, "index.ts");
    await Deno.writeTextFile(path, body);
    res.json({ path: dir });
  } catch (err) {
    console.error("[upload] Error:", err);
    res.status(STATUS_CODE.BadRequest).json({ error: "Bad request" });
  }
});

// Supabase-compatible edge function invocation: /functions/v1/:function_name
const FUNCTIONS_DIR = Deno.env.get("FUNCTIONS_DIR") || "./functions";
const EDGE_FUNCTIONS_MANAGEMENT_FOLDER = Deno.env.get("EDGE_FUNCTIONS_MANAGEMENT_FOLDER");

// Cached Supabase-compatible env vars (populated after ensureAuthKeys)
let supabaseEnvVars: [string, string][] = [];

async function getSupabaseEnvVars(): Promise<[string, string][]> {
  const envVarsObj = Deno.env.toObject();
  const envVars: [string, string][] = Object.keys(envVarsObj).map((k) => [k, envVarsObj[k]]);
  // Inject Supabase-compatible vars if not already in process env
  for (const [key, value] of supabaseEnvVars) {
    if (!envVarsObj[key]) {
      envVars.push([key, value]);
    }
  }

  // Load user-defined secrets from DB
  try {
    const { loadSecretsForEnv } = await import("./routes/functions.ts");
    const secrets = await loadSecretsForEnv();
    for (const [key, value] of secrets) {
      if (!envVarsObj[key]) {
        envVars.push([key, value]);
      }
    }
  } catch { /* secrets table may not exist yet */ }

  return envVars;
}

async function invokeEdgeFunction(req: any, res: any) {
  const functionName = req.params.function_name;
  let servicePath: string;

  // Support /tmp/ paths for backward compat (runtime/bao plugins)
  if (functionName.startsWith("tmp")) {
    try {
      servicePath = await Deno.realPath(`/tmp/${functionName}`);
      if (!servicePath.startsWith("/tmp/")) {
        res.status(400).json({ error: "Invalid service path" });
        return;
      }
    } catch (err) {
      console.error("[edge-function] Path error:", err);
      res.status(STATUS_CODE.BadRequest).json({ error: "Invalid service path" });
      return;
    }
  } else {
    // Reject path-traversal attempts: function names must be simple slugs
    // (no `..`, no slashes, no URL-encoded delimiters). Even though Express
    // route params don't match across slashes, `..` is still a valid
    // single-segment value that would resolve a join() above the parent.
    if (!/^[A-Za-z0-9_-]+$/.test(functionName)) {
      res.status(400).json({ error: "Invalid function name" });
      return;
    }
    // Prefer Studio's management folder (functions deployed through the
    // dashboard land there); fall back to FUNCTIONS_DIR for legacy /
    // CLI-deployed functions.
    let resolved: string | undefined;
    const tryResolve = async (base: string) => {
      const candidate = join(base, functionName);
      try {
        const real = await Deno.realPath(candidate);
        const baseReal = await Deno.realPath(base);
        // Symlink containment: the resolved real path must live inside the
        // resolved base — defends against a function folder being a symlink
        // pointing somewhere sensitive.
        if (real === baseReal || real.startsWith(baseReal + "/")) return real;
      } catch { /* not found */ }
      return undefined;
    };
    if (EDGE_FUNCTIONS_MANAGEMENT_FOLDER) {
      resolved = await tryResolve(EDGE_FUNCTIONS_MANAGEMENT_FOLDER);
    }
    if (!resolved) {
      resolved = await tryResolve(FUNCTIONS_DIR);
    }
    if (!resolved) {
      res.status(404).json({ error: `Function ${functionName} not found` });
      return;
    }
    servicePath = resolved;
  }

  try {
    await Deno.stat(servicePath);
  } catch {
    res.status(404).json({ error: `Function ${functionName} not found` });
    return;
  }

  // Check verify_jwt from function metadata
  try {
    const metaPath = join(servicePath, "function.json");
    const metaContent = await Deno.readTextFile(metaPath);
    const meta = JSON.parse(metaContent);
    if (meta.verify_jwt !== false) {
      const authHeader = req.headers.authorization;
      const apikey = req.headers.apikey;
      const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : apikey;
      if (!token) {
        res.status(401).json({ error: "Invalid JWT" });
        return;
      }
      const claims = await resolveApiCredential(token);
      if (!claims) {
        res.status(401).json({ error: "Invalid JWT" });
        return;
      }
    }
  } catch {
    // No function.json or parse error — fail closed: require a valid token
    // (matches the verify_jwt path; a tokenless caller must not slip through).
    const authHeader = req.headers.authorization;
    const apikey = req.headers.apikey;
    const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : apikey;
    if (!token) {
      res.status(401).json({ error: "Invalid JWT" });
      return;
    }
    const claims = await resolveApiCredential(token);
    if (!claims) {
      res.status(401).json({ error: "Invalid JWT" });
      return;
    }
  }

  // Check for import map
  let importMapPath: string | undefined;
  try {
    const denoJsonPath = join(servicePath, "deno.json");
    await Deno.stat(denoJsonPath);
    importMapPath = denoJsonPath;
  } catch { /* no import map */ }

  // Check for ESZIP bundle (deployed by Supabase CLI)
  // Format: EZBR magic (4 bytes) + Brotli-compressed ESZIP v2
  let maybeEszip: Uint8Array | undefined;
  let maybeEntrypoint: string | undefined;
  try {
    const eszipPath = join(servicePath, "esbuild.esz");
    const raw = await Deno.readFile(eszipPath);

    // Check for EZBR header and decompress
    const header = new TextDecoder().decode(raw.slice(0, 4));
    if (header === "EZBR") {
      const { brotliDecompressSync } = await import("node:zlib");
      maybeEszip = new Uint8Array(brotliDecompressSync(raw.slice(4)));
    } else {
      // Already raw eszip
      maybeEszip = raw;
    }

    // Read entrypoint from function.json metadata
    try {
      const metaContent = await Deno.readTextFile(join(servicePath, "function.json"));
      const meta = JSON.parse(metaContent);
      maybeEntrypoint = meta.entrypoint_path
        ? `file:///${meta.entrypoint_path}`
        : "file:///src/index.ts";
    } catch {
      maybeEntrypoint = "file:///src/index.ts";
    }
  } catch { /* no eszip bundle — use regular servicePath */ }

  // Dev hot-reload: fresh, cache-bypassing worker per request for functions
  // served from the devx workspace, so the coder's source edits go live without a
  // restart. Scoped to the workspace dir; baked platform functions are untouched.
  const _wsDir = Deno.env.get("DEVX_WORKSPACE_DIR") || "/tmp/devx-workspaces";
  const _hotReload = Deno.env.get("DEVX_HOT_RELOAD") === "true" && servicePath.startsWith(_wsDir);
  const createWorker = async () => {
    const workerOpts: Record<string, unknown> = {
      servicePath,
      memoryLimitMb: 150,
      workerTimeoutMs: 5 * 60 * 1000,
      noModuleCache: _hotReload,
      envVars: await getSupabaseEnvVars(),
      forceCreate: _hotReload,
      cpuTimeSoftLimitMs: 10000,
      cpuTimeHardLimitMs: 20000,
      importMapPath,
      context: {
        useReadSyncFileAPI: true,
        unstableSloppyImports: true,
      },
    };

    // If ESZIP bundle exists, pass it to the worker (skipped under hot-reload so
    // edited source always wins).
    if (maybeEszip && !_hotReload) {
      workerOpts.maybeEszip = maybeEszip;
      workerOpts.maybeEntrypoint = maybeEntrypoint;
    }

    return await EdgeRuntime.userWorkers.create(workerOpts);
  };

  const host = req.get("host") || "localhost";
  const protocol = req.protocol || "http";
  const webUrl = `${protocol}://${host}${req.originalUrl}`;
  const webHeaders = new Headers();
  for (const [key, val] of Object.entries(req.headers)) {
    if (val) webHeaders.set(key, Array.isArray(val) ? val.join(", ") : val as string);
  }
  let reqBody: Blob | undefined;
  if (req.method !== "GET" && req.method !== "HEAD") {
    const chunks: Uint8Array[] = [];
    for await (const chunk of req) {
      chunks.push(typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk);
    }
    if (chunks.length > 0) reqBody = new Blob(chunks);
  }
  const webReq = new Request(webUrl, {
    method: req.method,
    headers: webHeaders,
    body: reqBody,
  });

  const MAX_RETRIES = 3;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      const worker = await createWorker();
      const controller = new AbortController();
      const workerResponse = await worker.fetch(webReq, { signal: controller.signal });

      res.status(workerResponse.status);
      workerResponse.headers.forEach((value: string, key: string) => {
        res.setHeader(key, value);
      });

      // Support streaming (SSE)
      const contentType = workerResponse.headers.get("content-type") || "";
      if (contentType.includes("text/event-stream")) {
        const reader = workerResponse.body?.getReader();
        if (reader) {
          const pump = async () => {
            while (true) {
              const { done, value } = await reader.read();
              if (done) { res.end(); return; }
              res.write(value);
            }
          };
          pump().catch(() => res.end());
        } else {
          res.end();
        }
      } else {
        const body = await workerResponse.text();
        res.send(body);
      }
      return;
    } catch (e) {
      if (e instanceof Deno.errors.WorkerAlreadyRetired && attempt < MAX_RETRIES - 1) {
        continue;
      }
      console.error("[edge-function] Error:", e);
      res.status(STATUS_CODE.InternalServerError).json({ msg: "Internal server error" });
      return;
    }
  }
  res.status(STATUS_CODE.InternalServerError).json({ msg: "Worker unavailable after retries" });
}

app.all(`${BASE_PATH}/functions/v1/:function_name`, apiLimiter, invokeEdgeFunction);
app.all(`${BASE_PATH}/functions/v1/:function_name/*`, apiLimiter, invokeEdgeFunction);

// Function management API (Supabase CLI compatible)
app.use(functionsRouter);

// Serve self-hosted Shinylive assets (must be before SPA catch-all)
try {
  const shinyliveDistPath = join(Deno.cwd(), "shinylive");
  await Deno.stat(shinyliveDistPath);
  const serveShiny = (await import("express")).default.static;
  app.use(`${BASE_PATH}/shinylive`, serveShiny(shinyliveDistPath));
  console.log("Serving Shinylive assets from shinylive/");
} catch { /* shinylive assets not present — skip */ }

// Root redirect to the trex web console (admin UI front door). Gated by
// TREX_CONSOLE_ENABLED (default "true"). When "false", `/` is left unclaimed so
// an upstream host (e.g. d2e's own frontend) can own the root path — the web UI
// itself stays served at /plugins/trex/web/, it's just no longer auto-redirected.
const TREX_CONSOLE_ENABLED = (Deno.env.get("TREX_CONSOLE_ENABLED") ?? "true") !== "false";
if (TREX_CONSOLE_ENABLED) {
  // Under d2e (D2E_COMPAT), the d2e portal owns the root path, so `/` redirects
  // to /d2e/portal rather than the trex admin console. The trex web UI is still
  // reachable directly at /plugins/trex/web/.
  const rootTarget = Deno.env.get("D2E_COMPAT") === "true"
    ? "/d2e/portal"
    : "/plugins/trex/web/";
  app.get("/", (_req, res) => {
    res.redirect(rootTarget);
  });
} else {
  console.log(
    "[trex] root console redirect disabled (TREX_CONSOLE_ENABLED=false); web UI still served at /plugins/trex/web/",
  );
}

// HARD CUT detection: stored anon/service_role keys in trexdb.setting were
// signed with the previous BETTER_AUTH_SECRET-derived key. If the stored
// auth.jwtSecret doesn't match the current HKDF-derived one, the cached
// JWTs cannot be verified — drop the three settings rows so ensureAuthKeys
// regenerates them with the new derivation. Idempotent: a steady-state
// restart finds matching values and is a no-op.
try {
  const stored = await pool.query(
    "SELECT value FROM trexdb.setting WHERE key = 'auth.jwtSecret' LIMIT 1",
  );
  const storedSecret = stored.rows[0]?.value
    ? (typeof stored.rows[0].value === "string"
        ? stored.rows[0].value.replace(/^"|"$/g, "")
        : stored.rows[0].value)
    : null;
  const currentSecret = await getJwtSecret();
  if (storedSecret && storedSecret !== currentSecret) {
    console.warn("[boot] stored JWT secret does not match current derivation; purging auth.{anonKey,serviceRoleKey,jwtSecret} so they re-issue under the new key");
    await pool.query(
      "DELETE FROM trexdb.setting WHERE key IN ('auth.anonKey', 'auth.serviceRoleKey', 'auth.jwtSecret')",
    );
  }
} catch (err) {
  console.error("[boot] failed to reconcile stored JWT secret; continuing anyway:", err);
}

// Initialize auth keys (anon key, service_role key, sb keys) + cache for edge functions
try {
  const authKeys = await ensureAuthKeys();
  const sbKeys = await ensureSbKeys();
  console.log("[auth] Auth keys initialized");

  // Cache Supabase-compatible env vars for edge function workers
  const supabaseUrl = Deno.env.get("BETTER_AUTH_URL") || `http://localhost:8001${BASE_PATH}`;
  supabaseEnvVars = [
    ["SUPABASE_URL", supabaseUrl],
    ["SUPABASE_ANON_KEY", authKeys.anonKey],
    ["SUPABASE_SERVICE_ROLE_KEY", authKeys.serviceRoleKey],
    ["SUPABASE_PUBLISHABLE_KEY", sbKeys.publishable.key],
    ["SUPABASE_SECRET_KEY", sbKeys.secret.key],
    ["SUPABASE_DB_URL", Deno.env.get("DATABASE_URL") || ""],
  ];
  console.log("[functions] Supabase-compatible env vars cached for edge functions");
} catch (err) {
  console.error("[auth] Failed to initialize auth keys:", err);
}

// Load SSO providers
try {
  const tableCheck = await pool.query(
    `SELECT 1 FROM information_schema.tables WHERE table_schema = 'trexdb' AND table_name = 'sso_provider' LIMIT 1`
  );
  if (tableCheck.rows.length > 0) {
    const result = await pool.query(
      `SELECT id FROM trexdb.sso_provider WHERE enabled = true`
    );
    const names = result.rows.map((r: any) => r.id);
    console.log(`[auth] SSO providers: ${names.length > 0 ? names.join(", ") : "none"}`);
  }
} catch (err) {
  console.error("[auth] Failed to load SSO providers:", err);
}

// Bootstrap initial API key from env var (for Docker/CI)
const initialKeyName = Deno.env.get("TREX_INITIAL_API_KEY_NAME");
if (initialKeyName) {
  try {
    const existing = await pool.query("SELECT 1 FROM trexdb.api_key LIMIT 1");
    if (existing.rows.length === 0) {
      const { generateApiKey } = await import("./mcp/auth.ts");
      const adminResult = await pool.query(
        `SELECT id FROM trexdb."user" WHERE role = 'admin' ORDER BY "createdAt" ASC LIMIT 1`
      );
      if (adminResult.rows.length > 0) {
        const result = await generateApiKey(adminResult.rows[0].id, initialKeyName);
        console.log(`[mcp] Initial API key created: ${result.key.slice(0, 13)}...(redacted)`);
      }
    }
  } catch (err) {
    console.error("[mcp] Failed to bootstrap initial API key:", err);
  }
}

await runD2eBoot();

server.listen(8000, () => {
  console.log("server listening on port 8000");

  // The embedded WebAPI is part of the base image, not of d2e compatibility, so
  // it starts regardless of D2E_COMPAT (see WEBAPI_NATIVE_ENABLED). Starting it
  // here rather than from an external init job means a bare `restart` of this
  // container brings WebAPI back with it.
  //
  // It goes last, and deliberately after listen: WebAPI blocks on the OIDC
  // discovery document, and when trex is its own IdP that document is served by
  // this process. Starting it before the listener made the node wait on itself,
  // so WebAPI never launched and the health endpoint never answered.
  //
  // atlas-db-init chains off it rather than running inside runD2eBoot(): the
  // seeding waits for webapi.sec_role, which WebAPI's Flyway creates. From
  // runD2eBoot() that wait sits ahead of this line, so on a fresh database it
  // could never be satisfied — it timed out after ~120s and the stack came up
  // with no WebAPI admin permissions and no OIDC external role map, which is
  // what made SourceService.createSource answer "Access Denied" and stranded
  // d2e's dataset sync before it ever triggered the TrexSQL cache build.
  void startNativeWebApi()
    .catch((e) => console.error("[webapi] start failed:", (e as Error)?.message ?? e))
    .then(() => runD2eAtlasDbInit())
    .catch((e) => console.error("[d2e-compat] atlas-db-init failed:", (e as Error)?.message ?? e));
});

// Start the native realtime replication service without blocking boot — a
// failure here (e.g. transient DB unavailability) must not take the node down.
startRealtimeService().catch((e) => console.error("[realtime] failed to start:", e));
