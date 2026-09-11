/**
 * d2e-compat Express routes.
 *
 * Mounted only when D2E_COMPAT=true (see core/server/d2e-compat/index.ts).
 *
 * Routes and their protection levels:
 *
 *  /WebAPI/*             — logtoAuthn  (Logto JWT optional; WebAPI rejects unauthenticated callers itself)
 *  /logto                — public      (the Logto UI worker handles its own auth)
 *  /oauth/token          — public      (Logto PKCE token exchange; d2e base.ts: no authn/authz middleware)
 *  /portal/plugin.json   — public      (d2e portal.ts: no authn/authz middleware)
 *  /portal/env.js        — public      (d2e portal.ts: no authn/authz middleware)
 *  /trex/attach          — requireAdmin (ensure source and cache catalogs are attached)
 *  /trex/db/*            — requireAdmin (d2e: authn + authz → ALP_SYSTEM_ADMIN scope required)
 *  /trex/log             — requireAdmin (d2e: authn + authz → trex.log.write scope, assigned to ALP_SYSTEM_ADMIN)
 *
 * Env vars consumed (d2e names → trex Deno.env key):
 *   D2E_IDP                      — `logto` (default) or `trex`; selects the IdP
 *   LOGTO__ISSUER                — Logto issuer URL (shared with auth.ts)
 *   GATEWAY__WO_PROTOCOL_FQDN   — hostname used to build portal URLs
 *   LOGTO__CLIENT_ID             — OIDC client id
 *   LOGTO__SCOPE                 — OIDC scopes string
 *   LOGTO__TOKEN_URL             — token endpoint URL for /oauth/token exchange
 *   LOGTO__RESOURCE_API          — resource indicator appended to token request
 *   SECURITY_AUTH_OIDC_APISECRET — client_secret appended to token request
 *   APP_LOCALE                   — portal locale
 *   GIT_COMMIT                   — build commit SHA
 *   IDP__RELYING_PARTY           — portal IDP relying party
 *   IDP__REQUIRED_CLAIM          — portal IDP required claim
 *   DB_CREDENTIALS__PUBLIC_KEYS  — RSA public keys for credential encryption
 *   PORTAL__LOG_DISCLAIMER       — portal log disclaimer text
 *   USE_PUBLIC_WEBAPI_PROXY      — portal flag
 *   PUBLIC_WEBAPI_PROXY_URL      — portal URL
 *   PUBLIC_WEBAPI_DATASOURCE     — portal datasource
 *   GATEWAY__IDP_SUBJECT_PROP    — JWT subject claim key (default: sub)
 */

import type { Express } from "express";
import express from "express";
import { logtoAuthn, requireAdmin } from "./auth.ts";
import { pool } from "../db.ts";
import { getPluginsJson } from "../plugin/ui.ts";
import { getTrexPublications, syncTrexDatabaseManager } from "./dbm-sync.ts";
import { syncPrefectDatabaseCredentials } from "./prefect-sync.ts";
import { upsertDatabaseCredential } from "./db-credential.ts";
import { decryptSecret } from "../auth/crypto.ts";
import { resolveIdpConfig } from "./idp.ts";
import { postToIdpToken } from "./lib/idp-token.ts";
import {
  CACHE_DIR,
  ensureCacheAttached,
  ensureSourceAttached,
  normalizeDialect,
  parseAttachBody,
  redactSecrets,
  snowflakeExtrasFromRow,
  type ExecFn,
  type SourceCredential,
} from "./lib/attach.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Read a Deno env var; returns empty string if unset (never throws). */
function envGet(key: string): string {
  return Deno.env.get(key) ?? "";
}


/** Build a web Request from an Express req for proxying to a fetch-based worker. */
async function buildWebRequest(req: any): Promise<Request> {
  const proto = (req.headers["x-forwarded-proto"] as string | undefined) ?? "http";
  const host = req.headers.host ?? "localhost";
  const url = `${proto}://${host}${req.originalUrl}`;

  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers as Record<string, string | string[]>)) {
    if (v) headers.set(k, Array.isArray(v) ? v.join(", ") : String(v));
  }

  let body: ArrayBuffer | null = null;
  if (req.method !== "GET" && req.method !== "HEAD") {
    const chunks: Uint8Array[] = [];
    for await (const chunk of req as unknown as AsyncIterable<Uint8Array | string>) {
      chunks.push(typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk);
    }
    if (chunks.length) body = await new Blob(chunks as BlobPart[]).arrayBuffer();
  }

  return new Request(url, {
    method: req.method,
    headers,
    body: body as BodyInit | null,
    redirect: "manual",
  });
}

/** Pipe a web Response back to an Express res. */
async function pipeResponse(webRes: Response, res: any): Promise<void> {
  res.status(webRes.status);
  webRes.headers.forEach((val: string, key: string) => {
    if (key.toLowerCase() !== "transfer-encoding") res.setHeader(key, val);
  });
  res.send(Buffer.from(await webRes.arrayBuffer()));
}

// ---------------------------------------------------------------------------
// Validation helper (ported from d2e middleware/dbm.ts, without Hono)
// ---------------------------------------------------------------------------
const DB_CODE_RE = /^[A-Za-z0-9_]+$/;

function isValidDbCode(code: unknown): boolean {
  return typeof code === "string" && DB_CODE_RE.test(code);
}

// Accept either spelling on write. GET /trex/db/ emits the trexdb column `extra`
// under both names, so a client that round-trips the legacy `db_extra` alias must
// not silently drop its extras (Snowflake key-pair, BigQuery dataset, ...).
// deno-lint-ignore no-explicit-any
function extraJson(body: any): string | null {
  const extra = body.extra ?? body.db_extra;
  return extra != null ? JSON.stringify(extra) : null;
}

// ---------------------------------------------------------------------------
// /portal/env.js helpers
// ---------------------------------------------------------------------------
function certEscapeNewLine(str: string): string {
  return str.replace(/-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----/gs, (match) =>
    match.replace(/\n/g, "\\n")
  );
}

// ---------------------------------------------------------------------------
// /WebAPI proxy body handling
// ---------------------------------------------------------------------------
// Decide whether the proxy should re-serialize the middleware-parsed req.body
// (JSON.stringify) instead of streaming the raw request through.
//
// Re-serialize only when the request itself is JSON and a parser produced an
// object — including an empty {} or [] (e.g. the cohort-characterization
// result POST sends an empty filter; keying on `Object.keys(parsed).length`
// dropped those, and since the parser had already drained the raw stream the
// fallback read yielded nothing and the POST reached WebAPI bodiless:
// "Required request body is missing").
//
// Never re-serialize non-JSON requests: express.json() leaves req.body as {}
// for content types it does not parse (multipart, form-encoded), and their
// raw stream is still readable. Re-serializing that placeholder replaced a
// multipart payload with the literal string "{}" while keeping the multipart
// content-type — WebAPI's POST /source then failed with
// MissingServletRequestPartException ("Required part 'source' is not
// present"), which broke the d2e demo-dataset setup (E2E "Adding demo
// dataset... 500").
// Numbers and booleans count as parsed bodies too: the global json parser runs
// non-strict (see routes/cli-login.ts) so WebAPI's tag endpoints, which take a
// bare int, reach us with req.body === 2. That parser has already drained the
// raw stream, so refusing to re-serialize would forward the POST bodiless.
// Strings stay excluded — a raw, genuinely unparsed body also surfaces as a
// string, and re-serializing that would double-encode it.
export function shouldReserializeParsedBody(
  contentType: string | string[] | undefined,
  parsed: unknown,
): boolean {
  if (parsed === undefined || parsed === null) return false;
  const kind = typeof parsed;
  if (kind !== "object" && kind !== "number" && kind !== "boolean") return false;
  const ct = String(Array.isArray(contentType) ? contentType[0] : contentType ?? "").toLowerCase();
  return ct.includes("application/json") || ct.includes("+json");
}

// ---------------------------------------------------------------------------
// POST /trex/attach — per-id result shape and HTTP status selection
// ---------------------------------------------------------------------------
export interface AttachResult {
  type: "cache" | "connection";
  id: string;
  // The DuckDB catalog actually attached. Differs from `id` for a HANA cache,
  // whose catalog is `<databaseCode>_cache`.
  catalog?: string;
  // "skipped" = the dialect has no source-attach mapping (HANA is queried
  // directly). A skip is NOT an attach and must not be reported as one.
  status: "attached" | "skipped" | "failed";
  error?: string;
}

// 200 nothing failed · 207 partial · 500 fatal, or every item failed.
// Never 207-when-everything-failed: 207 is inside fetch's `res.ok`, so the
// caller (d2e portal TrexApiService.attach, which logs only on `!res.ok`)
// would read a total failure as success and go on to run the Prefect flow
// that then dies with "Catalog ... does not exist".
export function attachResponseStatus(results: AttachResult[], fatal: boolean): number {
  if (fatal) return 500;
  const failed = results.filter((r) => r.status === "failed").length;
  if (failed === 0) return 200;
  return failed === results.length ? 500 : 207;
}

// ---------------------------------------------------------------------------
// mountD2eRoutes — extends the Express app with all d2e thin-shell routes.
// ---------------------------------------------------------------------------
export function mountD2eRoutes(app: Express): void {
  // ─────────────────────────────────────────────────────────────────────────
  // /WebAPI/* proxy — Task 1.3 route; unchanged.
  // ─────────────────────────────────────────────────────────────────────────
  app.all(/^\/WebAPI\/.*/, logtoAuthn, async (req: any, res: any) => {
    // Forward only the path+query to the fixed in-container WebAPI; the request
    // must never influence the host (SSRF). The route already constrains the path
    // to /WebAPI/, but re-derive pathname+search against a fixed base and re-check
    // it so a crafted originalUrl (e.g. a protocol-relative //host) can't redirect
    // the proxy to another origin.
    const parsed = new URL((req as any).originalUrl, "http://localhost:8080");
    const safePath = `${parsed.pathname}${parsed.search}`;
    if (!safePath.startsWith("/WebAPI/")) {
      (res as any).status(400).json({ error: "Invalid WebAPI path" });
      return;
    }
    const target = `http://localhost:8080${safePath}`;
    const headers = new Headers();
    for (const [k, v] of Object.entries((req as any).headers as Record<string, string | string[]>)) {
      // Drop host and length/encoding headers: when the body was already parsed we
      // re-serialize it below, so the original content-length no longer matches —
      // let fetch recompute it (a stale content-length truncates/drops the body).
      const lk = k.toLowerCase();
      if (!v || lk === "host" || lk === "content-length" || lk === "transfer-encoding" || lk === "accept-encoding") continue;
      headers.set(k, Array.isArray(v) ? v.join(", ") : String(v));
    }
    const tok = (req as any).webApiToken;
    if (tok) headers.set("Authorization", `Bearer ${tok}`);
    let body: BodyInit | undefined;
    if ((req as any).method !== "GET" && (req as any).method !== "HEAD") {
      // A body-parsing middleware populates req.body and consumes the raw request
      // stream; the for-await read below would then see nothing and silently drop
      // the body (e.g. the WebAPI cache POST's schemaName → "schemaName is
      // required"). Re-serialize req.body when present; fall back to the raw stream
      // for unparsed bodies.
      const parsed = (req as any).body;
      if (shouldReserializeParsedBody((req as any).headers["content-type"], parsed)) {
        body = JSON.stringify(parsed);
        if (!headers.has("content-type")) headers.set("content-type", "application/json");
      } else {
        const chunks: Uint8Array[] = [];
        for await (const c of req as any) chunks.push(typeof c === "string" ? new TextEncoder().encode(c) : c);
        if (chunks.length) body = await new Blob(chunks as BlobPart[]).arrayBuffer();
      }
    }
    try {
      const r = await fetch(target, { method: (req as any).method, headers, body: body as BodyInit | undefined, redirect: "manual" });
      (res as any).status(r.status);
      r.headers.forEach((val, key) => { if (key.toLowerCase() !== "transfer-encoding") (res as any).setHeader(key, val); });
      (res as any).send(Buffer.from(await r.arrayBuffer()));
    } catch (e) {
      console.error(`[d2e-compat] WebAPI proxy error: ${e}`);
      (res as any).status(502).json({ error: "WebAPI proxy error" });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────
  // /logto — Logto UI worker  (PUBLIC)
  //
  // Ported from d2e services/trex/core/server/index.ts lines 229–292.
  // The EdgeRuntime global is available in the trex main at runtime.
  // servicePath uses the absolute path where the d2e Dockerfile copies the
  // Logto worker: /usr/src/logto.
  //
  // Degradation: if EdgeRuntime is absent (plain Deno, not the trex runtime),
  // the route returns 503 rather than crashing route registration.
  // ─────────────────────────────────────────────────────────────────────────
  app.all("/logto", async (req: any, res: any) => {
    const er = (globalThis as any).EdgeRuntime;
    if (!er) {
      console.warn("[d2e-compat] /logto: EdgeRuntime not available");
      (res as any).status(503).json({ error: "Logto worker unavailable (EdgeRuntime not present)" });
      return;
    }

    const webReq = await buildWebRequest(req);

    const createWorker = async () => {
      const memoryLimitMb = 150;
      const workerTimeoutMs = 5 * 60 * 1000;
      const noModuleCache = false;
      const envVarsObj = Deno.env.toObject();
      const envVars = Object.keys(envVarsObj).map((k) => [k, envVarsObj[k]]);
      const forceCreate = false;
      const cpuTimeSoftLimitMs = 10_000;
      const cpuTimeHardLimitMs = 20_000;
      const staticPatterns = ["./logto/**/*.html"];

      return await er.userWorkers.create({
        servicePath: "/usr/src/logto",
        memoryLimitMb,
        workerTimeoutMs,
        noModuleCache,
        envVars,
        forceCreate,
        cpuTimeSoftLimitMs,
        cpuTimeHardLimitMs,
        staticPatterns,
        context: {
          useReadSyncFileAPI: true,
          unstableSloppyImports: true,
        },
        otelConfig: {
          tracing_enabled: false,
          propagators: [],
        },
      });
    };

    const callWorker = async (): Promise<Response> => {
      try {
        const worker = await createWorker();
        const controller = new AbortController();
        return await worker.fetch(webReq, { signal: controller.signal });
      } catch (e: any) {
        // WorkerAlreadyRetired is an EdgeRuntime-only Deno error; check by name
        // to avoid a TS2339 on plain Deno.errors which lacks this type.
        if (e?.constructor?.name === "WorkerAlreadyRetired" || e?.name === "WorkerAlreadyRetired") {
          return await callWorker();
        }
        console.error(`[d2e-compat] worker proxy error: ${e}`);
        return new Response(JSON.stringify({ error: "Internal server error" }), {
          status: 500,
          headers: { "Content-Type": "application/json" },
        });
      }
    };

    try {
      const workerRes = await callWorker();
      await pipeResponse(workerRes, res);
    } catch (e) {
      console.error(`[d2e-compat] /logto worker error: ${e}`);
      (res as any).status(500).json({ error: "Logto worker error" });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────
  // /oauth/token — PKCE token exchange against the selected IdP  (PUBLIC)
  // Transport failures are retried; see postToIdpToken.
  //
  // Ported from d2e services/trex/core/server/routes/base.ts.
  // Forwards the form body to the IdP's token endpoint, appending client_secret
  // and resource from the resolved config if not already present (see idp.ts).
  // ─────────────────────────────────────────────────────────────────────────
  app.post("/oauth/token", express.urlencoded({ extended: true, limit: "1mb" }), async (req: any, res: any) => {
    console.log("[d2e-compat] /oauth/token: exchange code");
    const idpCfg = resolveIdpConfig(Deno.env.toObject());
    const tokenUrl = idpCfg.tokenUrl;
    if (!tokenUrl) {
      console.error("[d2e-compat] /oauth/token: no token endpoint configured for the selected IdP");
      (res as any).status(500).json({ error: "Token URL not configured" });
      return;
    }

    const params = new URLSearchParams();

    // Parse body — Express may have already parsed it as urlencoded or raw.
    const ct = ((req as any).headers["content-type"] ?? "") as string;
    if (
      ct.includes("application/x-www-form-urlencoded") &&
      (req as any).body &&
      typeof (req as any).body === "object"
    ) {
      for (const [k, v] of Object.entries((req as any).body as Record<string, string>)) {
        params.append(k, v);
      }
    } else {
      // Raw body — read stream.
      const chunks: Uint8Array[] = [];
      for await (const chunk of req as unknown as AsyncIterable<Uint8Array | string>) {
        chunks.push(typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk);
      }
      const buf = await new Blob(chunks as BlobPart[]).arrayBuffer();
      new URLSearchParams(new TextDecoder().decode(buf)).forEach((v, k) => params.append(k, v));
    }

    const resource = idpCfg.resource;
    if (!params.has("resource") && resource) params.append("resource", resource);

    const clientSecret = idpCfg.clientSecret;
    if (!params.has("client_secret") && clientSecret) params.append("client_secret", clientSecret);
    console.log(
      `[d2e-compat] /oauth/token: secret_present=${clientSecret.length > 0} len=${clientSecret.length} keys=${[...params.keys()].join(",")}`,
    );

    try {
      // client_secret_post only (secret is in the body). Logto rejects requests
      // that present client auth via two mechanisms, so do NOT also send a Basic
      // Authorization header.
      const r = await postToIdpToken(tokenUrl, params.toString());
      // Not every response is JSON: a rate-limited request comes back as plain
      // text, and parsing it unconditionally turned a 429 the caller could act
      // on into an opaque 500 that named nothing.
      const body = await r.text();
      let data: unknown;
      try {
        data = JSON.parse(body);
      } catch {
        data = { error: r.ok ? "invalid_response" : "upstream_error", error_description: body };
      }
      if (!r.ok) {
        console.error(`[d2e-compat] /oauth/token: identity provider returned ${r.status}: ${body}`);
      }
      (res as any).status(r.ok ? 200 : r.status).json(data);
    } catch (e) {
      console.error(`[d2e-compat] /oauth/token error: ${e}`);
      (res as any).status(500).json({ error: "Token exchange failed" });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────
  // /portal/plugin.json — plugin registry  (PUBLIC)
  //
  // Ported from d2e services/trex/core/server/routes/portal.ts.
  // d2e populates global.PLUGINS_JSON dynamically; trex does not use that
  // ambient global, so we degrade to an empty object.
  // ─────────────────────────────────────────────────────────────────────────
  app.get("/portal/plugin.json", (_req: any, res: any) => {
    // trex's UI plugin loader builds the merged ui-plugins JSON as plugins
    // register (ui.ts getPluginsJson). Read it lazily so it reflects every
    // registered plugin by request time. This is what the d2e portal renders
    // its nav/micro-frontends from.
    //
    // d2e served this as `c.json(global.PLUGINS_JSON)` where PLUGINS_JSON is a
    // STRING — i.e. the body is a JSON-encoded string (double-encoded). Consumers
    // rely on that: FeatureService/SystemService do `JSON.parse(await res.json())`
    // and the portal UI JSON.parses REACT_APP_PLUGINS. getPluginsJson() returns a
    // string, so res.json() reproduces the double-encoding. Using .send() here
    // would emit single-encoded object text and break those JSON.parse() calls
    // ("[object Object]" is not valid JSON).
    (res as any).json(getPluginsJson());
  });

  // ─────────────────────────────────────────────────────────────────────────
  // /portal/env.js — portal client environment  (PUBLIC)
  //
  // Ported from d2e services/trex/core/server/routes/portal.ts.
  //
  // Env vars consumed (d2e name → Deno.env key):
  //   GATEWAY__WO_PROTOCOL_FQDN, APP_LOCALE, GIT_COMMIT, IDP__RELYING_PARTY,
  //   IDP__REQUIRED_CLAIM, DB_CREDENTIALS__PUBLIC_KEYS,
  //   PORTAL__LOG_DISCLAIMER, USE_PUBLIC_WEBAPI_PROXY,
  //   PUBLIC_WEBAPI_PROXY_URL, PUBLIC_WEBAPI_DATASOURCE
  // ─────────────────────────────────────────────────────────────────────────
  app.get("/portal/env.js", (_req: any, res: any) => {
    const gatewayHost = envGet("GATEWAY__WO_PROTOCOL_FQDN") || "localhost";
    const gatewayBase = `https://${gatewayHost}/`;
    const idpCfg = resolveIdpConfig(Deno.env.toObject());
    const clientId = idpCfg.clientId;
    const scope = idpCfg.scope;
    const issuer = idpCfg.issuer;
    const authorizationUrl = `${gatewayBase}${idpCfg.authorizePath}`;
    const endSessionUrl =
      `${gatewayBase}${idpCfg.endSessionPath}?client_id=${clientId}&redirect={window.location.origin}/d2e/portal`;

    const clientEnv = {
      PUBLIC_URL: "/d2e/portal",
      REACT_APP_LOCALE: envGet("APP_LOCALE"),
      GIT_COMMIT: envGet("GIT_COMMIT"),
      REACT_APP_IDP_RELYING_PARTY: envGet("IDP__RELYING_PARTY"),
      REACT_APP_IDP_REQUIRED_CLAIM: envGet("IDP__REQUIRED_CLAIM"),
      REACT_APP_DN_BASE_URL: gatewayBase,
      REACT_APP_CURRENT_SYSTEM: "Local",
      REACT_APP_IDP_SUBJECT_PROP: "sub",
      REACT_APP_IDP_NAME_PROP: "username",
      REACT_APP_IDP_OIDC_CONFIG: `{ "client_id": "${clientId}", "redirect_uri": "{window.location.origin}/d2e/portal/login-callback", "authority": "${gatewayBase}", "authority_configuration": { "issuer": "${issuer}", "authorization_endpoint": "${authorizationUrl}", "token_endpoint": "https://${gatewayHost}/d2e/oauth/token", "end_session_endpoint": "${endSessionUrl}" }, "scope": "${scope}", "refresh_time_before_tokens_expiration_in_second": 180 }`,
      REACT_APP_DB_CREDENTIALS_PUBLIC_KEYS: certEscapeNewLine(envGet("DB_CREDENTIALS__PUBLIC_KEYS")).replace("}\\\n", "}"),
      // d2e set this to global.PLUGINS_JSON — the merged UI-plugins menu STRING
      // that the portal parses to build its nav/micro-frontends. Hardcoding "{}"
      // leaves the portal with no menu, so views like /researcher crash in a
      // useMemo (undefined.forEach) and render blank. getPluginsJson() returns the
      // same string served at /portal/plugin.json (read lazily so all registered
      // plugins are reflected).
      REACT_APP_PLUGINS: getPluginsJson(),
      REACT_APP_MRI_CONFIG_NAME: "OMOP_GDM_PA_CONF",
      REACT_APP_LOG_DISCLAIMER: envGet("PORTAL__LOG_DISCLAIMER"),
      REACT_APP_USE_PUBLIC_WEBAPI_PROXY: envGet("USE_PUBLIC_WEBAPI_PROXY"),
      REACT_APP_PUBLIC_WEBAPI_PROXY_URL: envGet("PUBLIC_WEBAPI_PROXY_URL"),
      REACT_APP_PUBLIC_WEBAPI_DATASOURCE: envGet("PUBLIC_WEBAPI_DATASOURCE"),
    };

    (res as any).setHeader("Content-Type", "application/javascript");
    (res as any).send(`window.ENV_DATA = ${JSON.stringify(clientEnv)}`);
  });

  // POST /trex/attach — ensure runtime source and cache catalogs exist.
  // Status selection lives in attachResponseStatus() below (unit-tested).
  //
  // Dataset creation calls this immediately after assigning a cache_id. A new
  // cache has no DuckDB file yet, so the attach must be allowed to create it
  // (DuckDB's ATTACH creates the file); otherwise the subsequent Prefect flow
  // fails with "Catalog ... does not exist". ATTACH IF NOT EXISTS makes
  // repeated requests idempotent.
  //
  // Per-id `status`: "attached" (an ATTACH ran), "skipped" (the dialect has no
  // source-attach mapping — HANA is queried directly) or "failed". A caller
  // must not read "skipped" as "the catalog now exists". HTTP: 200 all fine,
  // 207 partial, 500 everything failed (207 is inside `res.ok`, so an
  // all-failed 207 would read as success to a plain fetch client).
  app.post("/trex/attach", requireAdmin, async (req: any, res: any) => {
    let input;
    try {
      input = parseAttachBody((req as any).body);
    } catch (e) {
      (res as any).status(400).json({ error: (e as Error).message });
      return;
    }

    const results: AttachResult[] = [];
    let attachConn: any;
    let fatal = false;
    try {
      const Trex = (globalThis as any).Trex;
      if (!Trex?.TrexDB) {
        throw new Error("TrexDB is unavailable");
      }
      attachConn = new Trex.TrexDB("memory");
      const attachExec: ExecFn = (sql) => attachConn.execute(sql, []);

      for (const id of input.connectionIds) {
        try {
          // ORDER BY + LIMIT 1: the unique index is ("databaseId", username,
          // "userScope"), so several Admin rows with different usernames are
          // legal and an unordered rows[0] would pick one at random.
          // `enabled IS NOT FALSE` matches readRegistryDecrypted (the column is
          // nullable, and a NULL row is live everywhere else).
          const db = await pool.query<{
            id: string; dialect: string; host: string; port: number;
            databaseName: string; extra: unknown; username: string | null;
            password_encrypted: string | null;
          }>(
            `SELECT d.id, d.dialect, d.host, d.port, d."databaseName", d.extra,
                    dc.username, dc.password_encrypted
               FROM trexdb.database d
               LEFT JOIN trexdb.database_credential dc
                 ON dc."databaseId" = d.id AND dc."userScope" = 'Admin'
              WHERE d.id = $1 AND d.enabled IS NOT FALSE
              ORDER BY dc."updatedAt" DESC NULLS LAST
              LIMIT 1`,
            [id],
          );
          const row = db.rows[0];
          if (!row) throw new Error("enabled connection not found");
          if (!row.username || !row.password_encrypted) throw new Error("Admin credential not found");
          const connection: SourceCredential = {
            id: row.id,
            dialect: row.dialect,
            host: row.host,
            port: row.port,
            name: row.databaseName,
            adminUsername: row.username,
            adminPassword: await decryptSecret(row.password_encrypted),
            ...(normalizeDialect(row.dialect) === "snowflake" ? snowflakeExtrasFromRow(row.extra) : {}),
          };
          const attached = await ensureSourceAttached(connection, { exec: attachExec });
          results.push({
            type: "connection",
            id,
            status: attached ? "attached" : "skipped",
            ...(attached ? { catalog: `${id}__srcdb` } : { error: `no source attach for dialect ${row.dialect}` }),
          });
        } catch (e) {
          // redactSecrets: the postgres ATTACH embeds the decrypted password and
          // DuckDB echoes the whole DSN back in its connection errors.
          results.push({
            type: "connection",
            id,
            status: "failed",
            error: redactSecrets((e as Error).message),
          });
        }
      }

      // HANA datasets set cache_id = databaseCode (they're queried directly), but
      // the HANA *cache* catalog is `<code>_cache` — that's what boot.ts attaches
      // and what create_cachedb_hana_plugin writes. Attaching the bare code would
      // both miss the catalog the flow needs and create a stray <code>.db that
      // boot then re-attaches on every restart.
      const hanaIds = new Set<string>();
      if (input.cacheIds.length > 0) {
        const dialects = await pool.query<{ id: string; dialect: string }>(
          `SELECT id, dialect FROM trexdb.database WHERE id = ANY($1::text[])`,
          [input.cacheIds],
        );
        for (const row of dialects.rows) {
          if (normalizeDialect(row.dialect) === "hana") hanaIds.add(row.id);
        }
      }

      for (const id of input.cacheIds) {
        const catalog = hanaIds.has(id) ? `${id}_cache` : id;
        try {
          await ensureCacheAttached(catalog, {
            exec: attachExec,
            cacheDir: CACHE_DIR,
            createDbFileIfMissing: true,
          });
          results.push({ type: "cache", id, catalog, status: "attached" });
        } catch (e) {
          results.push({
            type: "cache",
            id,
            catalog,
            status: "failed",
            error: redactSecrets((e as Error).message),
          });
        }
      }
    } catch (e) {
      fatal = true;
      console.error(`[d2e-compat] POST /trex/attach: ${redactSecrets(String(e))}`);
    } finally {
      attachConn?.close?.();
    }

    // Single response point: closing the pool session first, and never sending
    // twice if the serializer throws.
    const failed = results.filter((r) => r.status === "failed");
    if (failed.length > 0) {
      // The only caller treats !res.ok as the trigger to log, so a silent 207
      // would lose this entirely — log it here regardless.
      console.error(
        `[d2e-compat] POST /trex/attach: ${failed.length}/${results.length} failed: ` +
          failed.map((f) => `${f.type} ${f.id}: ${f.error}`).join("; "),
      );
    }
    const status = attachResponseStatus(results, fatal);
    if (status === 500) {
      (res as any).status(500).json({ error: "Failed to attach databases", results });
      return;
    }
    (res as any).status(status).json({ results });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // /trex/db/*  — credential CRUD  (ADMIN-ONLY: requireAdmin)
  //
  // Ported from d2e services/trex/core/server/routes/dbm.ts.
  //
  // Schema mapping:
  //   d2e `trex.db`  →  trex `trexdb.database` + `trexdb.database_credential`
  //
  // The d2e DatabaseManager also calls:
  //   - Trex.DatabaseManager (ambient EdgeRuntime global) — not available;
  //     deferred to the parity phase.
  //   - PrefectAPI.createBlockDocument — not available in trex; skipped.
  //   - Trex.addDB (publication replication) — not available; skipped.
  // getPublications() is degraded to return an empty array.
  //
  // All endpoints use the trex pool (trexdb schema, search_path=trexdb,public).
  // ─────────────────────────────────────────────────────────────────────────

  // GET /trex/db/ — list all databases (credentials masked)
  app.get("/trex/db/", requireAdmin, async (_req: any, res: any) => {
    try {
      const client = await pool.connect();
      try {
        const dbRes = await client.query(
          `SELECT d.id, d.id AS code, d.host, d.port,
                  d."databaseName" AS name, d.dialect,
                  d."vocabSchemas" AS vocab_schemas, d.extra,
                  -- The legacy trex.db column was db_extra; trexdb.database
                  -- renamed it to extra. The d2e UI still reads db_extra, so
                  -- emit both (dbm-sync.ts does the same for its consumers).
                  d.extra AS db_extra,
                  d.description, d.enabled,
                  d."createdAt", d."updatedAt",
                  COALESCE(
                    json_agg(
                      json_build_object(
                        'username', dc.username,
                        'userScope', dc."userScope",
                        'serviceScope', dc."serviceScope"
                      )
                    ) FILTER (WHERE dc.id IS NOT NULL),
                    '[]'::json
                  ) AS credentials
           FROM trexdb.database d
           LEFT JOIN trexdb.database_credential dc ON dc."databaseId" = d.id
           GROUP BY d.id
           ORDER BY d."createdAt" DESC`
        );
        (res as any).json(dbRes.rows);
      } finally {
        client.release();
      }
    } catch (e) {
      console.error(`[d2e-compat] GET /trex/db/: ${e}`);
      (res as any).status(500).json({ error: "Internal server error" });
    }
  });

  // GET /trex/db/publications/ — sourced from the trex-native DatabaseManager.
  app.get("/trex/db/publications/", requireAdmin, (_req: any, res: any) => {
    (res as any).json(getTrexPublications());
  });

  // POST /trex/db/ — create / upsert a database entry
  app.post("/trex/db/", requireAdmin, async (req: any, res: any) => {
    const body: any = (req as any).body ?? {};
    const code = body.code || body.id;
    if (!isValidDbCode(code)) {
      (res as any).status(400).send("Database code invalid");
      return;
    }
    try {
      const client = await pool.connect();
      try {
        await client.query(
          `INSERT INTO trexdb.database
             (id, host, port, "databaseName", dialect, "vocabSchemas", extra, description)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8)
           ON CONFLICT (id) DO UPDATE SET
             host = EXCLUDED.host,
             port = EXCLUDED.port,
             "databaseName" = EXCLUDED."databaseName",
             dialect = EXCLUDED.dialect,
             "vocabSchemas" = EXCLUDED."vocabSchemas",
             extra = EXCLUDED.extra,
             description = EXCLUDED.description,
             "updatedAt" = NOW()`,
          [
            code,
            body.host ?? null,
            body.port ?? 5432,
            body.name ?? body.databaseName ?? null,
            body.dialect ?? "postgresql",
            body.vocabSchemas != null ? JSON.stringify(body.vocabSchemas) : null,
            extraJson(body),
            body.description ?? null,
          ]
        );
        if (Array.isArray(body.credentials)) {
          for (const cred of body.credentials) {
            await upsertDatabaseCredential(client, code, cred);
          }
        }
        // Push the updated registry into the trex-native DatabaseManager so the
        // source DB is attached/queryable (the d2e main did this on every write).
        await syncTrexDatabaseManager();
        // Re-seed the Prefect `database-credentials` block so flows can resolve this
        // database by code (the d2e main did this too; the port had skipped it).
        await syncPrefectDatabaseCredentials();
        (res as any).json({ id: code });
      } finally {
        client.release();
      }
    } catch (e) {
      console.error(`[d2e-compat] POST /trex/db/: ${e}`);
      (res as any).status(500).json({ error: "Internal server error" });
    }
  });

  // PUT /trex/db/ — update an existing database entry
  app.put("/trex/db/", requireAdmin, async (req: any, res: any) => {
    const body: any = (req as any).body ?? {};
    const code = body.code || body.id;
    if (!isValidDbCode(code)) {
      (res as any).status(400).send("Database code invalid");
      return;
    }
    try {
      const client = await pool.connect();
      try {
        await client.query(
          `UPDATE trexdb.database SET
             host = COALESCE($2, host),
             port = COALESCE($3::integer, port),
             "databaseName" = COALESCE($4, "databaseName"),
             dialect = COALESCE($5, dialect),
             "vocabSchemas" = COALESCE($6::jsonb, "vocabSchemas"),
             extra = COALESCE($7::jsonb, extra),
             description = COALESCE($8, description),
             "updatedAt" = NOW()
           WHERE id = $1`,
          [
            code,
            body.host ?? null,
            body.port != null ? String(body.port) : null,
            body.name ?? body.databaseName ?? null,
            body.dialect ?? null,
            body.vocabSchemas != null ? JSON.stringify(body.vocabSchemas) : null,
            extraJson(body),
            body.description ?? null,
          ]
        );
        if (Array.isArray(body.credentials)) {
          for (const cred of body.credentials) {
            await upsertDatabaseCredential(client, code, cred);
          }
        }
        // Push the updated registry into the trex-native DatabaseManager so the
        // source DB is attached/queryable (the d2e main did this on every write).
        await syncTrexDatabaseManager();
        // Re-seed the Prefect `database-credentials` block so flows can resolve this
        // database by code (the d2e main did this too; the port had skipped it).
        await syncPrefectDatabaseCredentials();
        (res as any).json({ id: code });
      } finally {
        client.release();
      }
    } catch (e) {
      console.error(`[d2e-compat] PUT /trex/db/: ${e}`);
      (res as any).status(500).json({ error: "Internal server error" });
    }
  });

  // DELETE /trex/db/:name — delete a database entry
  app.delete("/trex/db/:name", requireAdmin, async (req: any, res: any) => {
    const name = (req as any).params.name as string;
    if (!isValidDbCode(name)) {
      (res as any).status(400).send("Database code invalid");
      return;
    }
    try {
      const client = await pool.connect();
      try {
        await client.query("DELETE FROM trexdb.database WHERE id = $1", [name]);
        await syncTrexDatabaseManager();
        // Re-seed the Prefect `database-credentials` block so the removed database is
        // dropped from what flows resolve.
        await syncPrefectDatabaseCredentials();
        (res as any).json({ id: name });
      } finally {
        client.release();
      }
    } catch (e) {
      console.error(`[d2e-compat] DELETE /trex/db/${name}: ${e}`);
      (res as any).status(500).json({ error: "Internal server error" });
    }
  });

  // POST /trex/db/pub/:name — add a publication (replication) entry.
  // Degraded: Trex.addDB (ambient global for DuckDB replication) is not
  // available in the open-source trex binary; logs a warning and returns ok.
  app.post("/trex/db/pub/:name", requireAdmin, (_req: any, res: any) => {
    console.warn(
      "[d2e-compat] POST /trex/db/pub/:name: Trex.addDB not available — publication deferred to parity phase"
    );
    (res as any).json({ message: "ok", warning: "Publication replication is not available in this build" });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // /trex/log — audit log POST  (ADMIN-ONLY: requireAdmin)
  //
  // Ported from d2e services/trex/core/server/routes/log.ts.
  // Logs a usage-agreement audit event to console (persisting to a database
  // log table is deferred to the parity phase).
  //
  // IdP identity precedence (matches d2e log.ts exactly):
  //   1. oid from the nested thirdPartyToken (Azure AD token) in the Logto JWT
  //   2. Logto JWT claim at GATEWAY__IDP_SUBJECT_PROP (default "sub"), or "oid"
  //   3. req.logtoSubject (set by requireAdmin from the verified "sub" claim)
  //
  // Env vars: GATEWAY__IDP_SUBJECT_PROP (default "sub")
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Decode a JWT payload without signature verification.
   * Used ONLY for the nested thirdPartyToken (an Azure AD token whose signing
   * key is not in Logto's JWKS). The outer Logto token is already
   * cryptographically verified by requireAdmin via jwtVerify — this inner
   * decode-without-verify matches what d2e did (jwt.decode).
   */
  function decodeJwtPayload(token: string): Record<string, unknown> {
    const parts = token.split(".");
    if (parts.length < 2) throw new Error("Not a JWT");
    // base64url → base64 → binary
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = atob(b64.padEnd(b64.length + (4 - (b64.length % 4)) % 4, "="));
    return JSON.parse(json) as Record<string, unknown>;
  }

  app.post("/trex/log", requireAdmin, async (req: any, res: any) => {
    const body: any = (req as any).body ?? {};
    const { response } = body;

    if (!response) {
      (res as any).status(400).send("Log response is missing in the request body");
      return;
    }

    // requireAdmin verified the JWT and stashed the full claims on req.logtoPayload.
    const payload: Record<string, unknown> = (req as any).logtoPayload ?? {};
    const subjectProp = Deno.env.get("GATEWAY__IDP_SUBJECT_PROP") ?? "sub";

    let idpUserId: string | undefined;
    try {
      // Preferred: decode the nested Azure AD token and use its oid.
      const tp = payload["thirdPartyToken"] as string | undefined;
      if (!tp) throw new Error("no thirdPartyToken");
      const oid = decodeJwtPayload(tp)["oid"] as string | undefined;
      if (!oid) throw new Error("no oid in thirdPartyToken");
      idpUserId = oid;
    } catch {
      // Fallback: GATEWAY__IDP_SUBJECT_PROP claim, then "oid", then logtoSubject.
      console.info("[d2e-compat] /trex/log: third-party token not found or invalid, using Logto identity");
      idpUserId =
        (payload[subjectProp] as string | undefined) ??
        (payload["oid"] as string | undefined) ??
        ((req as any).logtoSubject as string | undefined);
    }

    try {
      console.info(
        `[Data2Evidence][AUDITLOG][${Date.now()}] Usage agreement ${response} by user: ${idpUserId}`
      );
      (res as any).json({ message: "success" });
    } catch (e) {
      console.error(`[d2e-compat] /trex/log error: ${e}`);
      (res as any).status(500).json({ error: "Log write failed" });
    }
  });
}
