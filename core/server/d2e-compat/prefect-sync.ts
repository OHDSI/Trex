// d2e-compat: keep the Prefect `database-credentials` secret block in sync with the
// trexdb registry on every /trex/db write (and delete).
//
// Prefect flows (datamodel-create, DQD, data-characterization) resolve a dataset's
// connection by loading the `database-credentials` Secret block and finding the entry
// whose `databaseCode` matches — see plugins/flows/_shared_flow_utils/dao/daobase.py
// (`Secret.load("database-credentials").get()`). The d2e main re-seeded this block on
// every DatabaseManager write (services/trex/core/server/lib/dbm.ts →
// PrefectAPI.createBlockDocument). The trexsql d2e-compat port had dropped that call
// ("PrefectAPI.createBlockDocument — not available in trex; skipped." in routes.ts), so
// a database registered during setup (demo_database, demo_database_hana) only ever made
// it into the block if alp-dataflow-gen-init happened to seed AFTER it existed — a boot
// race. When it lost the race the flow failed with:
//   ValueError: Database code '<code>' not found in 'DATABASE_CREDENTIALS' secret
//
// This module restores the re-seed by calling the Prefect REST API directly (the same
// endpoints alp-dataflow-gen-init/src/PrefectAPI.ts uses to seed the block at boot).
// It never throws: a Prefect hiccup must not 500 the /trex/db write (mirrors how
// syncTrexDatabaseManager degrades to a warning).
//
// Writes alone were not enough, though. Nothing re-seeded the block on a plain
// RESTART: the d2e seeder reads Trex.DatabaseManager (empty until boot's registry
// sync lands, and that sync sits behind the per-dataset cache attach loop), so on an
// environment with many caches it seeded an EMPTY block and every flow run failed with
//   ValueError: 'DATABASE_CREDENTIALS' secret is empty
// until someone edited a database in setup to trigger the write path above. So boot
// re-seeds too (reseedDatabaseCredentialsWithRetry, called from boot.ts): this module
// reads the trexdb registry DIRECTLY, so unlike the d2e seeder it does not depend on
// the in-memory manager being primed and is authoritative at any point during boot.
// Prefect itself may still be starting, hence the bounded retry.

import { pool } from "../db.ts";
import { decryptSecret } from "../auth/crypto.ts";

const BLOCK_NAME = "database-credentials";
const SECRET_SLUG = "secret";

/** Prefect REST API base (e.g. http://d2e-dataflow-gen-1:41120/d2e/api), or null when unset. */
function prefectBaseUrl(): string | null {
  const url = Deno.env.get("PREFECT_API_URL") ?? "";
  return url.length > 0 ? url.replace(/\/+$/, "") : null;
}

/** Decrypt a credential password with trex's native secret scheme, falling back to the
 *  plaintext column (scripts/tests may store plaintext) — same as dbm-sync.ts. */
async function recoverPassword(
  password: string | null | undefined,
  passwordEncrypted: string | null | undefined,
): Promise<string> {
  if (passwordEncrypted) {
    try {
      return await decryptSecret(passwordEncrypted);
    } catch {
      /* fall through to plaintext column */
    }
  }
  return password ?? "";
}

/** The flow's DAO matches dialects against "postgres"/"hana" — normalize "postgresql". */
function flowDialect(dialect: string | null | undefined): string {
  const d = (dialect ?? "").toLowerCase();
  return d === "postgresql" ? "postgres" : d;
}

/**
 * Build the flow's DBCredentialsType[] from the trexdb registry. Mirrors the boot
 * seeder (plugins/functions/alp-dataflow-gen-init/src/types.ts transformDBCredentials)
 * so a runtime-added DB is shaped identically to the boot-seeded ones.
 */
async function buildFlowCredentials(): Promise<any[]> {
  const client = await pool.connect();
  try {
    const r = await client.query(
      `SELECT d.id, d.host, d.port, d."databaseName" AS name, d.dialect, d.extra,
              COALESCE(
                json_agg(
                  json_build_object(
                    'username', dc.username,
                    'password', dc.password,
                    'password_encrypted', dc.password_encrypted,
                    'userScope', dc."userScope",
                    'serviceScope', dc."serviceScope"
                  )
                  -- Deterministic so the pick below is reproducible rather
                  -- than whatever order the join happened to produce.
                  ORDER BY dc."updatedAt" DESC NULLS LAST, dc.username
                ) FILTER (WHERE dc.id IS NOT NULL),
                '[]'::json
              ) AS credentials
         FROM trexdb.database d
         LEFT JOIN trexdb.database_credential dc ON dc."databaseId" = d.id
        WHERE d.enabled IS NOT FALSE
        GROUP BY d.id`,
    );
    const out: any[] = [];
    for (const row of r.rows) {
      const creds: any[] = row.credentials ?? [];
      // Several rows may share a userScope: the key is (databaseId, username,
      // userScope), so a database can legitimately carry more than one Read or
      // Admin user, and a stray registration adds one silently. json_agg above
      // is unordered, so `find` would then pick an arbitrary row -- the flow
      // block gets the wrong service user, every query fails with an
      // authorization error, and nothing says which credential was used.
      // Take the most recently updated, matching routes.ts and boot.ts, and say
      // so when the choice was ambiguous.
      const pick = (scope: string) => {
        const matches = creds.filter((c) => c.userScope === scope);
        if (matches.length > 1) {
          const names = matches.map((c) => c.username).sort().join(", ");
          console.warn(
            `[d2e-compat] database ${row.id} has ${matches.length} ${scope} credentials (${names}); using the most recently updated. Remove the duplicates -- the others are silently unused.`,
          );
        }
        return matches[0];
      };
      const read = pick("Read");
      const admin = pick("Admin");
      const extra = row.extra ?? {};
      out.push({
        readUser: read ? read.username : null,
        readPassword: read ? await recoverPassword(read.password, read.password_encrypted) : null,
        adminUser: admin ? admin.username : null,
        adminPassword: admin ? await recoverPassword(admin.password, admin.password_encrypted) : null,
        dialect: flowDialect(row.dialect),
        databaseName: row.name,
        databaseCode: row.id,
        host: row.host,
        port: row.port,
        encrypt: extra.encrypt ?? false,
        validateCertificate: extra.validateCertificate ?? false,
        sslTrustStore: extra.sslTrustStore ?? "",
        hostnameInCertificate: extra.hostnameInCertificate ?? "",
        enableAuditPolicies: extra.enableAuditPolicies ?? false,
        readRole: extra.readRole ?? "",
        // trexdb.database has no authenticationMode column; the d2e demo (postgres + HANA)
        // authenticates with username/password, so default to Password — the flow's
        // Literal[AuthMode] validation rejects a missing value. Matches the boot seeder.
        authMode: "Password",
        // BigQuery-specific fields (empty unless set in `extra`).
        type: extra.type ?? "",
        project_id: extra.project_id ?? "",
        private_key_id: extra.private_key_id ?? "",
        private_key: extra.private_key ?? "",
        client_email: extra.client_email ?? "",
        client_id: extra.client_id ?? "",
        auth_uri: extra.auth_uri ?? "",
        token_uri: extra.token_uri ?? "",
        auth_provider_x509_cert_url: extra.auth_provider_x509_cert_url ?? "",
        client_x509_cert_url: extra.client_x509_cert_url ?? "",
        universe_domain: extra.universe_domain ?? "",
        // Snowflake key-pair fields (null unless set in `extra`); the flow's
        // Optional[...] credential model treats null as "unset".
        warehouse: extra.warehouse ?? null,
        snowflakeSchema: extra.schema ?? null,
        role: extra.role ?? null,
        privateKey: extra.privateKey ?? null,
        privateKeyPassphrase: extra.privateKeyPassphrase ?? null,
      });
    }
    return out;
  } finally {
    client.release();
  }
}

async function pfJson(res: Response, ctx: string): Promise<any> {
  if (!res.ok) throw new Error(`${ctx} -> ${res.status} ${await res.text()}`);
  return await res.json();
}

const JSON_HEADERS = { "Content-Type": "application/json" };

/** Outcome of one re-seed pass:
 *  - "written": the block now matches the trexdb registry.
 *  - "skipped": nothing to do (no PREFECT_API_URL, or an empty registry under
 *    skipWhenEmpty) — a settled answer, so retrying cannot help.
 *  - "failed":  transient (registry read or Prefect call failed) — worth a retry. */
export type ReseedOutcome = "written" | "skipped" | "failed";

export interface SyncPrefectDatabaseCredentialsOptions {
  /** Leave the block untouched when the registry has no databases, instead of writing
   *  `[]` over it. Used by the boot path: an empty write is never useful (no databases
   *  means no flow can connect anyway) and would clobber the value Prefect carried over
   *  from the previous run. The /trex/db write path leaves this off, where an empty
   *  registry legitimately means "the last database was just deleted". */
  skipWhenEmpty?: boolean;
}

/**
 * Re-seed (create-or-update) the Prefect `database-credentials` secret block from the
 * current trexdb registry. No-op (with a warning) when PREFECT_API_URL is unset or
 * Prefect is unreachable, so the /trex/db write still succeeds.
 */
export async function syncPrefectDatabaseCredentials(
  options: SyncPrefectDatabaseCredentialsOptions = {},
): Promise<ReseedOutcome> {
  const base = prefectBaseUrl();
  if (!base) {
    console.warn("[d2e-compat] PREFECT_API_URL unset — skipping Prefect 'database-credentials' re-seed");
    return "skipped";
  }

  let value: any[];
  try {
    value = await buildFlowCredentials();
  } catch (e) {
    console.error(`[d2e-compat] prefect sync: failed to read trexdb registry: ${e}`);
    return "failed";
  }

  if (options.skipWhenEmpty && value.length === 0) {
    console.log(
      "[d2e-compat] trexdb registry has no databases — leaving Prefect " +
        "'database-credentials' untouched",
    );
    return "skipped";
  }

  try {
    const blockType = await pfJson(
      await fetch(`${base}/block_types/slug/${SECRET_SLUG}`, { headers: JSON_HEADERS }),
      "get secret block type",
    );
    const blockTypeId = blockType.id;

    const schemas = await pfJson(
      await fetch(`${base}/block_schemas/filter`, {
        method: "POST",
        headers: JSON_HEADERS,
        body: JSON.stringify({ block_schemas: { block_type_id: { any_: [blockTypeId] } } }),
      }),
      "get secret block schema",
    );
    const blockSchemaId = schemas[0].id;

    const codes = value.map((v) => v.databaseCode).join(", ");
    // Trailing slash is required: Prefect's FastAPI redirects POST /block_documents →
    // /block_documents/ with a 307, which not every client re-issues with the body.
    const createRes = await fetch(`${base}/block_documents/`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({
        name: BLOCK_NAME,
        data: { value },
        block_schema_id: blockSchemaId,
        block_type_id: blockTypeId,
      }),
    });

    if (createRes.ok) {
      console.log(`[d2e-compat] seeded Prefect '${BLOCK_NAME}' with ${value.length} database(s): [${codes}]`);
      return "written";
    }
    if (createRes.status !== 409) {
      throw new Error(`create block -> ${createRes.status} ${await createRes.text()}`);
    }

    // Block already exists — look up its id and PATCH the data in place.
    const existing = await pfJson(
      await fetch(`${base}/block_types/slug/${SECRET_SLUG}/block_documents/name/${BLOCK_NAME}`, {
        headers: JSON_HEADERS,
      }),
      "lookup existing block",
    );
    const patchRes = await fetch(`${base}/block_documents/${existing.id}`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify({ block_schema_id: blockSchemaId, data: { value }, merge_existing_data: false }),
    });
    if (!patchRes.ok) {
      throw new Error(`update block -> ${patchRes.status} ${await patchRes.text()}`);
    }
    console.log(`[d2e-compat] updated Prefect '${BLOCK_NAME}' with ${value.length} database(s): [${codes}]`);
    return "written";
  } catch (e) {
    console.error(`[d2e-compat] prefect 'database-credentials' re-seed failed: ${e}`);
    return "failed";
  }
}

const DEFAULT_RESEED_ATTEMPTS = 30;
const DEFAULT_RESEED_DELAY_MS = 10_000;

const DEFAULT_VERIFY_DELAY_MS = 120_000;

/** Parse a positive-integer env var, falling back on missing/garbage values. */
function positiveIntEnv(name: string, fallback: number): number {
  const parsed = Number(Deno.env.get(name));
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

/** Same, but 0 is a meaningful value (used to disable the verification pass). */
function nonNegativeIntEnv(name: string, fallback: number): number {
  const parsed = Number(Deno.env.get(name));
  return Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : fallback;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export interface ReseedRetryOptions {
  /** Total number of passes, including the first. Default 30 (env
   *  D2E_COMPAT_PREFECT_RESEED_ATTEMPTS). */
  attempts?: number;
  /** Delay between passes. Default 10s (env D2E_COMPAT_PREFECT_RESEED_DELAY_MS);
   *  30 × 10s covers a Prefect server that boots well after trex. */
  delayMs?: number;
  sleep?: (ms: number) => Promise<void>;
  log?: (message: string) => void;
  /** Seam for tests; defaults to the real re-seed with skipWhenEmpty. */
  attempt?: () => Promise<ReseedOutcome>;
}

/**
 * Re-seed the `database-credentials` block, retrying only while the failure looks
 * transient — Prefect is commonly still starting when trex boots. Returns the final
 * outcome and never throws, so callers can fire it off without a guard.
 */
export async function reseedDatabaseCredentialsWithRetry(
  options: ReseedRetryOptions = {},
): Promise<ReseedOutcome> {
  const attempts = options.attempts ??
    positiveIntEnv("D2E_COMPAT_PREFECT_RESEED_ATTEMPTS", DEFAULT_RESEED_ATTEMPTS);
  const delayMs = options.delayMs ??
    positiveIntEnv("D2E_COMPAT_PREFECT_RESEED_DELAY_MS", DEFAULT_RESEED_DELAY_MS);
  const sleep = options.sleep ?? defaultSleep;
  const log = options.log ?? ((m: string) => console.log(`[d2e-compat] ${m}`));
  const attempt = options.attempt ??
    (() => syncPrefectDatabaseCredentials({ skipWhenEmpty: true }));

  for (let pass = 1; pass <= attempts; pass++) {
    let outcome: ReseedOutcome;
    try {
      outcome = await attempt();
    } catch (e) {
      outcome = "failed";
      log(`prefect 'database-credentials' re-seed threw on pass ${pass}/${attempts}: ${e}`);
    }
    if (outcome !== "failed") return outcome;
    if (pass === attempts) {
      log(
        `prefect 'database-credentials' re-seed did not succeed after ${attempts} attempt(s); ` +
          `the block will be re-seeded on the next /trex/db write`,
      );
      return "failed";
    }
    await sleep(delayMs);
  }
  // Unreachable (attempts >= 1 always returns in the loop), but keeps the type total.
  return "failed";
}

export interface BootReseedOptions extends ReseedRetryOptions {
  /** Delay before the verification pass; 0 disables it. Default 120s (env
   *  D2E_COMPAT_PREFECT_RESEED_VERIFY_DELAY_MS). */
  verifyDelayMs?: number;
}

/**
 * The boot entry point: re-seed the block, then re-seed once more a while later.
 *
 * The second pass exists because we are not the only writer. d2e's
 * alp-dataflow-gen-init also seeds this block at startup, from
 * Trex.DatabaseManager rather than from trexdb, and a bundle without the
 * skip-when-empty guard will happily write `[]` over a good block — possibly
 * seconds AFTER our first pass, since it is gated on the Prefect health check.
 * One delayed re-seed (default 120s, comfortably past that seeder's own 3-minute
 * worker budget) repairs such a clobber automatically instead of leaving the
 * environment broken until someone edits a database in setup.
 *
 * Never throws. Not meant to be awaited by boot: it deliberately outlives it.
 */
export async function bootReseedDatabaseCredentials(
  options: BootReseedOptions = {},
): Promise<void> {
  const sleep = options.sleep ?? defaultSleep;
  const log = options.log ?? ((m: string) => console.log(`[d2e-compat] ${m}`));

  const first = await reseedDatabaseCredentialsWithRetry(options);
  // Nothing was written (no databases yet, or Prefect never came up) — a second
  // pass would have nothing to repair; the /trex/db write path covers what follows.
  if (first !== "written") return;

  const verifyDelayMs = options.verifyDelayMs ??
    nonNegativeIntEnv("D2E_COMPAT_PREFECT_RESEED_VERIFY_DELAY_MS", DEFAULT_VERIFY_DELAY_MS);
  if (verifyDelayMs <= 0) return;

  await sleep(verifyDelayMs);
  log(`re-checking Prefect '${BLOCK_NAME}' after ${verifyDelayMs}ms`);
  await reseedDatabaseCredentialsWithRetry(options);
}
