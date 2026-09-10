// d2e-compat/atlas-db-init.ts
// Replaces the d2e `webapi-init` container: applies services/atlas-db-init/*.sql
// after WebAPI's Flyway migrations and Logto's own migrations have landed.
// Runs from d2eAtlasDbInit(), which index.ts invokes after startNativeWebApi()
// — never from d2eBoot(), which completes before WebAPI has started.

export interface TableRef {
  schema: string;
  table: string;
}

export interface WaitOptions {
  attempts?: number;
  intervalMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Poll until every table exists. Bounded — returns false on exhaustion rather
 *  than looping forever, so a missing dependency can never hang trex's boot. */
export async function waitForTables(
  exists: (t: TableRef) => Promise<boolean>,
  tables: TableRef[],
  opts: WaitOptions = {},
): Promise<boolean> {
  const attempts = opts.attempts ?? 60;
  const intervalMs = opts.intervalMs ?? 2000;
  const sleep = opts.sleep ?? defaultSleep;

  for (let attempt = 0; attempt < attempts; attempt++) {
    let allPresent = true;
    for (const t of tables) {
      let present = false;
      try {
        present = await exists(t);
      } catch {
        present = false; // treat a probe failure as not-ready
      }
      if (!present) {
        allPresent = false;
        break; // no point probing the rest of this pass
      }
    }
    if (allPresent) return true;
    if (attempt < attempts - 1) await sleep(intervalMs);
  }
  return false;
}

/** Tables the seeding SQL reads from or writes to. `webapi.sec_role` is created
 *  by WebAPI's Flyway (which runs after trex_webapi_start returns, hence the
 *  wait); `logto.users` by Logto's own migrations. */
export const REQUIRED_TABLES: TableRef[] = [
  { schema: "webapi", table: "sec_role" },
  { schema: "logto", table: "users" },
];

/**
 * The tables worth waiting for, given the IdP in use.
 *
 * `logto.users` only means something when Logto is the IdP. A trex-authenticated
 * stack need never populate it, and waiting on it holds back the seeding WebAPI
 * authorization depends on: sec_external_role_map is what turns a token's
 * `admin` claim into WebAPI's admin role. Seeded late, the first caller gets
 * "403 Access Denied" from an otherwise correct stack — which is what a fresh
 * database produced, the setup running minutes before the map existed.
 *
 * Logto keeps the full list, so those deployments behave exactly as before.
 */
export function requiredTablesFor(idp: string | undefined): TableRef[] {
  return (idp ?? "").trim().toLowerCase() === "trex"
    ? REQUIRED_TABLES.filter((t) => t.schema !== "logto")
    : REQUIRED_TABLES;
}

/** psql meta-commands (`\gset`, `\if`, `\endif`, ...) are a psql client feature,
 *  not SQL. The retired webapi-init container piped these files through psql;
 *  this hook uses the wire protocol, whose simple-query parser rejects the whole
 *  string — so a file containing one applies NOTHING. Detect and report instead
 *  of failing silently; the SQL itself has to be fixed in the d2e repo. */
export function findPsqlMetaCommands(sql: string): string[] {
  const found: string[] = [];
  const add = (name: string) => {
    if (!found.includes(name)) found.push(name);
  };
  for (const raw of sql.split("\n")) {
    const line = raw.trimEnd();
    if (line.trimStart().startsWith("--")) continue;
    const leading = /^[ \t]*\\(\w+)/.exec(line);
    if (leading) add(`\\${leading[1]}`);
    // psql also accepts a meta-command appended to a statement: `... AS x \gset`.
    const trailing = /[ \t]\\(\w+)$/.exec(line);
    if (trailing) add(`\\${trailing[1]}`);
  }
  return found;
}

export interface AtlasDbInitDeps {
  readDir: (dir: string) => Promise<string[]>;
  readFile: (path: string) => Promise<string>;
  exec: (sql: string) => Promise<unknown>;
  tableExists: (t: TableRef) => Promise<boolean>;
  dir: string;
  log: (m: string) => void;
  err: (m: string) => void;
  wait?: WaitOptions;
  /** Which IdP the stack authenticates against; selects the tables to wait for. */
  idp?: string;
}

/** Returns the number of SQL files applied. Never throws — the caller runs
 *  off the boot path, where a failure must not take down the node. */
export async function applyAtlasDbInit(deps: AtlasDbInitDeps): Promise<number> {
  let names: string[];
  try {
    names = await deps.readDir(deps.dir);
  } catch {
    deps.log(`atlas-db-init skipped — ${deps.dir} not present`);
    return 0;
  }

  const files = names.filter((n) => n.endsWith(".sql")).sort();
  if (files.length === 0) {
    deps.log(`atlas-db-init skipped — no .sql files in ${deps.dir}`);
    return 0;
  }

  const required = requiredTablesFor(deps.idp);
  const ready = await waitForTables(deps.tableExists, required, deps.wait);
  if (!ready) {
    deps.err(
      `atlas-db-init skipped — ${required.map((t) => `${t.schema}.${t.table}`).join(" / ")}` + " not ready before timeout; will retry on next boot",
    );
    return 0;
  }

  let applied = 0;
  for (const name of files) {
    const path = `${deps.dir}/${name}`;
    try {
      const sql = await deps.readFile(path);
      const meta = findPsqlMetaCommands(sql);
      if (meta.length > 0) {
        deps.err(
          `atlas-db-init ${name} skipped: contains psql meta-command(s) ${
            meta.join(", ")
          } — not executable over the wire protocol`,
        );
        continue;
      }
      await deps.exec(sql);
      applied++;
    } catch (e) {
      deps.err(`atlas-db-init ${name} failed: ${(e as Error).message}`);
    }
  }
  deps.log(`atlas-db-init applied ${applied}/${files.length} file(s)`);
  return applied;
}
