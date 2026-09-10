import { assert, assertEquals } from "jsr:@std/assert";
import { findPsqlMetaCommands, waitForTables, type TableRef } from "./atlas-db-init.ts";

const TABLES: TableRef[] = [
  { schema: "webapi", table: "sec_role" },
  { schema: "logto", table: "users" },
];
const noSleep = () => Promise.resolve();

Deno.test("returns true immediately when all tables are present", async () => {
  let calls = 0;
  const ok = await waitForTables(() => {
    calls++;
    return Promise.resolve(true);
  }, TABLES, { attempts: 5, sleep: noSleep });
  assertEquals(ok, true);
  assertEquals(calls, 2); // one probe per table, single pass
});

Deno.test("retries until the missing table appears", async () => {
  let passes = 0;
  const ok = await waitForTables((t) => {
    if (t.table === "sec_role") return Promise.resolve(true);
    passes++;
    return Promise.resolve(passes >= 3);
  }, TABLES, { attempts: 10, sleep: noSleep });
  assertEquals(ok, true);
  assertEquals(passes, 3);
});

Deno.test("gives up after the attempt budget and returns false", async () => {
  let probes = 0;
  const ok = await waitForTables(() => {
    probes++;
    return Promise.resolve(false);
  }, TABLES, { attempts: 4, sleep: noSleep });
  assertEquals(ok, false);
  assertEquals(probes, 4); // stops probing a pass as soon as one table is missing
});

Deno.test("a probe error counts as not-ready rather than throwing", async () => {
  const ok = await waitForTables(() => Promise.reject(new Error("no connection")), TABLES, {
    attempts: 2,
    sleep: noSleep,
  });
  assertEquals(ok, false);
});

import { applyAtlasDbInit, REQUIRED_TABLES, requiredTablesFor } from "./atlas-db-init.ts";

function deps(over: Record<string, unknown> = {}) {
  const applied: string[] = [];
  const logs: string[] = [];
  return {
    applied,
    logs,
    d: {
      readDir: () => Promise.resolve(["200_admin.sql", "100_source.sql", "notes.md"]),
      readFile: (p: string) => Promise.resolve(`-- ${p}`),
      exec: (sql: string) => {
        applied.push(sql);
        return Promise.resolve(null);
      },
      tableExists: () => Promise.resolve(true),
      dir: "/usr/src/atlas-db-init",
      log: (m: string) => logs.push(m),
      err: (m: string) => logs.push(`ERR ${m}`),
      wait: { attempts: 2, sleep: () => Promise.resolve() },
      ...over,
    },
  };
}

Deno.test("applies only .sql files, in filename order", async () => {
  const { applied, d } = deps();
  const count = await applyAtlasDbInit(d as never);
  assertEquals(count, 2);
  assertEquals(applied[0], "-- /usr/src/atlas-db-init/100_source.sql");
  assertEquals(applied[1], "-- /usr/src/atlas-db-init/200_admin.sql");
});

Deno.test("applies nothing and logs when readiness times out", async () => {
  const { applied, logs, d } = deps({ tableExists: () => Promise.resolve(false) });
  const count = await applyAtlasDbInit(d as never);
  assertEquals(count, 0);
  // Nothing may reach the database when readiness times out — the next boot retries.
  assertEquals(applied.length, 0);
  assertEquals(logs.some((m) => m.startsWith("ERR")), true);
});

Deno.test("skips a file with psql meta-commands and says which ones", async () => {
  const { applied, logs, d } = deps({
    readDir: () => Promise.resolve(["220_external_role_map.sql", "100_source.sql"]),
    readFile: (p: string) =>
      Promise.resolve(
        p.endsWith("220_external_role_map.sql")
          ? "SELECT EXISTS (SELECT 1) AS have_role_map \\gset\n\n\\if :have_role_map\nSELECT 2;\n\\endif\n"
          : "SELECT 1;",
      ),
  });
  const count = await applyAtlasDbInit(d as never);
  assertEquals(count, 1);
  assertEquals(applied, ["SELECT 1;"]);
  const skip = logs.find((m) => m.includes("220_external_role_map.sql"));
  assertEquals(
    skip,
    "ERR atlas-db-init 220_external_role_map.sql skipped: contains psql meta-command(s) \\gset, \\if, \\endif — not executable over the wire protocol",
  );
});

Deno.test("findPsqlMetaCommands ignores backslashes inside statements and comments", () => {
  assertEquals(findPsqlMetaCommands("SELECT 'a\\gset b';\nSELECT 1;"), []);
  assertEquals(findPsqlMetaCommands("-- run this with \\gset\nSELECT 1;"), []);
  assertEquals(findPsqlMetaCommands("  \\gset\n"), ["\\gset"]);
});

Deno.test("applies nothing when the directory is absent", async () => {
  const { applied, d } = deps({ readDir: () => Promise.reject(new Error("ENOENT")) });
  const count = await applyAtlasDbInit(d as never);
  assertEquals(count, 0);
  assertEquals(applied.length, 0);
});

Deno.test("trex does not wait for logto.users before seeding", () => {
  // sec_external_role_map is what turns a token's `admin` claim into WebAPI's
  // admin role. Waiting on a table a trex stack need never populate delays that
  // seeding, and the first caller then gets 403 from a correctly configured
  // stack -- observed on a fresh database, with setup running minutes before the
  // map existed.
  assertEquals(requiredTablesFor("trex"), [{ schema: "webapi", table: "sec_role" }]);
});

Deno.test("logto keeps the full wait, unchanged", () => {
  for (const idp of ["logto", "", undefined, "LOGTO"]) {
    assertEquals(requiredTablesFor(idp), REQUIRED_TABLES, `idp=${idp}`);
  }
});

// ---------------------------------------------------------------------------
// Boot order (see the contract at the top of boot.ts)
// ---------------------------------------------------------------------------
// The seeding waits for webapi.sec_role, a table WebAPI's own Flyway creates.
// While the call lived in d2eBoot() that wait ran BEFORE index.ts started
// WebAPI, so on a fresh database it could never be satisfied: it blocked the
// event loop that had yet to launch the process that creates the table, gave up
// after ~120s, and the stack came up with no admin permissions and no OIDC
// external role map. WebAPI then answered "Access Denied" to
// SourceService.createSource, d2e's dataset sync aborted before it triggered the
// TrexSQL cache build, and the demo setup polled "Cache not ready" until it
// timed out. Asserted on the source because the failure is purely one of order.
const bootSrc = await Deno.readTextFile(new URL("./boot.ts", import.meta.url));
const serverSrc = await Deno.readTextFile(new URL("../index.ts", import.meta.url));

Deno.test("d2eBoot does not apply atlas-db-init — it runs before WebAPI exists", () => {
  const bootAt = bootSrc.indexOf("export async function d2eBoot");
  const blockNineAt = bootSrc.indexOf("// \u2500\u2500 Block 9: atlas-db-init");
  assert(bootAt !== -1 && blockNineAt > bootAt, "d2eBoot must end before Block 9 begins");
  assert(
    bootSrc.includes("export async function d2eAtlasDbInit"),
    "Block 9 must live in its own exported function",
  );
  const d2eBootBody = bootSrc.slice(bootAt, blockNineAt);
  assert(
    !d2eBootBody.includes("applyAtlasDbInit"),
    "atlas-db-init must not run from d2eBoot(); index.ts calls it after startNativeWebApi()",
  );
});

Deno.test("index.ts seeds only after startNativeWebApi()", () => {
  const startedAt = serverSrc.indexOf("startNativeWebApi()");
  const seededAt = serverSrc.indexOf("runD2eAtlasDbInit()");
  assert(startedAt !== -1, "index.ts must start the native WebAPI");
  assert(seededAt !== -1, "index.ts must run atlas-db-init");
  assert(seededAt > startedAt, "atlas-db-init must be chained after startNativeWebApi()");
  // ...and never back on the pre-listen boot path, where the same inversion returns.
  assert(
    serverSrc.indexOf("await runD2eBoot();") < startedAt,
    "runD2eBoot() stays ahead of WebAPI; only the seeding moved",
  );
});
