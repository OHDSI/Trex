// A plugin agent is not run from the repo. addAgentsPlugin STAGES it into
// /tmp/trex-agents-<hash>/, where the agent dir lands at <stage>/agent/ and the
// slice of core it may use lands at <stage>/agents/ — a different shape from
// the repo, where the same files sit at plugins/<p>/agent/ and
// core/server/agents/.
//
// So a RUNTIME import written as "../../../core/server/agents/..." resolves in
// the repo and silently breaks once staged: from <stage>/agent/ it climbs past
// /tmp to the filesystem root and asks for /core/server/agents/..., which does
// not exist. The worker then dies at module evaluation with
// "Module not found: file:///core/server/agents/...", the agent never boots,
// and every call to it fails — the devx coding agent was dead this way for two
// weeks while the loader tests, which load from the REPO dir, stayed green.
//
// Type-only imports are exempt: they are erased before the module is evaluated,
// so they never hit the loader. Everything a staged agent imports at runtime
// must go through an "eve/..." specifier from the generated import map (see
// agents.ts), which points inside the stage.
import { assertEquals } from "jsr:@std/assert";
import { walk } from "jsr:@std/fs/walk";
import { fromFileUrl } from "jsr:@std/path";

const REPO = fromFileUrl(new URL("../../../", import.meta.url));

/** `import ... from "<spec>"` / `export ... from "<spec>"`, capturing the statement head. */
const IMPORT_RE = /(^|\n)\s*(import|export)(\s+type)?\b([\s\S]*?)from\s*["']([^"']+)["']/g;

function offendingImports(source: string): string[] {
  const bad: string[] = [];
  for (const m of source.matchAll(IMPORT_RE)) {
    const isTypeKeyword = Boolean(m[3]);
    const clause = m[4];
    const spec = m[5];
    if (!/(\.\.\/)+core\/server\//.test(spec)) continue;
    // `import type {...}` and a clause whose every binding is `type X` are
    // erased at runtime and cannot reach the module loader.
    if (isTypeKeyword) continue;
    const bindings = clause.replace(/[{}]/g, "").split(",").map((s) => s.trim()).filter(Boolean);
    if (bindings.length > 0 && bindings.every((b) => b.startsWith("type "))) continue;
    bad.push(spec);
  }
  return bad;
}

Deno.test("no plugin agent imports core through a relative path at runtime", async () => {
  const found: string[] = [];
  for await (
    const entry of walk(`${REPO}plugins`, {
      exts: [".ts"],
      includeDirs: false,
      skip: [/node_modules/, /\/functions\//, /\.test\.ts$/],
    })
  ) {
    if (!/\/agent\//.test(entry.path)) continue;
    for (const spec of offendingImports(await Deno.readTextFile(entry.path))) {
      found.push(`${entry.path.slice(REPO.length)} -> ${spec}`);
    }
  }
  assertEquals(
    found,
    [],
    "these resolve in the repo but not in the staged layout; import them through an " +
      `"eve/..." specifier instead:\n  ${found.join("\n  ")}`,
  );
});

// Guards the exemption above: a type-only import must stay allowed, or the
// rule becomes unfollowable (types have no "eve/..." equivalent).
Deno.test("the rule exempts type-only imports and catches value imports", () => {
  assertEquals(offendingImports(`import type { X } from "../../../core/server/agents/eve-shim/types.ts";`), []);
  assertEquals(offendingImports(`import { type X, type Y } from "../../../core/server/agents/eve-shim/types.ts";`), []);
  assertEquals(
    offendingImports(`import { capHookOutput } from "../../../core/server/agents/service/context/hook-output.ts";`),
    ["../../../core/server/agents/service/context/hook-output.ts"],
  );
  assertEquals(
    offendingImports(`import {\n  realizeMcp,\n  type McpConnectFn,\n} from "../../../core/server/agents/connections/mcp.ts";`),
    ["../../../core/server/agents/connections/mcp.ts"],
  );
  assertEquals(offendingImports(`import { defineTool } from "eve/tools";`), []);
});
