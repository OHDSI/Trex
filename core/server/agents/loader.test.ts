import { assert, assertEquals, assertRejects } from "jsr:@std/assert";
import { loadAgent, packOfSkillName } from "./loader.ts";

const TOY = new URL("./testdata/toy-agent/agent", import.meta.url).pathname;

Deno.test("loadAgent loads instructions, config and tools from an eve-layout dir", async () => {
  const a = await loadAgent(TOY);
  assert(a.instructions.includes("toy demo agent"));
  assertEquals(a.config.model, "anthropic/claude-sonnet-5");
  assertEquals(Object.keys(a.tools), ["echo", "propose_card"]);
  assertEquals(a.tools.propose_card.clientOnly, true);
});

Deno.test("loadAgent parses skill metadata (frontmatter description)", async () => {
  const a = await loadAgent(TOY);
  assertEquals(a.skills.length, 1);
  assertEquals(a.skills[0].name, "greeting-style");
  assert(a.skills[0].description.includes("chipper"));
  assert(a.skills[0].path.endsWith("skills/greeting-style.md"));
});

Deno.test("loadAgent parses SKILL.md dir layout and first-line fallback description", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.mkdir(`${tmp}/skills/refunds`, { recursive: true });
  await Deno.writeTextFile(`${tmp}/skills/refunds/SKILL.md`, "# Refunds\nHandle refund requests step by step.\n");
  const a = await loadAgent(tmp);
  assertEquals(a.skills[0].name, "refunds");
  assertEquals(a.skills[0].description, "Handle refund requests step by step.");
});

Deno.test("loadAgent accepts EDN alternatives, with eve-native files winning", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.edn`, `{:instructions "from edn"}`);
  await Deno.writeTextFile(`${tmp}/agent.edn`, `{:model "bedrock/us.anthropic.claude-sonnet-4-6" :max-steps 7}`);
  await Deno.mkdir(`${tmp}/skills`);
  await Deno.writeTextFile(`${tmp}/skills/tips.edn`, `{:description "EDN tips" :content "Do the thing."}`);
  const a = await loadAgent(tmp);
  assertEquals(a.instructions, "from edn");
  assertEquals(a.config.model, "bedrock/us.anthropic.claude-sonnet-4-6");
  assertEquals(a.config.maxSteps, 7);
  assertEquals(a.skills[0].content, "Do the thing.");
  assertEquals(a.skills[0].description, "EDN tips");
  // eve-native files win over their EDN twins
  await Deno.writeTextFile(`${tmp}/instructions.md`, "from md");
  await Deno.writeTextFile(`${tmp}/skills/tips.md`, "MD tips.\n");
  const b = await loadAgent(tmp);
  assertEquals(b.instructions, "from md");
  assertEquals(b.skills.length, 1);
  assertEquals(b.skills[0].description, "MD tips.");
});

Deno.test("SKILL.md dir form wins over an EDN skill twin", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.mkdir(`${tmp}/skills/foo`, { recursive: true });
  await Deno.writeTextFile(`${tmp}/skills/foo/SKILL.md`, "From SKILL.md dir form.\n");
  await Deno.writeTextFile(`${tmp}/skills/foo.edn`, `{:description "from edn" :content "edn body"}`);
  const a = await loadAgent(tmp);
  assertEquals(a.skills.length, 1);
  assertEquals(a.skills[0].name, "foo");
  assertEquals(a.skills[0].description, "From SKILL.md dir form.");
  assert(a.skills[0].path.endsWith("skills/foo/SKILL.md"));
});

Deno.test("loadAgent loads subagents one level deep", async () => {
  const a = await loadAgent(TOY);
  assertEquals(Object.keys(a.subagents), ["shouter"]);
  assertEquals(Object.keys(a.subagents.shouter.tools), ["shout"]);
  assert(a.subagents.shouter.instructions.includes("shouter subagent"));
  // depth guard: a subagent's own subagents/ dir is ignored
  assertEquals(Object.keys(a.subagents.shouter.subagents).length, 0);
});

Deno.test("loadAgent surfaces malformed skill EDN as an error", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.mkdir(`${tmp}/skills`);
  await Deno.writeTextFile(`${tmp}/skills/bad.edn`, `{:description "x" :content`);
  await assertRejects(() => loadAgent(tmp), Error, "bad.edn");
});

Deno.test("nested subagents beyond one level are ignored with a log", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.mkdir(`${tmp}/subagents/inner/subagents/deep`, { recursive: true });
  await Deno.writeTextFile(`${tmp}/subagents/inner/instructions.md`, "inner agent");
  await Deno.writeTextFile(`${tmp}/subagents/inner/subagents/deep/instructions.md`, "too deep");
  const a = await loadAgent(tmp);
  assertEquals(Object.keys(a.subagents), ["inner"]);
  assertEquals(Object.keys(a.subagents.inner.subagents).length, 0);
});

Deno.test("loadAgent fails without instructions.md", async () => {
  const tmp = await Deno.makeTempDir();
  await assertRejects(() => loadAgent(tmp), Error, "instructions.md");
});

Deno.test("loadAgent tolerates missing agent.ts, tools, skills and subagents dirs", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  const a = await loadAgent(tmp);
  assertEquals(a.config.maxSteps, 25);
  assertEquals(Object.keys(a.tools).length, 0);
  assertEquals(a.skills.length, 0);
  assertEquals(Object.keys(a.subagents).length, 0);
});

// H2: agent-dir-root dynamic-tools.ts|js discovery (task-h2-brief.md).
// The provider function is written directly as branded (Object.assign(...,
// { __trexToolProvider: true })) rather than imported from eve-shim/tools.ts,
// so these fixtures don't need a resolvable import path from inside a temp
// dir — matches how the loader itself only checks the brand, never the
// factory's identity.

Deno.test("loadAgent discovers a root-level dynamic-tools.ts and exposes it as toolProvider", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.writeTextFile(
    `${tmp}/dynamic-tools.ts`,
    `export default Object.assign(
      (ctx) => Promise.resolve({ greet: { description: "hi " + ctx.sessionId, inputSchema: { type: "object" } } }),
      { __trexToolProvider: true },
    );`,
  );
  const a = await loadAgent(tmp);
  assert(a.toolProvider, "expected loadAgent to expose the root dynamic-tools.ts as toolProvider");
  const out = await a.toolProvider!({ sessionId: "s-1", env: () => undefined, sql: () => Promise.resolve({ rows: [] }) });
  assertEquals(out.greet.description, "hi s-1");
});

Deno.test("loadAgent discovers dynamic-tools.js the same as dynamic-tools.ts", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.writeTextFile(
    `${tmp}/dynamic-tools.js`,
    `export default Object.assign(() => Promise.resolve({}), { __trexToolProvider: true });`,
  );
  const a = await loadAgent(tmp);
  assert(a.toolProvider);
});

Deno.test("loadAgent tolerates a directory with no dynamic-tools.ts|js (toolProvider stays undefined)", async () => {
  const a = await loadAgent(TOY);
  assertEquals(a.toolProvider, undefined);
});

Deno.test("loadAgent rejects a root dynamic-tools.ts that doesn't default-export defineToolProvider(...)", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.writeTextFile(`${tmp}/dynamic-tools.ts`, `export default () => Promise.resolve({});`); // unbranded
  await assertRejects(() => loadAgent(tmp), Error, "defineToolProvider");
});

Deno.test("loadAgent never discovers a dynamic-tools.ts placed INSIDE tools/ as a provider — it hits the ordinary tools/ brand error instead", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.mkdir(`${tmp}/tools`);
  // Correctly branded as a tool PROVIDER, not a tool — tools/ only accepts
  // __trexTool-branded defineTool() results, so this must fail the same way
  // any other non-defineTool default export in tools/ does, not silently
  // get picked up as the agent's dynamic-tools.ts.
  await Deno.writeTextFile(
    `${tmp}/tools/dynamic-tools.ts`,
    `export default Object.assign(() => Promise.resolve({}), { __trexToolProvider: true });`,
  );
  await assertRejects(() => loadAgent(tmp), Error, "must default-export defineTool");
});

Deno.test("loadAgent ignores eve dirs we don't support, without failing", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.mkdir(`${tmp}/connections`);
  await Deno.mkdir(`${tmp}/sandbox`);
  const a = await loadAgent(tmp); // must not throw
  assertEquals(a.instructions, "hi");
});

Deno.test("loadAgent discovers channels/*.{ts,js} as branded ChannelDefs keyed by filename", async () => {
  const a = await loadAgent(TOY);
  // Name order, not Deno.readDir order — the loader sorts every directory
  // scan (see readDirSorted). The toy agent ships `webhook` plus the authored
  // `custom-hook` channel (Task 7).
  assertEquals(Object.keys(a.channels), ["custom-hook", "webhook"]);
  assert(a.channels.webhook.__trexChannel);
  assertEquals(a.channels.webhook.routes[0].method, "POST");
  assertEquals(a.channels.webhook.routes[0].path, "/message");
});

Deno.test("loadAgent no longer treats channels/ as an ignored eve dir", async () => {
  const logs: string[] = [];
  const orig = console.log;
  console.log = (...args: unknown[]) => logs.push(args.join(" "));
  try {
    await loadAgent(TOY);
  } finally {
    console.log = orig;
  }
  assert(
    !logs.some((l) => l.includes("channels") && l.includes("not supported")),
    `channels should not be logged as ignored; got: ${JSON.stringify(logs)}`,
  );
});

Deno.test("loadAgent rejects a channels/*.ts that doesn't default-export defineChannel(...)", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.mkdir(`${tmp}/channels`);
  await Deno.writeTextFile(`${tmp}/channels/bad.ts`, `export default { routes: [] };`); // unbranded
  await assertRejects(() => loadAgent(tmp), Error, "must default-export defineChannel");
});

// Regression coverage for the review fix to Task 6: a colocated *.test.ts
// file sitting next to a real tool/channel module (the established
// convention in this repo, e.g. plugins/claw/agent/tools/dispatchToCode.ts +
// dispatchToCode.test.ts) must be skipped by the tools/ and channels/ scans,
// not treated as a tool/channel module.

Deno.test("loadAgent skips a colocated tools/*.test.ts file instead of loading it as a tool", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.mkdir(`${tmp}/tools`);
  await Deno.writeTextFile(
    `${tmp}/tools/greet.ts`,
    `export default Object.assign(
      { description: "greet", inputSchema: { type: "object" }, execute: () => Promise.resolve({ ok: true }) },
      { __trexTool: true },
    );`,
  );
  // A colocated test file with no branded default export — if the loader
  // didn't skip it, this would throw "must default-export defineTool(...)".
  await Deno.writeTextFile(
    `${tmp}/tools/greet.test.ts`,
    `Deno.test("greet works", () => {});`,
  );
  const a = await loadAgent(tmp);
  assertEquals(Object.keys(a.tools), ["greet"]);
});

Deno.test("loadAgent skips a colocated channels/*.test.ts file instead of loading it as a channel", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.mkdir(`${tmp}/channels`);
  await Deno.writeTextFile(
    `${tmp}/channels/discord.ts`,
    `export default Object.assign({ routes: [] }, { __trexChannel: true });`,
  );
  // A colocated test file with no branded default export — if the loader
  // didn't skip it, this would throw "must default-export defineChannel(...)".
  await Deno.writeTextFile(
    `${tmp}/channels/discord.load.test.ts`,
    `Deno.test("discord loads", () => {});`,
  );
  const a = await loadAgent(tmp);
  assertEquals(Object.keys(a.channels), ["discord"]);
});

Deno.test("loadAgent discovers connections/*.{ts,js} as branded ConnectionDefs keyed by filename", async () => {
  const a = await loadAgent(TOY);
  assertEquals(Object.keys(a.connections), ["echo"]);
  assert(a.connections.echo.__trexConnection);
  assertEquals(a.connections.echo.type, "mcp");
  assertEquals(a.connections.echo.url, "http://localhost:9/mcp");
  // the loader sets `name` from the filename (the shim reserves the field)
  assertEquals(a.connections.echo.name, "echo");
});

Deno.test("loadAgent no longer treats connections/ as an ignored eve dir", async () => {
  const logs: string[] = [];
  const orig = console.log;
  console.log = (...args: unknown[]) => logs.push(args.join(" "));
  try {
    await loadAgent(TOY);
  } finally {
    console.log = orig;
  }
  assert(
    !logs.some((l) => l.includes("connections") && l.includes("not supported")),
    `connections should not be logged as ignored; got: ${JSON.stringify(logs)}`,
  );
});

Deno.test("loadAgent rejects a connections/*.ts that doesn't default-export a connection def", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.mkdir(`${tmp}/connections`);
  await Deno.writeTextFile(`${tmp}/connections/bad.ts`, `export default { description: "x" };`); // unbranded
  await assertRejects(
    () => loadAgent(tmp),
    Error,
    "must default-export defineMcpClientConnection",
  );
});


Deno.test("packOfSkillName derives pack provenance from the reserved '--' separator", () => {
  assertEquals(packOfSkillName("mypack--greeting"), "mypack");
  assertEquals(packOfSkillName("hand-authored"), null);   // single dashes are fine
  assertEquals(packOfSkillName("plain"), null);
  assertEquals(packOfSkillName("--weird"), null);          // no empty pack name
});

// --- role config survives loading (regression) -------------------------------
//
// resolveAgentRole is unit-tested in lib/subagent_role.test.ts and has always
// been correct. What was never tested is whether its output SURVIVES into
// LoadedAgent.config — and it did not. loadAgent assigned config.skills from
// the resolved role and then, two lines later, looped over ROLE_EDN_KEYS
// deleting each key from config to strip stray EDN spellings. ROLE_EDN_KEYS
// maps "skills" to "skills", so that loop deleted the field it had just set.
// Every agent.ts-authored agent loaded with config.skills === undefined, and a
// TS-authored subagent declaring a narrowing skills list received no narrowing
// at all.
//
// Nothing above covers this: every existing skills assertion is about
// LoadedAgent.skills — the on-disk skill FILES — which is a different field
// populated by a different code path.
Deno.test("a TS-authored agent's narrowing skills list survives into config (not stripped by the EDN key cleanup)", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.writeTextFile(
    `${tmp}/agent.ts`,
    'export default { model: "anthropic/claude-sonnet-5", skills: ["greeting-style"], reasoningEffort: "low" };\n',
  );
  const a = await loadAgent(tmp);
  assertEquals(a.config.skills, ["greeting-style"], "config.skills must survive loadAgent");
  assertEquals(a.config.reasoningEffort, "low");
  assertEquals(a.config.model, "anthropic/claude-sonnet-5");
});

Deno.test("the EDN-spelled role keys are still stripped from a TS-authored config", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  // The kebab spelling is normalized onto the real camelCase field; leaving
  // the kebab key on config too would be garbage, so it must not survive.
  await Deno.writeTextFile(`${tmp}/agent.ts`, 'export default { "reasoning-effort": "high" };\n');
  const a = await loadAgent(tmp);
  assertEquals(a.config.reasoningEffort, "high");
  // Object.hasOwn rather than an `in` over a cast: ResolvedAgentConfig has no
  // index signature, and asserting absence needs no cast at all.
  assertEquals(Object.hasOwn(a.config, "reasoning-effort"), false);
});

// The config.skills defect (above) was exactly this shape: assigned, then
// deleted two lines later by the ROLE_EDN_KEYS cleanup loop. escalate is a
// plain string field with no EDN spelling, so it must never be added to that
// map — this proves it survives a real loadAgent.
Deno.test("loadAgent preserves config.escalate", async () => {
  const tmp = await Deno.makeTempDir();
  await Deno.writeTextFile(`${tmp}/instructions.md`, "hi");
  await Deno.writeTextFile(`${tmp}/agent.ts`, 'export default { escalate: "!GitPush" };\n');
  const a = await loadAgent(tmp);
  assertEquals(a.config.escalate, "!GitPush");
});

// The loaded agent's shape must not depend on the order the filesystem
// enumerates a directory in. Deno.readDir is unordered by contract, and in
// practice ext4 (CI) hands back htree-hash order while APFS (dev machines)
// hands back something else again — which is how toolset.test.ts's
// `["echo", "propose_card", ...]` assertions could pass on one host and fail
// on another with nothing between them but the checkout. Sorting is what
// makes the tool list — the prefix of every model request, and the thing
// withToolCachePoint hangs its cache breakpoint off the end of — the same
// everywhere. Stubbing Deno.readDir is the only way to exercise this: on any
// single host the real enumeration order is a constant.
Deno.test("loadAgent orders tools/channels/connections/subagents by name, whatever order readDir yields", async () => {
  const orig = Deno.readDir;
  // deno-lint-ignore no-explicit-any
  (Deno as any).readDir = (path: string | URL) => {
    const inner = orig(path);
    return (async function* () {
      const all: Deno.DirEntry[] = [];
      for await (const e of inner) all.push(e);
      // Reverse-sorted: the worst case for a loader that just takes what it
      // is given, and independent of what this host's filesystem does.
      all.sort((x, y) => (x.name < y.name ? 1 : x.name > y.name ? -1 : 0));
      yield* all;
    })();
  };
  try {
    const a = await loadAgent(TOY);
    assertEquals(Object.keys(a.tools), ["echo", "propose_card"]);
    assertEquals(Object.keys(a.channels), ["custom-hook", "webhook"]);
    assertEquals(Object.keys(a.connections), ["echo"]);
    assertEquals(Object.keys(a.subagents), ["shouter"]);
    assertEquals(a.skills.map((s) => s.name), ["greeting-style"]);
  } finally {
    // deno-lint-ignore no-explicit-any
    (Deno as any).readDir = orig;
  }
});
