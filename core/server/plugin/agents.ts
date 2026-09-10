// The `agents` plugin type (spec 006): each declared agent runs as an
// edge-runtime worker whose servicePath is the core-shipped runtime service
// (core/server/agents/service). Routing/auth/SSE piping reuse the function
// plugin proxy (_addFunction).
import type { Express } from "express";
import { _addFunction, isTrustedPluginScope, substituteEnvVarsInObject, TRUSTED_PLUGIN_SCOPES } from "./function.ts";
import type { LiveWorkerConfig } from "./function.ts";
import { PLUGINS_BASE_PATH } from "../config.ts";
import { type AgentMemoryLink, generateMemoryArtifacts, parseMemoryLinks } from "./agent-memory.ts";
import { memoryWorkerBasePath } from "../memory/gbrain-worker/mount.ts";
import { createGatewaySigner, DiscordGatewayClient, gatewayModeEnabled } from "../agents/gateway/discord.ts";
import { createSlackGatewaySigner, SlackGatewayClient } from "../agents/gateway/slack.ts";
import { copyDirRecursive } from "./utils.ts";
import { collectSiblingImportDirs, SIBLING_STAGING_EXCLUDES } from "./agent-sibling-imports.ts";
import { packsForAgent, stageSkillPacks, type SkillPackEntry } from "./skill-packs.ts";
import { STALE_TURN_MS } from "../agents/service/turn-lifetime.ts";

// How long an agent worker may live. Imported from STALE_TURN_MS rather than
// restated, so raising one without the other is impossible: a worker outliving
// the stale-turn threshold would only keep alive a turn the sweep has already
// reaped, and a worker dying before it reintroduces the silent-drop this value
// exists to prevent. See the call site in addAgentsPlugin.
export const AGENT_WORKER_TIMEOUT_MS = STALE_TURN_MS;

export interface AgentEntry {
  name: string;
  dir: string;
  env?: Record<string, string>;
  memory?: AgentMemoryLink[];
}

export function normalizeAgentsValue(value: unknown): AgentEntry[] {
  const arr = Array.isArray(value) ? value : [value];
  return arr.map((e) => {
    const entry = e as { name?: string; dir?: string; env?: unknown; memory?: unknown };
    if (!entry?.name || !/^[a-z0-9][a-z0-9_-]*$/i.test(entry.name)) {
      throw new Error(`agents: each entry needs a name ([a-zA-Z0-9_-]), got ${JSON.stringify(e)}`);
    }
    const result: AgentEntry = { name: entry.name, dir: entry.dir ?? "agent" };
    if (entry.env && typeof entry.env === "object" && !Array.isArray(entry.env)) {
      result.env = entry.env as Record<string, string>;
    }
    if (entry.memory !== undefined) {
      result.memory = parseMemoryLinks(entry.memory);
    }
    return result;
  });
}

// Env vars forwarded from the host into agent workers when set.
const PASSTHROUGH_ENV = [
  "DATABASE_URL", "TREX_AGENTS_DEFAULT_MODEL",
  "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL",
  "GOOGLE_GENERATIVE_AI_API_KEY", "AWS_BEARER_TOKEN_BEDROCK", "AWS_REGION",
  // OAuth broker (task-7): the worker needs the root key to unwrap the DEK
  // (token encryption-at-rest) and derive the signed-state HMAC secret. Absent
  // → the broker stays unwired and oauth connections are skipped (see
  // service/index.ts) — every non-oauth agent still boots.
  "TREX_ROOT_KEY",
];

// Resolve the on-disk agents runtime dir (core/server/agents). import.meta.url
// is NOT a reliable disk path here: in the packaged image the main service
// executes from a build-time compile graph whose file URLs
// (file:///var/tmp/sb-compile-…) don't exist at runtime. Try meta-relative
// first (source checkouts, tests), then cwd-relative (packaged image — same
// convention as index.ts's shinylive path).
export async function resolveAgentsRuntimeDir(): Promise<string> {
  const candidates = [
    new URL("../agents/", import.meta.url).pathname,
    `${Deno.cwd()}/core/server/agents/`,
  ];
  for (const c of candidates) {
    try {
      await Deno.stat(`${c}service/index.ts`);
      return c;
    } catch { /* try next candidate */ }
  }
  throw new Error(
    `agents: cannot locate the agents runtime dir (tried ${candidates.join(", ")})`,
  );
}

// Authoring-time-only top-level entries under an agent dir that must never
// be staged into a worker's servicePath: an eval suite (e.g.
// plugins/devx/agent/evals/) is eve's own local dev/test harness — its own
// node_modules (@ai-sdk/amazon-bedrock, eve, etc., ~100MB) and .eve run
// artifacts have no runtime purpose and would otherwise be copied into every
// staged worker on every registration.
const AGENT_DIR_STAGING_EXCLUDES = new Set(["evals"]);

export async function buildAgentWorkerConfig(
  pluginDir: string,
  entry: AgentEntry,
  pluginFullName: string,
  skillPacks: SkillPackEntry[] = packsForAgent(entry.name),
): Promise<{ source: string; servicePath: string; importMapPath: string; env: Record<string, string> }> {
  const agentDir = `${pluginDir}/${entry.dir}`;
  // Fail registration early with a clear message rather than at first request.
  // Presence-only check: the loader (agents/loader.ts) accepts instructions.md
  // OR instructions.edn and owns full parsing/precedence at worker start.
  // NotFound falls through to the next check/the "missing" error below;
  // anything else (permissions, I/O) is a real failure and must surface
  // with its own cause rather than being swallowed into a misleading
  // "missing" message — matches loader.ts's readEdn/instructions.md handling.
  try {
    await Deno.stat(`${agentDir}/instructions.md`);
  } catch (e) {
    if (!(e instanceof Deno.errors.NotFound)) {
      throw new Error(`agents: failed to stat ${agentDir}/instructions.md: ${e instanceof Error ? e.message : e} (plugin ${pluginFullName})`);
    }
    try {
      await Deno.stat(`${agentDir}/instructions.edn`);
    } catch (e2) {
      if (!(e2 instanceof Deno.errors.NotFound)) {
        throw new Error(`agents: failed to stat ${agentDir}/instructions.edn: ${e2 instanceof Error ? e2.message : e2} (plugin ${pluginFullName})`);
      }
      throw new Error(`agents: ${agentDir}/instructions.md (or instructions.edn) is required but missing (plugin ${pluginFullName})`);
    }
  }

  // The worker's module loader only resolves file: specifiers under its own
  // servicePath (plus npm:/jsr:/remote specifiers) — out-of-tree file://
  // imports fail in the packaged image, statically at graph creation and
  // dynamically at module evaluation, regardless of fs permissions
  // (allowHostFsAccess governs runtime I/O like Deno.readTextFile, not
  // module resolution). So stage everything the worker imports inside the
  // servicePath: the core agents runtime (self-contained — relative imports
  // and bare specifiers only) and the agent's own dir (loader.ts
  // dynamic-imports agent.ts/tools/hooks from TREX_AGENT_DIR). Boot-time
  // snapshot semantics are unchanged: the pool reuses the first worker per
  // servicePath anyway, so live edits to a dev-mounted plugin already
  // required re-registration to take effect.
  const tmp = await Deno.makeTempDir({ prefix: "trex-agents-" });
  const runtimeSrc = await resolveAgentsRuntimeDir();
  // channels/connections must ride along: adapters resolve relative modules
  // (channels/types.ts etc.) inside the servicePath — first live claw boot
  // failed module resolution without them.
  for (const sub of ["service", "eve-shim", "channels", "connections"]) {
    await copyDirRecursive(`${runtimeSrc}${sub}`, `${tmp}/agents/${sub}`);
  }
  await Deno.copyFile(`${runtimeSrc}loader.ts`, `${tmp}/agents/loader.ts`);
  // service/index.ts imports ../../auth/{dek,keys}.ts — stage them at the
  // same relative depth.
  await Deno.mkdir(`${tmp}/auth`, { recursive: true });
  for (const f of ["dek.ts", "keys.ts"]) {
    await Deno.copyFile(`${runtimeSrc}../auth/${f}`, `${tmp}/auth/${f}`);
  }
  const stagedAgentDir = `${tmp}/agent`;
  await copyDirRecursive(agentDir, stagedAgentDir, AGENT_DIR_STAGING_EXCLUDES);

  // An agent may import ACROSS its own directory boundary into a sibling of
  // the plugin — devx's agent/agent.ts opens with ten `../functions/**`
  // imports. Those resolve to `${tmp}/functions/**` once staged, which nothing
  // put there, so the worker died at module evaluation with "Module not found:
  // file://.../functions/skills/resolver.ts" and every request to that agent
  // 500'd. Survivable while devx ran the legacy loop; fatal once the eve
  // runtime became the only path for it.
  //
  // Read from the agent's own imports rather than hardcoding `functions`, so
  // an agent that grows a new sibling does not reintroduce the same failure.
  // Staged at the same relative depth the source uses, which is what makes the
  // unchanged `../functions/...` specifiers resolve inside the servicePath.
  const siblingDirs = await collectSiblingImportDirs(agentDir, pluginDir);
  for (const sibling of siblingDirs) {
    await copyDirRecursive(`${pluginDir}/${sibling}`, `${tmp}/${sibling}`, SIBLING_STAGING_EXCLUDES);
  }

  // Linked-memory tools/skills (agent-linked-memory design, Task 3):
  // generated straight into the staged copy, never the plugin's own agent
  // dir on disk — same "everything the worker imports lives inside
  // servicePath" rule as the rest of this function. Validation that each
  // link names a DECLARED `trex.memory` plugin happens one level up, in
  // addAgentsPlugin, before this function is ever called for that entry.
  if (entry.memory?.length) {
    await generateMemoryArtifacts(stagedAgentDir, entry.memory);
  }

  // Skill packs (skills plugin type): every declared `trex.skills` pack
  // targeting this agent (exact name or "*") is staged into the agent's
  // staged dir — same servicePath-confinement rule as the linked-memory
  // artifacts above. The default comes from the global pack registry
  // (pre-pass-populated, so plugin scan order doesn't matter — see
  // skill-packs.ts); tests and explicit re-stage flows can inject.
  if (skillPacks.length) {
    await stageSkillPacks(stagedAgentDir, skillPacks);
  }

  const shimBase = `file://${tmp}/agents/eve-shim/`;
  const channelsBase = `file://${tmp}/agents/channels/`;
  const imports: Record<string, string> = {
    "eve": `${shimBase}mod.ts`,
    // Everything else core exposes to a staged agent, under its REAL layout.
    // A plugin agent cannot reach core by relative path: in the repo core sits
    // at core/server/agents/, but here it is <stage>/agents/, so
    // "../../../core/server/agents/x.ts" climbs past /tmp to the filesystem
    // root and the worker dies at module evaluation with
    // "Module not found: file:///core/server/agents/x.ts". A prefix mapping
    // rather than one entry per module: the set a plugin agent legitimately
    // needs keeps growing (six of these appeared in one file), and every
    // addition that has to be remembered here is another way to ship a broken
    // agent that still passes the repo-layout loader tests.
    "eve/core/": `file://${tmp}/agents/`,
    "eve/tools": `${shimBase}tools.ts`,
    "eve/evals": `${shimBase}evals.ts`,
    "eve/connections": `file://${tmp}/agents/connections/shim.ts`,
    "eve/channels": `${channelsBase}shim.ts`,
    "eve/channels/eve": `${channelsBase}adapters/eve.ts`,
    "eve/channels/discord": `${channelsBase}adapters/discord.ts`,
    "eve/channels/slack": `${channelsBase}adapters/slack.ts`,
    "eve/channels/telegram": `${channelsBase}adapters/telegram.ts`,
    "eve/channels/twilio": `${channelsBase}adapters/twilio.ts`,
    "eve/channels/github": `${channelsBase}adapters/github.ts`,
    "eve/channels/linear": `${channelsBase}adapters/linear.ts`,
    "eve/channels/teams": `${channelsBase}adapters/teams.ts`,
    "eve/slack/api": `${channelsBase}vendor/slack/api.ts`,
    "ai": "npm:ai@^6",
    // These MUST stay on the same @ai-sdk/provider major as ai@^6 (which pins
    // @ai-sdk/provider@3, model spec v2). @ai-sdk/openai@^4 / anthropic@^4 /
    // google@^4 pull @ai-sdk/provider@4 (spec v4); streamText (ai@6) then
    // rejects such a model with "Unsupported model version v4" and the turn
    // dies silently. Keep them at ^3 to match core/server/deno.json. Bedrock's
    // ^4.0.115 line still targets @ai-sdk/provider@3, so it stays at ^4.
    "@ai-sdk/anthropic": "npm:@ai-sdk/anthropic@^3",
    "@ai-sdk/openai": "npm:@ai-sdk/openai@^3",
    "@ai-sdk/google": "npm:@ai-sdk/google@^3",
    "@ai-sdk/amazon-bedrock": "npm:@ai-sdk/amazon-bedrock@^4.0.115",
    "zod": "npm:zod@^4",
    "pg": "npm:pg",
    "edn-data": "npm:edn-data@^1",
  };
  // Agent-provided deno.json imports win (e.g. extra npm deps for tools).
  try {
    const own = JSON.parse(await Deno.readTextFile(`${agentDir}/deno.json`));
    Object.assign(imports, own.imports ?? {});
  } catch { /* optional */ }

  const importMapPath = `${tmp}/import_map.json`;
  await Deno.writeTextFile(importMapPath, JSON.stringify({ imports }, null, 2));
  // The worker's static graph builder resolves bare specifiers from the
  // servicePath's deno.json, not from the importMapPath worker option (that
  // one only kicks in at runtime) — without this, graph creation fails with
  // `Import "edn-data" not a dependency` on the staged loader.ts.
  await Deno.writeTextFile(`${tmp}/deno.json`, JSON.stringify({ imports }, null, 2));

  // The runtime's worker pool keys workers by servicePath and reuses the
  // FIRST worker created for a given path (env vars and the import map are
  // creation-time only, baked in at worker start) — see
  // trex-runtime/crates/base's servicePath-keyed pool. If every agent
  // shared the core service dir as servicePath, every agent after the
  // first would silently run with the first agent's TREX_AGENT_DIR/env.
  // Give each agent its own servicePath (this temp dir, holding its
  // import_map.json and the staged runtime + agent code) whose index.ts
  // imports the staged service entrypoint — everything the graph needs is
  // in-tree.
  await Deno.writeTextFile(`${tmp}/index.ts`, `import "./agents/service/index.ts";\n`);

  const env: Record<string, string> = {};

  // Passthrough env vars from the host (if set)
  for (const k of PASSTHROUGH_ENV) {
    const v = Deno.env.get(k);
    if (v) env[k] = v;
  }

  // Entry-specific env (substituted), can override passthrough
  const entryEnv = substituteEnvVarsInObject(entry.env ?? {});
  Object.assign(env, entryEnv);

  // Reserved keys must not be overridden. TREX_AGENT_DIR points at the
  // staged copy: the worker can only import modules under its servicePath
  // (see above), and loader.ts dynamic-imports agent code from this dir.
  const reserved: Record<string, string> = {
    TREX_AGENT_DIR: stagedAgentDir,
    TREX_AGENT_NAME: entry.name,
    TREX_PLUGIN_NAME: pluginFullName,
  };
  Object.assign(env, reserved);

  // Linked-memory env — only injected when the agent actually declares
  // links, and set AFTER entry-specific env so a plugin manifest can't
  // clobber them (same non-overridable treatment as `reserved` above).
  //  - GBRAIN_MEMORY_TOKEN: the bearer token the generated tools
  //    (agent-memory.ts's renderMemoryTool) send to the memory worker's
  //    internal MCP endpoint. Read from the same host env var
  //    memory/gbrain-worker/mount.ts's buildMemoryWorkerConfig reads for the
  //    worker side, so both ends agree on the token.
  //  - MEMORY_MCP_URL: the internal memory-service base the generated tool
  //    fetches `${MEMORY_MCP_URL}/memory/<name>/mcp` against. RUNTIME-GATED:
  //    the actual agent-worker -> memory-worker reachability (bypassing the
  //    Express session layer, see mount.ts's module doc comment on
  //    fnmap/Trex.tokioChannel) can't be exercised here (trex-runtime
  //    submodule not checked out) — this only wires a configurable address
  //    (GBRAIN_MEMORY_INTERNAL_URL) with a sane localhost default so the
  //    generated tool has something to call once that path is verified.
  //  - TREX_AGENT_MEMORIES: comma-joined linked memory names, so agent code
  //    can enumerate its links without re-parsing the manifest.
  if (entry.memory?.length) {
    env.GBRAIN_MEMORY_TOKEN = Deno.env.get("GBRAIN_MEMORY_TOKEN") ?? "";
    // 8001 is the in-container plain-HTTP port (8000 is TLS), and the base
    // needs the mount prefix — the generated tool appends /memory/<name>/mcp.
    env.MEMORY_MCP_URL = Deno.env.get("GBRAIN_MEMORY_INTERNAL_URL") ??
      `http://127.0.0.1:8001${memoryWorkerBasePath()}`;
    env.TREX_AGENT_MEMORIES = entry.memory.map((l) => l.name).join(",");
  }

  return {
    source: `/${entry.name}`,
    servicePath: tmp,
    importMapPath,
    env,
  };
}

// _addFunction (function.ts) only applies [authContext, pluginAuthz] to
// plugins under a trusted scope (TRUSTED_PLUGIN_SCOPES: @trex, @ohdsi) —
// d2e/legacy function plugins authenticate themselves inside the worker using
// the forwarded Logto header, which an agents worker doesn't do. Until
// worker-side auth exists for agents, anything outside a trusted scope would
// mount a completely unauthenticated HTTP surface (session create, chat, tool
// execution).
export function isTrustedScopeAgentsPlugin(name: string): boolean {
  return isTrustedPluginScope(name);
}

// Pure — returns the subset of an agent's memory links whose name is NOT in
// the declared-memory allow-list (see plugin.ts's DECLARED_MEMORY_NAMES,
// populated in a pre-pass across every plugin's package.json before any
// plugin is dispatched, since agents (orderRank 5) load before memory (6)
// yet the two can live in different plugins scanned in either order).
// Exported standalone so it's testable without driving addAgentsPlugin's
// full Express-app path.
export function unknownMemoryLinks(
  links: AgentMemoryLink[] | undefined,
  declaredMemoryNames: ReadonlySet<string>,
): AgentMemoryLink[] {
  return (links ?? []).filter((l) => !declaredMemoryNames.has(l.name));
}

// Auth carve-out for channel routes (task-4). A channel route lives at
// {basePath}/eve/v1/<channelId>/... and is authenticated by the adapter's own
// platform-signature verify() inside the worker — NOT by a trex JWT — so it
// must bypass authContext/pluginAuthz at the proxy, which would otherwise 401
// an unauthenticated platform webhook (Discord/Slack/…). The session/chat/
// health/info routes are deliberately EXCLUDED from the exemption (negative
// lookahead) so their proxy auth is unchanged — weakening those would be a
// serious bug. Passed to _addFunction as fncfg.authExemptPattern.
//
// The `eve` channel is a SPECIAL case in the reserved set: it is the built-in
// WEB channel (adapters/eve.ts), trusted browser traffic that — unlike a
// platform webhook — carries NO platform signature. Instead it authenticates
// via the trex JWT exactly like the native session API (spec §5: eve-web =
// "trex JWT (existing)"). So `eve` MUST stay reserved (auth-enforced): leaving
// it exempt would let anyone create sessions, spend model tokens, run tools,
// and read other users' session streams (IDOR) with no credential.
//
// INVARIANT: the reserved set below (session|health|info|eve) MUST stay in sync
// with handler.ts's authenticated `/eve/v1/*` route set PLUS the built-in
// JWT-authed `eve` web channel. If a new AUTHED `/eve/v1/<seg>` route (or a new
// JWT-authed built-in channel) is ever added, `<seg>` MUST be added to this
// lookahead — otherwise `/eve/v1/<seg>` becomes auth-exempt (an unauthenticated
// hole). A channel named like a reserved word (e.g. a `sessionx` or
// `eventbridge` channel) is unaffected: the lookahead only excludes the exact
// segments, boundaried by `/` or end.
//
// The OAuth consent routes (task-7) at `/eve/v1/oauth/<connector>/{start,
// callback}` are DELIBERATELY NOT in the reserved set: they are auth-exempt on
// purpose (a provider's browser redirect carries no trex JWT) and are gated by
// the signed `state` verified inside the handlers (connections/oauth/routes.ts)
// — exactly like a channel route is gated by its adapter's signature verify.
// `oauth` must therefore stay OUT of the lookahead.
export function channelAuthExemptPattern(basePath: string): RegExp {
  const esc = basePath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${esc}/eve/v1/(?!(?:session|health|info|eve)(?:/|$))[^/]+`);
}

export interface AgentMountRecord {
  entry: AgentEntry;
  pluginDir: string;
  pluginFullName: string;
  basePath: string;
  // Mount-time env applied ON TOP of buildAgentWorkerConfig's env, re-applied
  // verbatim on every rebuild: TREX_AGENT_BASE always; the gateway signer's
  // DISCORD_PUBLIC_KEY when gateway mode is on (the ephemeral keypair lives
  // in startDiscordGateway's client — a rebuild must keep the SAME public key
  // or the loopback shim stops passing the adapter's signature gate).
  envOverrides: Record<string, string>;
  live: LiveWorkerConfig;
}

// One record per mounted agent, keyed `${pluginFullName}/${entry.name}`.
// The skills plugin type (skills.ts) uses this to find and re-stage agents
// that were already mounted when a pack targeting them is deployed.
export const AGENT_MOUNTS = new Map<string, AgentMountRecord>();

export function _clearAgentMountsForTest(): void {
  AGENT_MOUNTS.clear();
}

// Re-stages an agent's worker dir from source (picking up newly declared
// skill packs via buildAgentWorkerConfig's registry default) and atomically
// repoints the mount through the shared live ref (see function.ts's
// LiveWorkerConfig). On failure the swap never happens — the caller logs and
// the running agent keeps serving from its current staged dir.
export async function rebuildAgentMount(
  rec: AgentMountRecord,
  opts: { cleanupDelayMs?: number } = {},
): Promise<void> {
  const cfg = await buildAgentWorkerConfig(rec.pluginDir, rec.entry, rec.pluginFullName);
  const old = rec.live.servicePath;
  rec.live.servicePath = cfg.servicePath;
  rec.live.importMapPath = cfg.importMapPath;
  rec.live.xenv = { _shared: { ...cfg.env, ...rec.envOverrides } };
  // The previous worker may still be mid-request against the old dir —
  // delete after a grace period, not immediately. (First cleanup this code
  // path has ever had: boot-time staged dirs were never removed.)
  const delay = opts.cleanupDelayMs ?? 5 * 60_000;
  const rm = () => Deno.remove(old, { recursive: true }).catch(() => {});
  if (delay === 0) {
    await rm();
  } else {
    const t = setTimeout(rm, delay);
    // Cleanup must never keep the process alive.
    Deno.unrefTimer(t);
  }
}

export async function addAgentsPlugin(
  app: Express,
  value: unknown,
  dir: string,
  name: string,
  declaredMemoryNames: ReadonlySet<string> = new Set(),
): Promise<void> {
  if (!isTrustedScopeAgentsPlugin(name)) {
    // Log and skip, don't throw: one misconfigured/malicious plugin must
    // not take down boot for every other plugin.
    console.error(`agents: plugin ${name} skipped — agents plugins must be published under a trusted scope (${TRUSTED_PLUGIN_SCOPES.join(", ")}) (auth requirement)`);
    return;
  }
  for (const entry of normalizeAgentsValue(value)) {
    // Mirrors the trusted-scope guard above, but per-agent rather than
    // per-plugin: an unknown linked memory means this ONE agent is
    // misconfigured, not the whole plugin — skip just this entry (before any
    // filesystem work in buildAgentWorkerConfig) and keep registering the
    // plugin's other agents.
    const badLinks = unknownMemoryLinks(entry.memory, declaredMemoryNames);
    if (badLinks.length > 0) {
      for (const l of badLinks) {
        console.error(
          `agents: agent ${entry.name} (plugin ${name}) links unknown memory "${l.name}" — not declared by any trex.memory plugin; skipping agent`,
        );
      }
      continue;
    }
    // Per-entry failure isolation (same rationale as the unknown-memory-link
    // skip above): a staging failure for THIS agent (e.g. a skill pack
    // collision, see skill-packs.ts's assertVacant) must not abort the whole
    // plugin — the remaining entries still deserve a chance to register.
    try {
      const cfg = await buildAgentWorkerConfig(dir, entry, name);
      console.log(`add agent ${entry.name} @ ${cfg.env.TREX_AGENT_DIR}`);
      // _addFunction computes servicePath as `${dir}${fncfg.function}` and the
      // mounted URL from `source` + plugin scope; TREX_AGENT_BASE tells the
      // worker its mount point so it can strip the prefix. Always the
      // trusted-scope mount — the guard above rejects everything else.
      const scope = `/${name.slice(1, name.indexOf("/"))}`;
      const basePath = `${PLUGINS_BASE_PATH}${scope}${cfg.source}`;

      // Discord GATEWAY mode (agents/gateway/discord.ts): DISCORD_GATEWAY in the
      // agent's OWN manifest env swaps the inbound webhook for an outbound
      // gateway WebSocket — no public URL needed. Deliberately NO host-env
      // fallback: with one, a single host-wide DISCORD_GATEWAY=1 opened a
      // gateway client for EVERY registered agent on the same bot token —
      // identify rate-limit 429s, and each interaction fanned out to every
      // agent's route (racing callbacks, N sessions per command). An agent opts
      // in by passing the var through its trex.agents[].env block
      // (`"DISCORD_GATEWAY": "${DISCORD_GATEWAY:-}"`). The worker's DISCORD_PUBLIC_KEY
      // is overridden to a boot-time ephemeral key BEFORE _addFunction bakes the
      // env, so the loopback shim is the only principal that can pass the
      // adapter's signature-before-send gate (Discord never POSTs webhooks in
      // this mode — no Interactions Endpoint URL is registered — so the real
      // application key is unused). Must happen before _addFunction: worker env
      // is creation-time only.
      let gateway: { botToken: string; channelId: string; messages: boolean } | null = null;
      if (gatewayModeEnabled(cfg.env.DISCORD_GATEWAY)) {
        const botToken = cfg.env.DISCORD_BOT_TOKEN || Deno.env.get("DISCORD_BOT_TOKEN") || "";
        if (!botToken) {
          console.error(`agents: agent ${entry.name} (plugin ${name}) sets DISCORD_GATEWAY but has no DISCORD_BOT_TOKEN — gateway mode disabled`);
        } else {
          gateway = {
            botToken,
            channelId: cfg.env.DISCORD_GATEWAY_CHANNEL || "discord",
            // Messages mode is gateway-only (Discord never webhooks messages) and
            // needs the privileged MESSAGE_CONTENT intent enabled in the portal.
            messages: gatewayModeEnabled(cfg.env.DISCORD_MESSAGES),
          };
        }
      }
      const signer = gateway ? await createGatewaySigner() : null;

      // Slack SOCKET MODE (agents/gateway/slack.ts): same per-agent opt-in
      // discipline as DISCORD_GATEWAY above. The worker's SLACK_SIGNING_SECRET
      // is overridden to a boot-time ephemeral secret so the loopback shim is
      // the only principal that can pass the slack adapter's signature gate.
      let slackGateway: { appToken: string; channelId: string } | null = null;
      if (gatewayModeEnabled(cfg.env.SLACK_GATEWAY)) {
        const appToken = cfg.env.SLACK_APP_TOKEN || Deno.env.get("SLACK_APP_TOKEN") || "";
        if (!appToken) {
          console.error(`agents: agent ${entry.name} (plugin ${name}) sets SLACK_GATEWAY but has no SLACK_APP_TOKEN — slack gateway disabled`);
        } else {
          slackGateway = { appToken, channelId: cfg.env.SLACK_GATEWAY_CHANNEL || "slack" };
        }
      }
      const slackSigner = slackGateway ? createSlackGatewaySigner() : null;

      const envOverrides: Record<string, string> = { TREX_AGENT_BASE: basePath };
      if (signer) {
        cfg.env.DISCORD_PUBLIC_KEY = signer.publicKeyHex;
        envOverrides.DISCORD_PUBLIC_KEY = signer.publicKeyHex;
      }
      if (slackSigner) {
        cfg.env.SLACK_SIGNING_SECRET = slackSigner.secret;
        envOverrides.SLACK_SIGNING_SECRET = slackSigner.secret;
      }
      const live: LiveWorkerConfig = {
        servicePath: cfg.servicePath,
        importMapPath: cfg.importMapPath,
        xenv: { _shared: { ...cfg.env, ...envOverrides } },
      };
      // Re-registration (dev reload) overwrites the record. This is NOT a full
      // re-registration story on its own: Express keeps serving the FIRST
      // registered route's handler/ref regardless of what this map holds
      // afterward, and there is no re-registration path today anyway —
      // _addFunction's registerFromPath early-returns on a duplicate route.
      AGENT_MOUNTS.set(`${name}/${entry.name}`, {
        entry, pluginDir: dir, pluginFullName: name, basePath, envOverrides, live,
      });
      _addFunction(
        app,
        cfg.source,
        cfg.servicePath,
        cfg.importMapPath,
        {
          function: `/agents/${entry.name}`,
          allowHostFsAccess: true,
          // An agent turn is not a request/response function. A claw coding
          // turn makes several askCodeAgent hand-offs at 5-12 minutes each, so
          // it routinely outlives _callWorker's 30-minute default: observed
          // turns were killed at 29m01s and 23m25s with the runtime logging
          // `reason: "EarlyDrop"`, while every turn that completed ran under 12
          // minutes. The drop is silent to the turn — the worker dies before
          // finishTurn runs, so the turn stays `running` and every later
          // message on that session queues behind it until the stale sweep.
          //
          // Matches service/handler.ts's STALE_TURN_MS: past that the sweep
          // declares the turn abandoned and reaps it anyway, so a worker living
          // longer could only keep alive a turn the rest of the system has
          // already given up on.
          workerTimeoutMs: AGENT_WORKER_TIMEOUT_MS,
          // Channel subpaths ({basePath}/eve/v1/<channelId>/*) bypass proxy auth;
          // the worker enforces adapter signature verification instead. session/
          // chat/health/info keep authContext+pluginAuthz. See the pattern's doc.
          authExemptPattern: channelAuthExemptPattern(basePath),
          liveConfig: live,
        },
        dir,
        name,
        live.xenv,
      );

      if (gateway && signer) {
        // Loopback base: the in-process plain-HTTP listener (same convention as
        // GBRAIN_MEMORY_INTERNAL_URL in buildAgentWorkerConfig). The client
        // starts fire-and-forget and reconnects on its own; keyed by basePath so
        // a re-registration replaces the previous client instead of doubling up.
        const loopback = Deno.env.get("DISCORD_GATEWAY_LOOPBACK_URL") ?? "http://127.0.0.1:8001";
        startDiscordGateway(basePath, {
          botToken: gateway.botToken,
          forwardUrl: `${loopback}${basePath}/eve/v1/${gateway.channelId}`,
          signer,
          label: `${name}/${entry.name}`,
          ...(gateway.messages
            ? {
              // GUILD_MESSAGES | MESSAGE_CONTENT — interactions still need none.
              intents: (1 << 9) | (1 << 15),
              messageForwardUrl: `${loopback}${basePath}/eve/v1/${gateway.channelId}/messages`,
            }
            : {}),
        });
      }

      if (slackGateway && slackSigner) {
        const loopback = Deno.env.get("SLACK_GATEWAY_LOOPBACK_URL") ??
          Deno.env.get("DISCORD_GATEWAY_LOOPBACK_URL") ?? "http://127.0.0.1:8001";
        startSlackGateway(basePath, {
          appToken: slackGateway.appToken,
          forwardUrl: `${loopback}${basePath}/eve/v1/${slackGateway.channelId}`,
          signer: slackSigner,
          label: `${name}/${entry.name}`,
        });
      }
    } catch (e) {
      console.error(
        `agents: agent ${entry.name} (plugin ${name}) failed to register — skipping:`,
        e instanceof Error ? e.message : e,
      );
      continue;
    }
  }
}

// One gateway client per agent basePath; re-registering an agent (dev reload)
// stops the old client before starting the replacement.
const discordGateways = new Map<string, DiscordGatewayClient>();

function startDiscordGateway(basePath: string, opts: ConstructorParameters<typeof DiscordGatewayClient>[0]): void {
  discordGateways.get(basePath)?.stop();
  const client = new DiscordGatewayClient(opts);
  discordGateways.set(basePath, client);
  client.start();
  console.log(`agents: discord gateway mode enabled for ${opts.label} → ${opts.forwardUrl}`);
}

// One slack gateway client per agent basePath (same replacement discipline as discord).
const slackGateways = new Map<string, SlackGatewayClient>();

function startSlackGateway(basePath: string, opts: ConstructorParameters<typeof SlackGatewayClient>[0]): void {
  slackGateways.get(basePath)?.stop();
  const client = new SlackGatewayClient(opts);
  slackGateways.set(basePath, client);
  client.start();
  console.log(`agents: slack gateway mode enabled for ${opts.label} → ${opts.forwardUrl}`);
}

// Registered once by plugin.ts when the first agents-type plugin appears.
// Async because the migrations dir must be resolved from disk, not from
// import.meta.url — see resolveAgentsRuntimeDir (in the packaged image the
// meta URL points into a build-time compile graph that doesn't exist at
// runtime, so the migration runner failed with "Directory not found").
export async function agentsCoreMigrationTarget() {
  return {
    name: "agents-core",
    path: `${await resolveAgentsRuntimeDir()}migrations`,
    schema: "agents",
    database: "_config",
  };
}
