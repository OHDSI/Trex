// Loads an eve-layout agent directory into a runtime description.
// Layout (spec §3): instructions.md (required), agent.ts (optional),
// tools/*.ts|*.js (one tool per file, filename = tool name),
// skills/<name>.md or skills/<name>/SKILL.md (metadata parsed here, content
// loaded on demand by the built-in skill tool), subagents/<name>/ (each an
// eve-layout dir, ONE level deep), channels/*.ts|*.js (one channel per file,
// filename = channel id, default-exporting defineChannel(...)),
// connections/*.ts|*.js (one connection per file, filename = connection name,
// default-exporting defineMcpClientConnection/defineOpenApiConnection(...)).
// Unsupported eve dirs (sandbox/) are ignored with a log line so real eve
// projects still load.
//
// EDN alternatives (trex extension for CLJS-authored agents, spec §3): the
// eve-native file always wins when both exist, so directories stay portable
// to real eve. agent.edn {:model "..." :max-steps N}; instructions.edn (EDN
// string or {:instructions "..."}); skills/<name>.edn {:description "..."
// :content "..."}.
import { parseEDNString } from "edn-data";
import type { ChannelDef } from "./channels/types.ts";
import type { ConnectionDef } from "./connections/types.ts";
import type { AgentConfig, ResolvedAgentConfig, ToolDef, ToolProviderFn } from "./eve-shim/types.ts";
import { type ContextConfig, DEFAULT_CONTEXT_CONFIG } from "./service/context/budget.ts";

export interface SkillMeta {
  name: string;
  description: string;
  path: string;
  content?: string; // pre-extracted for EDN skills; md skills read from path
}

// deno-lint-ignore no-explicit-any
async function readEdn(path: string): Promise<any | null> {
  let text: string;
  try {
    text = await Deno.readTextFile(path);
  } catch (e) {
    if (e instanceof Deno.errors.NotFound) return null;
    throw new Error(`agents: failed to read ${path}: ${e instanceof Error ? e.message : e}`);
  }
  try {
    // keywordAs/mapAs make {:model "x"} arrive as {model: "x"}.
    const parsed = parseEDNString(text, { mapAs: "object", keywordAs: "string" });
    // edn-data is lenient and yields null for malformed input instead of
    // throwing — treat that as a parse failure unless the file really says nil.
    if (parsed === null && text.trim() !== "" && text.trim() !== "nil") {
      throw new Error("invalid EDN");
    }
    return parsed;
  } catch (e) {
    throw new Error(`agents: failed to parse ${path}: ${e instanceof Error ? e.message : e}`);
  }
}

export interface LoadedAgent {
  dir: string;
  instructions: string;
  config: ResolvedAgentConfig;
  tools: Record<string, ToolDef>;
  skills: SkillMeta[];
  subagents: Record<string, LoadedAgent>;
  // channels/*.{ts,js} — each default-exports a defineChannel(...) result;
  // key = filename sans ext (same shape as tools/, gated on __trexChannel).
  channels: Record<string, ChannelDef>;
  // connections/*.{ts,js} — each default-exports a defineMcpClientConnection /
  // defineOpenApiConnection result; key = filename sans ext (same shape as
  // channels/, gated on __trexConnection). The loader sets def.name from the
  // filename (the shim reserved a name? field for exactly this).
  connections: Record<string, ConnectionDef>;
  // H2: agent-dir-ROOT `dynamic-tools.ts`/`dynamic-tools.js` only (never
  // discovered inside tools/ — that dir is scanned separately and a
  // dynamic-tools.ts placed there is just an ordinary tools/ entry, which
  // throws the __trexTool brand-mismatch error like any other non-defineTool
  // default export). toolset.ts's buildSdkTools calls this at depth 0 only.
  toolProvider?: ToolProviderFn;
}

const IGNORED_DIRS = ["sandbox"];

// Description = frontmatter `description:` if a leading YAML block exists,
// else the first non-empty, non-heading line.
export function parseSkillDescription(markdown: string): string {
  const fm = markdown.match(/^---\n([\s\S]*?)\n---/);
  if (fm) {
    const d = fm[1].match(/^description:\s*(.+)$/m);
    if (d) return d[1].trim();
  }
  const body = fm ? markdown.slice(fm[0].length) : markdown;
  for (const line of body.split("\n")) {
    const t = line.trim();
    if (t && !t.startsWith("#")) return t;
  }
  return "";
}

// A skill staged from a skills-plugin pack is named `<pack>--<skill>`
// (plugin/skill-packs.ts's staging convention; "--" is rejected in pack and
// pack-skill names, and reserved — hand-authored skills should not use it).
// Returns the pack name, or null for a hand-authored skill.
export function packOfSkillName(name: string): string | null {
  const i = name.indexOf("--");
  return i > 0 ? name.slice(0, i) : null;
}

const EDN_KEY_MAP: Record<string, keyof ContextConfig> = {
  "fresh-tool-output-chars": "freshToolOutputChars",
  "stale-tool-output-chars": "staleToolOutputChars",
  "fresh-turns": "freshTurns",
  "compact-at-fraction": "compactAtFraction",
  "compact-at-tokens": "compactAtTokens",
  "verbatim-turns-after-compaction": "verbatimTurnsAfterCompaction",
  "context-window": "contextWindow",
  "summarization-prompt": "summarizationPrompt",
  "deferred-tools": "deferredTools",
};

// Explicit allowlist, NOT `key in out`. `out` starts as a spread of
// DEFAULT_CONTEXT_CONFIG, which deliberately omits the three OPTIONAL keys
// (`contextWindow`, `summarizationPrompt` and `compactAtTokens` have no
// default) — so an `in`-based guard silently DROPPED them, in camelCase and EDN kebab-case
// alike. That made `contextWindow` unsettable, and it is the spec's only
// escape hatch for budget.ts's CONTEXT_WINDOWS map lagging a model release.
// Any new ContextConfig field must be added here as well as to the type.
const CONTEXT_CONFIG_KEYS: ReadonlySet<keyof ContextConfig> = new Set([
  "freshToolOutputChars",
  "staleToolOutputChars",
  "freshTurns",
  "compactAtFraction",
  "compactAtTokens",
  "verbatimTurnsAfterCompaction",
  "contextWindow",
  "summarizationPrompt",
  "deferredTools",
]);

/** Merge an agent's partial `context` block over the conservative defaults. */
export function resolveContextConfig(raw: unknown): ContextConfig {
  if (!raw || typeof raw !== "object") return { ...DEFAULT_CONTEXT_CONFIG };
  // The merge is BY DYNAMIC KEY and ContextConfig has no index signature, so
  // the allowlisted overrides are collected in an open record and applied over
  // the defaults with Object.assign — which needs no cast in either direction.
  // The allowlist check is what makes that sound: nothing outside
  // CONTEXT_CONFIG_KEYS can ever reach `overrides`.
  const overrides: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    const key = (EDN_KEY_MAP[k] ?? k) as keyof ContextConfig;
    if (CONTEXT_CONFIG_KEYS.has(key)) overrides[key] = v;
  }
  return Object.assign({ ...DEFAULT_CONTEXT_CONFIG }, overrides);
}

// Task 14: per-subagent role config (reasoningEffort/skills). Only `skills`
// is a REDUCTION (ported from codex's role.rs — see resolveChildSkills
// below); `reasoningEffort` is a plain per-subagent override with nothing to
// cap it against, applied to the child's OWN resolved model. Both share the
// same allowlist + EDN-kebab-map pattern as resolveContextConfig above, and
// for the SAME reason: a key missing from the allowlist silently drops the
// field instead of erroring — that defect dropped
// contextWindow/summarizationPrompt/compactAtTokens last cycle (see
// lib/context_config.test.ts). Both keys are optional with no default, so —
// unlike resolveContextConfig — there is nothing to spread defaults over;
// this only ever ADDS a key when the raw config actually names it.
const ROLE_EDN_KEYS: Record<string, "reasoningEffort" | "skills"> = {
  "reasoning-effort": "reasoningEffort",
  "skills": "skills",
};
const AGENT_ROLE_KEYS: ReadonlySet<"reasoningEffort" | "skills"> = new Set(["reasoningEffort", "skills"]);

/** Extracts an agent's role config fields (reasoningEffort/skills) from a raw config object. */
export function resolveAgentRole(raw: unknown): Pick<AgentConfig, "reasoningEffort" | "skills"> {
  const out: Pick<AgentConfig, "reasoningEffort" | "skills"> = {};
  if (!raw || typeof raw !== "object") return out;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    const key = ROLE_EDN_KEYS[k] ?? (k as "reasoningEffort" | "skills");
    if (AGENT_ROLE_KEYS.has(key)) (out as Record<string, unknown>)[key] = v;
  }
  return out;
}

// Reducing only (codex role.rs): a role may narrow a child, never grant it
// something its parent does not have. `child === undefined` means the
// subagent declared no restriction of its own, so it inherits the parent's
// full set unchanged — NOT its own (potentially larger) list, and never a
// union of the two.
export function resolveChildSkills(parent: string[], child: string[] | undefined): string[] {
  if (child === undefined) return parent;
  const allowed = new Set(parent);
  return child.filter((s) => allowed.has(s));
}

// Deno.readDir yields entries in whatever order the filesystem hands them
// back: ext4's htree seed is per-volume, so two machines checking out the
// same commit can enumerate the same directory differently, and a CI runner
// can disagree with a developer's laptop. Everything scanned below is keyed
// into an ordered Record (or array) whose iteration order reaches the model:
// buildSdkTools walks `agent.tools` in insertion order to build the SDK tool
// set, that set is the prefix of every request (so a shuffled order is a
// prompt-cache miss), and withToolCachePoint puts its cache breakpoint on the
// LAST tool — which, for a subagent, gets no built-ins appended after it and
// is therefore whichever tool file the filesystem happened to yield last.
// Sorting by name here makes a loaded agent identical wherever it loads.
// skills/ already sorted its result for the same reason; nothing else did.
async function readDirSorted(path: string): Promise<Deno.DirEntry[]> {
  const entries: Deno.DirEntry[] = [];
  for await (const entry of Deno.readDir(path)) entries.push(entry);
  // Code-unit order, not localeCompare: the comparison must not depend on the
  // host's default locale either.
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return entries;
}

export async function loadAgent(dir: string, opts: { depth?: number } = {}): Promise<LoadedAgent> {
  const depth = opts.depth ?? 0;
  let instructions: string | null = null;
  try {
    instructions = await Deno.readTextFile(`${dir}/instructions.md`);
  } catch (e) {
    // NotFound falls through to the EDN alternative; anything else is real.
    if (!(e instanceof Deno.errors.NotFound)) {
      throw new Error(`agents: failed to read ${dir}/instructions.md: ${e instanceof Error ? e.message : e}`);
    }
  }
  if (instructions == null) {
    const edn = await readEdn(`${dir}/instructions.edn`);
    if (typeof edn === "string") instructions = edn;
    else if (edn && typeof edn.instructions === "string") instructions = edn.instructions;
  }
  if (instructions == null) {
    throw new Error(`agents: ${dir}/instructions.md is required but missing (or instructions.edn)`);
  }

  // ResolvedAgentConfig, not AgentConfig: this is what LoadedAgent.config is
  // declared as, and every branch below already produces a fully resolved
  // `context`. Typing the local honestly is what makes the return statement
  // type-check without a cast — and what keeps a future branch from assigning
  // a partial context and having it surface as an undefined field at some
  // reader far away instead of here.
  let config: ResolvedAgentConfig = { maxSteps: 25, context: { ...DEFAULT_CONTEXT_CONFIG } };
  let configLoaded = false;
  for (const f of ["agent.ts", "agent.js"]) {
    try {
      await Deno.stat(`${dir}/${f}`);
      const mod = await import(`file://${dir}/${f}`);
      if (mod.default) {
        // Both repairs that used to follow this assignment now happen BEFORE
        // it, so `config` is never transiently invalid:
        //
        // - `context` is resolved in the same expression that spreads
        //   mod.default. Its own `context` is a Partial<ContextConfig>, so a
        //   two-step version leaves `config` briefly holding an unresolved
        //   context that only convention stops a later edit from reading.
        // - the stray EDN-spelled keys are deleted from the copy. The spread
        //   copies e.g. `"reasoning-effort"` verbatim, under a name that is
        //   not an AgentConfig field at all; resolveAgentRole below normalizes
        //   its VALUE onto the real camelCase field, so the kebab spelling is
        //   garbage rather than a second competing piece of config. Stripping
        //   it here also means nothing has to reach into the resolved config
        //   through an index signature it does not have.
        const authored = { ...(mod.default as AgentConfig) } as AgentConfig & Record<string, unknown>;
        for (const ednKey of Object.keys(ROLE_EDN_KEYS)) delete authored[ednKey];
        config = { maxSteps: 25, ...authored, context: resolveContextConfig(authored.context) };
        // Task 14: normalize reasoningEffort/skills through the same
        // allowlist the EDN path uses below — resolveAgentRole is the one
        // place that decides what counts as valid role config, so a stray
        // kebab-case key on the TS side still resolves correctly instead of
        // silently never surfacing as the real camelCase field. Read off the
        // ORIGINAL mod.default, which still carries those kebab keys.
        const role = resolveAgentRole(mod.default);
        if (role.reasoningEffort !== undefined) config.reasoningEffort = role.reasoningEffort;
        if (role.skills !== undefined) config.skills = role.skills;
      }
      configLoaded = true;
      break;
    } catch (e) {
      if (e instanceof Deno.errors.NotFound) continue;
      throw new Error(`agents: failed to load ${dir}/${f}: ${e instanceof Error ? e.message : e}`);
    }
  }
  if (!configLoaded) {
    const edn = await readEdn(`${dir}/agent.edn`);
    if (edn && typeof edn === "object") {
      config = {
        maxSteps: typeof edn["max-steps"] === "number" ? edn["max-steps"] : 25,
        ...(typeof edn.model === "string" ? { model: edn.model } : {}),
        context: resolveContextConfig(edn.context),
        // Task 14: :reasoning-effort / :skills, via the same allowlist +
        // EDN-kebab map as resolveContextConfig above.
        ...resolveAgentRole(edn),
      };
    }
  }

  const tools: Record<string, ToolDef> = {};
  try {
    for (const entry of await readDirSorted(`${dir}/tools`)) {
      if (!entry.isFile) continue;
      // Colocated test files (e.g. dispatchToCode.test.ts) are the
      // established convention alongside tool/lib modules in this repo —
      // skip them rather than treating them as tool definitions.
      if (/\.test\.(ts|js|mts|mjs)$/.test(entry.name)) continue;
      const m = entry.name.match(/^(.+)\.(ts|js|mts|mjs)$/);
      if (!m) continue;
      const name = m[1];
      const mod = await import(`file://${dir}/tools/${entry.name}`);
      const def = mod.default;
      if (!def || !(def as { __trexTool?: boolean }).__trexTool) {
        throw new Error(`agents: ${dir}/tools/${entry.name} must default-export defineTool(...)`);
      }
      tools[name] = def as ToolDef;
    }
  } catch (e) {
    if (!(e instanceof Deno.errors.NotFound)) throw e;
  }

  // H2: agent-dir-ROOT dynamic-tools.ts|js only — a separate stat/import
  // from the tools/ scan above, so a dynamic-tools.ts placed *inside*
  // tools/ is never discovered here (it just hits the tools/ loop's
  // __trexTool brand-mismatch error like any other stray file there).
  let toolProvider: ToolProviderFn | undefined;
  for (const f of ["dynamic-tools.ts", "dynamic-tools.js"]) {
    try {
      await Deno.stat(`${dir}/${f}`);
    } catch (e) {
      if (e instanceof Deno.errors.NotFound) continue;
      throw new Error(`agents: failed to read ${dir}/${f}: ${e instanceof Error ? e.message : e}`);
    }
    // Import/brand errors below propagate as-is (not re-wrapped), same as
    // the tools/ loop's brand-mismatch error a few lines up.
    const mod = await import(`file://${dir}/${f}`);
    const fn = mod.default;
    if (!fn || !(fn as { __trexToolProvider?: boolean }).__trexToolProvider) {
      throw new Error(`agents: ${dir}/${f} must default-export defineToolProvider(...)`);
    }
    toolProvider = fn as ToolProviderFn;
    break;
  }

  const channels: Record<string, ChannelDef> = {};
  try {
    for (const entry of await readDirSorted(`${dir}/channels`)) {
      if (!entry.isFile) continue;
      // Colocated test files (e.g. discord.load.test.ts) are the established
      // convention alongside channel modules in this repo — skip them rather
      // than treating them as channel definitions (same rationale as the
      // tools/ scan above).
      if (/\.test\.(ts|js|mts|mjs)$/.test(entry.name)) continue;
      const m = entry.name.match(/^(.+)\.(ts|js|mts|mjs)$/);
      if (!m) continue;
      const name = m[1];
      const mod = await import(`file://${dir}/channels/${entry.name}`);
      const def = mod.default;
      if (!def || !(def as { __trexChannel?: boolean }).__trexChannel) {
        throw new Error(`agents: ${dir}/channels/${entry.name} must default-export defineChannel(...)`);
      }
      channels[name] = def as ChannelDef;
    }
  } catch (e) {
    if (!(e instanceof Deno.errors.NotFound)) throw e;
  }

  const connections: Record<string, ConnectionDef> = {};
  try {
    for (const entry of await readDirSorted(`${dir}/connections`)) {
      if (!entry.isFile) continue;
      const m = entry.name.match(/^(.+)\.(ts|js|mts|mjs)$/);
      if (!m) continue;
      const name = m[1];
      const mod = await import(`file://${dir}/connections/${entry.name}`);
      const def = mod.default;
      if (!def || !(def as { __trexConnection?: boolean }).__trexConnection) {
        throw new Error(
          `agents: ${dir}/connections/${entry.name} must default-export defineMcpClientConnection(...)/defineOpenApiConnection(...)`,
        );
      }
      // The loader owns the connection's name (= filename); the shim reserved
      // the field for exactly this so authored files don't repeat themselves.
      connections[name] = Object.assign(def as ConnectionDef, { name });
    }
  } catch (e) {
    if (!(e instanceof Deno.errors.NotFound)) throw e;
  }

  const skills: SkillMeta[] = [];
  try {
    for (const entry of await readDirSorted(`${dir}/skills`)) {
      if (entry.isFile && entry.name.endsWith(".md")) {
        const path = `${dir}/skills/${entry.name}`;
        skills.push({
          name: entry.name.slice(0, -3),
          description: parseSkillDescription(await Deno.readTextFile(path)),
          path,
        });
      } else if (entry.isFile && entry.name.endsWith(".edn")) {
        const name = entry.name.slice(0, -4);
        // eve-native wins when both exist: flat md twin or SKILL.md dir form
        try {
          await Deno.stat(`${dir}/skills/${name}.md`);
          continue;
        } catch { /* no md twin */ }
        try {
          await Deno.stat(`${dir}/skills/${name}/SKILL.md`);
          continue;
        } catch { /* no SKILL.md dir twin */ }
        const path = `${dir}/skills/${entry.name}`;
        const edn = await readEdn(path);
        if (edn && typeof edn === "object" && typeof edn.content === "string") {
          skills.push({
            name,
            description: typeof edn.description === "string" ? edn.description : "",
            path,
            content: edn.content,
          });
        } else {
          console.log(`agents: ${path} skipped — expected {:description :content}`);
        }
      } else if (entry.isDirectory) {
        try {
          await Deno.stat(`${dir}/skills/${entry.name}/SKILL.md`);
          const path = `${dir}/skills/${entry.name}/SKILL.md`;
          skills.push({
            name: entry.name,
            description: parseSkillDescription(await Deno.readTextFile(path)),
            path,
          });
        } catch { /* dir without SKILL.md — skip */ }
      }
    }
  } catch (e) {
    // Missing skills/ dir is fine; EDN parse failures etc. must fail loudly.
    if (!(e instanceof Deno.errors.NotFound)) throw e;
  }
  skills.sort((a, b) => a.name.localeCompare(b.name));

  const subagents: Record<string, LoadedAgent> = {};
  try {
    for (const entry of await readDirSorted(`${dir}/subagents`)) {
      if (!entry.isDirectory) continue;
      if (depth >= 1) {
        console.log(`agents: ${dir}/subagents ignored — subagents are one level deep only`);
        break;
      }
      subagents[entry.name] = await loadAgent(`${dir}/subagents/${entry.name}`, { depth: depth + 1 });
    }
  } catch (e) {
    if (!(e instanceof Deno.errors.NotFound)) throw e;
  }

  for (const d of IGNORED_DIRS) {
    try {
      await Deno.stat(`${dir}/${d}`);
      console.log(`agents: ${dir}/${d} present but not supported in v1 — ignored`);
    } catch { /* absent */ }
  }

  return { dir, instructions, config, tools, skills, subagents, channels, connections, toolProvider };
}
