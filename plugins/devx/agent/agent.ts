// V3 (task-v3-brief.md): resolveModel/filterTools/buildInstructions hooks —
// see core/server/agents/README.md's "Runtime hooks" section for the
// contract each is called under (per-request, never cached at agent-load
// time; a thrown resolveModel/buildInstructions propagates and fails the
// turn rather than silently falling back to env credentials or the static
// instructions.md).
import { defineAgent } from "eve";
import type { HookCtx, ModelSpec } from "eve";
// Type-only import: ToolDef isn't part of eve's public re-export surface
// (see eve-shim/mod.ts) — this is erased at build/runtime, same posture as
// lib/context.ts's own core-relative type-only imports (see that file's
// header comment for why this doesn't create a real dependency on core).
import type { AgentEngine, ToolDef } from "eve/core/eve-shim/types.ts";
import { createSidecarEngine } from "./lib/sidecar_engine.ts";
import { readMetadata } from "./lib/context.ts";
import { loadSkillsForPrompt } from "../functions/skills/resolver.ts";
import { ensureAppWorkspace, ensureWorkspace, readProjectRules } from "../functions/tools/workspace.ts";
import { assertEncryptionMigrated, assertProviderConfigEncryptionMigrated, readProviderKey } from "../functions/provider_key.ts";
import { assertProviderSupported } from "../functions/provider_support.ts";
import { classifyCoderError } from "../functions/error_codes.ts";
import { buildCoderContext, DEFAULT_MAX_STEPS } from "../functions/coder_context.ts";
import { loadHooks, runContextHook, runPostToolHooks, runPreToolHooks, runStopHooks } from "../functions/skills/hooks.ts";
import type { Hook } from "../functions/skills/types.ts";
import { materializeAttachments, renderAttachmentBlock } from "../functions/attachments.ts";
import { DEFERRED_TOOLS } from "./lib/deferred_tools.ts";
// Real runtime import (not type-only), same posture as dynamic-tools.ts's
// core/server/agents/connections/mcp.ts import above it.
import { capHookOutput } from "eve/core/service/context/hook-output.ts";
import { acceptDeclaredWorkspace, loadSessionScope, peekSessionScope, peekSessionScopeForCtx } from "./lib/session_scope.ts";

// Port of functions/tools/registry.ts's buildToolSet PLAN_MODE_TOOLS
// (registry.ts:197-205) — legacy names map 1:1 to the eve wrapper names
// ported in plugins/devx/agent/tools/ (batch A/B, task-v2-brief.md).
// NOTE: transcribed, not imported — the legacy const is unexported (declared
// inline inside buildToolSet), so keep this list in sync manually.
// Exported so lib/deferred_tools.test.ts can assert this set and
// DEFERRED_TOOLS stay disjoint. Deferral runs after filterTools, so a tool in
// both lists is dropped from plan mode outright — see DEFERRED_TOOLS' comment.
export const PLAN_MODE_TOOLS = new Set([
  "Read", "Glob", "Grep", "CodeSearch",
  "GitStatus", "GitLog", "GitBranchList",
  "AskUserQuestion", "WritePlan", "ExitPlanMode",
  "KBListRepos", "KBInit", "KBUpdate", "KBRead", "KBSearch",
  "KBListFiles", "KBOverview", "KBFindSymbols",
  "TaskGet", "TaskList",
  "CronList", "ToolSearch",
]);

// Task 16, deviation from task-16-brief.md: the brief's sample only adds
// this note to the static instructions.md file (kept below, for a human
// reading that file and for lib/deferred_tools.test.ts's literal-text
// check) — but instructions.md's content is NOT what a turn on this loop
// actually sends the model. buildInstructions below discards its own
// `base` argument (the resolved instructions.md text) entirely in favor of
// buildCoderContext's systemPrompt (see this file's header comment on
// defineAgent, "2. `base` ... used to be verbatim..."). Without appending
// this note to the REAL returned prompt too, the model would never learn
// ToolSearch exists to reveal DEFERRED_TOOLS — the whole mechanism would be
// silently unreachable on this loop. Appended unconditionally: this agent's
// `context.deferredTools` (below) is never empty.
// Exported so lib/prompt_parity.test.ts can assert the REAL returned prompt is
// exactly legacy's spine plus this note, rather than "starts with the spine
// and contains the note somewhere", which permitted arbitrary extra content.
// The categories listed track DEFERRED_TOOLS: knowledge base is deliberately
// absent, since the KB* tools are no longer deferred (they are plan-mode
// allowlisted — see deferred_tools.ts). Every OTHER deferred tool must be
// reachable from one of these categories, or the model has no phrasing that
// would lead it to ToolSearch for that tool — lib/deferred_tools.test.ts
// asserts that by ranking each parsed category against the real ToolSearch
// candidates, so the list here cannot drift from DEFERRED_TOOLS again.
// Categories are comma-separated between the two em dashes; that shape is
// what the test parses.
export const DEFERRED_TOOLS_NOTE =
  "Your tool list is partial. Less common tools — scheduled tasks, Figma, browser automation, " +
  "database inspection, image generation, web crawling, dependency installation — are not " +
  "listed above. Call ToolSearch to find and enable them; they become available from your " +
  "next message onward.";

interface ProviderRow {
  provider: string;
  model: string;
  api_key: string | null;
  api_key_encrypted?: string | null;
  api_key_iv?: string | null;
  base_url: string | null;
}

// Port of functions/index.ts:290-333 (settings assembly) + functions/agent.ts's
// createModel (:41-119), minus the Bedrock JSON-credential unpacking and the
// OpenAI-compatible client construction itself — those become core's job
// (model.ts's resolveModelSpec/buildModel) once we hand back a ModelSpec.
// This agent authors no escalate override (the deployment list stands).
// Declared once because BOTH loops must read the same value: defineAgent's
// `escalate` feeds handler.ts's resolveEscalate for the model loop, and
// lib/sidecar_engine.ts's gate needs it for the delegated one.
const AUTHORED_ESCALATE: string | undefined = undefined;

// resolveEngine and resolveModel both need the row, and BOTH run on every
// turn — so without this the information_schema probe plus the
// provider_configs/settings select would run twice per turn for every devx
// user, including the vast majority whose turns are never delegated. Cached on
// the request's own HookCtx object, exactly as turnHooks caches devx.hooks
// below: one entry per request, collected with the request. The promise (not
// its value) is cached so two concurrent hooks share one round trip.
const providerRowCache = new WeakMap<object, Promise<ProviderRow | undefined>>();

// The active provider row, or undefined when the user configured none.
// Extracted so resolveEngine below picks the SAME row resolveModel does — a
// second, differently-ordered lookup could route a turn to the sidecar while
// the model hook read a different provider.
function readProviderRow(ctx: HookCtx, userId: string): Promise<ProviderRow | undefined> {
  let p = providerRowCache.get(ctx);
  if (!p) {
    p = selectProviderRow(ctx, userId);
    providerRowCache.set(ctx, p);
  }
  return p;
}

async function selectProviderRow(ctx: HookCtx, userId: string): Promise<ProviderRow | undefined> {
  // Probe before selecting the encrypted columns — see provider_key.ts's
  // assertProviderConfigEncryptionMigrated header comment.
  await assertProviderConfigEncryptionMigrated(ctx.sql);
  const activeProviderResult = await ctx.sql(
    `SELECT pc.provider, pc.model, pc.api_key, pc.api_key_encrypted, pc.api_key_iv, pc.base_url
     FROM devx.provider_configs pc
     WHERE pc.user_id = $1 AND pc.is_active = true
     LIMIT 1`,
    [userId],
  );
  const row = activeProviderResult.rows[0] as ProviderRow | undefined;
  if (row) return row;

  // Fall back to the legacy devx.settings row (backward compat) when the
  // user has no active provider_configs row — functions/index.ts:305-333.
  // devx.settings now carries the same encrypted-pair columns as
  // provider_configs (V16) — resolved through the same readProviderKey call
  // below, not a second, differently-shaped resolution.
  await assertEncryptionMigrated("settings", ctx.sql);
  const legacyResult = await ctx.sql(
    `SELECT provider, model, api_key, api_key_encrypted, api_key_iv, base_url FROM devx.settings WHERE user_id = $1`,
    [userId],
  );
  return legacyResult.rows[0] as ProviderRow | undefined;
}

// A claude-code account's turns run on the sidecar's own agentic loop
// (lib/sidecar_engine.ts) instead of runner.ts's model loop; every other
// provider resolves undefined and is unaffected. Per-request, mirroring
// resolveModel — which is NOT consulted for a delegated turn: the engine
// holds its own credentials (a Claude Code OAuth token, not an API key).
async function resolveEngine(ctx: HookCtx): Promise<AgentEngine | undefined> {
  if (!ctx.userId) return undefined;
  const row = await readProviderRow(ctx, ctx.userId);
  if (row?.provider !== "claude-code") return undefined;
  return createSidecarEngine(ctx, { escalate: AUTHORED_ESCALATE });
}

async function resolveModel(ctx: HookCtx): Promise<ModelSpec> {
  if (!ctx.userId) {
    throw new Error("devx agent requires an authenticated user");
  }
  const userId = ctx.userId;
  const row = await readProviderRow(ctx, userId);

  // No silent model fallback: the former hardcoded anthropic/claude-sonnet
  // default resolved against the worker env's ANTHROPIC_API_KEY, silently
  // running unconfigured users on the operator's account.
  if (!row) {
    throw new Error("devx: no model provider configured — set up a provider in devx Settings");
  }

  // Resolve through the encryption helper before ANY use of the key below —
  // never let row.api_key (NULL once a row is encrypted) reach ModelSpec.apiKey
  // as undefined, which core's buildModel (model.ts:55/60/71) silently
  // backfills from the operator's own ANTHROPIC_API_KEY / GOOGLE_GENERATIVE_AI_
  // API_KEY / OPENAI_API_KEY env var — cross-tenant credential substitution on
  // any deployment where those vars happen to be set. A decrypt failure must
  // fail this turn the same way every other throw in this function does
  // (module header: "propagates and fails the turn"), never continue with an
  // absent key. classifyCoderError mirrors the wording index.ts's read sites
  // use, so the failure reads the same regardless of which loop produced it.
  let resolvedApiKey: string | null;
  try {
    resolvedApiKey = await readProviderKey(row);
  } catch (err) {
    // classifyCoderError's `safe` string is generic for the UI — log the
    // actual cause (e.g. a rotated DEVX_ENCRYPTION_KEY) so it's diagnosable
    // from the server log, not just a misleading UI message.
    console.error("[devx] provider key read failed for agents-loop turn:", err instanceof Error ? err.message : err);
    const classified = classifyCoderError(err instanceof Error ? err.message : String(err));
    throw new Error(classified.safe);
  }

  // A claude-code account has NO model credentials to hand back: it
  // authenticates the sidecar with a Claude Code OAuth token, and any
  // ModelSpec built here would carry no api_key — which core's buildModel
  // backfills from the operator's own env var (cross-tenant billing, the
  // failure this file guards against everywhere else). Such a turn runs on
  // resolveEngine above instead, and handler.ts skips the compaction
  // summarizer for it, so this throw is now unreachable on the delegating
  // path; it still stands for the /chat endpoint, which has no engine switch.
  if (row.provider === "claude-code") {
    // Wording unchanged on purpose: /chat is the only caller that can still
    // reach it, and for /chat the legacy endpoint IS still the answer.
    throw new Error("sidecar providers use the legacy endpoint");
  }

  // Engines that are gone, but whose stored rows still name them — the
  // provider_configs/settings tables were deliberately left unmigrated. This
  // gate must stay an explicit throw rather than being deleted: with no gate,
  // the fallback a few lines down maps every unrecognized provider name onto
  // `openai`, and such a row carries no api_key, so core's buildModel would
  // backfill ModelSpec.apiKey from the operator's own OPENAI_API_KEY — one
  // user's turn billed to, and authenticated as, the operator. Fail the turn
  // with something the user can act on instead.
  //
  // The `hostAgnostic` wording is why this passes a style: the message
  // surfaces through a runtime shared with other plugins, where an
  // unqualified "Settings" would not tell the user where to go.
  assertProviderSupported(row.provider, "hostAgnostic");

  // anthropic/google/bedrock map straight onto ModelSpec.provider; any other
  // provider name (including self-hosted/OpenAI-compatible endpoints) is the
  // OpenAI-compatible fallback branch createModel used for everything it
  // didn't special-case (functions/agent.ts:113-118).
  const provider: ModelSpec["provider"] =
    row.provider === "anthropic" || row.provider === "google" || row.provider === "bedrock" ? row.provider : "openai";

  // Bedrock credentials are packed as JSON in api_key (functions/agent.ts's
  // createModel, :56-75's "Credentials are packed as JSON in api_key"
  // branch) — unlike anthropic/google/openai, where api_key is used
  // verbatim, a bedrock row's api_key must be unpacked to tell a bearer
  // token apart from IAM access-key/secret-key credentials before it can be
  // handed to core's ModelSpec.apiKey (which core's resolveModelSpec/
  // bedrockModel treats as a bearer token ONLY — see eve-shim/types.ts's
  // ModelSpec doc comment). IAM creds have NO equivalent on this loop: core
  // never implemented the SigV4 accessKeyId/secretAccessKey path, only the
  // bearer-token custom-fetch one legacy's own createModel used for bearer
  // auth (see COMPAT.md's ToolContext.sql divergence entry, which also notes
  // this bedrock=bearer-only gap). Silently dropping IAM creds would swap in
  // whatever AWS_BEARER_TOKEN_BEDROCK happens to be set (or nothing at all,
  // producing a confusing downstream auth failure) — throw a clear,
  // actionable error instead. IAM-shaped bedrock credentials are a decided
  // unsupported configuration (not implementing SigV4 auth on this loop was
  // a deliberate call, not an oversight to fix later) — this throw is now
  // the SINGLE enforcement point for that decision, so reaching it in
  // production is the NORMAL path for a user on IAM-shaped bedrock creds,
  // not a sign that some other gate was bypassed. It must stay loud (same
  // "a thrown resolveModel fails the turn" posture as every other error
  // path in this file): a clear, actionable error a real user will see is
  // far better than silently swapping in whatever AWS_BEARER_TOKEN_BEDROCK
  // happens to be set to.
  let apiKey: string | undefined = resolvedApiKey ?? undefined;
  if (provider === "bedrock" && resolvedApiKey) {
    let parsed: unknown;
    let parseable = true;
    try {
      parsed = JSON.parse(resolvedApiKey);
    } catch {
      // Not JSON — legacy's own createModel silently falls through to the
      // AWS_BEARER_TOKEN_BEDROCK env var in this case (its catch{} is
      // empty); core's bedrockModel does the same env fallback when
      // ModelSpec.apiKey is undefined, so drop the unparseable value
      // rather than forwarding it as a bogus apiKey.
      parseable = false;
    }
    if (!parseable || typeof parsed !== "object" || parsed === null) {
      // Unparseable, or a valid-JSON scalar ("null", numbers, bare
      // strings): no recognizable credential structure — treat as absent
      // (env fallback). The property access below is guarded by the
      // object/null check so a stored "null" can't TypeError here
      // (merge-gate re-review ride-along a).
      apiKey = undefined;
    } else {
      const creds = parsed as { bearerToken?: unknown; accessKeyId?: unknown; secretAccessKey?: unknown };
      if (creds.bearerToken && typeof creds.bearerToken === "string") {
        apiKey = creds.bearerToken;
      } else if (creds.accessKeyId || creds.secretAccessKey) {
        throw new Error(
          "bedrock IAM (access key/secret key) credentials are not supported — " +
            "generate a bedrock bearer token and update this provider's credentials to use it",
        );
      } else {
        // Valid JSON object but NEITHER shape (e.g. {"bearerToken": ""} or
        // unrelated keys): never forward the raw JSON blob as a bearer
        // token — treat as absent, same env fallback as above.
        apiKey = undefined;
      }
    }
  }

  return {
    provider,
    modelId: row.model,
    apiKey,
    baseURL: row.base_url ?? undefined,
  };
}

// ctx.metadata is untrusted client input (same posture as lib/context.ts's
// readMetadata) — read directly here rather than through readMetadata,
// because that helper defaults an unset/invalid mode to "build" (right for
// workspace routing, which always needs SOME concrete choice) whereas this
// hook's contract requires "no mode / unknown mode" to mean "allow
// everything", not "treat it as build".
// Every eve built-in that can start, steer or read a subagent. This IS a
// hand-written name list, and it is a list of names in a package this one
// does not import — so it guarantees only that the delegation tools NAMED
// HERE are dropped in ask mode, and it cannot notice a new `agent_*` built-in
// added to core. lib/filter_tools.test.ts cross-checks it, but against a
// second literal in that same file, so a genuinely new built-in slips past
// both. Adding one to core means adding it here, deliberately; the real
// backstop is core's own restrictChildTools/metadata threading, which does
// not depend on any name list.
// Exported for that cross-check.
export const AGENT_TOOLS = new Set([
  "agent",
  "agent_spawn",
  "agent_list",
  "agent_wait",
  "agent_result",
  "agent_stop",
  "agent_send",
]);

export function readMode(metadata: unknown): "ask" | "plan" | "build" | undefined {
  const mode = (metadata as { mode?: unknown } | null | undefined)?.mode;
  return mode === "ask" || mode === "plan" || mode === "build" ? mode : undefined;
}

// Port of functions/tools/registry.ts's buildToolSet mode-filtering
// (registry.ts:180-221). The legacy "never" consent branch (registry.ts:190)
// is intentionally NOT ported — core's sticky always/never consent store
// (toolset.ts's authoredTool, keyed on userId/plugin/agentName/tool) now
// owns that decision.
function filterTools(name: string, def: ToolDef, ctx: HookCtx): boolean {
  // The session-creation-time allowlist (V14), never ctx.metadata. This hook is
  // synchronous, so it reads the snapshot buildInstructions primed on THIS ctx
  // object; a cold one fails the turn rather than run a restricted session
  // unrestricted. Neither this allowlist nor the declared workspace reaches a
  // CHILD session: a child turn carries the parent's metadata but its own
  // sessionId, so its scope row is empty. Contained only because `agent`/
  // `skill` are themselves dropped unless allowlisted.
  const scope = peekSessionScopeForCtx(ctx, ctx.sessionId);
  if (!scope) {
    throw new Error(`devx filterTools: session ${ctx.sessionId} has no loaded scope — buildInstructions must prime it before the tool set is built`);
  }
  // An EMPTY allowlist declares "no tools"; only an ABSENT one is "no restriction".
  if (scope.allowedTools && !scope.allowedTools.includes(name)) return false;

  const mode = readMode(ctx.metadata);

  // Build mode doesn't use tools in the legacy AI-SDK loop (raw streaming) —
  // registry.ts:208-209 drops EVERY tool, including (here) the eve built-in
  // skill/agent tools, which filterTools sees in the same merged set.
  if (mode === "build") return false;

  // Ask mode drops state-mutating tools — modifiesState is a devx-only
  // passthrough field carried by lib/context.ts's wrap(), not part of eve's
  // ToolDef shape, hence the cast. The eve built-in delegation tools carry no
  // modifiesState field (they're generic eve built-ins, not devx-authored
  // ToolDefs) but legacy's own Agent tool IS modifiesState:true and gets
  // dropped in ask mode (spawn_agent.ts:33) — name-check them explicitly here
  // to close that asymmetry (documented in task-v4-report.md).
  //
  // ALL of them, not just "agent". A subagent is a fully capable session: the
  // point of ask mode is that this session cannot change anything, and a
  // read-only session able to call agent_spawn could simply delegate the
  // writing. That made ask mode escapable in one tool call.
  if (mode === "ask" && (AGENT_TOOLS.has(name) || (def as { modifiesState?: boolean } | undefined)?.modifiesState)) {
    return false;
  }

  if (mode === "plan" && !PLAN_MODE_TOOLS.has(name)) return false;

  // No mode / unknown mode: agent-framework default, allow.
  return true;
}

// This loop's own contribution is ONLY the ai_rules winner-selection below —
// legacy semantics reproduced exactly (functions/agent.ts:171-177 +
// prompts.ts's wrapAiRules, :982-987): a SINGLE winner is chosen — workspace
// project rules (TREX.md/AI_RULES.md, read ONLY when metadata carries an
// appId, legacy's gate) || the user's devx.settings.ai_rules ||
// DEFAULT_AI_RULES. The surrounding prompt is no longer hand-assembled here:
// the resolved winner is handed to functions/coder_context.ts's
// buildCoderContext (the same builder the ai-sdk/coder-sidecar engines use),
// which interpolates it via prompts.ts's own wrapAiRules — the
// exact "wrap a real winner in <user_defined_ai_rules>, leave the
// DEFAULT_AI_RULES fallback unwrapped" logic this function used to replicate
// by hand. Passing the RAW resolved winner (not pre-wrapped) is deliberate:
// wrapAiRules already does the wrapping, so wrapping here first would
// double-wrap a real winner. Verified empirically (task-1-report.md) by
// diffing the assembled ai_rules section before/after this change for all
// three precedence cases — identical wrapped/unwrapped treatment in both.
//
// `base` (instructions + agent.skills listing + <context> metadata, built by
// toolset.ts's buildSystemPrompt) is accepted for hook-signature
// compatibility but is NO LONGER the prompt's spine for a TOP-LEVEL turn —
// buildCoderContext supplies its own base (prompts.ts's
// LOCAL_AGENT_SYSTEM_PROMPT via mode:"agent"). The static
// agent/instructions.md file this used to extend is intentionally left in
// place. It is not merely vestigial, for two reasons:
//   1. It still carries the "## d2e / edge functions" steer (test the
//      function through testing-d2e-functions, not just deno test, before
//      declaring done) that this rewrite otherwise silently dropped from
//      this loop; that steer now also lives in the shared prompt as
//      prompts.ts's D2E_TESTING_BLOCK (part of LOCAL_AGENT_SYSTEM_PROMPT),
//      the same fix applied for every other UI engine that never had it.
//   2. `base` — i.e. this exact file's content, unprocessed by this hook —
//      used to be verbatim what a SELF-DELEGATED SUBAGENT turn ran on: the
//      `agent` built-in ran the subagent as an in-process nested loop
//      (core/server/agents/service/toolset.ts's runSubagent, since deleted)
//      that built its system prompt from the static
//      buildSystemPrompt(target, ctx.metadata) and never called
//      resolveInstructions, so it never reached this function either. That
//      gap is closed at the root: a subagent is now a real CHILD SESSION
//      running an ordinary turn (core/server/agents/service/spawn.ts +
//      handler.ts's startTurn), so it goes through exactly the same
//      per-request path a top-level turn does — resolveInstructions
//      included — and its `base` gets discarded here exactly like a
//      top-level turn's does. See the defineAgent comment below for what a
//      subagent turn gets instead.
//
// askToolAvailable: false — this loop registers no mcp__ask__ask_question
// tool. eve's ask_question is unimplemented on this runtime altogether (see
// core/server/agents/COMPAT.md's "HITL is approval-only" note); the only
// question-asking tool here is the differently-named, legacy-ported
// AskUserQuestion (tools/AskUserQuestion.ts, a thin wrapper over
// planningQuestionnaireTool), which is NOT what buildAskQuestionRule's
// <asking-questions> block instructs the model to call. Passing `true` here
// would tell the model to MUST call a tool that does not exist.
//
// remoteChannel: false — this loop is the browser workbench (the "ui"
// coder profile), never a chat channel.
//
// settings.max_steps: undefined — this loop's step budget is set once at
// definition time (defineAgent's maxSteps below), not per turn — see the
// comment there for why the per-user setting cannot reach this loop.
export async function buildInstructions(base: string, ctx: HookCtx): Promise<string> {
  const userId = ctx.userId;

  // Primes the snapshot the SYNCHRONOUS filterTools reads (lib/session_scope.ts).
  // This hook is core's last async point before it builds the tool set, on both
  // the session-runner path (runner.ts) and /chat (handler.ts).
  await loadSessionScope(ctx.sessionId, ctx.sql, ctx);

  // User-level rules from devx.settings — same source functions/agent.ts:173
  // reads before the project-rules override. Falsy (null/empty) counts as
  // absent, matching legacy's `effectiveSettings.ai_rules || undefined`.
  let rules: string | undefined;
  if (userId) {
    const settingsResult = await ctx.sql(`SELECT ai_rules FROM devx.settings WHERE user_id = $1`, [userId]);
    rules = (settingsResult.rows[0] as { ai_rules?: string | null } | undefined)?.ai_rules || undefined;
  }

  // Project rules override user rules, but ONLY for app-scoped chats —
  // legacy gates the readProjectRules call on appId (functions/agent.ts:174).
  const { appId } = readMetadata(ctx.metadata);
  if (userId && appId) {
    const workspacePath = await ensureAppWorkspace(userId, appId);
    const projectRules = await readProjectRules(workspacePath);
    if (projectRules !== undefined) rules = projectRules;
  }

  // Skills listing for SKILL_USAGE_RULE ("The skills above are real and
  // invocable") — loadSkillsForPrompt is the one shared resolver every
  // dispatch path uses (functions/agent.ts, claude_code_agent.ts, index.ts,
  // and this loop).
  //
  // builtinOnly is a DELIBERATE divergence from the legacy loops (R12), NOT
  // an oversight: this loop's actual skill loader is core's `skillTool`,
  // which resolves against the `agent/skills -> ../skills` symlink, i.e.
  // built-in (filesystem-synced) skills only. Listing a user-created
  // devx.skills row here would have the model call `skill` and get back
  // `unknown skill`. Advertising a skill the agent cannot load is worse than
  // a listing that differs between loops — see loadSkillsForPrompt's own
  // comment for the full rationale.
  const skills = await loadSkillsForPrompt(userId, ctx.sql, { builtinOnly: true });

  const { systemPrompt } = await buildCoderContext({
    // Share filterTools' own helper so the prompt and the tool set can never
    // disagree about the mode. readMode returns undefined for unset/unknown,
    // which maps to "agent" -- preserving the previous behaviour for callers
    // that send no mode.
    mode: readMode(ctx.metadata) ?? "agent",
    aiRules: rules,
    // skillContext is deliberately NOT passed on this loop (R11). Legacy
    // PRE-INJECTS a resolved skill body into the system prompt because its
    // own `Skill` tool is a no-op stub returning a canned string — without
    // the injection the model could never see a skill's content. eve has
    // core's REAL `skill` built-in (core/server/agents/service/toolset.ts's
    // skillTool), which loads a skill body on demand mid-turn, so gap 2 is
    // closed here by a different mechanism, not left open. Accepting a
    // client-supplied skillContext instead would be a posture regression:
    // on legacy the value is SERVER-derived (functions/index.ts:756-775
    // resolves the slash command / skill intent and loads the body), and
    // nothing in the eve request path resolves it server-side.
    remoteChannel: false,
    askToolAvailable: false,
    settings: { max_steps: undefined },
    skills,
  });
  return `${systemPrompt}\n\n${DEFERRED_TOOLS_NOTE}`;
}

// Task 11 (fix round 2): core's turn-diff route has no live request, so it
// hands over what it read from the store instead of a HookCtx — the
// session's created_by as userId, and the DIFF'D TURN's own metadata (not
// necessarily the latest turn's). Mirrors lib/context.ts's toDevxCtx exactly
// — appId ? ensureAppWorkspace : ensureWorkspace — because that is where the
// turn's file tools actually wrote; returning undefined for a user-scoped
// turn reported "no workspace" for one that plainly has one. Only a turn with
// no userId at all is genuinely unresolvable.
export async function resolveWorkspace(
  info: { sessionId: string; turnId: string; userId?: string; metadata?: unknown },
): Promise<string | undefined> {
  const { appId } = readMetadata(info.metadata);
  if (!info.userId) return undefined;
  // A workspace declared at session creation (V14) wins — how an autonomous
  // run's isolated worktree survives, since appId alone derives the main app
  // tree. A rejected or unloaded one falls back instead of re-pointing consents.
  const declared = acceptDeclaredWorkspace(peekSessionScope(info.sessionId)?.workspace, info.userId);
  if (declared) return declared;
  return appId ? await ensureAppWorkspace(info.userId, appId) : await ensureWorkspace(info.userId);
}

// devx.hooks (PreToolUse/PostToolUse/Stop) rows are loaded ONCE PER TURN, not
// once per tool call — legacy loads them once at functions/agent.ts:235, and
// a per-call load would issue one query per tool. Cached on a WeakMap keyed
// by the request's HookCtx object itself, not a string session/user id: core
// builds exactly one HookCtx per request (toolset.ts's ToolBuildCtx.hookCtx,
// threaded through every authoredTool call for that turn via the `...ctx`
// spread — see toolset.ts's authoredTool), and that same object reaches every
// onToolCall/onToolResult/onTurnEnd call for the turn. Keying on the object
// itself, rather than a `${sessionId}:${userId}:${event}` string in a
// module-level Map, means the cache entry is garbage-collected along with
// the HookCtx when the turn ends — no unbounded growth in a long-lived
// worker, unlike a string-keyed Map that never evicts. The inner Map (event
// -> Promise<Hook[]>) covers the up-to-three events one turn can request.
const hookRowCache = new WeakMap<object, Map<string, Promise<Hook[]>>>();
function turnHooks(ctx: HookCtx, event: string): Promise<Hook[]> {
  let byEvent = hookRowCache.get(ctx);
  if (!byEvent) {
    byEvent = new Map();
    hookRowCache.set(ctx, byEvent);
  }
  let p = byEvent.get(event);
  if (!p) {
    // userId is the trusted identity (x-user-id via HookCtx), never read
    // from ctx.metadata.
    p = loadHooks(ctx.userId ?? "", event, ctx.sql);
    byEvent.set(event, p);
  }
  return p;
}

// H2: PreToolUse hooks. Runs inside toolset.ts's authoredTool AFTER the
// approval gate (see AgentConfig.onToolCall's doc comment in eve-shim/
// types.ts) and fails CLOSED — a throw here denies this one tool call and
// the turn continues, so genuine errors are left to propagate rather than
// being swallowed into a permissive `{ allow: true }`.
export async function onToolCall(
  call: { name: string; input: unknown },
  ctx: HookCtx,
): Promise<{ allow: boolean; input?: unknown; reason?: string }> {
  const hooks = await turnHooks(ctx, "PreToolUse");
  if (hooks.length === 0) return { allow: true };
  // onFailure is additive only -- runPreToolHooks' own deny/fail-closed
  // decision below is unchanged by whether ctx.emit exists.
  const result = await runPreToolHooks(
    call.name,
    (call.input ?? {}) as Record<string, unknown>,
    hooks,
    (info) => ctx.emit?.("hook.failed", info),
  );
  if (!result.allow) return { allow: false, reason: "blocked by a PreToolUse hook" };
  return result.modifiedArgs ? { allow: true, input: result.modifiedArgs } : { allow: true };
}

// H2: PostToolUse hooks.
export async function onToolResult(
  call: { name: string; input: unknown; result: unknown },
  ctx: HookCtx,
): Promise<unknown> {
  const hooks = await turnHooks(ctx, "PostToolUse");
  if (hooks.length === 0) return call.result;
  // runPostToolHooks (functions/skills/hooks.ts:75-80) is string-in/
  // string-out. A non-string tool result must pass through UNTOUCHED rather
  // than being JSON-stringified into a shape the model has never seen from
  // that tool before.
  if (typeof call.result !== "string") return call.result;
  return await runPostToolHooks(
    call.name,
    (call.input ?? {}) as Record<string, unknown>,
    call.result,
    hooks,
    (info) => ctx.emit?.("hook.failed", info),
  );
}

// H3: Stop hooks. Only reached after a successful turn (core never calls
// onTurnEnd for a failed one) and its errors are logged and swallowed by
// core, not propagated here.
export async function onTurnEnd(turn: { text: string; finishReason: string }, ctx: HookCtx): Promise<void> {
  const hooks = await turnHooks(ctx, "Stop");
  const { chatId } = readMetadata(ctx.metadata);
  if (!chatId) return;
  await runStopHooks(hooks, { chatId, content: turn.text }, (info) => ctx.emit?.("hook.failed", info));
}

// H4: UserPromptSubmit hooks inject extra context ahead of the model seeing
// the prompt. Routed through hooks.ts's runContextHook -- the same
// allowlisted devx-ext bridge (trex_devx_run_command) PreToolUse/PostToolUse/
// Stop use -- so the hook's command gets Task 4's filtered_env (no
// ANTHROPIC_API_KEY/DATABASE_URL/DEK/Discord/Logto secrets reaching the
// child) and the same ALLOWED_EXECUTABLES gate; a direct Deno.Command from
// this worker would bypass both. Not a trust-boundary control like
// onToolCall's fail-closed contract: a disallowed/failing/timed-out hook
// just contributes no text, it never fails the turn (runContextHook itself
// never throws, the try/catch here is defense-in-depth).
async function runUserPromptSubmitHooks(
  hooks: Hook[],
  prompt: string,
  workspacePath?: string,
  emit?: (name: string, data: unknown) => void,
): Promise<string[]> {
  const outputs: string[] = [];
  // Dot-prefixed so an over-cap spill doesn't litter the project root the
  // model browses. No workspace means no reachable place to point to --
  // capHookOutput truncates instead in that case.
  const spillPath = workspacePath ? `${workspacePath}/.devx/hook-spill` : undefined;
  for (const hook of hooks) {
    try {
      const text = await runContextHook(hook, { event: "UserPromptSubmit", prompt }, (info) => emit?.("hook.failed", info));
      // Cap and spill BEFORE this hook's output reaches the prompt — an
      // unbounded hook can undo the compaction that just ran to make room.
      // spillRoot is the workspace, so the pointer comes out workspace-
      // RELATIVE: the reader is the coding model, whose Read goes through
      // safeJoin, which rejects every absolute path.
      if (text) outputs.push((await capHookOutput(text, { spillPath, spillRoot: workspacePath })).text);
    } catch (err) {
      console.error("[devx] UserPromptSubmit hook failed:", err instanceof Error ? err.message : err);
      emit?.("hook.failed", { event: "UserPromptSubmit", error: err instanceof Error ? err.message : String(err) });
    }
  }
  return outputs;
}

// H3: attachment materialization, folded into buildUserMessage (per-turn
// content, not the cache-pointed system prompt — see AgentConfig.
// buildUserMessage's doc comment). Attachments are UI-reachable, not just
// channel-only (ChatInput.tsx), so ordinary browser turns need this too.
export async function buildUserMessage(base: string, ctx: HookCtx): Promise<string> {
  const { appId, attachments } = readMetadata(ctx.metadata);
  let message = base;
  if (ctx.userId && appId && attachments?.length) {
    // Same defensive shape filter and cap-of-10 the legacy path applies at
    // functions/index.ts:405-408 -- these urls are remote/untrusted input.
    const safe = attachments
      .filter((a) => a && typeof a.url === "string" && typeof a.name === "string")
      .slice(0, 10);
    if (safe.length > 0) {
      const workspacePath = await ensureAppWorkspace(ctx.userId, appId);
      const saved = await materializeAttachments(workspacePath, safe);
      // Only paths ever enter the prompt, never file content -- the coder
      // Reads them itself (images render multimodally through Read).
      message += renderAttachmentBlock(saved);
    }
  }

  // Appended AFTER attachments, never replacing them -- see this function's
  // header comment for why that ordering is load-bearing.
  const hooks = await turnHooks(ctx, "UserPromptSubmit");
  if (hooks.length > 0) {
    const workspacePath = ctx.userId && appId ? await ensureAppWorkspace(ctx.userId, appId) : undefined;
    const injected = await runUserPromptSubmitHooks(hooks, base, workspacePath, ctx.emit);
    for (const text of injected) message += `\n${text}`;
  }
  return message;
}

// H5: PreCompact/PostCompact hooks. Same allowlisted bridge/env-filter/
// ALLOWED_EXECUTABLES posture as H4 above -- runContextHook never throws,
// the try/catch here is defense-in-depth, matching compact.ts's own
// fail-open contract for onCompact (a throw here must never block
// compaction, which runs because context pressure is already a problem).
// pre's return value is spliced verbatim into compact.ts's summary input;
// post is side-effect only, compaction has already happened by the time it
// runs, so its return value is discarded.
export async function onCompact(
  phase: "pre" | "post",
  info: { messageCount: number; tokenEstimate: number },
  ctx: HookCtx,
): Promise<string | undefined> {
  const event = phase === "pre" ? "PreCompact" : "PostCompact";
  const hooks = await turnHooks(ctx, event);
  if (hooks.length === 0) return undefined;

  const outputs: string[] = [];
  for (const hook of hooks) {
    try {
      const text = await runContextHook(
        hook,
        { event, messageCount: info.messageCount, tokenEstimate: info.tokenEstimate },
        (failure) => ctx.emit?.("hook.failed", failure),
      );
      // post's output is never read -- only pre's feeds the summarizer.
      if (phase === "pre" && text) outputs.push((await capHookOutput(text)).text);
    } catch (err) {
      console.error(`[devx] ${event} hook failed:`, err instanceof Error ? err.message : err);
      ctx.emit?.("hook.failed", { event, error: err instanceof Error ? err.message : String(err) });
    }
  }
  if (phase !== "pre" || outputs.length === 0) return undefined;
  return outputs.join("\n");
}

// CLOSED: a self-delegated subagent turn now gets the shared contract
// above. `agent` (toolset.ts's agentTool, registered unconditionally at
// depth 0) resolves `target = ctx.agent` — a copy of THIS agent — whenever
// the model omits the `agent` argument; its tool description literally
// invites that ("Omit `agent` to delegate to a copy of yourself"). That
// path is reachable in exactly the mode that matters: useAgentsChat.ts's
// toAgentMode sends mode: undefined for this loop's main coder chat, and
// filterTools treats an undefined mode as "no restriction", so the `agent`
// tool is available there. The resulting subagent turn is no longer a
// nested in-process loop with a prompt of its own (toolset.ts's runSubagent,
// deleted): it is a real CHILD SESSION whose first turn goes through
// handler.ts's startTurn like any other, so it builds its system prompt via
// the same per-request resolveInstructions path a top-level turn takes —
// instead of the old static buildSystemPrompt(target, ctx.metadata), which
// never called resolveInstructions and so never reached
// agent.config.buildInstructions (i.e. buildInstructions above). So a
// self-delegated (or explicitly named) devx coder subagent now runs
// buildInstructions the same way a top-level turn does: the resolved
// ai_rules winner, <skills-protocol>, <commit-pr-hygiene>, and the
// cross-repo guard (GENERAL_GUIDELINES_BLOCK, prompts.ts) all reach it. The
// fix lives entirely in core/ — nothing in this file changed to close it.
// plugins/devx/functions/prompt_divergence.test.ts's ENGINES-list guard
// still cannot take credit for that, and still cannot catch a regression of
// it: the guard only ever scans plugins/devx, and the whole child-session
// path lives under core/server/agents/service/, a tree it never opens — see
// that file's header comment for why a green run there is not evidence
// either way for this path.
export default defineAgent({
  // Definition-time, not per-turn: eve's AgentConfig.maxSteps (eve-shim/
  // types.ts) is read once here and consumed by every streamText call that
  // reads agent.config.maxSteps for this agent — runner.ts (top-level
  // session turns), handler.ts's /chat endpoint, AND a self-delegated OR
  // named subagent's own turn, which is an ordinary child-session turn and
  // so reads the child LoadedAgent's config.maxSteps — the same defineAgent
  // config below when the child is a copy of this agent — not per turn. There is no
  // runtime hook that can override it, so the per-user settings.max_steps
  // and the channel profile's maxStepsFloor (both applied inside
  // buildCoderContext for the other three engines) CANNOT reach this loop
  // — buildInstructions above deliberately passes
  // `settings: { max_steps: undefined }` because there is nowhere for a
  // resolved value to go. Reaching per-turn control here would require the
  // agents runner (runner.ts) to accept a maxSteps override from a hook
  // result (e.g. buildInstructions or a new hook) instead of only reading
  // the static config value — out of scope for this change. Using the
  // shared DEFAULT_MAX_STEPS at least keeps this single hardcoded number in
  // sync with the other engines' fallback instead of drifting silently.
  //
  // Silent effect on a user's own setting: this went 25 -> 100 (DEFAULT_MAX_
  // STEPS), a 4x jump, for BOTH this loop's top-level turns and every nested
  // self-delegated/named subagent run (a child turn reads the same
  // agent.config.maxSteps). A user who deliberately set settings.max_steps
  // to something lower (e.g. 25) to cap spend gets 100 here with no signal
  // that their setting was ignored — devx.settings.max_steps is read and
  // applied for the other three engines but, per the paragraph above, has
  // nowhere to go on this loop. Do not flip a user to loop='agents' as a
  // silent default until either (a) the agents runner accepts a per-turn
  // maxSteps override sourced from settings/buildInstructions, or (b) the UI
  // tells the user their max_steps setting does not apply on this loop.
  maxSteps: DEFAULT_MAX_STEPS,
  resolveModel,
  resolveEngine,
  escalate: AUTHORED_ESCALATE,
  filterTools,
  buildInstructions,
  resolveWorkspace,
  onToolCall,
  onToolResult,
  onTurnEnd,
  buildUserMessage,
  onCompact,
  // Task 16: the long tail of less-common tools (KB, cron, Figma, browser
  // automation, DB inspection, image gen, AddDependency — see
  // lib/deferred_tools.ts's own comment for the full list and the
  // always-on names that must never be added here) withheld from every
  // request until ToolSearch reveals them (core's service/context/
  // toolsplit.ts + toolset.ts's buildSdkTools Step 6). `context` is a
  // `Partial<ContextConfig>` here, exactly as authored — resolveContextConfig
  // (loader.ts) fills in the rest (freshTurns, compactAtFraction, ...) at
  // load time; this raw defineAgent() return value carries only what's
  // explicitly set.
  context: {
    deferredTools: DEFERRED_TOOLS,
    // A COST ceiling, not a correctness limit. compactAtFraction (0.75) is
    // the correctness bound and stays in force; on the 1M-token windows this
    // agent's models have, it would first compact around 750k input tokens —
    // correct, but an enormously expensive single request. The trigger is
    // min(fraction * window, this). Expected to be tuned once there is real
    // data on where devx turns actually land; it is deliberately devx-only,
    // since claw and d2esupport set no context block at all.
    compactAtTokens: 200_000,
  },
});
