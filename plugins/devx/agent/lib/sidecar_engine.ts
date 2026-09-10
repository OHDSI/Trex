// The claude-code sidecar as an eve AgentEngine: it runs its OWN agentic loop,
// so eve hands it the whole turn (service/engine/delegate.ts). Two jobs live
// here — reshaping its SSE events into the SDK shapes core's translator reads,
// and answering its permission requests from eve's approval gate.
import { ensureAppWorkspace, ensureWorkspace } from "../../functions/tools/workspace.ts";
import { readMetadata } from "./context.ts";
import { acceptDeclaredWorkspace, loadSessionScope } from "./session_scope.ts";
import { UNAVAILABLE_TOOL_ERROR } from "../../functions/lib/eve_run.ts";
// Type-only, erased at runtime — same posture as agent.ts's ToolDef import
// (these types are not part of eve's public re-export surface).
import type { AgentEngine, EngineTurn, HookCtx } from "eve/core/eve-shim/types.ts";
// Real runtime imports, same posture as agent.ts's hook-output.ts import.
import { createStore } from "eve/core/service/store.ts";
import { publish } from "eve/core/service/stream.ts";
import { runApprovalGate } from "eve/core/service/approval-gate.ts";
import { toDevxToolInput } from "eve/core/service/engine/tool-input.ts";
import { deriveScopeKey } from "eve/core/service/scope-key.ts";
import { parseEscalateList, resolveEscalateFor } from "eve/core/service/approval-policy.ts";

export const SIDECAR_ENGINE_NAME = "claude-code";

// devx tool names the delegated loop can actually run. server.js's `tools`
// option names the SDK's BUILT-INS, so only a devx tool whose name IS one
// survives; the rest (CodeSearch, Git*, SearchReplace, Browser*, …) exist on
// the model loop alone, and the sidecar registers only the kb/ask MCP servers.
const DELEGATED_TOOL_NAMES: ReadonlySet<string> = new Set([
  "Read", "Write", "Edit", "Bash", "Glob", "Grep",
  "WebFetch", "WebSearch", "TodoWrite", "Skill",
]);

/**
 * The declared tools this path would silently drop. Returned so they can be
 * recorded as denials — a review that ran 3 of its 7 tools must never be
 * byte-identical, in devx.agent_results, to one that ran all 7.
 */
export function unavailableDelegatedTools(allowedTools: readonly string[] | undefined): string[] {
  if (!allowedTools) return [];
  return [...new Set(allowedTools)].filter((name) => !DELEGATED_TOOL_NAMES.has(name));
}

// The subset of the SDK's message shapes core's translator reads
// (service/engine/events.ts's SdkMessageLike). Declared rather than imported
// so this file produces the shape structurally, with no cast.
export interface SdkOutMessage {
  type: string;
  session_id: string;
  message?: { content: Array<Record<string, unknown>> };
  is_error?: boolean;
  result?: string;
  stop_reason?: string;
  usage?: { input_tokens?: number; output_tokens?: number };
}

// What the sidecar's canUseTool bridge expects back (sdk.d.ts's
// PermissionResult): `message` is required on a deny.
export type PermissionDecision =
  | { behavior: "allow"; updatedInput: Record<string, unknown> }
  | { behavior: "deny"; message: string };

export interface SidecarEvent {
  type: string;
  [k: string]: unknown;
}

// streamClaudeCodeChat's own surface, narrowed to what this file passes and
// reads. Injectable so the engine is testable without a running sidecar.
export type SidecarStream = (args: {
  chatId: string;
  userId: string;
  appId?: string;
  chatMode: string;
  workspacePathOverride?: string;
  allowedTools?: readonly string[];
  settings: Record<string, unknown>;
  history: Array<{ role: string; content: string }>;
  send: (e: SidecarEvent) => void;
  sqlFn: HookCtx["sql"];
  resolvePermission?: (
    req: { id: string; toolName: string; input: Record<string, unknown> },
  ) => Promise<PermissionDecision>;
}) => Promise<{ content: string; toolCalls: unknown[] }>;

interface SettingsRow {
  model?: string | null;
  ai_rules?: string | null;
  max_steps?: number | null;
}

// The `<!--tool:id-->` breadcrumb streamClaudeCodeChat splices into its text
// so the legacy UI can place tool cards inside a reloaded message. It is a
// transport artefact of that UI, not model output, so it must not land in
// eve's persisted message text.
const TOOL_MARKER = /^\n<!--tool:[^>]*-->\n$/;

// Push-to-pull bridge: streamClaudeCodeChat calls `send` synchronously as the
// SSE stream arrives, while an AgentEngine must be pulled from.
function messageQueue() {
  const items: SdkOutMessage[] = [];
  let wake: (() => void) | null = null;
  let closed = false;
  return {
    push(m: SdkOutMessage) {
      items.push(m);
      wake?.();
      wake = null;
    },
    close() {
      closed = true;
      wake?.();
      wake = null;
    },
    async *drain(): AsyncGenerator<SdkOutMessage> {
      while (true) {
        const next = items.shift();
        if (next !== undefined) {
          yield next;
          continue;
        }
        if (closed) return;
        await new Promise<void>((r) => (wake = r));
      }
    },
  };
}

// One devx SSE event -> zero or one SDK-shaped message. `sessionId` fills the
// SDK's `session_id` field, which the translator requires present but
// delegate.ts re-points at eve's own turn id before anything is emitted.
export function toSdkMessage(e: SidecarEvent, sessionId: string): SdkOutMessage | null {
  switch (e.type) {
    case "chunk": {
      const text = typeof e.content === "string" ? e.content : "";
      if (!text || TOOL_MARKER.test(text)) return null;
      return { type: "assistant", session_id: sessionId, message: { content: [{ type: "text", text }] } };
    }
    case "tool_call_start":
      return {
        type: "assistant",
        session_id: sessionId,
        message: { content: [{ type: "tool_use", id: e.callId, name: e.name, input: e.args ?? {} }] },
      };
    case "tool_call_end":
      return {
        type: "user",
        session_id: sessionId,
        message: { content: [{ type: "tool_result", tool_use_id: e.callId, content: e.result ?? "" }] },
      };
    default:
      // step/subagent_*/questionnaire/consent_request and the rest are legacy
      // UI chrome with no eve counterpart — the same drop posture events.ts keeps.
      return null;
  }
}

// (plugin, agent) must match what a native devx tool call keys its sticky
// consent on, or a grant made through the UI would never match here — so it
// is read from the session row rather than hardcoded.
async function gateContext(sql: HookCtx["sql"], sessionId: string) {
  const r = await sql(`SELECT plugin, agent FROM agents.sessions WHERE id = $1`, [sessionId]);
  const row = r.rows[0] as { plugin?: string; agent?: string } | undefined;
  return { plugin: row?.plugin, agentName: row?.agent };
}

async function readSettings(sql: HookCtx["sql"], userId: string): Promise<SettingsRow> {
  const r = await sql(`SELECT model, ai_rules, max_steps FROM devx.settings WHERE user_id = $1`, [userId]);
  return (r.rows[0] as SettingsRow | undefined) ?? {};
}

// `escalate` is the agent's AUTHORED override, supplied by agent.ts from the
// same constant it declares to defineAgent so the two loops cannot drift. The
// approval timings are test seams: a "must NOT gate" test has to fail fast
// rather than park for the production 30 minutes.
export interface SidecarEngineDeps {
  stream?: SidecarStream;
  escalate?: string;
  approvalPollMs?: number;
  approvalTimeoutMs?: number;
}

/**
 * Builds the per-request engine. Bound to `ctx` (sql/userId/env/metadata) the
 * way resolveModel's ModelSpec is, which is what keeps the switch per-account.
 */
export function createSidecarEngine(ctx: HookCtx, deps: SidecarEngineDeps = {}): AgentEngine {
  return {
    name: SIDECAR_ENGINE_NAME,
    run: (turn: EngineTurn) => runSidecarTurn(ctx, deps, turn),
  };
}

async function* runSidecarTurn(
  ctx: HookCtx,
  deps: SidecarEngineDeps,
  turn: EngineTurn,
): AsyncGenerator<SdkOutMessage> {
  const injected = deps.stream;
  const authoredEscalate = deps.escalate;
  // Dynamic, matching functions/index.ts's own two call sites: the sidecar
  // module is only pulled in for an account that actually runs on it, so it
  // cannot break agent load for every other provider.
  const stream = injected ?? (await import("../../functions/claude_code_agent.ts")).streamClaudeCodeChat;
  const userId = ctx.userId;
  if (!userId) throw new Error("devx sidecar engine requires an authenticated user");
  const { appId } = readMetadata(ctx.metadata);
  const store = createStore(ctx.sql);
  const [{ plugin, agentName }, settings, unattended, channelBound, approverReachable, scope] = await Promise.all([
    gateContext(ctx.sql, turn.sessionId),
    readSettings(ctx.sql, userId),
    store.isUnattended(turn.sessionId),
    store.isChannelBound(turn.sessionId),
    store.isApproverReachable(turn.sessionId),
    // Core's delegated path (handler.ts's runDelegatedTurn) calls NEITHER
    // resolveInstructions nor buildSdkTools, so agent.ts's filterTools /
    // resolveWorkspace never fire here — this engine reads the scope itself.
    loadSessionScope(turn.sessionId, ctx.sql),
  ]);
  // The same workspace authoredTool keys a stored consent on (agent.ts's
  // resolveWorkspace) — a grant for one app must not cover another. A session
  // that declared an isolated run worktree gets that instead, through the SAME
  // validator agent.ts uses; a rejected value falls back to the derived tree.
  const workspace = acceptDeclaredWorkspace(scope.workspace, userId) ??
    (appId ? await ensureAppWorkspace(userId, appId) : await ensureWorkspace(userId));
  const escalate = resolveEscalateFor(authoredEscalate, parseEscalateList(ctx.env("AGENTS_ESCALATE_TOOLS")), agentName);
  // handler.ts:978 does exactly this before handing `unattended` to the tool
  // set: a channel-bound session never writes the unattended column
  // (spawn.ts's own note), so reading the column alone would gate every Write
  // and Bash on a claw coder session and park it on a human who is not there.
  const noHuman = unattended || channelBound;

  // THE re-pointing (Task 6): the sidecar's permission request is decided by
  // eve's gate against this turn's own row, not by devx's
  // tool_consents/pending_consents round trip.
  const resolvePermission = async (
    req: { id: string; toolName: string; input: Record<string, unknown> },
  ): Promise<PermissionDecision> => {
    // Second of two allowlist layers, checked before the gate so no stored
    // consent can override it: the SDK `tools` option governs BUILT-INS only,
    // so the kb/ask MCP tools are caught only here.
    if (scope.allowedTools && !scope.allowedTools.includes(req.toolName)) {
      return { behavior: "deny", message: `${req.toolName} is not in this session's tool allowlist` };
    }
    const mapped = toDevxToolInput(req.toolName, req.input);
    const refusal = await runApprovalGate({
      toolName: mapped.tool,
      input: mapped.input,
      scopeKey: deriveScopeKey(mapped.tool, mapped.input, workspace),
      sessionId: turn.sessionId,
      store,
      turnId: turn.turnId,
      emit: (e) => publish(turn.sessionId, e),
      userId,
      plugin,
      agentName,
      unattended: noHuman,
      channelBound,
      approverReachable,
      escalate,
      approvalPollMs: deps.approvalPollMs,
      approvalTimeoutMs: deps.approvalTimeoutMs,
      signal: turn.signal,
    });
    // The sidecar re-runs the tool with updatedInput, so it must get the
    // SDK's own shape back — the devx mapping above exists only to scope the
    // consent, never to rewrite the call.
    return refusal ? { behavior: "deny", message: refusal.error } : { behavior: "allow", updatedInput: req.input };
  };

  // Do not silently degrade: a tool this path cannot provide is never CALLED,
  // so it leaves no trace of its own. One failed action.result each is what
  // carries it into eve_run.ts's `denials` and the durability behind them.
  for (const toolName of unavailableDelegatedTools(scope.allowedTools)) {
    publish(turn.sessionId, {
      type: "action.result",
      data: {
        turnId: turn.turnId,
        result: {
          kind: "tool-result",
          callId: `unavailable:${turn.turnId}:${toolName}`,
          toolName,
          output: { error: `${toolName} ${UNAVAILABLE_TOOL_ERROR} (${SIDECAR_ENGINE_NAME})` },
        },
        status: "failed",
      },
    });
  }

  const queue = messageQueue();
  let usage: { input_tokens?: number; output_tokens?: number } | undefined;
  const run = stream({
    // eve's session id, not metadata.chatId: it keys the sidecar's resumed
    // session and the per-chat worktree, and client metadata must not be able
    // to point either at another chat's transcript.
    chatId: turn.sessionId,
    userId,
    appId,
    chatMode: "agent",
    // Without this the sidecar re-derives appId ? app tree : user tree, and an
    // autonomous run mutates the main app tree instead of its own worktree.
    workspacePathOverride: workspace,
    // Becomes the SDK's `tools` option (the base built-in set) in
    // fn-claude-code/server.js. resolvePermission below still re-checks it:
    // that is what covers MCP tools, which `tools` does not govern.
    allowedTools: scope.allowedTools,
    // auto_approve is deliberately NOT forwarded: eve's gate owns that
    // decision now (resolveApproval's unattended/escalate tiers), and a
    // forwarded `true` would short-circuit the gate before it ever ran.
    settings: {
      provider: SIDECAR_ENGINE_NAME,
      model: settings.model ?? undefined,
      ai_rules: settings.ai_rules ?? undefined,
      max_steps: settings.max_steps ?? undefined,
      auto_approve: false,
    },
    // The engine keeps its own transcript across turns (it resumes its
    // session), so only this turn's prompt is handed over.
    history: [{ role: "user", content: turn.prompt }],
    send: (e) => {
      if (e.type === "token_usage") {
        usage = {
          input_tokens: Number(e.prompt_tokens) || undefined,
          output_tokens: Number(e.completion_tokens) || undefined,
        };
        return;
      }
      const m = toSdkMessage(e, turn.sessionId);
      if (m) queue.push(m);
    },
    sqlFn: ctx.sql,
    resolvePermission,
  });

  // A terminal message either way: delegate.ts fails a turn whose stream ends
  // without one, so the sidecar's own failure must arrive as `result`.
  const settle: Promise<SdkOutMessage> = run.then(
    () => ({ type: "result", session_id: turn.sessionId, is_error: false, stop_reason: "stop", usage }),
    (err: unknown) => ({
      type: "result",
      session_id: turn.sessionId,
      is_error: true,
      result: err instanceof Error ? err.message : String(err),
    }),
  );
  settle.finally(() => queue.close());

  for await (const m of queue.drain()) yield m;
  yield await settle;
}
