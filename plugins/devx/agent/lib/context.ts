// Adapter: eve's per-request ToolContext -> the legacy devx AgentContext
// (plugins/devx/functions/tools/types.ts) that the ~76 pre-existing devx
// tools are written against. Ported tools keep their original signature
// (execute(args, devxCtx)) unmodified; wrap() below is the one place a
// ported tools/<name>.ts file has to touch to become an eve-authored tool.
//
// Field-by-field mapping (task-v1-brief.md):
//  - userId:        ONLY from ToolContext.userId (the x-user-id-authenticated
//                    caller — see core/server/agents/README.md's
//                    "ToolContext.userId" section). NEVER from metadata,
//                    which is client-supplied and untrusted.
//  - workspacePath:  ensureWorkspace/ensureAppWorkspace, reused as-is from
//                    ../../functions/tools/workspace.ts (relative import —
//                    same worker substrate/filesystem, not copied).
//  - send:           routed through evectx.emit (H3), defaulting the event
//                    name to "devx" when the payload carries none.
//  - sql:            the query fn threaded onto ToolContext via
//                    core's hookCtx.sql -> ToolContext.sql (see the sibling
//                    core-side commit "feat(agents): expose hookCtx.sql on
//                    ToolContext" — authoredTool in toolset.ts).
//  - requireConsent: stubbed to always-approve. Consent is now enforced
//                    BEFORE execute() ever runs, via the tool's own
//                    needsApproval (mapped from defaultConsent === "ask" in
//                    wrap() below) plus H4 sticky always/never decisions.
//                    This field only exists so ported tools that still call
//                    ctx.requireConsent(...) inline keep compiling/running.
import { defineTool } from "eve/tools";
// Type-only imports: erased at build/runtime, so importing straight from
// core's agents module here does not create a real runtime dependency
// (agent directories must stay portable to real eve — see eve-shim/types.ts's
// header comment). The runtime-visible surface is only "eve"/"eve/tools",
// same as every other agent-authored file.
import type { QueryFn, ToolContext, ToolDef } from "eve/core/eve-shim/types.ts";
import { ensureAppWorkspace, ensureWorkspace } from "../../functions/tools/workspace.ts";
import { acceptDeclaredWorkspace, peekSessionScope } from "./session_scope.ts";
import type { AgentContext as DevxAgentContext, ConsentLevel } from "../../functions/tools/types.ts";

export type { DevxAgentContext };

// Client-advisory metadata contract from the (future) devx-agent UI. All
// three fields are untrusted client input — never used for authorization,
// only to pick a workspace path / label events. `mode` selection (which
// system-prompt variant to build) is wired via V3's buildInstructions hook,
// not read here.
export interface DevxMetadata {
  mode: "ask" | "plan" | "build";
  chatId: string;
  appId?: string;
  // NO skillContext field here, deliberately (R11): on the legacy loop
  // skillContext is SERVER-derived — index.ts resolves a slash command or
  // matches skill intent and loads the body itself. Accepting it as client
  // metadata would turn a server-resolved value into untrusted client input
  // that lands verbatim in the system prompt. eve does not need the
  // pre-injection at all: see agent.ts's buildCoderContext call site.
  //
  // Untrusted client-supplied passthrough (same posture as mode/chatId/appId
  // above), consumed by agent.ts's buildUserMessage hook, which applies the
  // same defensive shape filter + cap-of-10 the legacy path applies at
  // functions/index.ts:405-408 before ever fetching anything. Reachable from
  // the browser UI, not just a chat channel (ChatInput.tsx), so it must be
  // handled on this loop too. Never used for authorization.
  attachments?: Array<{ url: string; name: string; contentType?: string }>;
}

// Exported for agent.ts's buildInstructions hook (V3), which needs the same
// chatId/appId extraction to derive a workspacePath — reused as-is rather
// than duplicated. NOTE: filterTools (agent.ts) does NOT reuse this for its
// own mode reading — this function's "unset -> build" default is right for
// workspace routing (some concrete mode must be picked) but wrong for
// filterTools's "no mode -> allow everything" contract, so that hook reads
// ctx.metadata.mode directly instead. See agent.ts's own readMode.
export function readMetadata(metadata: unknown): DevxMetadata {
  const m = (metadata ?? {}) as Partial<DevxMetadata>;
  return {
    mode: m.mode === "ask" || m.mode === "plan" ? m.mode : "build",
    chatId: typeof m.chatId === "string" ? m.chatId : "",
    appId: typeof m.appId === "string" ? m.appId : undefined,
    // Passed through raw (array-shape only) -- the per-item shape filter and
    // cap-of-10 live in agent.ts's buildUserMessage, right where the fetch
    // happens, matching the legacy validation site (functions/index.ts:
    // 405-408) rather than duplicating it here.
    attachments: Array.isArray(m.attachments) ? (m.attachments as DevxMetadata["attachments"]) : undefined,
  };
}

// Ownership-verification cache for chatId (SECURITY fix, final-007 review
// finding #1): keyed on `${userId}:${chatId}`, small and process-lifetime —
// ownership of a devx.chats row is effectively immutable for our purposes
// (chats aren't transferred between users), so caching the verdict across
// calls in the same worker process is safe. Capped and FIFO-evicted (Map
// preserves insertion order) purely to bound memory on a long-lived worker;
// correctness does not depend on the cache at all; it's fine to skip it (a
// re-verification on eviction just costs one extra query).
const chatOwnershipCache = new Map<string, boolean>();
const CHAT_OWNERSHIP_CACHE_MAX = 500;

// Verifies that `chatId` belongs to `userId` via devx.chats.user_id — the
// legacy route validated this at the HTTP layer (see this file's header
// comment); the agents path has no equivalent, so tools that scope DB writes
// by `ctx.chatId` alone (e.g. functions/tools/update_todos.ts's
// `DELETE FROM devx.todos WHERE chat_id = $1`, which has no user_id column
// to double-check against) would otherwise let a caller write into ANY
// chat by simply naming it in client-supplied `metadata.chatId`. Fails
// CLOSED on every negative signal — no row, or the query itself throwing —
// because an unverified chatId must never flow into a chat-scoped write.
async function verifyChatOwnership(sql: QueryFn, chatId: string, userId: string): Promise<boolean> {
  const cacheKey = `${userId}:${chatId}`;
  const cached = chatOwnershipCache.get(cacheKey);
  if (cached !== undefined) return cached;

  let owned: boolean;
  try {
    const result = await sql(`SELECT 1 FROM devx.chats WHERE id = $1 AND user_id = $2`, [chatId, userId]);
    owned = result.rows.length > 0;
  } catch {
    // Fail closed: a DB error is NOT evidence of ownership, and must not be
    // treated as such. Deliberately not cached — a transient DB blip
    // shouldn't durably poison this chat for the rest of the process.
    return false;
  }

  if (chatOwnershipCache.size >= CHAT_OWNERSHIP_CACHE_MAX) {
    const oldestKey = chatOwnershipCache.keys().next().value;
    if (oldestKey !== undefined) chatOwnershipCache.delete(oldestKey);
  }
  chatOwnershipCache.set(cacheKey, owned);
  return owned;
}

// Adapts eve's ToolContext (+ the worker's sql query fn) into the legacy
// devx AgentContext shape. `evectx.sql` is required here — a ported tool
// that needs it will fail loudly (a clear error, not a silent undefined
// call) if the caller never wired a hookCtx.sql through, same posture as
// the rest of the H1/H2 hooks (see core/server/agents/README.md).
export async function toDevxCtx(evectx: ToolContext & { sql: QueryFn }): Promise<DevxAgentContext> {
  if (!evectx.sql) {
    throw new Error("devx agent adapter: ToolContext.sql is required but was not provided — is hookCtx.sql wired?");
  }
  const { chatId: rawChatId, appId: rawAppId } = readMetadata(evectx.metadata);
  const userId = evectx.userId ?? "";

  // SECURITY (final-007 review finding #1): metadata.chatId is client-supplied
  // and untrusted (see this file's header comment) — a chatId is only allowed
  // to flow into the returned ctx (and therefore into every chat-scoped tool
  // write) once ownership is verified against the AUTHENTICATED userId. No
  // userId at all means verification is impossible, so anonymous sessions get
  // NO chat-scoped writes either (fail closed, not "trust it"). appId is
  // blanked alongside chatId on failure too, even though appId-derived
  // workspace paths are independently safe (ensureAppWorkspace always scopes
  // by the real userId) — an unverified chatId must never reach a devxCtx
  // consumer under ANY field name.
  let chatId = rawChatId;
  let appId = rawAppId;
  if (chatId) {
    const owned = userId ? await verifyChatOwnership(evectx.sql, chatId, userId) : false;
    if (!owned) {
      chatId = "";
      appId = undefined;
    }
  }

  // Same session-declared workspace (V14), acceptance check and snapshot as
  // agent.ts's resolveWorkspace: that one keys the consents, this one decides
  // where the tools write, and a run worktree is isolated only if both agree.
  const declared = acceptDeclaredWorkspace(peekSessionScope(evectx.sessionId)?.workspace, userId);
  const workspacePath = declared ?? (appId ? await ensureAppWorkspace(userId, appId) : await ensureWorkspace(userId));
  return {
    chatId,
    userId,
    appId: appId ?? null,
    workspacePath,
    send: (data: unknown) => {
      const type = (data as { type?: string } | null | undefined)?.type ?? "devx";
      evectx.emit?.(type, data);
    },
    sql: evectx.sql,
    requireConsent: () => Promise.resolve(true),
  };
}

// Legacy tool definition shape (plugins/devx/functions/tools/types.ts's
// ToolDefinition), minus `name` (eve derives the tool name from the
// tools/<name>.ts filename) and `parameters`/`getConsentPreview` (V2 maps
// ToolDefinition.parameters onto this `schema` field at the call site; a
// getConsentPreview has no eve-side equivalent now that approval prompts
// are driven by needsApproval, not a custom preview string).
export interface LegacyToolDef<T = unknown> {
  description: string;
  schema: unknown; // JSON Schema or zod — forwarded to defineTool's inputSchema verbatim
  execute: (args: T, ctx: DevxAgentContext) => Promise<string>;
  modifiesState?: boolean;
  defaultConsent?: ConsentLevel;
}

// Wraps one legacy devx tool definition as an eve-authored ToolDef.
// `modifiesState` is carried through as a passthrough field for V3's
// filterTools to read (e.g. dropping state-mutating tools in ask/plan
// mode) — not part of eve's ToolDef shape, but defineTool/Object.assign
// (eve-shim/tools.ts) doesn't strip unknown fields, so it survives onto
// the branded result.
export function wrap<T = unknown>(def: LegacyToolDef<T>): ToolDef & { modifiesState?: boolean } {
  const toolDef: ToolDef & { modifiesState?: boolean } = {
    description: def.description,
    inputSchema: def.schema,
    needsApproval: def.defaultConsent === "ask",
    modifiesState: def.modifiesState,
    execute: async (input: unknown, ctx?: ToolContext) => {
      const devxCtx = await toDevxCtx((ctx ?? { sessionId: "" }) as ToolContext & { sql: QueryFn });
      return await def.execute(input as T, devxCtx);
    },
  };
  return defineTool(toolDef) as ToolDef & { modifiesState?: boolean };
}
