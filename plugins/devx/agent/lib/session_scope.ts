// The scope a devx session declares AT CREATION (agents.sessions, V14): the
// tool allowlist filterTools enforces and the workspace resolveWorkspace
// honours on the model loop, and sidecar_engine.ts applies on the delegated
// (claude-code) loop, which runs neither hook. Read from the session row,
// NEVER from ctx.metadata — a restriction the model can restate per turn is
// one it can widen.
import type { QueryFn } from "eve/core/eve-shim/types.ts";
import { getRunWorktreePath } from "../../functions/tools/workspace.ts";

export interface SessionScope {
  /** undefined = none declared, i.e. every tool allowed. An EMPTY array is a
   * declared allowlist OF NOTHING and drops every tool. */
  allowedTools?: readonly string[];
  /** Exactly as declared — validated per use by acceptDeclaredWorkspace. */
  workspace?: string;
}

const NOTHING_DECLARED: SessionScope = Object.freeze({});

export function parseSessionScopeRow(row: unknown): SessionScope {
  const r = row && typeof row === "object" ? row as Record<string, unknown> : {};
  const scope: SessionScope = {};
  // Only a strict `true` declares, matching handler.ts's approverReachable
  // read: a stray truthy value must not turn an unrestricted session into an
  // allowlisted one, nor the reverse.
  if (r.tool_allowlist_declared === true) {
    scope.allowedTools = Array.isArray(r.tool_allowlist) ? r.tool_allowlist.filter((t): t is string => typeof t === "string") : [];
  }
  if (typeof r.workspace_path === "string" && r.workspace_path !== "") scope.workspace = r.workspace_path;
  return scope;
}

// One read per session per worker: the row is written before the session's
// first turn and never changes. Bounded like context.ts's chatOwnershipCache
// so a long-lived worker cannot accumulate an entry per session forever.
const CACHE_MAX = 512;
const loaded = new Map<string, SessionScope>();
const inFlight = new Map<string, Promise<SessionScope>>();

// The hook-to-hook handoff, keyed on the request's own HookCtx object (the
// identical object in buildInstructions and filterTools, same pattern as
// agent.ts's providerRowCache). Eviction from `loaded` above is insertion-
// ordered, not LRU, so a busy worker could otherwise drop the IN-FLIGHT
// turn's own entry between the two hooks and fail it.
const byCtx = new WeakMap<object, SessionScope>();

function remember(sessionId: string, scope: SessionScope): SessionScope {
  if (loaded.size >= CACHE_MAX) {
    const oldest = loaded.keys().next().value;
    if (oldest !== undefined) loaded.delete(oldest);
  }
  loaded.set(sessionId, scope);
  return scope;
}

// node-postgres surfaces the server's SQLSTATE on the error's `code` (the pool
// is created in core/server/agents/service/index.ts).
function pgErrorCode(e: unknown): string | undefined {
  const code = (e as { code?: unknown } | null | undefined)?.code;
  return typeof code === "string" ? code : undefined;
}

/** 42703 = undefined_column: agents.sessions predates V14. */
export function isUndefinedColumn(e: unknown): boolean {
  return pgErrorCode(e) === "42703";
}

export function loadSessionScope(sessionId: string, sql: QueryFn, ctx?: object): Promise<SessionScope> {
  const pin = (s: SessionScope) => {
    if (ctx) byCtx.set(ctx, s);
    return s;
  };
  const cached = loaded.get(sessionId);
  if (cached) return Promise.resolve(pin(cached));
  const pending = inFlight.get(sessionId);
  if (pending) return pending.then(pin);
  // Wrapped so a query fn that throws SYNCHRONOUSLY lands in the catch below
  // rather than escaping into the caller's hook.
  const p = Promise.resolve()
    .then(() =>
      sql(
        `SELECT tool_allowlist, tool_allowlist_declared, workspace_path FROM agents.sessions WHERE id = $1`,
        [sessionId],
      )
    )
    .then((r) => {
      // A MISSING row is not "nothing declared". Every session that reaches a
      // turn has a row (it is inserted at creation, and a declared scope is
      // written onto it before the turn is posted), so an empty result is a
      // failed read wearing a success's clothes — and caching it would restore
      // exactly the fail-open the catch below no longer allows.
      if (r.rows.length === 0) {
        throw new Error(`devx: session ${sessionId} has no agents.sessions row — refusing to run it unscoped`);
      }
      return remember(sessionId, parseSessionScopeRow(r.rows[0]));
    })
    // ONLY the pre-V14 shape (undefined_column) is "nothing declared", and only
    // that is cached. Any other failure — a connection blip on the first turn —
    // would otherwise drop the allowlist AND the workspace for the worker's
    // whole lifetime, so it fails the turn instead: same fail-safe posture as
    // agent.ts's filterTools throw on a cold snapshot.
    .catch((e) => {
      if (!isUndefinedColumn(e)) throw e;
      console.log(`devx: session ${sessionId} predates V14 (${pgErrorCode(e)}) — treating as nothing declared`);
      return remember(sessionId, NOTHING_DECLARED);
    })
    .finally(() => inFlight.delete(sessionId));
  inFlight.set(sessionId, p);
  return p.then(pin);
}

/** The already-loaded scope, for the synchronous hooks (filterTools,
 * resolveWorkspace) that cannot await. undefined = never loaded. */
export function peekSessionScope(sessionId: string): SessionScope | undefined {
  return loaded.get(sessionId);
}

/** Same, for a hook that holds the request's HookCtx: the ctx-pinned entry
 * first, so no amount of cache pressure can cold-start a live turn. */
export function peekSessionScopeForCtx(ctx: object, sessionId: string): SessionScope | undefined {
  return byCtx.get(ctx) ?? loaded.get(sessionId);
}

/**
 * The declared workspace, but only when it is a value devx itself could have
 * produced for THIS user: an isolated run worktree. Round-tripping the declared
 * path through devx's own generator and comparing for equality (not a prefix
 * test) rejects `..`, anything outside the managed base dir, and anything
 * shaped like an ensureWorkspace/ensureAppWorkspace result — and it does so
 * without depending on a per-turn metadata.appId. It matters because the
 * workspace is half of every consent scope key (service/scope-key.ts).
 */
export function acceptDeclaredWorkspace(
  declared: string | undefined,
  userId: string | undefined,
): string | undefined {
  if (!declared || !userId) return undefined;
  const segments = declared.split("/");
  const leaf = segments.pop();
  const marker = segments.pop();
  const app = segments.pop();
  if (leaf && app && marker === ".worktrees" && declared === getRunWorktreePath(userId, app, leaf)) return declared;
  console.log(`devx: declared workspace ${JSON.stringify(declared)} is not a run worktree for this session — falling back to the derived workspace`);
  return undefined;
}
