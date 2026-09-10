// V3 (task-v3-brief.md): port of functions/agent.ts's Phase 6 MCP tool
// injection (~350-444) as eve's dynamic-tools.ts contract (H2). Called by
// core's buildSdkTools() fresh on every top-level turn (never cached, never
// at subagent depth) with the same per-request HookCtx resolveModel/
// filterTools/buildInstructions get — see core/server/agents/loader.ts and
// service/toolset.ts.
//
// Task 8 (agents-connections): the HTTP MCP realization here now routes
// through the SHARED connection layer (core/server/agents/connections/mcp.ts's
// realizeMcp + formatMcpResult), the same connect/list/callTool/format
// mechanism a file-based `connections/*.ts` MCP connection uses — deleting the
// devx-specific duplication of that HTTP client path (which mcp.ts's header
// notes it mirrors). Only the RUNTIME realization changed: a devx.mcp_servers
// ROW is mapped to an MCP ConnectionDef and realized through realizeMcp, then
// mapped back to the SAME `mcp_<server>_<tool>` ToolDef shape (name +
// needsApproval + description + inputSchema) the legacy path produced — parity
// is byte-identical (see lib/dynamic_tools.test.ts's parity checks). The
// per-user mcp_servers UI/storage (functions/routes/mcp_routes.ts) and the
// legacy AI-SDK loop's own Phase 6 injection (functions/agent.ts, flag
// `loop != "agents"`) are UNTOUCHED — this file is only reached on the
// agents-loop path.
//
// stdio transport stays on mcpManager: the shared ConnectionDef is URL/HTTP
// only (no command/args/env; realizeMcp's defaultConnect builds only
// HTTP/SSE transports), so a `transport:"stdio"` row cannot be expressed as a
// connection def. mcp.ts only ever duplicated the HTTP client path, so keeping
// stdio on mcpManager is not residual duplication — it is the sole
// implementation of that transport, realized here exactly as before.
//
// Placement note: this file lives at the agent-dir ROOT (plugins/devx/agent/
// dynamic-tools.ts), NOT inside tools/ — loader.ts scans those as two
// separate, non-overlapping steps (a dynamic-tools.ts placed inside tools/
// would just hit the tools/ loop's __trexTool brand-mismatch error like any
// other stray file there).
import { defineToolProvider } from "eve/tools";
// Type-only: see agent.ts's header comment for why ToolDef/HookCtx come from
// core's eve-shim here rather than "eve"'s public surface / "eve" directly
// for the type (HookCtx IS re-exported by "eve", used here as a type only).
import type { HookCtx, ToolDef } from "eve/core/eve-shim/types.ts";
import type { ConnectionDef } from "eve/core/connections/types.ts";
import {
  formatMcpResult,
  hashResolvedAuth,
  type McpConnectFn,
  realizeMcp,
} from "eve/core/connections/mcp.ts";
import { mcpManager } from "../functions/mcp_manager.ts";

interface McpServerRow {
  name: string;
  transport: "stdio" | "http";
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
}

// Cache-key namespace fed to realizeMcp's client cache (which keys by
// `${agentDir} ${conn.name} ${authHash}`). devx.mcp_servers rows are PER USER
// (schema `UNIQUE(user_id, name)`), so the cache MUST be user-scoped: two
// users can each name a server "github" pointing at different urls with no
// auth headers → identical (conn.name, authHash) → without the userId
// dimension realizeMcp would hand user B the client (and endpoint) user A
// connected. Folding userId into the agentDir slot (realizeMcp treats it as an
// opaque cache-key segment, nothing else) keeps every user's client isolated.
const CACHE_NS = "devx-dynamic-mcp";

// Logged at most once per process — this is an operational/config note
// ("no request identity, MCP tools unavailable this turn"), not a per-call
// error worth spamming every turn.
let warnedNoIdentity = false;

// The legacy ToolDef contract (functions/agent.ts:367-379 and the pre-Task-8
// dynamic-tools.ts): tool name `mcp_<server>_<tool>`, description
// `[MCP: <server>] <desc>`, inputSchema `{type:"object", ...schema}`,
// needsApproval ALWAYS true (an MCP tool with no explicit consent row is never
// auto-approved — core's sticky always/never consent store now owns the
// per-call decision the legacy devx.mcp_tool_consents read used to). Both
// realizer branches (shared realizeMcp for http, mcpManager for stdio) funnel
// through this so the produced tool set is identical regardless of which ran.
function mcpToolDef(
  serverName: string,
  toolName: string,
  description: string,
  inputSchema: Record<string, unknown>,
  execute: (input: unknown) => Promise<string>,
): { name: string; def: ToolDef } {
  return {
    name: `mcp_${serverName}_${toolName}`,
    def: {
      description: `[MCP: ${serverName}] ${description}`,
      inputSchema: { type: "object", ...inputSchema },
      needsApproval: true,
      execute: (input: unknown) => execute(input),
    },
  };
}

// Extracted from the default export so tests can inject a fake `connect`
// (realizeMcp's connect seam) and exercise the http realization end-to-end
// without a live MCP server. Production calls it with the default connect.
export async function buildDevxMcpTools(
  ctx: HookCtx,
  connect?: McpConnectFn,
): Promise<Record<string, ToolDef>> {
  if (!ctx.userId || !ctx.sql) {
    if (!warnedNoIdentity) {
      console.warn("devx dynamic-tools: no userId/sql on this request — skipping MCP tools");
      warnedNoIdentity = true;
    }
    return {};
  }
  const userId = ctx.userId;

  const mcpServersResult = await ctx.sql(
    `SELECT name, transport, command, args, env, url, headers
     FROM devx.mcp_servers WHERE user_id = $1 AND enabled = true`,
    [userId],
  );
  const servers = mcpServersResult.rows as McpServerRow[];
  if (servers.length === 0) return {};

  const tools: Record<string, ToolDef> = {};

  // stdio → mcpManager (untouched; the shared layer can't express stdio). Not
  // wrapped in an extra try/catch: mcpManager.getTools already skips a failing
  // server internally, and a genuine throw propagates to buildSdkTools, which
  // logs it and continues with the static tool set — same posture as before.
  const stdioServers = servers.filter((s) => s.transport === "stdio");
  if (stdioServers.length > 0) {
    const mcpTools = await mcpManager.getTools(userId, stdioServers);
    for (const t of mcpTools) {
      const { name, def } = mcpToolDef(
        t.serverName,
        t.name,
        t.description,
        t.inputSchema,
        (input) => mcpManager.executeTool(userId, t.serverName, t.name, input),
      );
      tools[name] = def;
    }
  }

  // http → shared realizeMcp. Each server is realized in its own try/catch so
  // one unreachable/misconfigured server yields nothing while the others still
  // contribute their tools (mirrors mcpManager.getTools's per-server skip and
  // the shared connection provider's H2 log+continue posture — a broken server
  // never fails the turn).
  const httpServers = servers.filter((s) => s.transport !== "stdio");
  for (const row of httpServers) {
    try {
      const headers = row.headers ?? {};
      const conn: ConnectionDef = {
        __trexConnection: true,
        type: "mcp",
        name: row.name,
        description: `devx MCP server ${row.name}`,
        url: row.url,
        headers,
      };
      const authHash = await hashResolvedAuth(headers);
      const { client, tools: realized } = await realizeMcp(
        conn,
        headers,
        `${CACHE_NS}:${userId}`,
        authHash,
        connect,
      );
      for (const rt of realized) {
        const remoteName = rt.name;
        const { name, def } = mcpToolDef(
          row.name,
          remoteName,
          rt.description,
          rt.inputSchema,
          async (input) => formatMcpResult(await client.callTool({ name: remoteName, arguments: input })),
        );
        tools[name] = def;
      }
    } catch (e) {
      console.error(
        `devx dynamic-tools: MCP server "${row.name}" failed to realize — skipping its tools this turn: ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    }
  }

  return tools;
}

export default defineToolProvider((ctx: HookCtx): Promise<Record<string, ToolDef>> => buildDevxMcpTools(ctx));
