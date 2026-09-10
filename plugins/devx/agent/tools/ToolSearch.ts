// Task 15: reveals and activates this agent's deferred tools (lib/
// deferred_tools.ts's DEFERRED_TOOLS, wired into agent.ts's
// context.deferredTools in Task 16) by ranked name/description search.
//
// Unlike every other ported tools/<name>.ts file in this directory, this
// one does NOT go through wrap()/toDevxCtx (lib/context.ts): the legacy
// AgentContext that adapter builds has no notion of "activate a tool for
// this session" (nor any need for one, on the AI-SDK loop, where every tool
// is always visible). This file talks to eve's raw ToolContext directly and
// uses its ToolContext.activateTools capability (core/server/agents/
// eve-shim/types.ts, wired in toolset.ts's authoredTool) instead -- the
// narrow "activate my own session's deferred tools" write, not the whole
// AgentStore.
//
// Candidates are read from the legacy TOOL_DEFINITIONS registry (name +
// description -- the same catalog every OTHER ported tool's description
// ultimately traces back to), filtered down to this agent's deferred set.
// Importing registry.ts directly here (not tool_search.ts) is the SAFE
// direction of the pre-existing registry.ts<->tool_search.ts import cycle:
// registry.ts's `TOOL_DEFINITIONS` array literal reads the not-yet-
// initialized `toolSearchTool` binding at module-eval time if tool_search.ts
// is entered first (see that file's own header comment for the full TDZ
// story) -- entering via registry.ts, as this file does, reproduces the
// safe production order instead.
import { defineTool } from "eve/tools";
import type { ToolContext } from "eve/core/eve-shim/types.ts";
import { TOOL_DEFINITIONS } from "../../functions/tools/registry.ts";
import { DEFERRED_TOOLS } from "../lib/deferred_tools.ts";

const NAME_WEIGHT = 3;
const DESC_WEIGHT = 1;
const MAX_RESULTS = 10;

/**
 * Splits text into lowercase whole words. Tool names are PascalCase
 * (`DatabaseSchema`, `ExecuteSQL`, `KBSearch`), so case boundaries are word
 * boundaries here just as much as spaces and punctuation are: an acronym run
 * followed by a capitalized word splits between the two (`KBSearch` ->
 * `kb`,`search`), and a letter/digit boundary splits as well.
 */
function tokenize(text: string): Set<string> {
  const spaced = text
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/([a-zA-Z])([0-9])/g, "$1 $2");
  return new Set(spaced.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean));
}

/**
 * Ranks candidates by query-term match count, weighting a name match above a
 * description match, and returns the top MAX_RESULTS. Pure -- no I/O, no
 * agent/session state -- so it's directly testable (../lib/tool_search.test.ts)
 * without a loaded agent or store. The previous implementation (a substring
 * filter, delegated wholesale to the legacy toolSearchTool) could not rank
 * at all -- every match was equally relevant, in registry order.
 *
 * Terms match WHOLE TOKENS, not substrings. Substring containment made every
 * short term a wildcard over longer unrelated words: "knowledge base" scored
 * the DB tools highest, because "base" is inside "database" and a name hit
 * outweighs a description hit -- so the query that should surface the
 * knowledge-base tools surfaced ExecuteSQL/DatabaseSchema/TableData instead.
 */
export function rankDeferredTools<T extends { name: string; description: string }>(
  query: string,
  candidates: T[],
): T[] {
  const terms = [...tokenize(query)];
  if (terms.length === 0) return [];
  return candidates
    .map((c) => {
      const name = tokenize(c.name);
      const desc = tokenize(c.description);
      const score = terms.reduce(
        (s, t) => s + (name.has(t) ? NAME_WEIGHT : 0) + (desc.has(t) ? DESC_WEIGHT : 0),
        0,
      );
      return { c, score };
    })
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, MAX_RESULTS)
    .map((x) => x.c);
}

const DEFERRED_SET = new Set(DEFERRED_TOOLS);
/**
 * The corpus this tool actually searches. Exported so
 * ../lib/deferred_tools.test.ts can assert that agent.ts's
 * DEFERRED_TOOLS_NOTE still names a category leading to every deferred tool
 * -- against the real candidates, not a hand-written stand-in that could
 * drift from the registry.
 */
export const DEFERRED_TOOL_CANDIDATES: { name: string; description: string }[] = TOOL_DEFINITIONS
  .filter((t) => DEFERRED_SET.has(t.name))
  .map((t) => ({ name: t.name, description: t.description }));
const CANDIDATES = DEFERRED_TOOL_CANDIDATES;

export default defineTool({
  description:
    "Search for tools not currently in your tool list (knowledge base, scheduled tasks, " +
    "Figma, browser automation, database inspection, image generation, and more) by name " +
    "or description. A match becomes callable starting with your NEXT message, not this one.",
  inputSchema: {
    type: "object",
    properties: {
      query: { type: "string", description: "Search query to match against tool names and descriptions" },
    },
    required: ["query"],
  },
  execute: async (input: unknown, ctx?: ToolContext) => {
    const { query } = input as { query: string };
    const matches = rankDeferredTools(query, CANDIDATES);
    if (matches.length === 0) return `No tools found matching "${query}".`;
    // Persisted so the match stays visible on every LATER turn of this
    // session too, not just this one (see store.ts's activateTools) --
    // safe to skip when no store was wired (e.g. a bare unit test ctx).
    await ctx?.activateTools?.(matches.map((m) => m.name));
    const lines = matches.map((t) => `- **${t.name}**: ${t.description}`);
    return `Found ${matches.length} tool(s), now available starting with your next message:\n${lines.join("\n")}`;
  },
});
