// Group resolution: step 6 of the flow.
//
// trex resolves group membership; d2e maps groups to roles. That seam is why
// nothing here interprets what it reads — the values are opaque identifiers as
// the upstream states them (Entra group GUIDs, Logto role names), and any
// meaning they carry belongs to the relying party.
import type { ProviderConfig } from "./types.ts";

/**
 * The groups a validated id_token asserts, per the provider's groups_source.
 *
 * - `claim`  — the value of `groups_claim`, passed through RAW: no sorting, no
 *              de-duplication, no case folding, no filtering. A relying party
 *              that receives a different list from the one the upstream issued
 *              cannot reason about it.
 * - `none`   — nothing.
 * - `graph`  — nothing, for now. The MS Graph resolver is a later phase
 *              (spec: "Phasing", 4); returning [] here is what that phase
 *              replaces, and is the same non-fatal empty list the current
 *              connector falls back to when Graph fails.
 *
 * Never throws. A provider that is misconfigured, or an upstream that omits
 * the claim or puts something other than an array of strings in it, yields an
 * empty list — a sign-in must not fail over group metadata.
 *
 * An array whose members are not all strings is treated as no group list at
 * all rather than filtered down to the strings in it: dropping members
 * silently would hand the relying party a partial membership that looks
 * complete, which is worse than none.
 */
export function resolveGroups(
  claims: Record<string, unknown>,
  provider: Pick<ProviderConfig, "groupsSource" | "groupsClaim">,
): string[] {
  if (provider.groupsSource !== "claim") return [];
  const name = provider.groupsClaim;
  if (typeof name !== "string" || name.length === 0) return [];

  const raw = claims[name];
  if (!Array.isArray(raw)) return [];
  if (!raw.every((v) => typeof v === "string")) return [];
  return raw as string[];
}
