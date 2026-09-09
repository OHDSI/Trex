// Whether an upstream identity may become, or join, a trex user.
//
// The rule that matters: an unverified upstream email links to nothing, ever.
// A provider that lets someone set an address they do not control would
// otherwise be a takeover path into any existing account with that address.
import type { ProviderConfig, UpstreamIdentity } from "./types.ts";

export type LinkDecision =
  | { action: "link"; userId: string }
  | { action: "provision" }
  | { action: "refuse"; reason: string };

export function decideLink(
  identity: UpstreamIdentity,
  provider: ProviderConfig,
  existingUserId: string | null,
): LinkDecision {
  if (!identity.emailVerified) {
    return { action: "refuse", reason: "upstream_email_unverified" };
  }
  if (existingUserId) {
    return { action: "link", userId: existingUserId };
  }
  if (provider.autoProvision) {
    return { action: "provision" };
  }
  return { action: "refuse", reason: "no_account" };
}
