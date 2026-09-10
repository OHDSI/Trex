// Whether an upstream identity may become, or join, a trex user.
//
// The rule that matters: an unverified upstream email links to nothing, ever.
// A provider that lets someone set an address they do not control would
// otherwise be a takeover path into any existing account with that address.
//
// Two further guards, both optional and both applying ONLY to an upstream
// identity seen for the first time (an identity that already has an account
// row is an established link and never reaches this module):
//
//   * `emailDomainAllowlist` — a verified address is still only as trustworthy
//     as the provider that asserted it. With several upstreams configured,
//     nothing in the flow otherwise stops the least-trusted of them asserting
//     an address in a domain it has no authority over.
//   * `allowElevatedAutoLink` — even inside an allowed domain, silently handing
//     a federated identity an existing *administrator's* account is a decision
//     a deployment should make on purpose, not a default.
import type { ProviderConfig, UpstreamIdentity } from "./types.ts";

/** The trex user an upstream address resolved to, as far as linking cares. */
export interface ExistingUser {
  id: string;
  /** trexdb."user".role: 'user' (or NULL) by default, 'admin' for a trex admin. */
  role: string | null;
}

export type LinkDecision =
  | { action: "link"; userId: string }
  | { action: "provision" }
  // Fixed codes, never upstream text: they are returned to a browser.
  // "upstream_email_unverified" | "email_domain_not_allowed" |
  // "elevated_account_link_refused" | "no_account" from here, and
  // "account_disabled" from resolveFederatedUser's existing-link path.
  | { action: "refuse"; reason: string };

/**
 * The domain part of an address, lower-cased, or null if there isn't one.
 *
 * Split on the LAST '@', not the first: a local part may legitimately contain
 * one when quoted (`"a@b"@example.test`), and an attacker who controls the
 * local part at a permissive upstream would otherwise choose what trex reads
 * as the domain — `"victim@allowed.test"@attacker.test` must resolve to
 * attacker.test, never allowed.test.
 */
export function emailDomain(email: string): string | null {
  const at = email.lastIndexOf("@");
  // at <= 0 covers both "no @ at all" and an empty local part.
  if (at <= 0 || at === email.length - 1) return null;
  return email.slice(at + 1).toLowerCase();
}

/**
 * `null`/empty allowlist means unrestricted, which is the pre-existing
 * behaviour and what every existing row has.
 *
 * An address whose domain cannot be determined is refused whenever a list is
 * set — a restriction that cannot be evaluated must not pass.
 */
export function emailDomainAllowed(email: string, allowlist: string[] | null): boolean {
  if (!allowlist || allowlist.length === 0) return true;
  const domain = emailDomain(email);
  if (!domain) return false;
  // Domains are case-insensitive. loadProviders already lower-cases the stored
  // list; doing it again here costs nothing and keeps this function correct for
  // any caller, including a test that passes a list straight in.
  return allowlist.some((entry) => entry.trim().toLowerCase() === domain);
}

/**
 * Whether a trex user holds more than an ordinary account.
 *
 * `trexdb."user".role` is trex's own system role (distinct from the named
 * application roles in `user_role`): it defaults to 'user', is set to 'admin'
 * for the first user / ADMIN_EMAIL, and is what auth-router's admin endpoints
 * gate on. So the only *non*-elevated values are the default ones.
 *
 * Deliberately "anything that is not 'user'" rather than "=== 'admin'": those
 * admin gates are equality checks against a name, so a deployment that adds a
 * further privileged value later would silently fall outside a check written
 * the other way round. Erring towards "elevated" costs an operator one opt-in
 * flag; erring the other way costs an account.
 */
export function isElevatedRole(role: string | null | undefined): boolean {
  if (role === null || role === undefined) return false;
  const normalised = role.trim().toLowerCase();
  return normalised !== "" && normalised !== "user";
}

export function decideLink(
  identity: UpstreamIdentity,
  provider: ProviderConfig,
  existing: ExistingUser | null,
): LinkDecision {
  if (!identity.emailVerified) {
    return { action: "refuse", reason: "upstream_email_unverified" };
  }
  // Before either branch: an address outside the allowlist is not this
  // provider's to speak for, so it may neither claim an existing account nor
  // mint a new one.
  if (!emailDomainAllowed(identity.email, provider.emailDomainAllowlist)) {
    return { action: "refuse", reason: "email_domain_not_allowed" };
  }
  if (existing) {
    if (isElevatedRole(existing.role) && !provider.allowElevatedAutoLink) {
      return { action: "refuse", reason: "elevated_account_link_refused" };
    }
    return { action: "link", userId: existing.id };
  }
  if (provider.autoProvision) {
    // Provisioning creates a role-'user' row (see provisionUser), so it cannot
    // produce an elevated account and needs no guard of its own.
    return { action: "provision" };
  }
  return { action: "refuse", reason: "no_account" };
}
