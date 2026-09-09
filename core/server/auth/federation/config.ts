// Provider configuration and claim normalisation. No database, no express:
// pure functions of their input so they can be tested directly.
import type { UpstreamIdentity } from "./types.ts";

/** Off unless explicitly enabled, like the native IdP and the OIDC provider. */
export function federationEnabled(
  raw: string | undefined = Deno.env.get("TREX_FEDERATION_ENABLED"),
): boolean {
  return raw === "true" || raw === "1";
}

/**
 * Upstream providers disagree about claim names — Entra calls the subject `oid`
 * and the address `upn`. `claim_map` moves those onto canonical fields so the
 * rest of the flow never branches per provider. An unmapped field falls back to
 * its standard OIDC name.
 */
export function applyClaimMap(
  claims: Record<string, unknown>,
  map: Record<string, string>,
): UpstreamIdentity {
  const read = (field: string) => claims[map[field] ?? field];

  const sub = read("sub");
  if (typeof sub !== "string" || sub.length === 0) {
    throw new Error("upstream id_token carries no usable subject");
  }
  const email = read("email");
  if (typeof email !== "string" || email.length === 0) {
    throw new Error("upstream id_token carries no usable email");
  }
  const name = read("name");
  // Absent means unverified. Never default this to true: the whole link policy
  // rests on it.
  const verified = read("email_verified") === true;

  return {
    sub,
    email,
    ...(typeof name === "string" ? { name } : {}),
    emailVerified: verified,
  };
}
