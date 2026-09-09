// id_token validation. Everything downstream trusts whatever this function
// returns, so it enforces signature, issuer, audience, expiry, nonce AND the
// permitted algorithm set — an id_token that is merely well-formed proves
// nothing about who issued it.
import { createLocalJWKSet, createRemoteJWKSet, jwtVerify } from "npm:jose";
import type { DiscoveryDoc } from "./discovery.ts";

export async function verifyIdToken(
  token: string,
  opts: { doc: DiscoveryDoc; clientId: string; nonce: string },
): Promise<Record<string, unknown>> {
  const { doc, clientId, nonce } = opts;

  // Tests inject a JWKS directly via `_jwks` so verification runs without a
  // network round trip. Production never sets this field, so it always falls
  // through to the real jwks_uri, where jose owns caching and kid rotation.
  const local = (doc as DiscoveryDoc & { _jwks?: unknown })._jwks;
  const jwks = local
    ? createLocalJWKSet(local as Parameters<typeof createLocalJWKSet>[0])
    : createRemoteJWKSet(new URL(doc.jwks_uri));

  const { payload } = await jwtVerify(token, jwks, {
    issuer: doc.issuer,
    audience: clientId,
    // Restrict to what the provider itself advertises. Without this an
    // attacker who can influence the JWKS (or force a downgrade) picks the
    // algorithm instead of the provider.
    algorithms: doc.id_token_signing_alg_values_supported,
  });

  if (payload.nonce !== nonce) {
    throw new Error("id_token nonce does not match the authorization request");
  }
  return payload as Record<string, unknown>;
}
