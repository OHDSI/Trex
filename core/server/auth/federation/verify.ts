// id_token validation. Everything downstream trusts whatever this function
// returns, so it enforces signature, issuer, audience, expiry, nonce AND the
// permitted algorithm set — an id_token that is merely well-formed proves
// nothing about who issued it.
//
// Named verifyFederatedIdToken, not verifyIdToken: oidc/id-token.ts already
// exports a verifyIdToken with a different signature (verifies a token this
// provider issued, against its own keys). Distinct names keep an import of one
// from silently compiling against the other.
import { createRemoteJWKSet, jwtVerify } from "npm:jose";
import type { DiscoveryDoc } from "./discovery.ts";

// One remote JWKS per issuer, reused across calls. jose caches keys and a
// kid-miss cooldown inside the object it returns from createRemoteJWKSet; a
// fresh one per sign-in would throw that away and put a JWKS fetch on every
// login instead of only after rotation.
const remoteSets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function remoteJwks(jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
  let set = remoteSets.get(jwksUri);
  if (!set) {
    set = createRemoteJWKSet(new URL(jwksUri));
    remoteSets.set(jwksUri, set);
  }
  return set;
}

export async function verifyFederatedIdToken(
  token: string,
  opts: {
    doc: DiscoveryDoc;
    clientId: string;
    nonce: string;
    // Test-only: injects a local JWKS (e.g. from createLocalJWKSet) so tests
    // run with no network. Lives in the signature, not in provider-derived
    // data, so it can never be triggered by anything a discovery document
    // carries. Production always omits it and resolves against jwks_uri.
    jwks?: Parameters<typeof jwtVerify>[1];
  },
): Promise<Record<string, unknown>> {
  const { doc, clientId, nonce } = opts;
  const jwks = opts.jwks ?? remoteJwks(doc.jwks_uri);

  const { payload } = await jwtVerify(token, jwks, {
    issuer: doc.issuer,
    audience: clientId,
    // Restrict to what the provider itself advertises. Without this an
    // attacker who can influence the JWKS (or force a downgrade) picks the
    // algorithm instead of the provider.
    algorithms: doc.id_token_signing_alg_values_supported,
  });

  // A caller-supplied nonce is required to mean anything; without the presence
  // check, a token that carries no nonce claim would verify against a caller
  // passing "" or undefined, defeating the replay protection nonce exists for.
  if (typeof nonce !== "string" || nonce.length === 0 || payload.nonce !== nonce) {
    throw new Error("id_token nonce does not match the authorization request");
  }
  return payload as Record<string, unknown>;
}
