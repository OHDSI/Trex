// Provider metadata, fetched once and cached. Fetching it per sign-in would put
// an upstream outage directly in the login path; caching it forever would make
// a key rotation permanent breakage, so it is refetched once the cache entry
// is older than DISCOVERY_TTL_SECONDS.
export interface DiscoveryDoc {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  id_token_signing_alg_values_supported: string[];
}

export const DISCOVERY_TTL_SECONDS = 3600;

// Asymmetric algorithms suitable for verifying id_tokens against a JWKS.
// Excludes "none" (algorithm-confusion vector) and HS* (symmetric, inappropriate for third-party verification).
const ALLOWED_SIGNING_ALGS = new Set(["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]);

const cache = new Map<string, { doc: DiscoveryDoc; fetchedAt: number }>();

export function clearDiscoveryCache(): void {
  cache.clear();
}

export async function loadDiscovery(
  url: string,
  fetchImpl: typeof fetch = fetch,
  now: number = Math.floor(Date.now() / 1000),
): Promise<DiscoveryDoc> {
  const hit = cache.get(url);
  if (hit && now - hit.fetchedAt < DISCOVERY_TTL_SECONDS) return hit.doc;

  const res = await fetchImpl(url);
  if (!res.ok) throw new Error(`discovery fetch failed: ${res.status}`);
  // Untyped on purpose: this is attacker-influenced JSON from the network, not
  // a DiscoveryDoc yet. Read from it field-by-field below rather than casting,
  // so an unexpected key (e.g. one a later feature interprets specially) can
  // never ride along onto the document the rest of the code trusts.
  const raw = await res.json() as Record<string, unknown>;

  for (const field of ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"] as const) {
    if (typeof raw[field] !== "string" || (raw[field] as string).length === 0) {
      throw new Error(`discovery document is incomplete: missing ${field}`);
    }
  }

  // Absent means "assume RS256", per OIDC Discovery. Recorded explicitly so
  // verify.ts never has to treat undefined as "anything goes".
  const advertised = Array.isArray(raw.id_token_signing_alg_values_supported)
    ? raw.id_token_signing_alg_values_supported as string[]
    : ["RS256"];

  // Filter to asymmetric algorithms only. Rejects "none" (algorithm-confusion vector) and
  // HS* (symmetric, unsuitable for verifying third-party signatures against their JWKS).
  const filtered = advertised.filter(alg => ALLOWED_SIGNING_ALGS.has(alg));
  if (filtered.length === 0) {
    throw new Error(`discovery document lists no usable signing algorithms; advertised: ${advertised.join(", ")}`);
  }

  const doc: DiscoveryDoc = {
    issuer: raw.issuer as string,
    authorization_endpoint: raw.authorization_endpoint as string,
    token_endpoint: raw.token_endpoint as string,
    jwks_uri: raw.jwks_uri as string,
    ...(typeof raw.userinfo_endpoint === "string" ? { userinfo_endpoint: raw.userinfo_endpoint } : {}),
    id_token_signing_alg_values_supported: Object.freeze(filtered) as string[],
  };

  // Freeze to prevent mutations from poisoning the cache. The algorithm array is frozen
  // separately above to catch poisoning on the field that matters most for security.
  cache.set(url, { doc: Object.freeze(doc), fetchedAt: now });
  return doc;
}
