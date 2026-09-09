// PKCE (RFC 7636, S256 only). Mandatory on every provider: without it an
// intercepted authorization code can be redeemed by whoever intercepted it.
const UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

export function createVerifier(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(64));
  let out = "";
  for (const b of bytes) out += UNRESERVED[b % UNRESERVED.length];
  return out;
}

export async function challengeFor(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
