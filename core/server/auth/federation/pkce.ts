// PKCE (RFC 7636, S256 only). Mandatory on every provider: without it an
// intercepted authorization code can be redeemed by whoever intercepted it.
const UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

/** RFC 7636's minimum verifier length. We generate at this length exactly. */
const VERIFIER_LENGTH = 64;

// A byte mod UNRESERVED.length is biased: 256 is not a multiple of 66, so the
// low 256 % 66 = 58 symbols would land 4/256 of the time and the rest 3/256.
// Rejection sampling removes the bias instead of accepting it: only keep
// bytes below the largest multiple of the alphabet length that still fits in
// a byte (floor(256 / 66) * 66 = 198), and redraw the rest. Every kept byte
// then maps onto the alphabet uniformly, at the cost of discarding ~22.7% of
// the bytes we draw (58 in 256), so we pull extra randomness to keep the
// output length exact without a variable number of retries.
const REJECTION_BOUND = Math.floor(256 / UNRESERVED.length) * UNRESERVED.length;

export function createVerifier(): string {
  const chars: string[] = [];
  // Draw more bytes than needed up front (rejection discards under a quarter
  // of them) so the common case needs no second call to getRandomValues.
  let pool = crypto.getRandomValues(new Uint8Array(VERIFIER_LENGTH * 2));
  let offset = 0;
  while (chars.length < VERIFIER_LENGTH) {
    if (offset >= pool.length) {
      pool = crypto.getRandomValues(new Uint8Array(VERIFIER_LENGTH * 2));
      offset = 0;
    }
    const b = pool[offset++];
    if (b >= REJECTION_BOUND) continue;
    chars.push(UNRESERVED[b % UNRESERVED.length]);
  }
  return chars.join("");
}

export async function challengeFor(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
