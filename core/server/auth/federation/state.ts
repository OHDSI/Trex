// The `state` parameter: encrypted, then signed, rather than stored. It carries
// everything the callback needs (which provider, where to return to, the nonce
// and the PKCE verifier), so a callback requires no server-side lookup — the
// signature means none of it can be altered by the browser it travels through,
// and the encryption means none of it can be read there either.
//
// Why encrypted and not merely signed: the state rides in the same redirect URL
// as the authorization code, and that URL is written to the identity provider's
// logs and handed on in Referer headers. client_secret is optional — a provider
// registered as a public client authenticates with PKCE alone — so anyone who
// captured a plaintext state held both the code and its code_verifier, and
// could redeem the code upstream themselves. PKCE bought almost nothing.
//
// Why not a server-side store keyed by a state id: trex can run several
// replicas, and the callback is a fresh browser navigation that any of them may
// answer. A per-process store would refuse every sign-in whose callback landed
// on a different replica. (consumeState has that same per-process limitation
// today, but its failure mode is a weaker replay guarantee, not a broken
// sign-in.) Encryption keeps the state self-contained: every replica derives
// the same key from TREX_ROOT_KEY, so nothing has to be shared between them.
import { deriveSubkeyBase64, LABELS } from "../keys.ts";

export interface StatePayload {
  provider: string;
  redirectTo: string;
  nonce: string;
  verifier: string;
  /**
   * SHA-256 of the browser-binding value held in the federation cookie, which
   * ties this state to the browser that started the flow. Signing alone does
   * not do that: a signed state is valid in ANY browser, so an attacker who
   * starts a flow, authenticates as themselves and then hands the resulting
   * callback URL to a victim signs that victim into the attacker's account
   * (login CSRF). The hash rather than the value, so a state that ends up in a
   * log or a Referer still gives up nothing that would let it be replayed.
   */
  bind: string;
  /** Unix seconds. Short — this only has to survive one redirect round trip. */
  exp: number;
}

export const STATE_TTL_SECONDS = 600;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): Uint8Array {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = norm.length % 4 === 0 ? norm : norm + "=".repeat(4 - (norm.length % 4));
  return Uint8Array.from(atob(pad), (c) => c.charCodeAt(0));
}

/** AES-GCM nonce length. 96 bits is the size the mode is specified around. */
const IV_BYTES = 12;

/** The two keys a state is protected with, both derived from the root key. */
export interface StateKeys {
  /** HMAC-SHA-256 over the encoded body, like the agents OAuth broker's. */
  mac: CryptoKey;
  /** AES-256-GCM over the payload. */
  enc: CryptoKey;
}

export async function stateKeys(rootKey?: string): Promise<StateKeys> {
  const macRaw = await deriveSubkeyBase64(LABELS.federationState, rootKey);
  const encRaw = await deriveSubkeyBase64(LABELS.federationStateEncryption, rootKey);
  const [mac, enc] = await Promise.all([
    crypto.subtle.importKey(
      "raw",
      Uint8Array.from(atob(macRaw), (c) => c.charCodeAt(0)),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"],
    ),
    crypto.subtle.importKey(
      "raw",
      Uint8Array.from(atob(encRaw), (c) => c.charCodeAt(0)),
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    ),
  ]);
  return { mac, enc };
}

/**
 * `<base64url(iv ‖ ciphertext)>.<base64url(HMAC of that)>`.
 *
 * Encrypt-then-MAC: the signature covers the ciphertext, so a tampered state is
 * rejected before anything is decrypted, and the token keeps the shape (and the
 * single-use keying in consumeState) it already had.
 */
export async function signState(payload: StatePayload, keys: StateKeys): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
      keys.enc,
      encoder.encode(JSON.stringify(payload)).buffer as ArrayBuffer,
    ),
  );
  const sealed = new Uint8Array(iv.length + ciphertext.length);
  sealed.set(iv);
  sealed.set(ciphertext, iv.length);

  const body = b64url(sealed);
  const sig = await crypto.subtle.sign("HMAC", keys.mac, encoder.encode(body));
  return `${body}.${b64url(new Uint8Array(sig))}`;
}

export async function verifyState(
  token: string,
  keys: StateKeys,
  now: number = Math.floor(Date.now() / 1000),
): Promise<StatePayload> {
  const dot = token.indexOf(".");
  if (dot === -1) throw new Error("state is malformed");
  const body = token.slice(0, dot);
  const provided = token.slice(dot + 1);

  const expected = b64url(
    new Uint8Array(await crypto.subtle.sign("HMAC", keys.mac, encoder.encode(body))),
  );
  // Length-independent comparison is unnecessary here (both are fixed-length
  // base64 of a SHA-256 MAC), but constant-time comparison still matters.
  if (!constantTimeEquals(provided, expected)) throw new Error("state signature is invalid");

  const sealed = b64urlDecode(body);
  if (sealed.length <= IV_BYTES) throw new Error("state is malformed");
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: sealed.slice(0, IV_BYTES).buffer as ArrayBuffer },
        keys.enc,
        sealed.slice(IV_BYTES).buffer as ArrayBuffer,
      ),
    );
  } catch {
    // The MAC already passed, so this is a body sealed under a different
    // encryption key — a root-key rotation mid-flow, or two deployments
    // sharing a MAC key they should not. Either way it is not ours to read.
    throw new Error("state could not be decrypted");
  }

  const payload = JSON.parse(decoder.decode(plaintext)) as StatePayload;
  if (payload.exp <= now) throw new Error("state has expired");
  return payload;
}

/**
 * Compares two same-alphabet strings without leaking where they first
 * differ. Shared with the browser-binding check, which compares a value an
 * attacker supplies against one they are trying to guess.
 *
 * `expected` must be the value this server just computed (an HMAC or a
 * SHA-256 digest, both fixed-length base64url) — callers keep it in that
 * position at both call sites. The loop below is bounded by
 * `expected.length`, never by `candidate.length`, so an attacker who
 * controls `candidate` cannot influence how much work the comparison does:
 * a `candidate` longer than `expected` is refused up front without the
 * loop ever running.
 */
export function constantTimeEquals(candidate: string, expected: string): boolean {
  if (candidate.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= candidate.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

/**
 * The form the browser-binding value takes inside the signed state. A plain
 * digest, not an HMAC: the state it travels in is already signed, so this only
 * has to be irreversible, and keeping it keyless means it can be recomputed in
 * a test without deriving anything.
 */
export async function hashBinding(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return b64url(new Uint8Array(digest));
}
