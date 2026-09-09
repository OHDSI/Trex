// The `state` parameter, signed rather than stored. It carries everything the
// callback needs (which provider, where to return to, the nonce and the PKCE
// verifier), so a callback requires no server-side lookup — and because it is
// signed, none of it can be altered by the browser it travels through.
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

/** HMAC key for state, derived from the root key like the agents OAuth broker's. */
export async function stateKey(rootKey?: string): Promise<CryptoKey> {
  const raw = await deriveSubkeyBase64(LABELS.federationState, rootKey);
  return crypto.subtle.importKey(
    "raw",
    Uint8Array.from(atob(raw), (c) => c.charCodeAt(0)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export async function signState(payload: StatePayload, key: CryptoKey): Promise<string> {
  const body = b64url(encoder.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
  return `${body}.${b64url(new Uint8Array(sig))}`;
}

export async function verifyState(
  token: string,
  key: CryptoKey,
  now: number = Math.floor(Date.now() / 1000),
): Promise<StatePayload> {
  const dot = token.indexOf(".");
  if (dot === -1) throw new Error("state is malformed");
  const body = token.slice(0, dot);
  const provided = token.slice(dot + 1);

  const expected = b64url(
    new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(body))),
  );
  // Length-independent comparison is unnecessary here (both are fixed-length
  // base64 of a SHA-256 MAC), but constant-time comparison still matters.
  if (!constantTimeEquals(provided, expected)) throw new Error("state signature is invalid");

  const payload = JSON.parse(decoder.decode(b64urlDecode(body))) as StatePayload;
  if (payload.exp <= now) throw new Error("state has expired");
  return payload;
}

/**
 * Compares two same-alphabet strings without leaking where they first differ.
 * Shared with the browser-binding check, which compares a value an attacker
 * supplies against one they are trying to guess.
 */
export function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
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
