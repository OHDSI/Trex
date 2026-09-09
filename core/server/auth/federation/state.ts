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
  /** Unix seconds. Short — this only has to survive one redirect round trip. */
  exp: number;
}

export const STATE_TTL_SECONDS = 600;

const encoder = new TextEncoder();

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** HMAC key for state, derived from the root key like the agents OAuth broker's. */
export async function stateKey(rootKey?: string): Promise<CryptoKey> {
  const raw = await deriveSubkeyBase64(LABELS.agentsOAuthState, rootKey);
  return crypto.subtle.importKey(
    "raw",
    Uint8Array.from(atob(raw), (c) => c.charCodeAt(0)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export async function signState(payload: StatePayload, key: CryptoKey): Promise<string> {
  const body = btoa(JSON.stringify(payload)).replace(/=+$/, "");
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
  if (provided.length !== expected.length) throw new Error("state signature is invalid");
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= provided.charCodeAt(i) ^ expected.charCodeAt(i);
  if (diff !== 0) throw new Error("state signature is invalid");

  const payload = JSON.parse(atob(body)) as StatePayload;
  if (payload.exp <= now) throw new Error("state has expired");
  return payload;
}
