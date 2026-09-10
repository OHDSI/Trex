const encoder = new TextEncoder();

export const LABELS = {
  betterAuthSession: "trex.better-auth.session.v1",
  jwtHs256: "trex.jwt.hs256.v1",
  pgmetaAes: "trex.pgmeta.aes.v1",
  dekWrap: "trex.dek.wrap.v1",
  devxTokenAes: "trex.devx.token.aes.v1",
  // HMAC key for the agents OAuth broker's signed `state` (anti-CSRF/replay on
  // the auth-exempt consent routes). Derived from the root key so no separate
  // secret needs provisioning; rotating the root key rotates it.
  agentsOAuthState: "trex.agents.oauth.state.v1",
  // HMAC key for the OIDC federation relying-party's signed `state` (carries
  // provider, return path, nonce and PKCE verifier through the browser
  // redirect). A distinct subkey from agentsOAuthState above: same pattern
  // (derived from the root key, no separate provisioning), but a different
  // label — sharing one HMAC key across two unrelated signing contexts would
  // let a MAC minted for one verify in the other over the same bytes.
  federationState: "trex.federation.state.v1",
  // AES-GCM key for the SAME state's body. The state is signed for integrity
  // and encrypted for confidentiality, because it carries the PKCE
  // code_verifier and travels in the same URL as the authorization code — a
  // URL that lands in the identity provider's logs and in Referer headers.
  // A separate label from federationState above: one key, two primitives is
  // exactly the key-reuse this scheme's per-purpose subkeys exist to avoid.
  federationStateEncryption: "trex.federation.state.enc.v1",
} as const;

export type SubkeyLabel = typeof LABELS[keyof typeof LABELS];

const SALT = encoder.encode("trex/v1");

function b64decode(s: string): Uint8Array {
  // tolerate url-safe and padding-less variants
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = norm.length % 4 === 0 ? norm : norm + "=".repeat(4 - (norm.length % 4));
  const bin = atob(pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

let _cached: Uint8Array | null = null;

export function getRootKey(): Uint8Array {
  if (_cached) return _cached;
  const raw = Deno.env.get("TREX_ROOT_KEY");
  if (!raw) {
    throw new Error(
      "TREX_ROOT_KEY is not set. The trex-init container is responsible for " +
      "generating and exporting it; see scripts/derive-secrets.ts.",
    );
  }
  let bytes: Uint8Array;
  try { bytes = b64decode(raw); } catch {
    throw new Error("TREX_ROOT_KEY is not valid base64");
  }
  if (bytes.length < 32) {
    throw new Error(
      `TREX_ROOT_KEY must decode to at least 32 bytes, got ${bytes.length}`,
    );
  }
  _cached = bytes.slice(0, 32);
  return _cached;
}

/** Test-only. Drops the cached root so a new TREX_ROOT_KEY env value is honored. */
export function _resetRootKeyCache(): void { _cached = null; }

export async function deriveSubkey(
  label: SubkeyLabel,
  root: Uint8Array = getRootKey(),
): Promise<Uint8Array> {
  const material = await crypto.subtle.importKey(
    "raw", root.buffer as ArrayBuffer, "HKDF", false, ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: SALT, info: encoder.encode(label) },
    material,
    256,
  );
  return new Uint8Array(bits);
}

/**
 * Convenience: derive and base64-encode (no padding, no url-safe substitution)
 * for use as a string secret passed to libraries that expect raw text.
 *
 * `root`, when given, is used as raw key material in place of `TREX_ROOT_KEY`
 * (encoded as UTF-8, not base64-decoded, and not subject to the 32-byte
 * minimum enforced on the env-sourced root) — this lets callers such as tests
 * derive subkeys without any environment setup. Omitting it preserves the
 * existing behaviour of reading and validating `TREX_ROOT_KEY`.
 */
export async function deriveSubkeyBase64(label: SubkeyLabel, root?: string): Promise<string> {
  const bytes = await deriveSubkey(label, root !== undefined ? encoder.encode(root) : undefined);
  return btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join("")).replace(/=+$/, "");
}
