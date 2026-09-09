// Request-shaping helpers for the relying-party routes: where a browser may be
// sent back to, what redirect_uri the upstream sees, and single use of a state.
//
// Separate from router.ts, which imports express, because express drags in
// @types/node and this deployment's node_modules does not declare it — a test
// that imported router.ts would fail to type-check before running a single
// assertion. These are pure functions of their input either way, which is how
// the rest of federation/ is organised (see config.ts).
import { readCookie } from "../oidc/config.ts";
import { constantTimeEquals, hashBinding } from "./state.ts";

/**
 * Only same-origin paths are honoured: an absolute URL here would turn the
 * callback into an open redirect, and `//host` is absolute despite looking
 * relative. Mirrors d2e's login page rule.
 *
 * Two cases beyond the plain `//` check, both of which a browser resolves to an
 * authority rather than a path: a backslash in the authority position
 * (`/\evil.test` — WHATWG URL treats `\` as `/` there), and control characters,
 * which are stripped before parsing and so can re-form `//host` out of a string
 * that passed a naive prefix test.
 */
export function safeRedirectTo(raw: string | undefined): string {
  // typeof rather than a truthiness check alone: express hands back an array
  // for a repeated query parameter (?redirect_to=a&redirect_to=b), and the
  // callers' `as string` would otherwise reach .startsWith on an array.
  if (typeof raw !== "string" || !raw.startsWith("/")) return "/";
  if (raw.length > 1 && (raw[1] === "/" || raw[1] === "\\")) return "/";
  // deno-lint-ignore no-control-regex
  if (/[\x00-\x1f\x7f]/.test(raw)) return "/";
  return raw;
}

/**
 * The redirect_uri the upstream sees, which must be byte-identical in the
 * authorization request and in the token exchange or the provider rejects the
 * code.
 *
 * Configuration wins over the request, for the same reason the OIDC provider
 * derives its issuer from `TREX_OIDC_ISSUER` rather than from Host: a proxied
 * or spoofed `X-Forwarded-Host` would otherwise vary the value per caller. The
 * header fallback keeps a single-host deployment working with no extra
 * configuration; anything behind a proxy it does not control should set
 * `TREX_FEDERATION_REDIRECT_URI` to the URI registered at the provider.
 */
export function callbackUri(
  // deno-lint-ignore no-explicit-any
  req: any,
  basePath: string,
  configured: string | undefined = Deno.env.get("TREX_FEDERATION_REDIRECT_URI"),
): string {
  if (configured && configured.length > 0) return configured;
  // Either header can arrive repeated or as a list ("https, http"); the first
  // entry is what the outermost proxy saw, i.e. what the browser used.
  const first = (v: unknown): string | undefined => {
    const s = Array.isArray(v) ? v[0] : v;
    return typeof s === "string" ? s.split(",")[0].trim() : undefined;
  };
  // req.protocol before the "https" default: on a plain-HTTP deployment with no
  // proxy header, defaulting to https produces a redirect_uri the provider has
  // not registered and the sign-in fails with nothing to point at. Express
  // derives req.protocol from the connection, and from X-Forwarded-Proto itself
  // once `trust proxy` is set.
  const proto = first(req.headers["x-forwarded-proto"]) ?? first(req.protocol) ?? "https";
  const host = first(req.headers["x-forwarded-host"]) ?? first(req.headers.host);
  return `${proto}://${host}${basePath}/auth/v1/callback`;
}

/**
 * Single-use enforcement for `state`.
 *
 * The state is signed rather than stored, so on its own it stays valid for its
 * whole TTL and a captured callback URL could be replayed at will. This
 * remembers the states already redeemed until they expire, which closes that
 * window — but only within one process: replicas do not share the map, so a
 * replay aimed at another replica is stopped only by the upstream refusing to
 * redeem its authorization code twice, which OAuth requires of it.
 *
 * Call this only AFTER verifyState succeeds, so nothing can fill the map with
 * unsigned junk, and the entries are bounded by a TTL trex itself signed.
 */
const consumedStates = new Map<string, number>();

export function consumeState(
  state: string,
  exp: number,
  now: number = Math.floor(Date.now() / 1000),
): boolean {
  for (const [key, expiresAt] of consumedStates) {
    if (expiresAt <= now) consumedStates.delete(key);
  }
  if (consumedStates.has(state)) return false;
  consumedStates.set(state, exp);
  return true;
}

/**
 * An upstream error code, echoed back only when it is a bounded token. The
 * provider chooses this text, and it lands in a JSON body a browser renders.
 */
export function safeErrorCode(raw: unknown): string {
  const s = Array.isArray(raw) ? raw[0] : raw;
  return typeof s === "string" && /^[a-z_]{1,64}$/.test(s) ? s : "upstream_error";
}

// ── Browser binding ─────────────────────────────────────────────────────────
//
// A signed state proves trex issued it. It does NOT prove the browser
// presenting it is the one that started the flow — and without that, an
// attacker can start a federation flow, authenticate as themselves, keep the
// resulting callback URL instead of following it, and get a victim to open it.
// The victim's browser is then silently signed in as the attacker, and
// everything the victim does next happens in the attacker's account. This is
// login CSRF, the attack `state` exists to prevent; consumeState does not touch
// it, because the attacker never redeems the state themselves.
//
// The fix is the standard one: a random value in a cookie at /authorize, its
// hash inside the signed state, and a comparison at /callback. Only a browser
// holding the cookie can complete the flow the state describes.

/**
 * `__Host-` is the strong form: it forbids a Domain attribute and requires
 * Secure and Path=/, so no sibling subdomain and no plaintext response can set
 * or overwrite it. A browser rejects it outright without Secure, though, which
 * over plain HTTP would leave the cookie unset and every sign-in refused — so a
 * non-HTTPS deployment falls back to the unprefixed name. Both names are read
 * back, so a flow that starts on one and returns on the other still completes.
 */
export const BINDING_COOKIE = "__Host-trex_federation";
export const BINDING_COOKIE_INSECURE = "trex_federation";

/**
 * Same test the native token response uses to decide on the Secure flag. The
 * override is a parameter rather than an inline env read so a test can pin it;
 * a test that let the default fire would pass or fail with the developer's
 * environment.
 */
export function isSecureRequest(
  // deno-lint-ignore no-explicit-any
  req: any,
  forced: string | undefined = Deno.env.get("TREX_FORCE_SECURE_COOKIES"),
): boolean {
  if (forced === "1") return true;
  if (req?.protocol === "https") return true;
  const forwarded = req?.headers?.["x-forwarded-proto"];
  const first = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  return typeof first === "string" && first.split(",")[0].trim() === "https";
}

export function bindingCookieName(secure: boolean): string {
  return secure ? BINDING_COOKIE : BINDING_COOKIE_INSECURE;
}

/** The prefixed cookie wins: it is the one an attacker cannot have written. */
export function readBindingCookie(header: string | undefined): string | null {
  return readCookie(header, BINDING_COOKIE) ?? readCookie(header, BINDING_COOKIE_INSECURE);
}

/**
 * Whether the browser presenting this callback is the one that started the
 * flow. Absent cookie is a refusal, not a pass: that is exactly what a victim's
 * browser looks like in the attack above.
 */
export async function bindingMatches(
  cookieHeader: string | undefined,
  bind: string,
): Promise<boolean> {
  const presented = readBindingCookie(cookieHeader);
  if (!presented || typeof bind !== "string" || bind.length === 0) return false;
  return constantTimeEquals(await hashBinding(presented), bind);
}
