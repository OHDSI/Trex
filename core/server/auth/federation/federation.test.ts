import { assertEquals, assertNotEquals, assertRejects, assertThrows } from "jsr:@std/assert";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "npm:jose";
import { applyClaimMap, federationEnabled } from "./config.ts";
import { hashBinding, signState, stateKeys, verifyState } from "./state.ts";
import { challengeFor, createVerifier } from "./pkce.ts";
import { clearDiscoveryCache, loadDiscovery } from "./discovery.ts";
import { verifyFederatedIdToken } from "./verify.ts";
import { decideLink } from "./link.ts";
import { resolveGroups } from "./groups.ts";
import { findLinkedUser, resolveFederatedUser } from "./providers.ts";
import {
  _resetInsecureBindingWarning,
  bindingCookieName,
  bindingMatches,
  callbackUri,
  consumeState,
  isSecureRequest,
  readBindingCookie,
  safeRedirectTo,
  warnIfInsecureBinding,
} from "./request.ts";
import type { ProviderConfig, UpstreamIdentity } from "./types.ts";

Deno.test("federationEnabled is off unless explicitly enabled", () => {
  assertEquals(federationEnabled(undefined), false);
  assertEquals(federationEnabled("false"), false);
  assertEquals(federationEnabled("true"), true);
  assertEquals(federationEnabled("1"), true);
});

Deno.test("applyClaimMap renames upstream claims onto canonical fields", () => {
  const identity = applyClaimMap(
    { oid: "abc-123", upn: "jo@example.test", name: "Jo", email_verified: true },
    { sub: "oid", email: "upn", name: "name", email_verified: "email_verified" },
  );
  assertEquals(identity, {
    sub: "abc-123",
    email: "jo@example.test",
    name: "Jo",
    emailVerified: true,
  });
});

Deno.test("applyClaimMap falls back to standard claim names when unmapped", () => {
  const identity = applyClaimMap(
    { sub: "s-1", email: "a@b.test", email_verified: false },
    {},
  );
  assertEquals(identity.sub, "s-1");
  assertEquals(identity.email, "a@b.test");
  assertEquals(identity.emailVerified, false);
});

Deno.test("applyClaimMap rejects a missing subject", () => {
  assertThrows(
    () => applyClaimMap({ email: "a@b.test" }, {}),
    Error,
    "subject",
  );
});

Deno.test("applyClaimMap treats a missing email_verified as unverified", () => {
  const identity = applyClaimMap({ sub: "s-1", email: "a@b.test" }, {});
  assertEquals(identity.emailVerified, false);
});

const payload = {
  provider: "logto",
  redirectTo: "/atlas/",
  nonce: "n-1",
  verifier: "v-1",
  bind: "YmluZGluZy1oYXNo",
  exp: 2_000_000_000,
};

Deno.test("state round-trips through sign and verify", async () => {
  const keys = await stateKeys("test-root-key");
  const token = await signState(payload, keys);
  assertEquals(await verifyState(token, keys, 1_000_000_000), payload);
});

Deno.test("state with a tampered body is rejected", async () => {
  const keys = await stateKeys("test-root-key");
  const token = await signState(payload, keys);
  const [body, sig] = token.split(".");
  const forged = btoa(JSON.stringify({ ...payload, redirectTo: "/evil" }))
    .replace(/=+$/, "");
  await assertRejects(
    () => verifyState(`${forged}.${sig}`, keys, 1_000_000_000),
    Error,
    "signature",
  );
  assertNotEquals(body, forged);
});

Deno.test("state signed with another key is rejected", async () => {
  const token = await signState(payload, await stateKeys("root-a"));
  const keysB = await stateKeys("root-b");
  await assertRejects(
    () => verifyState(token, keysB, 1_000_000_000),
    Error,
    "signature",
  );
});

Deno.test("expired state is rejected", async () => {
  const keys = await stateKeys("test-root-key");
  const token = await signState(payload, keys);
  await assertRejects(
    () => verifyState(token, keys, 2_000_000_001),
    Error,
    "expired",
  );
});

// The reason the body is encrypted at all: this token rides in the same URL as
// the authorization code, and that URL reaches the identity provider's logs and
// any Referer header the browser sends on. A plaintext state would hand whoever
// read it the PKCE code_verifier — and client_secret is optional, so for a
// public-client provider that is everything needed to redeem the code upstream.
Deno.test("nothing in the state is readable from the token", async () => {
  const keys = await stateKeys("test-root-key");
  const token = await signState(payload, keys);

  assertEquals(token.includes(payload.verifier), false);
  assertEquals(token.includes(payload.nonce), false);
  assertEquals(token.includes(payload.redirectTo), false);
  assertEquals(token.includes(payload.provider), false);

  // Nor after undoing the transport encoding: the bytes are ciphertext.
  const body = token.slice(0, token.indexOf("."));
  const norm = body.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = atob(norm + "=".repeat((4 - (norm.length % 4)) % 4));
  assertEquals(decoded.includes(payload.verifier), false);
  assertEquals(decoded.includes(payload.nonce), false);
  // No field names either — the JSON itself never leaves the process.
  // (Single characters are not asserted on: over ~250 bytes of ciphertext any
  // given byte value turns up by chance, and the test would flake.)
  assertEquals(decoded.includes("verifier"), false);
  assertEquals(decoded.includes("redirectTo"), false);
});

Deno.test("the same payload seals differently every time", async () => {
  const keys = await stateKeys("test-root-key");
  // A fresh GCM nonce per state: two flows started with identical parameters
  // must not produce the same token, or consumeState would treat the second as
  // a replay of the first and refuse a legitimate sign-in.
  assertNotEquals(await signState(payload, keys), await signState(payload, keys));
});

// The MAC is over the ciphertext, so it passes here and decryption is what
// refuses — a root-key rotation between /authorize and /callback, in effect.
Deno.test("a body sealed under a different encryption key is refused", async () => {
  const a = await stateKeys("root-a");
  const b = await stateKeys("root-b");
  const mismatched = await signState(payload, { mac: a.mac, enc: b.enc });
  await assertRejects(
    () => verifyState(mismatched, a, 1_000_000_000),
    Error,
    "decrypted",
  );
});

Deno.test("a malformed state is refused, not thrown at", async () => {
  const keys = await stateKeys("test-root-key");
  await assertRejects(() => verifyState("no-dot-here", keys), Error, "malformed");
  await assertRejects(() => verifyState("", keys), Error, "malformed");
});

Deno.test("verifier is unreserved-charset and long enough for RFC 7636", () => {
  const v = createVerifier();
  assertEquals(v.length >= 43 && v.length <= 128, true);
  assertEquals(/^[A-Za-z0-9\-._~]+$/.test(v), true);
});

Deno.test("verifiers are not repeated", () => {
  assertNotEquals(createVerifier(), createVerifier());
});

Deno.test("challenge is the base64url SHA-256 of the verifier", async () => {
  // Known vector from RFC 7636 appendix B.
  const challenge = await challengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
  assertEquals(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
});

const DOC = {
  issuer: "https://logto.test/oidc",
  authorization_endpoint: "https://logto.test/oidc/auth",
  token_endpoint: "https://logto.test/oidc/token",
  jwks_uri: "https://logto.test/oidc/jwks",
  id_token_signing_alg_values_supported: ["RS256", "ES384"],
};

function stubFetch(doc: unknown, counter: { n: number }): typeof fetch {
  return ((_url: string) => {
    counter.n++;
    return Promise.resolve(new Response(JSON.stringify(doc), { status: 200 }));
  }) as unknown as typeof fetch;
}

Deno.test("discovery document is fetched and parsed", async () => {
  clearDiscoveryCache();
  const c = { n: 0 };
  const doc = await loadDiscovery("https://logto.test/.well-known/openid-configuration", stubFetch(DOC, c));
  assertEquals(doc.token_endpoint, "https://logto.test/oidc/token");
  assertEquals(c.n, 1);
});

Deno.test("discovery document is cached within its TTL", async () => {
  clearDiscoveryCache();
  const c = { n: 0 };
  const url = "https://logto.test/.well-known/openid-configuration";
  await loadDiscovery(url, stubFetch(DOC, c), 1000);
  await loadDiscovery(url, stubFetch(DOC, c), 1060);
  assertEquals(c.n, 1);
});

Deno.test("discovery cache expires", async () => {
  clearDiscoveryCache();
  const c = { n: 0 };
  const url = "https://logto.test/.well-known/openid-configuration";
  await loadDiscovery(url, stubFetch(DOC, c), 1000);
  await loadDiscovery(url, stubFetch(DOC, c), 1000 + 3601);
  assertEquals(c.n, 2);
});

Deno.test("a discovery document missing required endpoints is rejected", async () => {
  clearDiscoveryCache();
  const c = { n: 0 };
  await assertRejects(
    () => loadDiscovery("https://x.test/d", stubFetch({ issuer: "https://x.test" }, c)),
    Error,
    "incomplete",
  );
});

Deno.test("discovery cache is frozen; mutations do not affect subsequent fetches", async () => {
  clearDiscoveryCache();
  const c = { n: 0 };
  const url = "https://logto.test/.well-known/openid-configuration";
  const doc1 = await loadDiscovery(url, stubFetch(DOC, c), 1000);

  // Attempt to mutate top-level string property; frozen objects reject mutations
  try {
    (doc1 as unknown as Record<string, unknown>).token_endpoint = "https://evil.test/token";
  } catch {
    // Expected: frozen object in strict mode
  }

  // Attempt to mutate the algorithm array via push; frozen array rejects mutations
  try {
    doc1.id_token_signing_alg_values_supported.push("HS256");
  } catch {
    // Expected: frozen array in strict mode
  }

  // Attempt to mutate array via index assignment; frozen array rejects mutations
  try {
    (doc1.id_token_signing_alg_values_supported as unknown[])[0] = "none";
  } catch {
    // Expected: frozen array in strict mode
  }

  // Fetch again from cache; returns the same frozen instance
  const doc2 = await loadDiscovery(url, stubFetch(DOC, c), 1001);
  // All mutations are rejected; cached value is unchanged
  assertEquals(doc2.token_endpoint, "https://logto.test/oidc/token");
  assertEquals(doc2.id_token_signing_alg_values_supported, ["RS256", "ES384"]);
  assertEquals(c.n, 1); // Only one fetch, no refetch
});

Deno.test("discovery cache expires at exactly the TTL boundary", async () => {
  clearDiscoveryCache();
  const c = { n: 0 };
  const url = "https://logto.test/.well-known/openid-configuration";
  await loadDiscovery(url, stubFetch(DOC, c), 1000);
  // Fetch exactly DISCOVERY_TTL_SECONDS later (3600); should treat as expired
  await loadDiscovery(url, stubFetch(DOC, c), 1000 + 3600);
  assertEquals(c.n, 2);
});

Deno.test("discovery filters algorithms to asymmetric only", async () => {
  clearDiscoveryCache();
  const c = { n: 0 };
  const doc = await loadDiscovery(
    "https://logto.test/.well-known/openid-configuration",
    stubFetch({
      ...DOC,
      id_token_signing_alg_values_supported: ["RS256", "none"],
    }, c),
  );
  assertEquals(doc.id_token_signing_alg_values_supported, ["RS256"]);
});

Deno.test("discovery rejects a document advertising no usable signing algorithms", async () => {
  clearDiscoveryCache();
  const c = { n: 0 };
  await assertRejects(
    () => loadDiscovery(
      "https://logto.test/.well-known/openid-configuration",
      stubFetch({ ...DOC, id_token_signing_alg_values_supported: ["none"] }, c),
    ),
    Error,
    "no usable signing algorithms",
  );
});

Deno.test("discovery rejects HS256 as unsuitable for JWKS verification", async () => {
  clearDiscoveryCache();
  const c = { n: 0 };
  await assertRejects(
    () => loadDiscovery(
      "https://logto.test/.well-known/openid-configuration",
      stubFetch({ ...DOC, id_token_signing_alg_values_supported: ["HS256"] }, c),
    ),
    Error,
    "no usable signing algorithms",
  );
});

Deno.test("discovery defaults absent id_token_signing_alg_values_supported to RS256", async () => {
  clearDiscoveryCache();
  const c = { n: 0 };
  const doc = await loadDiscovery(
    "https://logto.test/.well-known/openid-configuration",
    stubFetch({
      issuer: "https://logto.test/oidc",
      authorization_endpoint: "https://logto.test/oidc/auth",
      token_endpoint: "https://logto.test/oidc/token",
      jwks_uri: "https://logto.test/oidc/jwks",
    }, c),
  );
  assertEquals(doc.id_token_signing_alg_values_supported, ["RS256"]);
});

async function signedIdToken(over: Record<string, unknown> = {}) {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "k1";
  const token = await new SignJWT({ nonce: "n-1", email: "jo@example.test", ...over })
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(over.iss as string ?? "https://logto.test/oidc")
    .setAudience(over.aud as string ?? "d2e-client")
    .setSubject("s-1")
    .setExpirationTime("5m")
    .sign(privateKey);
  return { token, jwks: createLocalJWKSet({ keys: [jwk] }) };
}

Deno.test("a well-formed id_token verifies", async () => {
  const { token, jwks } = await signedIdToken();
  const claims = await verifyFederatedIdToken(token, {
    doc: DOC, clientId: "d2e-client", nonce: "n-1", jwks,
  });
  assertEquals(claims.sub, "s-1");
});

Deno.test("a wrong audience is rejected", async () => {
  const { token, jwks } = await signedIdToken({ aud: "someone-else" });
  await assertRejects(
    () => verifyFederatedIdToken(token, { doc: DOC, clientId: "d2e-client", nonce: "n-1", jwks }),
    Error,
    "aud",
  );
});

Deno.test("a wrong issuer is rejected", async () => {
  const { token, jwks } = await signedIdToken({ iss: "https://evil.test" });
  await assertRejects(
    () => verifyFederatedIdToken(token, { doc: DOC, clientId: "d2e-client", nonce: "n-1", jwks }),
    Error,
    "iss",
  );
});

Deno.test("a mismatched nonce is rejected", async () => {
  const { token, jwks } = await signedIdToken({ nonce: "other" });
  await assertRejects(
    () => verifyFederatedIdToken(token, { doc: DOC, clientId: "d2e-client", nonce: "n-1", jwks }),
    Error,
    "nonce",
  );
});

Deno.test("a token with no nonce claim is rejected even against an empty-string nonce", async () => {
  const { token, jwks } = await signedIdToken({ nonce: undefined });
  await assertRejects(
    () => verifyFederatedIdToken(token, { doc: DOC, clientId: "d2e-client", nonce: "", jwks }),
    Error,
    "nonce",
  );
});

Deno.test("an algorithm the provider does not advertise is rejected", async () => {
  const { token, jwks } = await signedIdToken();
  const doc = { ...DOC, id_token_signing_alg_values_supported: ["ES384"] };
  await assertRejects(
    () => verifyFederatedIdToken(token, { doc, clientId: "d2e-client", nonce: "n-1", jwks }),
    Error,
    "alg",
  );
});

const provider = (over: Partial<ProviderConfig> = {}): ProviderConfig => ({
  id: "logto", displayName: "Logto", clientId: "c", clientSecret: "s",
  issuer: "https://logto.test/oidc", discoveryUrl: "https://logto.test/d",
  scopes: "openid profile email", claimMap: {}, groupsSource: "none",
  groupsClaim: null, linkPolicy: "verified_email", autoProvision: false, ...over,
});
const identity = (verified: boolean): UpstreamIdentity => ({
  sub: "s-1", email: "jo@example.test", emailVerified: verified,
});

Deno.test("verified email + existing user links", () => {
  assertEquals(decideLink(identity(true), provider(), "u-1"), { action: "link", userId: "u-1" });
});

Deno.test("unverified email never links, even to an existing user", () => {
  const d = decideLink(identity(false), provider(), "u-1");
  assertEquals(d.action, "refuse");
});

Deno.test("unverified email is refused even when auto-provision is on", () => {
  const d = decideLink(identity(false), provider({ autoProvision: true }), null);
  assertEquals(d.action, "refuse");
});

Deno.test("verified email, no user, auto-provision off is refused", () => {
  const d = decideLink(identity(true), provider(), null);
  assertEquals(d.action, "refuse");
});

Deno.test("verified email, no user, auto-provision on provisions", () => {
  assertEquals(
    decideLink(identity(true), provider({ autoProvision: true }), null),
    { action: "provision" },
  );
});

// ── Group resolution (groups.ts) ────────────────────────────────────────────

Deno.test("groups_source 'claim' reads the configured claim, raw", () => {
  const p = provider({ groupsSource: "claim", groupsClaim: "roles" });
  // Order, case and duplicates are the upstream's to decide; d2e maps them.
  assertEquals(
    resolveGroups({ roles: ["Zeta", "alpha", "Zeta"] }, p),
    ["Zeta", "alpha", "Zeta"],
  );
});

Deno.test("groups_claim names an arbitrary claim, not just 'groups'", () => {
  const claims = { groups: ["wrong"], "http://schemas.test/groups": ["right"] };
  assertEquals(
    resolveGroups(claims, provider({
      groupsSource: "claim",
      groupsClaim: "http://schemas.test/groups",
    })),
    ["right"],
  );
});

Deno.test("an absent, empty or non-array claim yields no groups, never an error", () => {
  const p = provider({ groupsSource: "claim", groupsClaim: "groups" });
  assertEquals(resolveGroups({}, p), []);
  assertEquals(resolveGroups({ groups: [] }, p), []);
  assertEquals(resolveGroups({ groups: null }, p), []);
  assertEquals(resolveGroups({ groups: "admins" }, p), []);
  assertEquals(resolveGroups({ groups: { a: 1 } }, p), []);
  // Configured for claims but with no claim named: nothing to read.
  assertEquals(
    resolveGroups({ groups: ["a"] }, provider({ groupsSource: "claim", groupsClaim: null })),
    [],
  );
});

// A partial list that looks complete is worse than none: the relying party
// would map it to roles and silently under-grant.
Deno.test("an array with non-string members is treated as no group list", () => {
  const p = provider({ groupsSource: "claim", groupsClaim: "groups" });
  assertEquals(resolveGroups({ groups: ["a", 2] }, p), []);
  assertEquals(resolveGroups({ groups: [{ id: "a" }] }, p), []);
});

Deno.test("'none' and (for now) 'graph' resolve to no groups", () => {
  const claims = { groups: ["admins"] };
  assertEquals(resolveGroups(claims, provider({ groupsSource: "none", groupsClaim: "groups" })), []);
  // The MS Graph resolver is a later phase; until it exists this must be an
  // empty list rather than the id_token claim it would not have used anyway.
  assertEquals(resolveGroups(claims, provider({ groupsSource: "graph", groupsClaim: "groups" })), []);
});

// ── Identity resolution (providers.ts) ──────────────────────────────────────

/**
 * A pg client stubbed by which statement it is asked to run. Enough to drive
 * resolveFederatedUser, which is the only place the two lookups are ordered
 * against each other, without a database.
 */
function stubClient(rows: { linked?: unknown[]; byEmail?: unknown[] }) {
  const seen: string[] = [];
  return {
    seen,
    // deno-lint-ignore no-explicit-any
    query(sql: string, _params: unknown[]): Promise<any> {
      // The link lookup joins user, so it must be recognised first.
      if (sql.includes("FROM trexdb.account a")) {
        seen.push("link");
        return Promise.resolve({ rows: rows.linked ?? [] });
      }
      if (sql.includes('FROM trexdb."user"')) {
        seen.push("email");
        return Promise.resolve({ rows: rows.byEmail ?? [] });
      }
      throw new Error(`unexpected query: ${sql}`);
    },
  };
}

Deno.test("an existing link is found and reports whether its user is disabled", async () => {
  const live = await findLinkedUser(
    stubClient({ linked: [{ userId: "u-1", disabled: false }] }),
    "logto",
    "s-1",
  );
  assertEquals(live, { userId: "u-1", disabled: false });

  const banned = await findLinkedUser(
    stubClient({ linked: [{ userId: "u-1", disabled: true }] }),
    "logto",
    "s-1",
  );
  assertEquals(banned, { userId: "u-1", disabled: true });

  assertEquals(await findLinkedUser(stubClient({}), "logto", "s-1"), null);
});

// The upstream changed the address. The link is the identity, so the sign-in
// lands on the linked user and never looks at whoever now holds that email.
Deno.test("an existing link wins over a different email", async () => {
  const client = stubClient({
    linked: [{ userId: "u-linked", disabled: false }],
    byEmail: [{ id: "u-someone-else" }],
  });
  assertEquals(
    await resolveFederatedUser(client, provider(), {
      sub: "s-1",
      email: "changed@example.test",
      emailVerified: true,
    }),
    { action: "link", userId: "u-linked" },
  );
  // Not merely outranked: the email question is never asked.
  assertEquals(client.seen, ["link"]);
});

// An unverified upstream email would refuse a *new* link; it is irrelevant to
// one that already exists, because no linking decision is being made.
Deno.test("an existing link does not re-ask the verified-email question", async () => {
  const client = stubClient({ linked: [{ userId: "u-linked", disabled: false }] });
  assertEquals(
    await resolveFederatedUser(client, provider(), {
      sub: "s-1",
      email: "jo@example.test",
      emailVerified: false,
    }),
    { action: "link", userId: "u-linked" },
  );
  assertEquals(client.seen, ["link"]);
});

Deno.test("an existing link to a disabled user is refused", async () => {
  const client = stubClient({
    linked: [{ userId: "u-banned", disabled: true }],
    // Would be email-linkable if the flow ever fell through to it.
    byEmail: [{ id: "u-someone-else" }],
  });
  const decision = await resolveFederatedUser(client, provider(), identity(true));
  assertEquals(decision, { action: "refuse", reason: "account_disabled" });
  // And it stops there rather than falling through to provision or re-link.
  assertEquals(client.seen, ["link"]);
});

Deno.test("with no link, a verified email links as before", async () => {
  const client = stubClient({ byEmail: [{ id: "u-2" }] });
  assertEquals(
    await resolveFederatedUser(client, provider(), identity(true)),
    { action: "link", userId: "u-2" },
  );
  assertEquals(client.seen, ["link", "email"]);
});

Deno.test("with no link and no matching user, the provider's policy decides", async () => {
  assertEquals(
    await resolveFederatedUser(stubClient({}), provider(), identity(true)),
    { action: "refuse", reason: "no_account" },
  );
  assertEquals(
    await resolveFederatedUser(stubClient({}), provider({ autoProvision: true }), identity(true)),
    { action: "provision" },
  );
  // An unverified upstream email still links to nothing.
  assertEquals(
    (await resolveFederatedUser(
      stubClient({ byEmail: [{ id: "u-2" }] }),
      provider(),
      identity(false),
    )).action,
    "refuse",
  );
});

// ── Federation RP routes (router.ts) ────────────────────────────────────────

Deno.test("redirect_to accepts same-origin paths", () => {
  assertEquals(safeRedirectTo("/atlas/"), "/atlas/");
  assertEquals(safeRedirectTo("/d2e/portal?x=1"), "/d2e/portal?x=1");
});

Deno.test("redirect_to rejects absolute URLs and protocol-relative ones", () => {
  assertEquals(safeRedirectTo("https://evil.test/x"), "/");
  assertEquals(safeRedirectTo("//evil.test/x"), "/");
  assertEquals(safeRedirectTo("javascript:alert(1)"), "/");
});

Deno.test("redirect_to falls back when absent or malformed", () => {
  assertEquals(safeRedirectTo(undefined), "/");
  assertEquals(safeRedirectTo(""), "/");
  // A repeated query parameter arrives as an array, whatever the cast claims.
  assertEquals(safeRedirectTo(["/a", "/b"] as unknown as string), "/");
});

// Browsers normalise a backslash to a slash in the authority position, so
// "/\evil.test" is protocol-relative in practice even though it is not "//".
// Control characters are stripped before parsing, which re-forms "//host" out
// of something that passed a naive prefix check.
Deno.test("redirect_to rejects backslash and control-character smuggling", () => {
  assertEquals(safeRedirectTo("/\\evil.test/x"), "/");
  assertEquals(safeRedirectTo("/\t/evil.test/x"), "/");
  assertEquals(safeRedirectTo("/\n/evil.test"), "/");
});

Deno.test("callback URI prefers explicit configuration over request headers", () => {
  const req = { headers: { "x-forwarded-proto": "http", host: "internal:33001" } };
  assertEquals(
    callbackUri(req, "/trex", "https://trex.example/trex/auth/v1/callback"),
    "https://trex.example/trex/auth/v1/callback",
  );
});

Deno.test("callback URI falls back to the forwarded origin", () => {
  assertEquals(
    callbackUri(
      { headers: { "x-forwarded-proto": "https, http", "x-forwarded-host": "trex.test" } },
      "/trex",
      // Explicit rather than omitted: the parameter default reads
      // TREX_FEDERATION_REDIRECT_URI, so leaving it out makes this test pass or
      // fail depending on the developer's environment.
      "",
    ),
    "https://trex.test/trex/auth/v1/callback",
  );
  assertEquals(
    callbackUri({ headers: { host: "trex.test" } }, "", ""),
    "https://trex.test/auth/v1/callback",
  );
  // A plain-HTTP deployment with no proxy header must not claim https: the
  // provider would reject a redirect_uri it never registered.
  assertEquals(
    callbackUri({ protocol: "http", headers: { host: "localhost:33001" } }, "/trex", ""),
    "http://localhost:33001/trex/auth/v1/callback",
  );
  // A proxy header still wins over the connection's own protocol.
  assertEquals(
    callbackUri(
      { protocol: "http", headers: { "x-forwarded-proto": "https", host: "trex.test" } },
      "/trex",
      "",
    ),
    "https://trex.test/trex/auth/v1/callback",
  );
});

Deno.test("a state is accepted once and refused on replay", () => {
  assertEquals(consumeState("sig-once", 100, 10), true);
  assertEquals(consumeState("sig-once", 100, 11), false);
  assertEquals(consumeState("sig-once", 100, 12), false);
});

Deno.test("consumed states stop being remembered once they expire", () => {
  assertEquals(consumeState("sig-expiring", 100, 10), true);
  // Past its own expiry the entry is pruned; verifyState rejects such a state
  // before consumeState is ever reached, so nothing is re-openable in practice.
  assertEquals(consumeState("sig-expiring", 100, 101), true);
});

Deno.test("a callback carrying the matching binding cookie is accepted", async () => {
  const value = "browser-binding-value";
  const bind = await hashBinding(value);
  assertEquals(await bindingMatches(`__Host-trex_federation=${value}`, bind, true), true);
  // The unprefixed name is what a plain-HTTP deployment sets, and is accepted
  // only on a non-secure request — local sign-in has to keep working.
  assertEquals(await bindingMatches(`trex_federation=${value}; other=x`, bind, false), true);
});

Deno.test("a callback carrying the wrong binding cookie is refused", async () => {
  const bind = await hashBinding("browser-binding-value");
  assertEquals(await bindingMatches("__Host-trex_federation=someone-elses", bind, true), false);
  // A near miss must not pass either: the comparison is over the hashes.
  assertEquals(
    await bindingMatches("__Host-trex_federation=browser-binding-valuf", bind, true),
    false,
  );
});

// The victim in the login-CSRF attack: the attacker's callback URL opened in a
// browser that never started a flow, so it holds no cookie at all.
Deno.test("a callback with no binding cookie is refused", async () => {
  const bind = await hashBinding("browser-binding-value");
  assertEquals(await bindingMatches(undefined, bind, true), false);
  assertEquals(await bindingMatches("", bind, true), false);
  assertEquals(await bindingMatches("unrelated=1", bind, true), false);
  // And a state carrying no binding at all can never be satisfied.
  assertEquals(await bindingMatches("__Host-trex_federation=anything", "", true), false);
});

// The cookie-shadowing attack the __Host- prefix exists to stop. The victim
// holds no prefixed cookie — they never started a flow — so falling back to the
// unprefixed name would hand the whole binding back: the attacker reads their
// own binding value off their own Set-Cookie, plants it under the weak name
// from a sibling subdomain or over plaintext for any sibling host, and the
// victim's browser presents a value that matches.
Deno.test("on a secure request the unprefixed cookie never satisfies the binding", async () => {
  const value = "browser-binding-value";
  const bind = await hashBinding(value);
  assertEquals(await bindingMatches(`trex_federation=${value}`, bind, true), false);
  // Not even alongside a prefixed cookie that does not match.
  assertEquals(
    await bindingMatches(`__Host-trex_federation=other; trex_federation=${value}`, bind, true),
    false,
  );
  // And the converse, so a plain-HTTP deployment still signs in: there the
  // unprefixed name is the one that was set, and the prefixed one is ignored.
  assertEquals(await bindingMatches(`trex_federation=${value}`, bind, false), true);
  assertEquals(await bindingMatches(`__Host-trex_federation=${value}`, bind, false), false);
});

Deno.test("the binding hash hides the cookie value and is stable", async () => {
  const hash = await hashBinding("browser-binding-value");
  assertEquals(hash, await hashBinding("browser-binding-value"));
  assertNotEquals(hash, await hashBinding("browser-binding-valuf"));
  assertEquals(hash.includes("browser-binding-value"), false);
  // base64url: safe to carry in a URL-borne state and to log.
  assertEquals(/^[A-Za-z0-9_-]+$/.test(hash), true);
});

Deno.test("only the name this request's scheme mandates is read", () => {
  const header = "trex_federation=plain; __Host-trex_federation=prefixed";
  assertEquals(readBindingCookie(header, true), "prefixed");
  assertEquals(readBindingCookie(header, false), "plain");
  // A secure request sees nothing at all when only the weak name is present.
  assertEquals(readBindingCookie("trex_federation=plain", true), null);
  assertEquals(readBindingCookie("__Host-trex_federation=prefixed", false), null);
  assertEquals(readBindingCookie(undefined, true), null);
});

Deno.test("the weak cookie name is announced once, not per request", () => {
  _resetInsecureBindingWarning();
  const said: string[] = [];
  warnIfInsecureBinding(false, (m) => said.push(m));
  warnIfInsecureBinding(false, (m) => said.push(m));
  warnIfInsecureBinding(false, (m) => said.push(m));
  assertEquals(said.length, 1);
  // An operator has to be able to act on it, so it names the remedy.
  assertEquals(said[0].includes("TREX_FORCE_SECURE_COOKIES=1"), true);
  assertEquals(said[0].includes("X-Forwarded-Proto"), true);

  // A secure deployment hears nothing.
  _resetInsecureBindingWarning();
  const quiet: string[] = [];
  warnIfInsecureBinding(true, (m) => quiet.push(m));
  assertEquals(quiet.length, 0);
  _resetInsecureBindingWarning();
});

Deno.test("__Host- is used only where the cookie can carry Secure", () => {
  assertEquals(bindingCookieName(true), "__Host-trex_federation");
  assertEquals(bindingCookieName(false), "trex_federation");
  // The third argument is pinned for the same reason callbackUri's is.
  assertEquals(isSecureRequest({ protocol: "https", headers: {} }, ""), true);
  assertEquals(isSecureRequest({ headers: { "x-forwarded-proto": "https, http" } }, ""), true);
  assertEquals(isSecureRequest({ headers: {} }, ""), false);
  assertEquals(isSecureRequest({ headers: {} }, "1"), true);
});
