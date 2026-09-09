import { assertEquals, assertNotEquals, assertRejects, assertThrows } from "jsr:@std/assert";
import { applyClaimMap, federationEnabled } from "./config.ts";
import { signState, stateKey, verifyState } from "./state.ts";
import { challengeFor, createVerifier } from "./pkce.ts";
import { clearDiscoveryCache, loadDiscovery } from "./discovery.ts";

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
  exp: 2_000_000_000,
};

Deno.test("state round-trips through sign and verify", async () => {
  const key = await stateKey("test-root-key");
  const token = await signState(payload, key);
  assertEquals(await verifyState(token, key, 1_000_000_000), payload);
});

Deno.test("state with a tampered body is rejected", async () => {
  const key = await stateKey("test-root-key");
  const token = await signState(payload, key);
  const [body, sig] = token.split(".");
  const forged = btoa(JSON.stringify({ ...payload, redirectTo: "/evil" }))
    .replace(/=+$/, "");
  await assertRejects(
    () => verifyState(`${forged}.${sig}`, key, 1_000_000_000),
    Error,
    "signature",
  );
  assertNotEquals(body, forged);
});

Deno.test("state signed with another key is rejected", async () => {
  const token = await signState(payload, await stateKey("root-a"));
  const keyB = await stateKey("root-b");
  await assertRejects(
    () => verifyState(token, keyB, 1_000_000_000),
    Error,
    "signature",
  );
});

Deno.test("expired state is rejected", async () => {
  const key = await stateKey("test-root-key");
  const token = await signState(payload, key);
  await assertRejects(
    () => verifyState(token, key, 2_000_000_001),
    Error,
    "expired",
  );
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
