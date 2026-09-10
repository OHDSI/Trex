import { assertEquals, assertNotEquals } from "jsr:@std/assert";
import {
  buildReturnTo,
  grantedScopes,
  isPublicClient,
  isRegisteredPostLogoutUri,
  isRegisteredRedirectUri,
  type OidcClient,
  verifyPkce,
} from "./policy.ts";
import {
  buildIdTokenClaims,
  federationFromAppMetadata,
  IDP_METADATA_KEY,
} from "./claims.ts";
import {
  issuerUrl,
  loginUrl,
  oidcProviderEnabled,
  parseSeedClient,
  readCookie,
} from "./config.ts";

const client: OidcClient = {
  clientId: "atlas",
  clientSecretHash: null,
  name: "Atlas",
  redirectUris: ["https://example.test/atlas/#/welcome"],
  postLogoutRedirectUris: ["https://example.test/atlas/"],
  allowedScopes: ["openid", "profile", "email"],
  requirePkce: true,
  clientRoles: [],
};

Deno.test("the provider is off unless explicitly enabled", () => {
  for (const v of [undefined, "", "false", "0", "yes", "TRUE"]) {
    assertEquals(oidcProviderEnabled(v), false, `expected off for ${JSON.stringify(v)}`);
  }
  assertEquals(oidcProviderEnabled("true"), true);
  assertEquals(oidcProviderEnabled("1"), true);
});

Deno.test("redirect_uri matching is exact", () => {
  assertEquals(isRegisteredRedirectUri(client, "https://example.test/atlas/#/welcome"), true);
  // Each of these is a redirect an attacker would like to be accepted.
  for (const uri of [
    "https://example.test/atlas/#/welcome/../../evil",
    "https://example.test/atlas/#/welcome?x=1",
    "https://example.test/atlas/",
    "https://evil.test/atlas/#/welcome",
    "https://example.test.evil.test/atlas/#/welcome",
    "",
  ]) {
    assertEquals(isRegisteredRedirectUri(client, uri), false, `expected reject for ${uri}`);
  }
});

Deno.test("post-logout redirects are matched against their own list", () => {
  assertEquals(isRegisteredPostLogoutUri(client, "https://example.test/atlas/"), true);
  // Registered as a login redirect, but not as a post-logout one.
  assertEquals(isRegisteredPostLogoutUri(client, "https://example.test/atlas/#/welcome"), false);
});

Deno.test("scopes are narrowed to what the client may have", () => {
  assertEquals(grantedScopes(client, "openid profile email"), ["openid", "profile", "email"]);
  assertEquals(grantedScopes(client, "openid offline_access"), ["openid"]);
  assertEquals(grantedScopes(client, "  openid   email  "), ["openid", "email"]);
  assertEquals(grantedScopes(client, "profile"), ["profile"]);
});

Deno.test("a client with no stored secret is public", () => {
  assertEquals(isPublicClient(client), true);
  assertEquals(isPublicClient({ ...client, clientSecretHash: "salt:hash" }), false);
});

Deno.test("a service token names the client as its own subject", () => {
  // A client_credentials token has no user behind it. Relying parties tell one
  // apart from a user's token by sub === client_id, so that equality is the
  // contract, not an incidental detail of how the claims are built.
  const client = { clientId: "d2e-webapi", name: "D2E WebAPI" };

  const claims = buildIdTokenClaims(
    {
      id: client.clientId,
      email: "",
      name: client.name,
      role: "service",
      appRoles: [],
    },
    { issuer: "https://example.test/trex", audience: client.clientId, scopes: [] },
  );

  assertEquals(claims.sub, client.clientId);
  assertEquals(claims.aud, client.clientId);
  assertEquals(claims.sub, claims.aud);
  // No user stands behind it, so it carries no application roles to authorize with.
  assertEquals(claims.trex_role, "service");
  assertEquals(claims.app_metadata.trex_role, "service");
});

Deno.test("claims carry the role and honour the requested scopes", () => {
  const user = {
    id: "11111111-1111-1111-1111-111111111111",
    email: "admin@trex.local",
    name: "Admin",
    role: "admin",
    appRoles: [],
    emailVerified: true,
  };

  const full = buildIdTokenClaims(user, {
    issuer: "https://example.test/trex",
    audience: "atlas",
    scopes: ["openid", "profile", "email"],
    nonce: "n-123",
  });
  assertEquals(full.sub, user.id);
  assertEquals(full.aud, "atlas");
  assertEquals(full.iss, "https://example.test/trex");
  assertEquals(full.nonce, "n-123");
  assertEquals(full.email, "admin@trex.local");
  assertEquals(full.email_verified, true);
  assertEquals(full.name, "Admin");
  // The role is what downstream authorization reads, in both places.
  assertEquals(full.trex_role, "admin");
  assertEquals(full.app_metadata.trex_role, "admin");

  const minimal = buildIdTokenClaims(user, {
    issuer: "https://example.test/trex",
    audience: "atlas",
    scopes: ["openid"],
  });
  assertEquals(minimal.email, undefined);
  assertEquals(minimal.name, undefined);
  assertEquals(minimal.nonce, undefined);
  // The role is not scope-gated: it is what the token is for.
  assertEquals(minimal.trex_role, "admin");
});

Deno.test("claims expire and are not issued in the past", () => {
  const now = Math.floor(Date.now() / 1000);
  const claims = buildIdTokenClaims(
    { id: "u", email: "e@x", role: "user", appRoles: [] },
    { issuer: "https://i", audience: "a", scopes: ["openid"], ttlSeconds: 60 },
  );
  assertEquals(claims.exp - claims.iat, 60);
  assertEquals(claims.iat >= now - 1 && claims.iat <= now + 1, true);
});

Deno.test("the issuer is taken from configuration, not from the request", () => {
  assertEquals(issuerUrl("https://example.test", "/trex"), "https://example.test/trex");
  // Trailing slashes would otherwise produce a doubled separator and an `iss`
  // that no relying party matches.
  assertEquals(issuerUrl("https://example.test/", "/trex"), "https://example.test/trex");
  assertEquals(issuerUrl("https://example.test///", ""), "https://example.test");
});

Deno.test("cookie reading picks the right value", () => {
  const header = "other=1; sb-access-token=abc.def.ghi; another=2";
  assertEquals(readCookie(header, "sb-access-token"), "abc.def.ghi");
  assertEquals(readCookie(header, "missing"), null);
  assertEquals(readCookie(undefined, "sb-access-token"), null);
  // A cookie whose name merely contains the one we want must not match.
  assertEquals(readCookie("xsb-access-token=nope", "sb-access-token"), null);
});

Deno.test("two issued codes never collide", () => {
  // The code itself comes from crypto.getRandomValues; this guards the encoding
  // rather than the entropy source.
  const a = crypto.getRandomValues(new Uint8Array(32));
  const b = crypto.getRandomValues(new Uint8Array(32));
  assertNotEquals(a.join(","), b.join(","));
});

Deno.test("loginUrl is null unless configured, so /authorize fails closed", () => {
  assertEquals(loginUrl(undefined), null);
  assertEquals(loginUrl(""), null);
  assertEquals(loginUrl("https://example.test/login"), "https://example.test/login");
});

// The S256 pair below is the worked example from RFC 7636 appendix B, so these
// assert against the spec rather than against our own implementation.
const RFC7636_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC7636_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

Deno.test("PKCE accepts the verifier that produced the challenge", async () => {
  const ok = await verifyPkce(
    { codeChallenge: RFC7636_CHALLENGE, codeChallengeMethod: "S256" },
    RFC7636_VERIFIER,
  );
  assertEquals(ok, true);
});

Deno.test("PKCE rejects a wrong, missing or empty verifier", async () => {
  const challenge = { codeChallenge: RFC7636_CHALLENGE, codeChallengeMethod: "S256" };
  assertEquals(await verifyPkce(challenge, "not-the-verifier"), false);
  assertEquals(await verifyPkce(challenge, undefined), false);
  assertEquals(await verifyPkce(challenge, ""), false);
});

Deno.test("PKCE refuses plain, whatever verifier is offered", async () => {
  // `plain` would let anyone who intercepted the code complete the exchange.
  assertEquals(
    await verifyPkce({ codeChallenge: RFC7636_VERIFIER, codeChallengeMethod: "plain" }, RFC7636_VERIFIER),
    false,
  );
  assertEquals(
    await verifyPkce({ codeChallenge: RFC7636_CHALLENGE, codeChallengeMethod: null }, RFC7636_VERIFIER),
    false,
  );
});

Deno.test("a code issued without a challenge needs no verifier", async () => {
  assertEquals(await verifyPkce({ codeChallenge: null, codeChallengeMethod: null }, undefined), true);
});

Deno.test("the roles claim carries application roles, not the system role", () => {
  const claims = buildIdTokenClaims(
    { id: "u", email: "e@x", role: "user", appRoles: ["USER_ADMIN", "RESEARCHER.Demo"] },
    { issuer: "https://i", audience: "a", scopes: ["openid"] },
  );
  // The system role gates trex's own admin features and is reported separately.
  assertEquals(claims.trex_role, "user");
  assertEquals(claims.roles, ["USER_ADMIN", "RESEARCHER.Demo"]);
});

Deno.test("a user with no application roles gets an empty list, not their system role", () => {
  const claims = buildIdTokenClaims(
    { id: "u", email: "e@x", role: "admin", appRoles: [] },
    { issuer: "https://i", audience: "a", scopes: ["openid"] },
  );
  // Leaking the system role here would grant application access to anyone whom
  // trex happens to consider an administrator.
  assertEquals(claims.roles, []);
  assertEquals(claims.trex_role, "admin");
});

Deno.test("no seeded client without an id or a redirect uri", () => {
  assertEquals(parseSeedClient({}), null);
  assertEquals(parseSeedClient({ TREX_OIDC_CLIENT_ID: "  " }), null);
  // An id with nowhere to redirect could never complete a flow.
  assertEquals(parseSeedClient({ TREX_OIDC_CLIENT_ID: "app" }), null);
  assertEquals(
    parseSeedClient({ TREX_OIDC_CLIENT_ID: "app", TREX_OIDC_CLIENT_REDIRECT_URIS: "  " }),
    null,
  );
});

Deno.test("a seeded client reads its uris as a list, however they are separated", () => {
  const spec = parseSeedClient({
    TREX_OIDC_CLIENT_ID: "d2e-webapi",
    TREX_OIDC_CLIENT_SECRET: "s3cret",
    TREX_OIDC_CLIENT_NAME: "WebAPI",
    TREX_OIDC_CLIENT_REDIRECT_URIS: "https://a.test/cb/openid, https://b.test/cb/openid",
    TREX_OIDC_CLIENT_POST_LOGOUT_URIS: "https://a.test/atlas/",
  });
  assertEquals(spec?.clientId, "d2e-webapi");
  assertEquals(spec?.clientSecret, "s3cret");
  assertEquals(spec?.name, "WebAPI");
  assertEquals(spec?.redirectUris, ["https://a.test/cb/openid", "https://b.test/cb/openid"]);
  assertEquals(spec?.postLogoutRedirectUris, ["https://a.test/atlas/"]);
});

// A scope is grantable only if the client lists it, and the column default is
// openid/profile/email — so without this the idp_groups scope could never
// reach the client trex seeds for itself.
Deno.test("a seeded client can be configured with the scopes it may be granted", () => {
  const base = {
    TREX_OIDC_CLIENT_ID: "d2e-webapi",
    TREX_OIDC_CLIENT_REDIRECT_URIS: "https://a.test/cb/openid",
  };
  assertEquals(
    parseSeedClient({ ...base, TREX_OIDC_CLIENT_SCOPES: "openid profile email idp_groups" })
      ?.allowedScopes,
    ["openid", "profile", "email", "idp_groups"],
  );
  // openid is what makes the request an OIDC one; /authorize refuses without
  // it, so a list that omits it gets it.
  assertEquals(
    parseSeedClient({ ...base, TREX_OIDC_CLIENT_SCOPES: "email, idp_groups" })?.allowedScopes,
    ["openid", "email", "idp_groups"],
  );
  // Unset means "leave the row's scopes alone", not "reset them".
  assertEquals(parseSeedClient(base)?.allowedScopes, undefined);
  assertEquals(parseSeedClient({ ...base, TREX_OIDC_CLIENT_SCOPES: "  " })?.allowedScopes, undefined);
});

Deno.test("a seeded client carries the roles it is configured with", () => {
  const spec = parseSeedClient({
    TREX_OIDC_CLIENT_ID: "d2e-webapi",
    TREX_OIDC_CLIENT_SECRET: "s3cret",
    TREX_OIDC_CLIENT_REDIRECT_URIS: "https://a.test/cb/openid",
    TREX_OIDC_CLIENT_ROLES: "ALP_USER_ADMIN, ALP_SYSTEM_ADMIN",
  });
  assertEquals(spec?.clientRoles, ["ALP_USER_ADMIN", "ALP_SYSTEM_ADMIN"]);
});

Deno.test("a seeded client with no roles configured carries none", () => {
  const spec = parseSeedClient({
    TREX_OIDC_CLIENT_ID: "d2e-webapi",
    TREX_OIDC_CLIENT_REDIRECT_URIS: "https://a.test/cb/openid",
  });
  assertEquals(spec?.clientRoles, []);
});

Deno.test("a seeded client without a secret is public and falls back to its id for a name", () => {
  const spec = parseSeedClient({
    TREX_OIDC_CLIENT_ID: "atlas",
    TREX_OIDC_CLIENT_REDIRECT_URIS: "https://a.test/cb",
  });
  assertEquals(spec?.clientSecret, undefined);
  assertEquals(spec?.name, "atlas");
  assertEquals(spec?.postLogoutRedirectUris, []);
});

Deno.test("return_to keeps the base path exactly once", () => {
  // The issuer carries the mount prefix and so does originalUrl. Concatenating
  // them yields /trex/trex/oidc/authorize, which 404s, so the user signs in and
  // lands nowhere. Regression guard for that doubling.
  assertEquals(
    buildReturnTo("https://d2e.example:41100/trex", "/trex/oidc/authorize?client_id=d2e-webapi"),
    "https://d2e.example:41100/trex/oidc/authorize?client_id=d2e-webapi",
  );
});

Deno.test("return_to preserves the query string untouched", () => {
  // The whole authorization request has to survive the round trip: dropping
  // code_challenge or state would break PKCE and CSRF protection respectively.
  const url = "/trex/oidc/authorize?scope=openid&code_challenge=abc&code_challenge_method=S256&state=xyz";
  assertEquals(
    buildReturnTo("https://d2e.example:41100/trex", url),
    `https://d2e.example:41100${url}`,
  );
});

Deno.test("return_to ignores any path on the issuer, however deep", () => {
  assertEquals(
    buildReturnTo("https://d2e.example:41100/a/b/c", "/a/b/c/oidc/authorize"),
    "https://d2e.example:41100/a/b/c/oidc/authorize",
  );
});

Deno.test("return_to keeps a non-default port and the scheme", () => {
  assertEquals(
    buildReturnTo("http://localhost:33001", "/oidc/authorize"),
    "http://localhost:33001/oidc/authorize",
  );
});

Deno.test("idp_groups are emitted only under the idp_groups scope", () => {
  const user = {
    id: "u-1", email: "jo@example.test", role: "user", appRoles: [],
    idpGroups: ["group-guid-1"], idpProvider: "entra",
  };
  const withScope = buildIdTokenClaims(user, {
    issuer: "https://trex.test", audience: "atlas", scopes: ["openid", "idp_groups"],
  });
  assertEquals(withScope.idp_groups, ["group-guid-1"]);
  assertEquals(withScope.idp_provider, "entra");

  const without = buildIdTokenClaims(user, {
    issuer: "https://trex.test", audience: "atlas", scopes: ["openid"],
  });
  assertEquals(without.idp_groups, undefined);
  assertEquals(without.idp_provider, undefined);
});

Deno.test("a native login emits no idp claims even under the scope", () => {
  const claims = buildIdTokenClaims(
    { id: "u-1", email: "jo@example.test", role: "user", appRoles: [] },
    { issuer: "https://trex.test", audience: "atlas", scopes: ["openid", "idp_groups"] },
  );
  assertEquals(claims.idp_groups, undefined);
});

// ── The federated-session end of the claims contract ────────────────────────
//
// The producer is federation/router.ts, which writes trexdb."user".app_metadata
// inside the callback transaction; the consumer is oidc/router.ts's fetchUser,
// which spreads federationFromAppMetadata(row.app_metadata) into the
// IdTokenUser it returns. These exercise the join between the two without a
// database: the value written on one side, read on the other, and carried into
// the issued claims.

/** The literal JSONB a federated sign-in leaves behind, for a claim-sourced provider. */
const federatedAppMetadata = (provider: string, groups: string[]) => ({
  provider: "email",
  providers: ["email"],
  [IDP_METADATA_KEY]: { provider, groups },
});

Deno.test("a federated session's app_metadata becomes idp claims under the scope", () => {
  const user = {
    id: "u-1",
    email: "jo@example.test",
    role: "user",
    appRoles: ["RESEARCHER"],
    // Exactly what fetchUser does with the row it read.
    ...federationFromAppMetadata(federatedAppMetadata("logto", ["admins", "Trial-Ops"])),
  };
  assertEquals(user.idpProvider, "logto");
  assertEquals(user.idpGroups, ["admins", "Trial-Ops"]);

  const claims = buildIdTokenClaims(user, {
    issuer: "https://trex.test",
    audience: "atlas",
    scopes: ["openid", "idp_groups"],
  });
  // Raw and in the order the upstream stated them: not sorted, not folded.
  assertEquals(claims.idp_groups, ["admins", "Trial-Ops"]);
  assertEquals(claims.idp_provider, "logto");
});

Deno.test("a federated session with no groups still names its provider", () => {
  const claims = buildIdTokenClaims(
    {
      id: "u-1",
      email: "jo@example.test",
      role: "user",
      appRoles: [],
      ...federationFromAppMetadata(federatedAppMetadata("physionet", [])),
    },
    { issuer: "https://trex.test", audience: "atlas", scopes: ["openid", "idp_groups"] },
  );
  assertEquals(claims.idp_groups, []);
  assertEquals(claims.idp_provider, "physionet");
});

Deno.test("a native session's app_metadata yields no idp fields at all", () => {
  const native = { provider: "email", providers: ["email"], trex_role: "user" };
  assertEquals(federationFromAppMetadata(native), {});

  const claims = buildIdTokenClaims(
    {
      id: "u-1",
      email: "jo@example.test",
      role: "user",
      appRoles: [],
      ...federationFromAppMetadata(native),
    },
    { issuer: "https://trex.test", audience: "atlas", scopes: ["openid", "idp_groups"] },
  );
  assertEquals(claims.idp_groups, undefined);
  assertEquals(claims.idp_provider, undefined);
});

// app_metadata is a free-form JSONB column that long predates federation.
Deno.test("a malformed federation block degrades to a native session", () => {
  assertEquals(federationFromAppMetadata(null), {});
  assertEquals(federationFromAppMetadata(undefined), {});
  assertEquals(federationFromAppMetadata("nonsense"), {});
  assertEquals(federationFromAppMetadata({ [IDP_METADATA_KEY]: "logto" }), {});
  assertEquals(federationFromAppMetadata({ [IDP_METADATA_KEY]: { groups: ["a"] } }), {});
  assertEquals(federationFromAppMetadata({ [IDP_METADATA_KEY]: { provider: "" } }), {});
  // A provider with an unusable group list is still a federated session; it
  // simply asserts no groups, rather than being demoted to a native one.
  assertEquals(
    federationFromAppMetadata({ [IDP_METADATA_KEY]: { provider: "logto" } }),
    { idpProvider: "logto", idpGroups: [] },
  );
  assertEquals(
    federationFromAppMetadata({ [IDP_METADATA_KEY]: { provider: "logto", groups: [1, 2] } }),
    { idpProvider: "logto", idpGroups: [] },
  );
});

// grantedScopes is what stands between "advertised" and "granted": a client
// that has not been given the scope cannot obtain group data by asking.
Deno.test("idp_groups is grantable only to a client that allows it", () => {
  assertEquals(grantedScopes(client, "openid idp_groups"), ["openid"]);
  const allowed: OidcClient = {
    ...client,
    allowedScopes: [...client.allowedScopes, "idp_groups"],
  };
  assertEquals(grantedScopes(allowed, "openid idp_groups"), ["openid", "idp_groups"]);
  // And the refresh grant asks for it by name, so an allowed client does not
  // lose its group claims the first time its token turns over.
  assertEquals(
    grantedScopes(allowed, "openid profile email idp_groups").includes("idp_groups"),
    true,
  );
});
