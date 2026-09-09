import { assertEquals, assertNotEquals, assertRejects, assertThrows } from "jsr:@std/assert";
import { applyClaimMap, federationEnabled } from "./config.ts";
import { signState, stateKey, verifyState } from "./state.ts";

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
