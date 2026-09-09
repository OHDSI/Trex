import { assertEquals, assertThrows } from "jsr:@std/assert";
import { applyClaimMap, federationEnabled } from "./config.ts";

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
