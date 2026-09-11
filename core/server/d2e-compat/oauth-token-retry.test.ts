import { assert, assertEquals } from "jsr:@std/assert";
import { postToIdpToken } from "./lib/idp-token.ts";

const noSleep = (_ms: number) => Promise.resolve();

Deno.test("an unreachable IdP is retried until it answers", async () => {
  let calls = 0;
  const res = await postToIdpToken("https://idp/token", "grant_type=x", 30_000, noSleep, () => {
    calls++;
    // The shape Deno's fetch throws when nothing is listening yet.
    if (calls < 3) return Promise.reject(new TypeError("error sending request"));
    return Promise.resolve(new Response("{}", { status: 200 }));
  });
  assertEquals(calls, 3);
  assertEquals(res.status, 200);
});

Deno.test("an HTTP answer is returned as-is, never retried", async () => {
  for (const status of [400, 429, 500]) {
    let calls = 0;
    const res = await postToIdpToken("https://idp/token", "grant_type=x", 30_000, noSleep, () => {
      calls++;
      return Promise.resolve(new Response("nope", { status }));
    });
    assertEquals(calls, 1, `status ${status} must not be retried`);
    assertEquals(res.status, status);
  }
});

Deno.test("the transport error surfaces once the budget is spent", async () => {
  let calls = 0;
  // Budget below the first backoff, so it gives up after a single attempt.
  await postToIdpToken("https://idp/token", "grant_type=x", 1, noSleep, () => {
    calls++;
    return Promise.reject(new TypeError("error sending request"));
  })
    .then(() => assert(false, "must not resolve when the IdP never answers"))
    .catch((e) => assertEquals((e as Error).message, "error sending request"));
  assertEquals(calls, 1);
});
