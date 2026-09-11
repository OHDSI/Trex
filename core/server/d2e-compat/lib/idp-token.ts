/** How long /oauth/token keeps retrying an unreachable IdP before giving up. */
const IDP_TOKEN_RETRY_BUDGET_MS = 30_000;

/**
 * POST the token request, retrying only while the IdP is unreachable.
 *
 * The plugin init functions run as edge-runtime workers, dispatched the moment
 * plugins are registered rather than awaited, so they are not ordered against
 * anything in boot. fhir-init posts here while Logto is still migrating the
 * database trex just provisioned for it; the forward then fails at the
 * transport layer ("error sending request"), the route answers 500, and the
 * init dies for good — taking dataset creation with it. Measured gap between
 * the first failed post and discovery being served: ~16s.
 *
 * Only a throw from fetch is retried. Any HTTP answer is the IdP speaking —
 * including 4xx and 429 — and is handed back untouched, so a bad grant still
 * fails fast instead of being retried into the budget.
 */
export async function postToIdpToken(
  tokenUrl: string,
  body: string,
  budgetMs: number = IDP_TOKEN_RETRY_BUDGET_MS,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
  doFetch: typeof fetch = fetch,
): Promise<Response> {
  const deadline = Date.now() + budgetMs;
  let delay = 500;
  for (;;) {
    try {
      return await doFetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });
    } catch (e) {
      if (Date.now() + delay >= deadline) throw e;
      console.warn(
        `[d2e-compat] /oauth/token: IdP unreachable, retrying in ${delay}ms: ${(e as Error)?.message ?? e}`,
      );
      await sleep(delay);
      delay = Math.min(delay * 2, 4_000);
    }
  }
}
