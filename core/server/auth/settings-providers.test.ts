import { assertEquals } from "jsr:@std/assert";
import { loadExternalProviders } from "./settings-providers.ts";

Deno.test("a failing provider query still yields email-only settings", async () => {
  // Simulates a missing sso_provider table (pre-migration) or a transient
  // database error. /settings must still resolve with something a sign-in
  // page can render — email/password only — rather than 500ing the whole
  // GoTrue-compatible discovery endpoint that runs unconditionally at boot.
  const failingClient = {
    query: () => Promise.reject(new Error(`relation "trexdb.sso_provider" does not exist`)),
  };
  const external = await loadExternalProviders(failingClient);
  assertEquals(external, { email: true });
});

Deno.test("a successful provider query is advertised alongside email", async () => {
  const client = {
    query: () =>
      Promise.resolve({
        rows: [{
          id: "entra",
          displayName: "Entra",
          clientId: "x",
          clientSecret: "y",
          issuer: "https://entra.example",
          discovery_url: null,
          scopes: [],
          claim_map: {},
          groups_source: null,
          groups_claim: null,
          link_policy: null,
          auto_provision: false,
        }],
      }),
  };
  const external = await loadExternalProviders(client);
  assertEquals(external, { email: true, entra: true });
});
