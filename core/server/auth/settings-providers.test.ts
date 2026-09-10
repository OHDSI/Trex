import { assertEquals } from "jsr:@std/assert";
import { loadExternalProviders } from "./settings-providers.ts";

// Deliberately explicit in every call below: the parameter defaults to
// federationEnabled(), which reads TREX_FEDERATION_ENABLED.
Deno.test("a failing provider query still yields email-only settings", async () => {
  // Simulates a missing sso_provider table (pre-migration) or a transient
  // database error. /settings must still resolve with something a sign-in
  // page can render — email/password only — rather than 500ing the whole
  // GoTrue-compatible discovery endpoint that runs unconditionally at boot.
  const failingClient = {
    query: () => Promise.reject(new Error(`relation "trexdb.sso_provider" does not exist`)),
  };
  const external = await loadExternalProviders(failingClient, true);
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
  const external = await loadExternalProviders(client, true);
  assertEquals(external, { email: true, entra: true });
});

// The routes are mounted only when TREX_FEDERATION_ENABLED is on. Advertising
// a provider while they are not gives the sign-in page a button whose
// /authorize does not exist.
Deno.test("providers are not advertised while federation is disabled", async () => {
  let asked = false;
  const client = {
    query: () => {
      asked = true;
      return Promise.resolve({
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
      });
    },
  };
  assertEquals(await loadExternalProviders(client, false), { email: true });
  // Not merely hidden: a disabled deployment does not query for them at all.
  assertEquals(asked, false);
});
