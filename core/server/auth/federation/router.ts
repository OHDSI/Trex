// The federation relying-party endpoints.
//
// These are NOT the OIDC provider's /authorize (that lives under
// `${BASE_PATH}/oidc` and faces the other way, serving relying parties such as
// WebAPI). These send the browser OUT to an upstream identity provider and
// receive it back, then issue exactly the session the native password grant
// issues — so from the moment /callback finishes the request is
// indistinguishable from a native login, and neither the OIDC provider nor any
// relying party needs to know federation exists.
import { Router } from "express";
import { authLimiter } from "../../middleware/rate-limit.ts";
import { createTokenResponse } from "../auth-router.ts";
import { IDP_METADATA_KEY } from "../oidc/claims.ts";
import { applyClaimMap, federationEnabled } from "./config.ts";
import { loadDiscovery } from "./discovery.ts";
import { resolveGroups } from "./groups.ts";
import { challengeFor, createVerifier } from "./pkce.ts";
import { loadProviders, provisionUser, resolveFederatedUser, upsertAccount } from "./providers.ts";
import {
  bindingCookieName,
  bindingMatches,
  callbackUri,
  consumeState,
  isSecureRequest,
  safeErrorCode,
  safeRedirectTo,
  warnIfInsecureBinding,
} from "./request.ts";
import { hashBinding, signState, STATE_TTL_SECONDS, stateKeys, verifyState } from "./state.ts";
import { verifyFederatedIdToken } from "./verify.ts";

// Re-exported so these read as one unit from outside; request.ts exists only to
// keep express out of the unit tests' module graph.
export { bindingMatches, callbackUri, consumeState, safeErrorCode, safeRedirectTo };

// deno-lint-ignore no-explicit-any
type Req = any;
// deno-lint-ignore no-explicit-any
type Res = any;

export function registerFederationRoutes(
  // deno-lint-ignore no-explicit-any
  app: any,
  basePath: string,
  // deno-lint-ignore no-explicit-any
  pool: any,
): void {
  if (!federationEnabled()) return;
  const router = Router();

  router.get("/authorize", authLimiter, async (req: Req, res: Res) => {
    let client;
    try {
      client = await pool.connect();
      const providers = await loadProviders(client);
      const provider = providers.get(String(req.query.provider ?? ""));
      if (!provider) {
        res.status(400).json({ error: "invalid_request", error_description: "Unknown provider" });
        return;
      }
      const doc = await loadDiscovery(provider.discoveryUrl);
      const verifier = createVerifier();
      const nonce = crypto.randomUUID();

      // Ties the flow to this browser (see request.ts). SameSite=Lax rather
      // than Strict on purpose: the browser reaches /callback through a
      // top-level cross-site redirect from the identity provider, and a Strict
      // cookie is withheld on exactly that navigation, which would refuse every
      // legitimate sign-in. Lax is sent on a top-level cross-site GET, which is
      // what this is.
      const binding = `${crypto.randomUUID()}${crypto.randomUUID()}`;
      const secure = isSecureRequest(req);
      // A deployment that lands here is weakening its own binding, usually by
      // accident (a TLS-terminating proxy sending no X-Forwarded-Proto), and
      // nothing else about the request would show it.
      warnIfInsecureBinding(secure);
      res.cookie(bindingCookieName(secure), binding, {
        httpOnly: true,
        sameSite: "lax",
        secure,
        path: "/",
        maxAge: STATE_TTL_SECONDS * 1000,
      });

      const state = await signState({
        provider: provider.id,
        redirectTo: safeRedirectTo(req.query.redirect_to as string | undefined),
        nonce,
        verifier,
        bind: await hashBinding(binding),
        exp: Math.floor(Date.now() / 1000) + STATE_TTL_SECONDS,
      }, await stateKeys());

      const url = new URL(doc.authorization_endpoint);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", provider.clientId);
      url.searchParams.set("redirect_uri", callbackUri(req, basePath));
      url.searchParams.set("scope", provider.scopes);
      url.searchParams.set("state", state);
      url.searchParams.set("nonce", nonce);
      url.searchParams.set("code_challenge", await challengeFor(verifier));
      url.searchParams.set("code_challenge_method", "S256");
      res.redirect(302, url.toString());
    } catch (err) {
      // The detail stays in the log. Anything thrown here — a discovery fetch,
      // a database error, a key derivation — can name internal hosts or
      // configuration, and this response goes straight to a browser.
      console.error("[federation] /authorize failed:", err);
      if (!res.headersSent) {
        res.status(500).json({
          error: "server_error",
          error_description: "Federated sign-in could not be started",
        });
      }
    } finally {
      client?.release();
    }
  });

  router.get("/callback", authLimiter, async (req: Req, res: Res) => {
    let client;
    try {
      // The upstream declined (consent refused, and so on). Say so without
      // reflecting whatever text it chose to put in error_description.
      if (req.query.error) {
        res.status(401).json({
          error: safeErrorCode(req.query.error),
          error_description: "The identity provider refused the sign-in",
        });
        return;
      }

      const rawState = String(req.query.state ?? "");
      const state = await verifyState(rawState, await stateKeys());

      // Before the token exchange, before any database work: a callback that
      // did not start in this browser is login CSRF and must cost nothing to
      // refuse. The cookie is cleared either way — it has served its purpose on
      // success, and on failure it is not this browser's to keep.
      // The name is chosen by THIS request's scheme, and only that name is
      // read: on HTTPS an unprefixed cookie is ignored even when no prefixed
      // one is present, or a sibling host could plant the value it needs.
      const bound = await bindingMatches(req.headers.cookie, state.bind, isSecureRequest(req));
      clearBinding(req, res);
      if (!bound) {
        res.status(401).json({
          error: "invalid_request",
          error_description: "This sign-in did not start in this browser",
        });
        return;
      }

      // Only after the signature and expiry check, so the replay map holds
      // nothing an attacker chose and nothing that outlives its own TTL.
      if (!consumeState(rawState, state.exp)) {
        res.status(401).json({
          error: "invalid_request",
          error_description: "This sign-in has already been completed",
        });
        return;
      }

      client = await pool.connect();
      const providers = await loadProviders(client);
      const provider = providers.get(state.provider);
      if (!provider) {
        res.status(400).json({ error: "invalid_request", error_description: "Unknown provider" });
        return;
      }
      const doc = await loadDiscovery(provider.discoveryUrl);

      const form = new URLSearchParams({
        grant_type: "authorization_code",
        code: String(req.query.code ?? ""),
        // Must be byte-identical to the one /authorize sent, hence the same
        // function rather than a second copy of the string.
        redirect_uri: callbackUri(req, basePath),
        client_id: provider.clientId,
        code_verifier: state.verifier,
      });
      // client_secret_post. A provider registered as a public client has no
      // secret and authenticates with PKCE alone, so an absent one is omitted
      // rather than sent as "".
      if (provider.clientSecret) form.set("client_secret", provider.clientSecret);

      const tokenRes = await fetch(doc.token_endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept": "application/json",
        },
        body: form,
      });
      if (!tokenRes.ok) {
        // The upstream body goes to the log only: it commonly echoes the
        // request, client_id included, and is not ours to show a browser.
        const detail = await tokenRes.text().catch(() => "");
        console.error(
          `[federation] token exchange with ${provider.id} failed: ${tokenRes.status} ${detail}`,
        );
        res.status(401).json({
          error: "invalid_grant",
          error_description: "Upstream token exchange failed",
        });
        return;
      }
      const tokens = await tokenRes.json();
      if (typeof tokens.id_token !== "string") {
        throw new Error(`upstream ${provider.id} returned no id_token`);
      }
      const claims = await verifyFederatedIdToken(tokens.id_token, {
        doc,
        clientId: provider.clientId,
        nonce: state.nonce,
      });
      const identity = applyClaimMap(claims, provider.claimMap);
      // Step 6 of the flow. Read off the validated id_token, so the claim is
      // one this provider signed; raw, so d2e sees what the upstream said.
      const groups = resolveGroups(claims, provider);

      // Identity first, email second: an upstream subject already linked to a
      // trex user IS that user, whatever address the upstream now asserts.
      const decision = await resolveFederatedUser(client, provider, identity);
      if (decision.action === "refuse") {
        // The reasons are trex's own fixed codes, not upstream text.
        res.status(403).json({ error: "access_denied", error_description: decision.reason });
        return;
      }
      // One transaction for the whole write sequence: provisioning a user and
      // then failing to write its account row would leave a user who exists,
      // owns no credential and no upstream link, and cannot sign in by any
      // route — and whose email would be found by the next flow's
      // findUserIdByEmail and linked to.
      let sessionUser;
      await client.query("BEGIN");
      try {
        const userId = decision.action === "link"
          ? decision.userId
          : await provisionUser(client, identity);

        await upsertAccount(client, {
          userId,
          providerId: provider.id,
          accountId: identity.sub,
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token,
          accessTokenExpiresAt: tokens.expires_in
            ? new Date(Date.now() + tokens.expires_in * 1000)
            : undefined,
          scope: tokens.scope,
          idToken: tokens.id_token,
        });

        // Two things at once, and both belong to this sign-in.
        //
        // last_sign_in_at is parity with the native grants, which stamp it on
        // every successful login; without it a federated user never records a
        // sign-in.
        //
        // The idp block is how the OIDC provider learns, later and on a
        // different request, that this user's current session came from an
        // upstream and which groups it asserted. fetchUser() there is handed
        // nothing but a user id — no session row, no code record — so the
        // fact has to be durable and keyed by the user. It is written inside
        // this transaction with the account row it describes, and dropped
        // again by a native password sign-in, so it always describes the most
        // recent sign-in rather than accumulating.
        await client.query(
          `UPDATE trexdb."user"
              SET last_sign_in_at = NOW(),
                  app_metadata = COALESCE(app_metadata, '{}'::jsonb)
                                 || jsonb_build_object($2::text, $3::jsonb),
                  "updatedAt" = NOW()
            WHERE id = $1`,
          [
            userId,
            IDP_METADATA_KEY,
            JSON.stringify({ provider: provider.id, groups }),
          ],
        );

        // The columns createTokenResponse's DbUser needs, named rather than
        // SELECT *: the session it signs is built out of this row.
        const { rows } = await client.query(
          `SELECT id, name, email, image, role, banned, "emailVerified", email_confirmed_at,
                  last_sign_in_at, "mustChangePassword", user_metadata, app_metadata,
                  password_hash, "createdAt", "updatedAt"
             FROM trexdb."user"
            WHERE id = $1 AND "deletedAt" IS NULL AND banned IS NOT TRUE`,
          [userId],
        );
        // Belt and braces on the disabled-user rule: whichever path resolved
        // the user — an existing link or a fresh email match — no session is
        // ever built from a row this SELECT would not return.
        if (!rows.length) {
          throw new Error("federated user is gone or deactivated between link and session");
        }
        sessionUser = rows[0];
        await client.query("COMMIT");
      } catch (err) {
        // A rollback that itself fails must not replace the real error.
        await client.query("ROLLBACK").catch(() => {});
        throw err;
      }

      // Issue exactly the session the password grant issues: it sets the
      // sb-access-token cookie the OIDC provider reads and returns its body
      // rather than writing one, so the redirect below is what the browser gets.
      await createTokenResponse(sessionUser, undefined, res);
      // Signed, so already safe; re-checked because the cost is nil and this is
      // the one redirect an attacker would want to reach.
      res.redirect(302, safeRedirectTo(state.redirectTo));
    } catch (err) {
      // Same rule as /authorize: an upstream URL, a JWKS failure or a database
      // message must not reach the browser. One generic code covers every
      // failure of the exchange, and the detail goes to the log.
      console.error("[federation] /callback failed:", err);
      if (!res.headersSent) {
        res.status(401).json({
          error: "invalid_request",
          error_description: "Federated sign-in failed",
        });
      }
    } finally {
      client?.release();
    }
  });

  app.use(`${basePath}/auth/v1`, router);
  console.log(`Federation endpoints mounted on ${basePath}/auth/v1/{authorize,callback}`);
}

/**
 * Clears the browser-binding cookie. Both names, because a deployment can
 * change its mind about HTTPS between the two legs of one flow and a stale
 * cookie under the other name would then outlive the sign-in it belonged to.
 */
function clearBinding(req: Req, res: Res): void {
  const secure = isSecureRequest(req);
  for (const name of [bindingCookieName(true), bindingCookieName(false)]) {
    res.clearCookie(name, {
      httpOnly: true,
      sameSite: "lax",
      // The prefixed name is only ever valid with Secure; the plain one takes
      // whatever this request is, matching how it was set.
      secure: name.startsWith("__Host-") ? true : secure,
      path: "/",
    });
  }
}
