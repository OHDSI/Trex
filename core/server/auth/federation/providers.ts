// The only module in federation/ that talks to the database.
import { decryptWithDek, encryptWithDek } from "../dek.ts";
import { decideLink, type ExistingUser, type LinkDecision } from "./link.ts";
import type { ProviderConfig, UpstreamIdentity } from "./types.ts";

// deno-lint-ignore no-explicit-any
type PgClient = any;

/**
 * Enabled providers that are actually federatable. A row with no issuer is
 * configuration in progress, not a provider — returning it would produce a
 * sign-in button that 500s.
 */
export async function loadProviders(client: PgClient): Promise<Map<string, ProviderConfig>> {
  const { rows } = await client.query(
    `SELECT id, "displayName", "clientId", "clientSecret", issuer, discovery_url,
            scopes, claim_map, groups_source, groups_claim, link_policy, auto_provision,
            email_domain_allowlist, allow_elevated_auto_link
       FROM trexdb.sso_provider
      WHERE enabled = true AND issuer IS NOT NULL`,
  );
  const out = new Map<string, ProviderConfig>();
  for (const r of rows) {
    out.set(r.id, {
      id: r.id,
      displayName: r.displayName,
      clientId: r.clientId,
      clientSecret: r.clientSecret,
      issuer: r.issuer,
      // Most providers publish discovery at the standard well-known path; only
      // the odd one out needs discovery_url set explicitly.
      discoveryUrl: r.discovery_url ??
        r.issuer.replace(/\/+$/, "") + "/.well-known/openid-configuration",
      scopes: r.scopes,
      claimMap: r.claim_map ?? {},
      groupsSource: r.groups_source,
      groupsClaim: r.groups_claim,
      linkPolicy: r.link_policy,
      autoProvision: r.auto_provision,
      emailDomainAllowlist: normaliseDomains(r.email_domain_allowlist),
      // `=== true` rather than a truthiness test: this decides whether an
      // upstream may take over an administrator's account, and the one value
      // that must enable it is the boolean true. Anything else — including a
      // column an older database has not got — stays off.
      allowElevatedAutoLink: r.allow_elevated_auto_link === true,
    });
  }
  return out;
}

/**
 * The trex user a verified upstream address resolves to, if any — with the
 * role, because whether it may be auto-linked at all depends on it (see
 * decideLink's elevated-account guard).
 */
export async function findLinkCandidateByEmail(
  client: PgClient,
  email: string,
): Promise<ExistingUser | null> {
  const { rows } = await client.query(
    // A match here becomes a link decision: an upstream identity is handed
    // the account it resolves to. Soft-deleted and banned users must never
    // resolve, or a deactivated account is resurrected for whoever controls
    // that address at the identity provider. Both columns are nullable with
    // NULL meaning "not disabled", so `banned = false` alone would wrongly
    // drop NULL rows; `IS NOT TRUE` treats NULL and false as not-banned.
    `SELECT id, role FROM trexdb."user"
      WHERE lower(email) = lower($1)
        AND "deletedAt" IS NULL
        AND banned IS NOT TRUE
      LIMIT 1`,
    [email],
  );
  const row = rows[0];
  if (!row) return null;
  return { id: row.id, role: row.role ?? null };
}

/**
 * A configured allowlist, reduced to bare lower-cased domains. Whitespace and
 * a leading '@' (a natural way to write a domain in configuration) are
 * tolerated; anything empty is dropped, and a list left with nothing in it
 * becomes `null`, i.e. "no restriction" — the same as an unset column.
 */
function normaliseDomains(raw: unknown): string[] | null {
  if (!Array.isArray(raw)) return null;
  const out = raw
    .filter((d): d is string => typeof d === "string")
    .map((d) => d.trim().replace(/^@/, "").toLowerCase())
    .filter((d) => d.length > 0);
  return out.length > 0 ? out : null;
}

/** An existing (providerId, accountId) link, and whether its user may sign in. */
export interface LinkedAccount {
  userId: string;
  /** Soft-deleted or banned. The link is real; the account may not be used. */
  disabled: boolean;
}

/**
 * The user an upstream identity is already linked to.
 *
 * `UNIQUE("providerId","accountId")` on trexdb.account IS the identity: this,
 * not the email address, is what says "this upstream subject is this trex
 * user". Email only ever answers the *linking* question, and only for an
 * upstream identity nobody has seen before — otherwise a person who changes
 * their address at the identity provider is silently re-targeted onto whoever
 * now holds that address in trex, and an administrator editing a federated
 * user's trex email orphans the link.
 *
 * The row is returned even when the user is disabled, with the fact reported
 * rather than filtered out. Dropping a disabled user here would make an
 * existing link indistinguishable from no link at all, and the flow would fall
 * through to the email path and try to provision the banned user's address
 * again — hitting user.email's UNIQUE constraint inside the transaction and
 * surfacing as an opaque failure instead of "this account is deactivated".
 */
export async function findLinkedUser(
  client: PgClient,
  providerId: string,
  accountId: string,
): Promise<LinkedAccount | null> {
  const { rows } = await client.query(
    `SELECT a."userId" AS "userId",
            (u."deletedAt" IS NOT NULL OR u.banned IS TRUE) AS disabled
       FROM trexdb.account a
       JOIN trexdb."user" u ON u.id = a."userId"
      WHERE a."providerId" = $1 AND a."accountId" = $2
      LIMIT 1`,
    [providerId, accountId],
  );
  const row = rows[0];
  if (!row) return null;
  return { userId: row.userId, disabled: row.disabled === true };
}

/**
 * Which trex user this upstream identity signs in as, in the one order that is
 * safe: the existing link first, the email question only when there is none.
 *
 * Deliberately NOT done here: rewriting the trex user's email to whatever the
 * upstream now asserts. `user.email` is trex's own identifier — it is UNIQUE,
 * it is what the password grant authenticates against, and it is what an
 * administrator sees. An upstream that changes it would be able to move a trex
 * account onto an address it chose, collide with another user's address and
 * fail the whole sign-in inside the transaction, or quietly redirect a native
 * login. The link, not the address, carries the identity; a drifted address is
 * for an administrator to reconcile.
 */
export async function resolveFederatedUser(
  client: PgClient,
  provider: ProviderConfig,
  identity: UpstreamIdentity,
): Promise<LinkDecision> {
  const linked = await findLinkedUser(client, provider.id, identity.sub);
  if (linked) {
    // A ban has to stop this path too, or a banned user keeps signing in
    // through the link they already have.
    if (linked.disabled) return { action: "refuse", reason: "account_disabled" };
    // The link IS the identity: whatever the upstream now says the address is,
    // and whether or not it says it is verified, this is the user.
    return { action: "link", userId: linked.userId };
  }
  // First sighting of this upstream identity. Only now does email decide
  // anything, and only under the provider's link policy — and only here do the
  // domain allowlist and the elevated-account guard apply. An identity with an
  // account row above has already been through them and keeps signing in.
  return decideLink(identity, provider, await findLinkCandidateByEmail(client, identity.email));
}

/** A federated user has no password: no row in account with providerId 'credential'. */
export async function provisionUser(client: PgClient, identity: UpstreamIdentity): Promise<string> {
  const id = crypto.randomUUID();
  await client.query(
    `INSERT INTO trexdb."user" (id, name, email, "emailVerified", email_confirmed_at, role)
     VALUES ($1, $2, $3, true, NOW(), 'user')`,
    [id, identity.name ?? identity.email, identity.email],
  );
  return id;
}

/**
 * Encrypt one upstream token for storage, or return SQL NULL if there isn't one.
 *
 * The null mapping is load-bearing, not tidiness. upsertAccount's ON CONFLICT
 * preserves a stored refresh token when the incoming one is absent, and it does
 * that with COALESCE(EXCLUDED, stored) — a *null test*, never a comparison. So
 * the rule the plaintext version relied on has to survive verbatim: an absent
 * token must reach the statement as NULL. Encrypting "" (or the string
 * "undefined") would produce a perfectly good ciphertext, COALESCE would take
 * it, and the stored refresh token would be destroyed by a sign-in that simply
 * did not carry one.
 *
 * Nothing anywhere compares these columns, which is what makes ciphertext safe
 * here at all: AES-GCM with a fresh IV encrypts the same token differently
 * every time, so the stored value churns on each sign-in even when the upstream
 * token has not changed. Only null-ness is ever tested, and that is preserved.
 *
 * Failure is fatal to the sign-in by design. The DEK is initialised at boot
 * (index.ts, before server.listen, and a failure there aborts boot), so the
 * only way this throws in practice is a genuinely broken key state — and
 * storing a live upstream credential in the clear because encryption was
 * unavailable is precisely the outcome this change exists to prevent. The
 * caller's transaction rolls back and /callback answers with its generic
 * failure, with the detail in the log.
 */
async function sealToken(
  value: string | null | undefined,
  label: string,
): Promise<string | null> {
  if (typeof value !== "string" || value.length === 0) return null;
  try {
    return await encryptWithDek(value);
  } catch (err) {
    // Never log the value; name the column and re-throw.
    throw new Error(`could not encrypt upstream ${label}: ${err}`);
  }
}

/** Reverse of sealToken. NULL stays null; ciphertext is decrypted or throws. */
async function openToken(value: string | null | undefined, label: string): Promise<string | null> {
  if (typeof value !== "string" || value.length === 0) return null;
  try {
    return await decryptWithDek(value);
  } catch (err) {
    // A decrypt failure means the stored value is not usable under the current
    // key — a rotated/lost KEK, or a row written before these columns were
    // encrypted. Surfacing it beats handing a caller a token-shaped null and
    // letting it conclude the upstream never issued one.
    throw new Error(`could not decrypt stored upstream ${label}: ${err}`);
  }
}

/** The upstream tokens held for one linked identity, decrypted. */
export interface UpstreamTokens {
  userId: string;
  accessToken: string | null;
  refreshToken: string | null;
  idToken: string | null;
  accessTokenExpiresAt: Date | null;
  scope: string | null;
}

/**
 * Read back what upsertAccount stored. The three token columns are ciphertext
 * at rest (see sealToken), so every reader must come through here rather than
 * SELECTing the columns directly — including phase 5's PhysioNet token broker,
 * which is the first consumer this exists for.
 */
export async function readAccountTokens(
  client: PgClient,
  providerId: string,
  accountId: string,
): Promise<UpstreamTokens | null> {
  const { rows } = await client.query(
    `SELECT "userId", "accessToken", "refreshToken", "idToken",
            "accessTokenExpiresAt", scope
       FROM trexdb.account
      WHERE "providerId" = $1 AND "accountId" = $2
      LIMIT 1`,
    [providerId, accountId],
  );
  const row = rows[0];
  if (!row) return null;
  return {
    userId: row.userId,
    accessToken: await openToken(row.accessToken, "access token"),
    refreshToken: await openToken(row.refreshToken, "refresh token"),
    idToken: await openToken(row.idToken, "id token"),
    accessTokenExpiresAt: row.accessTokenExpiresAt ?? null,
    scope: row.scope ?? null,
  };
}

export async function upsertAccount(client: PgClient, args: {
  userId: string;
  providerId: string;
  accountId: string;
  accessToken?: string;
  refreshToken?: string;
  accessTokenExpiresAt?: Date;
  scope?: string;
  idToken?: string;
}): Promise<void> {
  // These are live credentials at another identity provider: an access token
  // that speaks for the person at the upstream, a refresh token that mints more
  // of them, and an id_token. They are encrypted under the DEK before they
  // reach the statement, so the row (and any dump or replica of it) holds no
  // usable credential. RLS on trexdb.account remains the outer guard; this is
  // the one that survives a copy of the data.
  const [accessToken, refreshToken, idToken] = await Promise.all([
    sealToken(args.accessToken, "access token"),
    sealToken(args.refreshToken, "refresh token"),
    sealToken(args.idToken, "id token"),
  ]);
  await client.query(
    `INSERT INTO trexdb.account
       (id, "userId", "accountId", "providerId", "accessToken", "refreshToken",
        "accessTokenExpiresAt", scope, "idToken")
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     ON CONFLICT ("providerId", "accountId") DO UPDATE SET
       -- Kept in step with the user this sign-in was actually granted to, so
       -- the row can never disagree with the identity resolution above. In the
       -- ordinary path this is a no-op: the link is what selected the user.
       "userId" = EXCLUDED."userId",
       "accessToken" = EXCLUDED."accessToken",
       -- Providers commonly return a refresh token only on first authorization;
       -- overwriting a stored one with NULL on a later sign-in would strand
       -- whatever depends on it (see phase 5's refresh-token use).
       "refreshToken" = COALESCE(EXCLUDED."refreshToken", trexdb.account."refreshToken"),
       "accessTokenExpiresAt" = EXCLUDED."accessTokenExpiresAt",
       scope = EXCLUDED.scope,
       "idToken" = EXCLUDED."idToken",
       "updatedAt" = NOW()`,
    [
      crypto.randomUUID(), args.userId, args.accountId, args.providerId,
      accessToken, refreshToken,
      args.accessTokenExpiresAt ?? null, args.scope ?? null, idToken,
    ],
  );
}
