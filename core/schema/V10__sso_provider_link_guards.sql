-- Two optional guards on the *first* link between an upstream identity and an
-- existing trex user. Neither changes anything for a provider that does not
-- set them, and neither is consulted once trexdb.account already holds a
-- (providerId, accountId) row — an established link is the identity and keeps
-- working.
--
-- Why they exist: decideLink() links on any verified upstream email. With more
-- than one upstream configured, the least-trusted of them can assert an
-- administrator's address and be handed that administrator's trex account,
-- including a native password account that never opted into federation.
ALTER TABLE trexdb.sso_provider
  -- NULL (and an empty array) means "no restriction" — exactly today's
  -- behaviour, so existing rows are unaffected. When set, a verified upstream
  -- email whose domain is not listed is refused outright: it neither links to
  -- an existing user nor provisions a new one.
  ADD COLUMN IF NOT EXISTS email_domain_allowlist  TEXT[],
  -- Off by default: the safe default is that a federated identity seen for the
  -- first time may NOT silently become an administrator, whatever email the
  -- upstream asserts. A deployment that genuinely wants its IdP to own admin
  -- identities turns this on per provider.
  ADD COLUMN IF NOT EXISTS allow_elevated_auto_link BOOLEAN NOT NULL DEFAULT false;

-- Postgres has no `ADD CONSTRAINT IF NOT EXISTS`, and nothing guarantees this
-- migration runs exactly once against a given database (a rebuilt schema, a
-- manual replay). Same pg_constraint guard as V9.
--
-- A NULL or empty element is configuration that cannot mean anything: NULL
-- would make `<> ALL` comparisons return NULL, and '' matches no domain the
-- application would ever derive. Rejecting both at the boundary keeps the
-- allowlist's "empty means unrestricted" rule unambiguous — the difference
-- between a list of nothing and a list containing nothing is exactly the kind
-- of thing that turns a deny into an allow.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint
      WHERE conname = 'sso_provider_email_domain_allowlist_check'
        AND conrelid = 'trexdb.sso_provider'::regclass
  ) THEN
    ALTER TABLE trexdb.sso_provider
      ADD CONSTRAINT sso_provider_email_domain_allowlist_check
      CHECK (
        email_domain_allowlist IS NULL
        OR (
          array_position(email_domain_allowlist, NULL::text) IS NULL
          AND '' <> ALL (email_domain_allowlist)
        )
      );
  END IF;
END
$$;

COMMENT ON COLUMN trexdb.sso_provider.email_domain_allowlist IS
  'Optional. When set, only a verified upstream email whose domain (after the last "@", compared case-insensitively) is listed may link or provision. NULL or empty means no restriction.';

COMMENT ON COLUMN trexdb.sso_provider.allow_elevated_auto_link IS
  'When false (default), a first-time federated identity is refused rather than auto-linked to an existing trex user whose role is elevated (anything other than the default "user").';
