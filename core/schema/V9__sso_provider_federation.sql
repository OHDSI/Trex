-- Federation configuration for sso_provider.
--
-- Additive: existing rows keep working and simply are not usable for
-- federation until an issuer is set. `enabled` alone no longer implies
-- federatable, so loadProviders() requires issuer IS NOT NULL.
ALTER TABLE trexdb.sso_provider
  ADD COLUMN IF NOT EXISTS issuer         TEXT,
  ADD COLUMN IF NOT EXISTS discovery_url  TEXT,
  ADD COLUMN IF NOT EXISTS scopes         TEXT    NOT NULL DEFAULT 'openid profile email',
  ADD COLUMN IF NOT EXISTS claim_map      JSONB   NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS groups_source  TEXT    NOT NULL DEFAULT 'none',
  ADD COLUMN IF NOT EXISTS groups_claim   TEXT,
  ADD COLUMN IF NOT EXISTS link_policy    TEXT    NOT NULL DEFAULT 'verified_email',
  ADD COLUMN IF NOT EXISTS auto_provision BOOLEAN NOT NULL DEFAULT false;

-- Postgres has no `ADD CONSTRAINT IF NOT EXISTS`. Nothing here guarantees this
-- migration only ever runs once against a given database (a rebuilt schema,
-- a manual replay), so a bare ADD CONSTRAINT could still hit an
-- already-constrained table. Guard it on pg_constraint instead.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint
      WHERE conname = 'sso_provider_groups_source_check'
        AND conrelid = 'trexdb.sso_provider'::regclass
  ) THEN
    ALTER TABLE trexdb.sso_provider
      ADD CONSTRAINT sso_provider_groups_source_check
      CHECK (groups_source IN ('claim', 'graph', 'none'));
  END IF;
END
$$;

-- ProviderConfig.linkPolicy is typed as the literal "verified_email"; enforce
-- that guarantee in the database too; a stray row is otherwise a runtime
-- type violation the app would only discover by crashing on it.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint
      WHERE conname = 'sso_provider_link_policy_check'
        AND conrelid = 'trexdb.sso_provider'::regclass
  ) THEN
    ALTER TABLE trexdb.sso_provider
      ADD CONSTRAINT sso_provider_link_policy_check
      CHECK (link_policy IN ('verified_email'));
  END IF;
END
$$;

-- Auto-provisioning lets an upstream mint trex users. Off by default; turning
-- it on is a per-provider decision.
COMMENT ON COLUMN trexdb.sso_provider.auto_provision IS
  'When true, a verified upstream identity with no matching trex user creates one.';
