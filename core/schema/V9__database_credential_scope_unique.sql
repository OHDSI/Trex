-- database_credential is keyed on (databaseId, username, userScope) by the code
-- that writes it: d2e-compat/db-credential.ts upserts with
--   ON CONFLICT ("databaseId", username, "userScope")
-- and d2e-compat/routes.ts documents the same key. That index was never
-- created, so on a fresh install the upsert fails with Postgres 42P10
-- ("no unique or exclusion constraint matching the ON CONFLICT specification").
--
-- V1 instead declared UNIQUE ("databaseId", username), which is also wrong in
-- the other direction: it forbids one service user holding both an Admin and a
-- Read row for the same database, which several deployments do.
--
-- Replace the two-column constraint with the three-column one the code expects.
ALTER TABLE trexdb.database_credential
  DROP CONSTRAINT IF EXISTS "database_credential_databaseId_username_key";

CREATE UNIQUE INDEX IF NOT EXISTS database_credential_db_user_scope_key
  ON trexdb.database_credential ("databaseId", username, "userScope");
