-- +goose Up
-- ADR-227: the oldest binary schema this database still serves. An expand
-- migration leaves the floor; a contract migration (one that removes or
-- reinterprets something an older binary uses) raises it to its own version.
-- Only the schema owner can set the version table's comment, and every role
-- reads it without a grant. Binaries before 81 require an exact head instead.
-- (A DO block: the version table is created by the migration runner, not by a
-- migration, so the SQL code generator does not know it.)
-- +goose StatementBegin
DO $$ BEGIN
 EXECUTE 'COMMENT ON TABLE public.goose_db_version IS ''asservat:oldest-binary-schema=81''';
END $$;
-- +goose StatementEnd
