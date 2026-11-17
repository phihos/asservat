-- +goose Up
-- ADR-335 D5: approval submits the reviewed request itself. An ad hoc grant
-- stores the request_capture input with the requester's verified groups,
-- scopes, identity policy revision and the end of their authentication.
-- Approval uses these groups only before that end. A decision notifies the
-- grant's capture ID on the capture progress channel, so a console waiting
-- for that capture rereads the grant. No Down: every statement can be
-- reapplied.
ALTER TABLE access_grant ADD COLUMN IF NOT EXISTS submission jsonb;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notify_grant_capture() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM pg_notify('asservat_capture_progress',NEW.capture_id::text);
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION notify_grant_capture() FROM PUBLIC;
DROP TRIGGER IF EXISTS access_grant_decision_notify ON access_grant;
CREATE TRIGGER access_grant_decision_notify AFTER UPDATE ON access_grant
 FOR EACH ROW WHEN (NEW.capture_id IS NOT NULL AND NEW.decision IS DISTINCT FROM OLD.decision) EXECUTE FUNCTION notify_grant_capture();
