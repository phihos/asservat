-- +goose Up
-- ADR-330 D1 / REQ-INT-003: a committed change of a capture's progress
-- revision notifies the hub-api in the writing transaction, so status
-- readers wait for the change instead of polling.
-- +goose StatementBegin
CREATE FUNCTION notify_capture_progress() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM pg_notify('asservat_capture_progress',NEW.id::text);
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION notify_capture_progress() FROM PUBLIC;
CREATE TRIGGER context_capture_progress_notify AFTER UPDATE ON context_capture
 FOR EACH ROW WHEN (NEW.progress_revision IS DISTINCT FROM OLD.progress_revision) EXECUTE FUNCTION notify_capture_progress();

-- +goose Down
DROP TRIGGER context_capture_progress_notify ON context_capture;
DROP FUNCTION notify_capture_progress();
