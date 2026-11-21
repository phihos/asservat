-- +goose Up
-- REQ-INT-003 / ADR-330 D1: a pending query result becomes readable when its
-- worker's certificate is activated. That change notifies the query ID on the
-- status channel, so get_query_result with after_revision waits for it
-- instead of the client polling.
-- No Down: every statement can be reapplied.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notify_query_worker_ready() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM pg_notify('asservat_capture_progress',q.id::text) FROM public.context_query q WHERE q.worker_id=NEW.worker_id;
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION notify_query_worker_ready() FROM PUBLIC;
DROP TRIGGER IF EXISTS download_worker_certificate_query_notify ON download_worker_certificate;
CREATE TRIGGER download_worker_certificate_query_notify AFTER UPDATE ON download_worker_certificate
 FOR EACH ROW WHEN (NEW.activated_at IS DISTINCT FROM OLD.activated_at) EXECUTE FUNCTION notify_query_worker_ready();
