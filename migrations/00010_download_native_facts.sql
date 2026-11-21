-- +goose Up
-- REQ-DLD-003: a download session keeps the verified native size and SHA-256
-- from the moment it becomes Ready, so later Completed, Cancelled and Failed
-- statuses still report them. They are set once and never change.
-- Worker progress of a Preparing session notifies the session ID on the
-- status channel, so a status read waiting with after_revision resumes the
-- preparation when its worker advances instead of polling.
-- No Down: every statement can be reapplied.
ALTER TABLE artifact_download ADD COLUMN IF NOT EXISTS native_size bigint;
ALTER TABLE artifact_download ADD COLUMN IF NOT EXISTS native_sha256 bytea;
ALTER TABLE artifact_download DROP CONSTRAINT IF EXISTS artifact_download_native_facts;
ALTER TABLE artifact_download ADD CONSTRAINT artifact_download_native_facts CHECK((native_size IS NULL)=(native_sha256 IS NULL) AND (native_size IS NULL OR native_size>=0) AND (native_sha256 IS NULL OR octet_length(native_sha256)=32));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_download_session() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['state','charged_output','charged_read','emitted_bytes','generation','active_batch','native_size','native_sha256']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','charged_output','charged_read','emitted_bytes','generation','active_batch','native_size','native_sha256']) OR NEW.charged_output<OLD.charged_output OR NEW.charged_read<OLD.charged_read OR NEW.emitted_bytes<OLD.emitted_bytes OR NEW.generation<OLD.generation THEN
  RAISE EXCEPTION 'immutable download session or decreasing spend' USING ERRCODE='23514';
 END IF;
 IF OLD.native_sha256 IS NOT NULL AND ROW(NEW.native_size,NEW.native_sha256) IS DISTINCT FROM ROW(OLD.native_size,OLD.native_sha256) THEN
  RAISE EXCEPTION 'immutable download native facts' USING ERRCODE='23514';
 END IF;
 IF OLD.state IN ('Completed','Cancelled','Expired','Denied','Failed') AND NEW.state<>OLD.state THEN
  RAISE EXCEPTION 'terminal download session' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION notify_download_worker_progress() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE session uuid;
BEGIN
 IF TG_TABLE_NAME='download_worker' THEN
  session:=NEW.session_id;
 ELSE
  SELECT w.session_id INTO session FROM public.download_worker w WHERE w.id=NEW.worker_id;
 END IF;
 IF session IS NOT NULL THEN
  PERFORM pg_notify('asservat_capture_progress',session::text);
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION notify_download_worker_progress() FROM PUBLIC;
DROP TRIGGER IF EXISTS download_worker_progress_notify ON download_worker;
CREATE TRIGGER download_worker_progress_notify AFTER INSERT OR UPDATE ON download_worker
 FOR EACH ROW EXECUTE FUNCTION notify_download_worker_progress();
DROP TRIGGER IF EXISTS download_worker_enrollment_progress_notify ON download_worker_enrollment;
CREATE TRIGGER download_worker_enrollment_progress_notify AFTER INSERT OR UPDATE ON download_worker_enrollment
 FOR EACH ROW EXECUTE FUNCTION notify_download_worker_progress();
DROP TRIGGER IF EXISTS download_worker_certificate_progress_notify ON download_worker_certificate;
CREATE TRIGGER download_worker_certificate_progress_notify AFTER INSERT OR UPDATE ON download_worker_certificate
 FOR EACH ROW EXECUTE FUNCTION notify_download_worker_progress();
