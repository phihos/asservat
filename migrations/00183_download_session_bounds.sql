-- +goose Up
-- ADR-312 and ADR-335 D9: a download session runs to its original authority,
-- access and allocation bounds. It has no request-count cap and no fixed
-- 8-hour ceiling; the request counter only enforced that cap. Responses are
-- bounded by the same session deadline.
-- No Down: sessions without a request cap or 8-hour ceiling cannot be
-- represented earlier. IF EXISTS keeps a re-Up after a downgrade probe
-- working, as in 00167.
ALTER TABLE artifact_download DROP CONSTRAINT IF EXISTS artifact_download_check;
ALTER TABLE artifact_download DROP CONSTRAINT IF EXISTS artifact_download_deadline_check;
ALTER TABLE artifact_download ADD CONSTRAINT artifact_download_deadline_check CHECK(deadline>created_at);
ALTER TABLE download_response DROP CONSTRAINT IF EXISTS download_response_check;
ALTER TABLE download_response DROP CONSTRAINT IF EXISTS download_response_until_check;
ALTER TABLE download_response ADD CONSTRAINT download_response_until_check CHECK(isfinite(started_at) AND until_at>started_at AND lease_until<=until_at);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_download_session() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['state','charged_output','charged_read','emitted_bytes','generation','active_batch']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','charged_output','charged_read','emitted_bytes','generation','active_batch']) OR NEW.charged_output<OLD.charged_output OR NEW.charged_read<OLD.charged_read OR NEW.emitted_bytes<OLD.emitted_bytes OR NEW.generation<OLD.generation THEN
  RAISE EXCEPTION 'immutable download session or decreasing spend' USING ERRCODE='23514';
 END IF;
 IF OLD.state IN ('Completed','Cancelled','Expired','Denied','Failed') AND NEW.state<>OLD.state THEN
  RAISE EXCEPTION 'terminal download session' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
ALTER TABLE artifact_download DROP COLUMN IF EXISTS requests, DROP COLUMN IF EXISTS request_limit;
DROP INDEX IF EXISTS download_principal_streams;
