-- +goose Up
-- Display metadata from the already authenticated profile manifest. Historical
-- NULL pairs remain unknown; the original audit and verdict are never backfilled.
-- Registration.Validate bounds dates to 2020..9999; verified manifest windows
-- already lie between that registration's anchor and original write cutoff.
ALTER TABLE context_verification
 ADD COLUMN acquisition_started_at timestamptz,
 ADD COLUMN acquisition_completed_at timestamptz,
 ADD CONSTRAINT context_verification_acquisition_window CHECK (
  (acquisition_started_at IS NULL AND acquisition_completed_at IS NULL) OR
  (acquisition_started_at IS NOT NULL AND acquisition_completed_at IS NOT NULL
   AND isfinite(acquisition_started_at) AND isfinite(acquisition_completed_at)
   AND acquisition_started_at>='2020-01-01 00:00:00+00'
   AND acquisition_completed_at<'10000-01-01 00:00:00+00'
   AND acquisition_started_at<=acquisition_completed_at));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_context_verification() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.capture_id,NEW.root_id,NEW.expectation_digest,NEW.copies_digest,NEW.intent_digest,NEW.authority_digest,NEW.permission_epoch,NEW.permission_sequence,NEW.verified_at,NEW.native_bytes,NEW.acquisition_started_at,NEW.acquisition_completed_at) IS DISTINCT FROM
 ROW(OLD.capture_id,OLD.root_id,OLD.expectation_digest,OLD.copies_digest,OLD.intent_digest,OLD.authority_digest,OLD.permission_epoch,OLD.permission_sequence,OLD.verified_at,OLD.native_bytes,OLD.acquisition_started_at,OLD.acquisition_completed_at) THEN
  RAISE EXCEPTION 'immutable context verification' USING ERRCODE='23514';
 END IF;
 IF OLD.audit_acknowledged_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
  RAISE EXCEPTION 'immutable context verification audit' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
-- A timing-bearing audit must not be reinterpreted by a pre-134 reader.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM context_verification WHERE acquisition_started_at IS NOT NULL OR acquisition_completed_at IS NOT NULL) THEN
  RAISE EXCEPTION 'retained acquisition-window verification prevents rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_context_verification() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.capture_id,NEW.root_id,NEW.expectation_digest,NEW.copies_digest,NEW.intent_digest,NEW.authority_digest,NEW.permission_epoch,NEW.permission_sequence,NEW.verified_at,NEW.native_bytes) IS DISTINCT FROM
 ROW(OLD.capture_id,OLD.root_id,OLD.expectation_digest,OLD.copies_digest,OLD.intent_digest,OLD.authority_digest,OLD.permission_epoch,OLD.permission_sequence,OLD.verified_at,OLD.native_bytes) THEN
  RAISE EXCEPTION 'immutable context verification' USING ERRCODE='23514';
 END IF;
 IF OLD.audit_acknowledged_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
  RAISE EXCEPTION 'immutable context verification audit' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
ALTER TABLE context_verification
 DROP CONSTRAINT context_verification_acquisition_window,
 DROP COLUMN acquisition_started_at,
 DROP COLUMN acquisition_completed_at;
