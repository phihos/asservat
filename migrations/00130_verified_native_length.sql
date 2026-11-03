-- +goose Up
-- Verified publication metadata, never an upload assertion or configured limit.
-- NULL preserves historical audit identity and means unknown, including on replay.
ALTER TABLE context_verification ADD COLUMN native_bytes bigint CHECK(native_bytes>=0 AND native_bytes<=1099511627776);
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

-- +goose Down
-- Retained size-bearing audit digests cannot be reinterpreted by an older binary.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM context_verification WHERE native_bytes IS NOT NULL) THEN
  RAISE EXCEPTION 'retained native-length verification prevents rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_context_verification() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.capture_id,NEW.root_id,NEW.expectation_digest,NEW.copies_digest,NEW.intent_digest,NEW.authority_digest,NEW.permission_epoch,NEW.permission_sequence,NEW.verified_at) IS DISTINCT FROM
 ROW(OLD.capture_id,OLD.root_id,OLD.expectation_digest,OLD.copies_digest,OLD.intent_digest,OLD.authority_digest,OLD.permission_epoch,OLD.permission_sequence,OLD.verified_at) THEN
  RAISE EXCEPTION 'immutable context verification' USING ERRCODE='23514';
 END IF;
 IF OLD.audit_acknowledged_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
  RAISE EXCEPTION 'immutable context verification audit' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
ALTER TABLE context_verification DROP COLUMN native_bytes;
