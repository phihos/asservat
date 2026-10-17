-- +goose Up
-- Fresh complete observations are separate from immutable history and from the
-- independently durable watch-resume cursor. There is no writable Ready bit.
ALTER TABLE retention_source ADD COLUMN observed_sequence bigint;
ALTER TABLE retention_source ADD COLUMN observed_at timestamptz;
ALTER TABLE retention_source ADD COLUMN fresh_until timestamptz;
-- Preserve the highest accepted or known-changing LIST watermark even while
-- a source is not available. An older delayed response cannot renew a previously invalidated
-- observation or erase known outstanding history across restart.
ALTER TABLE retention_source ADD COLUMN list_cursor text NOT NULL DEFAULT '' CHECK(length(list_cursor)<=128 AND (list_cursor='' OR list_cursor ~ '^[1-9][0-9]*$'));
ALTER TABLE retention_source ADD CONSTRAINT retention_observation_bounds CHECK(
 (observed_sequence IS NULL)=(observed_at IS NULL)
 AND (observed_at IS NULL)=(fresh_until IS NULL)
 AND (observed_sequence IS NULL OR (observed_sequence BETWEEN 1 AND sequence
 AND fresh_until>observed_at AND fresh_until<=observed_at+interval '5 seconds')));
-- No destructive down: a restore must qualify observations again, not revive
-- an older readable source by dropping its completeness boundary.

-- +goose StatementBegin
CREATE FUNCTION retain_list_watermark() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.list_cursor<>'' AND (length(NEW.list_cursor)<length(OLD.list_cursor)
 OR (length(NEW.list_cursor)=length(OLD.list_cursor) AND NEW.list_cursor COLLATE "C"<OLD.list_cursor COLLATE "C")) THEN
  RAISE EXCEPTION 'retention list watermark cannot rewind';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER retention_list_watermark BEFORE UPDATE ON retention_source FOR EACH ROW EXECUTE FUNCTION retain_list_watermark();
