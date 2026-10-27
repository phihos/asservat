-- +goose Up
-- ADR-244 (S-04 increment 2): ADR-166 streaming custody is qualified up to
-- 256 MiB native, the largest S-04 frozen recording ceiling. Its worst-case
-- data object (256 MiB plus 32 frames of 64 KiB cipher overhead) needs 33
-- parts of 8 MiB, so the temporary charge covers one upload slot plus 33
-- part slots. The journal, its one-use claims, the deferred journal
-- requirement above one frame and the release rules are unchanged. The checks
-- only widen: an older binary never writes such an attempt, so the ADR-227
-- compatibility floor stays at 81.
ALTER TABLE custody_attempt DROP CONSTRAINT custody_attempt_native_limit_check;
ALTER TABLE custody_attempt ADD CONSTRAINT custody_attempt_native_limit_check CHECK (native_limit BETWEEN 0 AND 268435456);
ALTER TABLE custody_stream DROP CONSTRAINT custody_stream_temporary_bytes_check;
ALTER TABLE custody_stream ADD CONSTRAINT custody_stream_temporary_bytes_check CHECK (temporary_bytes BETWEEN 1 AND 270532608);
ALTER TABLE custody_stream DROP CONSTRAINT custody_stream_temporary_objects_check;
ALTER TABLE custody_stream ADD CONSTRAINT custody_stream_temporary_objects_check CHECK (temporary_objects BETWEEN 2 AND 34);
-- No destructive Down: narrowing could invalidate retained larger attempts.
