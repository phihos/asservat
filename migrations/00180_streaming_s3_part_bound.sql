-- +goose Up
-- Streaming custody size follows the S3 multipart limit of 10,000 parts of
-- one 8 MiB frame each: 9,922 native frames (83,231,768,576 bytes) whose
-- ciphertext fills at most 10,000 parts. The journal keeps only the latest
-- part, so its 16 KiB state bound no longer limits the artifact size.
-- No Down: the wider bounds stay. IF EXISTS keeps a re-Up after a downgrade
-- probe working, as in 00167.
ALTER TABLE custody_attempt DROP CONSTRAINT IF EXISTS custody_attempt_native_limit_check;
ALTER TABLE custody_attempt ADD CONSTRAINT custody_attempt_native_limit_check CHECK (native_limit BETWEEN 0 AND 83231768576);
ALTER TABLE custody_stream DROP CONSTRAINT IF EXISTS custody_stream_temporary_bytes_check;
ALTER TABLE custody_stream ADD CONSTRAINT custody_stream_temporary_bytes_check CHECK (temporary_bytes BETWEEN 1 AND 83882016768);
ALTER TABLE custody_stream DROP CONSTRAINT IF EXISTS custody_stream_temporary_objects_check;
ALTER TABLE custody_stream ADD CONSTRAINT custody_stream_temporary_objects_check CHECK (temporary_objects BETWEEN 2 AND 10001);
