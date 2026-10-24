-- +goose Up
-- ADR-200 revision (2026-10-23): an accepted retention_source observation is
-- current for 30 seconds after its own (original LIST/guard) observation
-- instead of five, like the binding (00072), root capacity source (00073),
-- permission stream and fleet trust (00074). Late hub-worker retention
-- refreshes no longer refuse retained-policy resolution for queries and
-- downloads. Invalidation, suspension, takeover and recovery blocking still
-- clear the observation at once; bookmarks still never renew it.
ALTER TABLE retention_source DROP CONSTRAINT retention_observation_bounds;
ALTER TABLE retention_source ADD CONSTRAINT retention_observation_bounds CHECK(
 (observed_sequence IS NULL)=(observed_at IS NULL)
 AND (observed_at IS NULL)=(fresh_until IS NULL)
 AND (observed_sequence IS NULL OR (observed_sequence BETWEEN 1 AND sequence
 AND fresh_until>observed_at AND fresh_until<=observed_at+interval '30 seconds')));

-- +goose Down
-- Narrow observations stored under the 30-second rule to five seconds after
-- their own observation (shortening only; an expired row stays expired).
UPDATE retention_source SET fresh_until=observed_at+interval '5 seconds' WHERE observed_at IS NOT NULL AND fresh_until>observed_at+interval '5 seconds';
ALTER TABLE retention_source DROP CONSTRAINT retention_observation_bounds;
ALTER TABLE retention_source ADD CONSTRAINT retention_observation_bounds CHECK(
 (observed_sequence IS NULL)=(observed_at IS NULL)
 AND (observed_at IS NULL)=(fresh_until IS NULL)
 AND (observed_sequence IS NULL OR (observed_sequence BETWEEN 1 AND sequence
 AND fresh_until>observed_at AND fresh_until<=observed_at+interval '5 seconds')));
