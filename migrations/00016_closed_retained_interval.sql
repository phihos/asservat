-- +goose Up
-- A newly increased cleanup budget may consume an existing artifact's entire
-- readable lifetime. Close reads at its original anchor while keeping the hard
-- deadline unchanged. Original registration and new-acquisition bounds remain
-- strictly positive; this only broadens the restrictive overlay representation.
ALTER TABLE custody_attempt DROP CONSTRAINT custody_retention_bounds;
ALTER TABLE custody_attempt ADD CONSTRAINT custody_retention_bounds
 CHECK(anchor_at<=effective_expires_at AND effective_expires_at<effective_delete_by
 AND effective_expires_at<=expires_at AND effective_delete_by<=delete_by);
-- No destructive down: closed evidence must never regain a readable interval.
