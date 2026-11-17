-- +goose Up
-- Superseded by 00198: native size and the profile acquisition window are
-- catalog columns; context_verification is dropped.
SELECT 1;

-- +goose Down
SELECT 1;
