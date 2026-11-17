-- +goose Up
-- ADR-330 D9: a preview stores nothing. request_capture recomputes the plan
-- and derives its request ID from the requester, idempotency key and plan
-- digest; context_capture.preview_id, recording_save_group.preview_id and
-- access_grant.preview_id now hold that request ID. Drop the stored preview
-- blueprints, their fences and expiry. No Down: every statement can be
-- reapplied.
DROP TABLE IF EXISTS context_preview_fence, context_preview;
DROP FUNCTION IF EXISTS context_preview_read_until(uuid,uuid), context_preview_immutable(),
 guard_context_preview_fence();
