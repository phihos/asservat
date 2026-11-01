-- ADR-236: one keyset page of a workload's accepted captures, newest first.
-- Visibility is decided per row by the caller after this routing-only read.
-- name: ListCaptureHistory :many
SELECT c.* FROM context_capture c
WHERE c.root_id=sqlc.arg(root_id) AND c.history_cluster_id=sqlc.arg(cluster_id) AND c.history_namespace_uid=sqlc.arg(namespace_uid)::text AND c.history_workload_uid=sqlc.arg(workload_uid)::text
 AND c.history_origin=ANY(sqlc.arg(origins)::text[])
 AND c.created_at<=sqlc.arg(snapshot_before)::timestamptz
 AND ((NOT c.history_parameters_required AND c.created_at>sqlc.arg(not_before)::timestamptz) OR (c.history_parameters_required AND EXISTS(SELECT 1 FROM capture_history_parameter h WHERE h.capture_id=c.id AND h.root_id=c.root_id AND h.visible AND h.selector_key=sqlc.arg(selector_key)::bytea AND h.summary_expires_at>clock_timestamp())))
 AND (sqlc.narg(after_at)::timestamptz IS NULL OR (c.created_at,c.id)<(sqlc.narg(after_at)::timestamptz,sqlc.narg(after_id)::uuid))
ORDER BY c.created_at DESC,c.id DESC LIMIT sqlc.arg(page_limit);

-- name: ReadHistoryCapture :one
SELECT * FROM context_capture WHERE root_id=$1 AND id=$2 AND history_workload_uid IS NOT NULL;

-- The progress facts of several captures in one snapshot (same shape as
-- ReadContextProgressFacts).
-- name: ReadCaptureHistoryFacts :many
SELECT sqlc.embed(c),a.state AS custody_state,a.request_digest,
 a.copies_digest,a.effective_expires_at,a.effective_delete_by,
 v.capture_id AS verified_capture_id,v.root_id AS verified_root_id,v.verified_at,
 v.expectation_digest,v.copies_digest AS verified_copies_digest,v.intent_digest AS verified_intent_digest,
 v.authority_digest,v.permission_epoch,v.permission_sequence,v.audit_acknowledged_at,v.audit_digest,
 cat.artifact_id AS catalog_artifact_id,cat.published_at,
 hp.state AS history_parameters_state,ha.state AS history_custody_state,hp.visible AS history_visible,hp.summary_expires_at AS history_summary_expires,ha.effective_expires_at AS history_settings_expires
FROM context_capture c
JOIN custody_attempt a ON a.id=c.attempt_id
LEFT JOIN context_verification v ON v.capture_id=c.id AND v.root_id=c.root_id
LEFT JOIN context_catalog cat ON cat.capture_id=c.id AND cat.root_id=c.root_id
LEFT JOIN capture_history_parameter hp ON hp.capture_id=c.id AND hp.root_id=c.root_id
LEFT JOIN custody_attempt ha ON ha.id=hp.attempt_id
WHERE c.root_id=sqlc.arg(root_id) AND c.id=ANY(sqlc.arg(ids)::uuid[]);

-- name: ReadAPIExecutions :many
SELECT * FROM context_execution WHERE root_id=sqlc.arg(root_id) AND capture_id=ANY(sqlc.arg(ids)::uuid[]);
