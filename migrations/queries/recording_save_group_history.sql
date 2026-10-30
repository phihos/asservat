-- Routing-only merged keyset. Group children never occupy public history rows.
-- The original first member is used only for indexed workload routing; every
-- member is independently checked before the parent becomes visible.
-- name: ListCaptureHistoryCandidates :many
WITH candidates AS (
 SELECT c.id,c.created_at,false AS grouped,1::integer AS member_count FROM context_capture c
 WHERE c.root_id=sqlc.arg(root_id) AND c.group_id IS NULL
  AND c.history_cluster_id=sqlc.arg(cluster_id) AND c.history_namespace_uid=sqlc.arg(namespace_uid)::text AND c.history_workload_uid=sqlc.arg(workload_uid)::text
  AND c.history_origin=ANY(sqlc.arg(origins)::text[])
  AND c.created_at<=sqlc.arg(snapshot_before)::timestamptz
  AND ((NOT c.history_parameters_required AND c.created_at>sqlc.arg(not_before)::timestamptz) OR (c.history_parameters_required AND EXISTS(SELECT 1 FROM capture_history_parameter h WHERE h.capture_id=c.id AND h.root_id=c.root_id AND h.visible AND h.selector_key=sqlc.arg(selector_key)::bytea AND h.summary_expires_at>clock_timestamp())))
 UNION ALL
 SELECT g.id,g.accepted_at AS created_at,true AS grouped,cardinality(g.child_ids) AS member_count FROM recording_save_group g
 JOIN context_capture first_child ON first_child.id=g.child_ids[1] AND first_child.root_id=g.root_id AND first_child.group_id=g.id AND first_child.group_ordinal=0
 JOIN capture_history_parameter h ON h.capture_id=g.id AND h.root_id=g.root_id
 WHERE g.root_id=sqlc.arg(root_id) AND first_child.history_cluster_id=sqlc.arg(cluster_id)
  AND first_child.history_namespace_uid=sqlc.arg(namespace_uid)::text AND first_child.history_workload_uid=sqlc.arg(workload_uid)::text
  AND 'manual'=ANY(sqlc.arg(origins)::text[]) AND g.accepted_at<=sqlc.arg(snapshot_before)::timestamptz
  AND h.visible AND h.selector_key=sqlc.arg(selector_key)::bytea AND h.summary_expires_at>clock_timestamp()
)
SELECT id,created_at,grouped,member_count FROM candidates
WHERE sqlc.narg(after_at)::timestamptz IS NULL OR (created_at,id)<(sqlc.narg(after_at)::timestamptz,sqlc.narg(after_id)::uuid)
ORDER BY created_at DESC,id DESC LIMIT sqlc.arg(page_limit);

-- name: ReadHistoryCaptureRows :many
SELECT * FROM context_capture WHERE root_id=sqlc.arg(root_id) AND id=ANY(sqlc.arg(ids)::uuid[]) AND history_workload_uid IS NOT NULL;

-- name: ReadHistoryGroupHeaders :many
SELECT * FROM recording_save_group WHERE root_id=sqlc.arg(root_id) AND id=ANY(sqlc.arg(ids)::uuid[]);

-- name: ReadHistoryGroupMembers :many
SELECT * FROM context_capture WHERE root_id=sqlc.arg(root_id) AND group_id=ANY(sqlc.arg(ids)::uuid[]) ORDER BY group_id,group_ordinal;

-- name: ReadHistoryGroupParameters :many
SELECT h.*,a.state AS custody_state,a.effective_expires_at FROM capture_history_parameter h
JOIN custody_attempt a ON a.id=h.attempt_id
WHERE h.root_id=sqlc.arg(root_id) AND h.capture_id=ANY(sqlc.arg(ids)::uuid[]);
