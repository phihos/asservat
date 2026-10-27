-- name: EnsureHistoryQuota :exec
INSERT INTO capture_history_quota(root_id,selector_key) VALUES($1,$2) ON CONFLICT DO NOTHING;
-- name: LockHistoryQuota :one
SELECT used FROM capture_history_quota WHERE root_id=$1 AND selector_key=$2 FOR UPDATE;
-- name: ChangeHistoryQuota :execrows
UPDATE capture_history_quota SET used=used+sqlc.arg(amount)::integer WHERE root_id=$1 AND selector_key=$2 AND used+sqlc.arg(amount)::integer BETWEEN 0 AND sqlc.arg(maximum)::integer;
-- name: ReadHistoryParameter :one
SELECT * FROM capture_history_parameter WHERE root_id=$1 AND capture_id=$2;
-- name: LockHistoryParameter :one
SELECT * FROM capture_history_parameter WHERE root_id=$1 AND capture_id=$2 FOR UPDATE;
-- name: InsertHistoryParameter :exec
INSERT INTO capture_history_parameter(root_id,capture_id,attempt_id,selector_key,settings_key,mac_version,expectation_json,retention_json,summary_expires_at,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);
-- name: ClaimHistoryParameterWrite :execrows
UPDATE capture_history_parameter SET state='write_claimed',write_id=$3,write_digest=$4,write_started_at=$5,write_until=$6,write_executor_epoch=$7 WHERE root_id=$1 AND capture_id=$2 AND state='reserved' AND write_id IS NULL;
-- name: CompleteHistoryParameterWrite :execrows
UPDATE capture_history_parameter SET state='available',writer_completion_json=$4,copies_digest=$5 WHERE root_id=$1 AND capture_id=$2 AND state='write_claimed' AND write_id=$3;
-- name: ListHistoryEvictionCandidates :many
SELECT * FROM capture_history_parameter WHERE root_id=sqlc.arg(root_id) AND visible AND attempt_id IN (SELECT id FROM custody_attempt WHERE allocation_id=sqlc.arg(allocation_id)) AND (sqlc.narg(selector)::bytea IS NULL OR selector_key=sqlc.narg(selector)::bytea)
ORDER BY created_at,capture_id LIMIT 16 FOR UPDATE;
-- name: HideHistoryParameter :execrows
UPDATE capture_history_parameter SET visible=false WHERE root_id=$1 AND capture_id=$2 AND visible;
-- name: MarkHistoryParameterDeleted :execrows
UPDATE capture_history_parameter SET state='deleted' WHERE root_id=$1 AND capture_id=$2 AND state='deleting';
-- name: AcknowledgeHistoryPurge :execrows
UPDATE capture_history_parameter SET purge_completion_json=$3 WHERE root_id=$1 AND capture_id=$2 AND state='deleting' AND purge_completion_json IS NULL;

-- name: ReadHistoryParameterByAttempt :one
SELECT * FROM capture_history_parameter WHERE root_id=$1 AND attempt_id=$2;
-- name: BindHistoryDelete :execrows
UPDATE capture_history_parameter SET state='deleting',delete_id=$3,delete_executor_epoch=$4,delete_started_at=$5,delete_until=$6,delete_fence=$7 WHERE root_id=$1 AND capture_id=$2 AND state IN('reserved','available','deleting');

-- name: ListExpiredHistorySummaries :many
SELECT * FROM capture_history_parameter WHERE root_id=$1 AND visible AND summary_expires_at<=sqlc.arg(through)::timestamptz ORDER BY summary_expires_at,capture_id LIMIT 16 FOR UPDATE;

-- name: ListHistoryRetirementCandidates :many
SELECT h.capture_id,a.cluster_id,h.state FROM capture_history_parameter h JOIN custody_attempt a ON a.id=h.attempt_id
WHERE h.root_id=$1 AND (sqlc.narg(after_id)::uuid IS NULL OR h.capture_id>sqlc.narg(after_id)::uuid) AND (((h.visible OR h.state='deleted') AND h.summary_expires_at<=sqlc.arg(through)::timestamptz) OR (h.state IN('reserved','available','deleting') AND (a.effective_expires_at<=sqlc.arg(through)::timestamptz OR NOT h.visible OR (h.state='reserved' AND a.write_until<=sqlc.arg(through)::timestamptz))))
ORDER BY h.capture_id LIMIT 16;

-- name: DeleteSettledHistoryParameters :execrows
DELETE FROM capture_history_parameter h WHERE h.capture_id IN(SELECT old.capture_id FROM capture_history_parameter old WHERE old.root_id=$1 AND old.state='deleted' AND NOT old.visible AND old.summary_expires_at<=sqlc.arg(through)::timestamptz ORDER BY old.summary_expires_at,old.capture_id LIMIT 16);

-- name: DeleteUnusedHistoryCounters :execrows
DELETE FROM capture_history_quota q WHERE q.root_id=$1 AND q.selector_key IN(SELECT old.selector_key FROM capture_history_quota old WHERE old.root_id=$1 AND old.used=0 AND old.selector_key<>decode(repeat('00',32),'hex') AND NOT EXISTS(SELECT 1 FROM capture_history_parameter h WHERE h.root_id=old.root_id AND h.selector_key=old.selector_key) ORDER BY old.selector_key LIMIT 16);
