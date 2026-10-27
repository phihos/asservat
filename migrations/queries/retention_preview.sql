-- ADR-240: the installation's retention sources for the impact preview, hub
-- first. The caller bounds the row count.
-- name: ListRetentionPreviewSources :many
SELECT * FROM retention_source WHERE root_id=sqlc.arg(root_id)
ORDER BY hub DESC,cluster_id,namespace_uid LIMIT sqlc.arg(row_limit);

-- ADR-240: one keyset page of retained context registrations whose effective
-- deletion deadline has not passed, in the catch-up's attempt order
-- (retention_context_scan index). Already overdue artifacts cannot be
-- shortened into anything sooner than due. Only the columns that the
-- retained-artifact reader uses (retainedContext/admittedRecord) are read.
-- name: ListRetentionPreviewContexts :many
SELECT c.id,c.root_id,c.submission_digest,c.scope_digest,c.expectation_json,c.pod_pin_json,c.attempt_id,c.created_at,c.deadline,c.state,
 a.cluster_id,a.request_digest,a.effective_expires_at,a.effective_delete_by,a.retention_sequence
FROM context_capture c JOIN custody_attempt a ON a.id=c.attempt_id
WHERE c.root_id=sqlc.arg(root_id) AND a.state<>'deleted' AND a.effective_delete_by>clock_timestamp()
 AND (sqlc.narg(after_attempt)::uuid IS NULL OR c.attempt_id>sqlc.narg(after_attempt)::uuid)
ORDER BY c.attempt_id LIMIT sqlc.arg(page_limit);

-- ADR-240: candidate lifecycle decisions of one page's shortened attempts;
-- the caller keeps exactly the (attempt, sequence) pair it read. Decisions
-- are immutable, so that pair names one row.
-- name: ReadRetentionPreviewDecisions :many
SELECT * FROM retention_decision
WHERE root_id=sqlc.arg(root_id) AND attempt_id=ANY(sqlc.arg(attempt_ids)::uuid[]) AND sequence=ANY(sqlc.arg(sequences)::bigint[]);
