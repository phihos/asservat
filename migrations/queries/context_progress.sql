-- name: ReadContextProgressFacts :one
SELECT sqlc.embed(c),a.state AS custody_state,a.request_digest,
 a.copies_digest,a.effective_expires_at,a.effective_delete_by,
 v.capture_id AS verified_capture_id,v.root_id AS verified_root_id,v.verified_at,
 v.expectation_digest,v.copies_digest AS verified_copies_digest,v.intent_digest AS verified_intent_digest,
 v.authority_digest,v.permission_epoch,v.permission_sequence,v.audit_acknowledged_at,v.audit_digest,
 cat.artifact_id AS catalog_artifact_id,cat.published_at
FROM context_capture c
JOIN custody_attempt a ON a.id=c.attempt_id
LEFT JOIN context_verification v ON v.capture_id=c.id AND v.root_id=c.root_id
LEFT JOIN context_catalog cat ON cat.capture_id=c.id AND cat.root_id=c.root_id
WHERE c.id=$1 AND c.root_id=$2;

-- name: ObserveOverdueContextCaptures :execrows
UPDATE context_capture SET deadline_observed_at=clock_timestamp()
WHERE id IN (
 SELECT c.id FROM context_capture c
 WHERE c.root_id=$1 AND c.deadline_observed_at IS NULL AND c.deadline<=clock_timestamp()
 AND NOT EXISTS(SELECT 1 FROM context_catalog cat WHERE cat.capture_id=c.id AND cat.root_id=c.root_id)
 ORDER BY c.deadline,c.id LIMIT sqlc.arg(page_limit)
);
