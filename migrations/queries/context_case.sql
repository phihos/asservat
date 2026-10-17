-- name: ReadContextCaseRoutes :many
SELECT r.* FROM context_case_locator r
JOIN context_catalog cat ON cat.artifact_id=r.artifact_id AND cat.capture_id=r.capture_id AND cat.root_id=r.root_id
JOIN context_capture c ON c.id=r.capture_id AND c.root_id=r.root_id
JOIN context_verification v ON v.capture_id=r.capture_id AND v.root_id=r.root_id
JOIN custody_attempt a ON a.id=c.attempt_id AND a.artifact_id=r.artifact_id
WHERE r.root_id=$1 AND r.case_id=$2 AND v.audit_acknowledged_at IS NOT NULL
AND a.state='stored_unpublished' AND a.copies_digest=v.copies_digest AND clock_timestamp()<a.effective_expires_at
ORDER BY r.artifact_id LIMIT 101;
