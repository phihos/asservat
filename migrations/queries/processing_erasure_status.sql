-- name: ReadAppliedProcessingErasure :one
SELECT p.id, p.applied_at, p.retire_by, n.artifact_id, d.expires_at AS access_until, d.delete_by,
       a.effective_delete_by, a.state AS custody_state, a.deleted_at, d.audit_acknowledged_at,
       coalesce(public.retention_lifecycle_receipt_current(d.root_id,d.id,d.audit_receipt_json), false)::boolean AS audit_receipt_current
FROM processing_decision p
JOIN retention_decision d ON d.id=p.id AND d.root_id=p.root_id
JOIN custody_attempt a ON a.id=d.attempt_id
JOIN context_processing n ON n.root_id=p.root_id AND n.attempt_id=a.id
 AND n.artifact_id=a.artifact_id AND n.cluster_id=a.cluster_id
WHERE p.root_id=sqlc.arg(root_id)::uuid AND p.id=sqlc.arg(request_id)::uuid
 AND p.action='request_early_erasure' AND p.applied_at IS NOT NULL
 AND p.scope->>'Kind'='artifact'
 AND p.scope#>>'{Location,ArtifactID}'=n.artifact_id::text
 AND p.scope#>>'{Location,AttemptID}'=n.attempt_id::text
 AND p.scope#>>'{Location,ClusterID}'=n.cluster_id::text
 AND d.sequence<=a.retention_sequence AND d.expires_at=a.anchor_at
 AND a.effective_expires_at=a.anchor_at AND d.delete_by=d.previous_delete_by
 AND a.effective_delete_by<=d.delete_by;
