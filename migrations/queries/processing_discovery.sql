-- name: ScanProcessingDiscovery :many
-- Keep the case and workload index ranges independent. Materialize the page
-- before reading accepted purpose/class metadata from the capture record.
WITH scanned AS MATERIALIZED (
 (
  SELECT p.*, r.case_id, a.state, a.effective_expires_at, a.effective_delete_by, a.copies_digest
  FROM context_case_locator r
  JOIN context_processing p ON p.root_id=r.root_id AND p.artifact_id=r.artifact_id AND p.capture_id=r.capture_id
    AND p.cluster_id=r.cluster_id AND p.namespace_uid=r.namespace_uid AND p.workload_uid=r.workload_uid AND p.pod_uid=r.pod_uid
  JOIN custody_attempt a ON a.id=p.attempt_id AND a.artifact_id=p.artifact_id AND a.cluster_id=p.cluster_id
  WHERE r.root_id=sqlc.arg(root_id)::uuid AND r.case_id=sqlc.narg(case_id)::uuid
    AND r.artifact_id>sqlc.arg(after_artifact_id)::uuid
    AND p.retire_by>sqlc.arg(observed_at)::timestamptz AND a.state<>'deleted'
  ORDER BY r.artifact_id
  LIMIT sqlc.arg(scan_limit)::integer
 )
 UNION ALL
 (
  SELECT p.*, r.case_id, a.state, a.effective_expires_at, a.effective_delete_by, a.copies_digest
  FROM context_processing p
  JOIN context_case_locator r ON r.root_id=p.root_id AND r.artifact_id=p.artifact_id AND r.capture_id=p.capture_id
    AND r.cluster_id=p.cluster_id AND r.namespace_uid=p.namespace_uid AND r.workload_uid=p.workload_uid AND r.pod_uid=p.pod_uid
  JOIN custody_attempt a ON a.id=p.attempt_id AND a.artifact_id=p.artifact_id AND a.cluster_id=p.cluster_id
  WHERE sqlc.narg(case_id)::uuid IS NULL AND p.root_id=sqlc.arg(root_id)::uuid
    AND p.cluster_id=sqlc.narg(cluster_id)::uuid AND p.namespace_uid=sqlc.arg(namespace_uid)::text AND p.workload_uid=sqlc.arg(workload_uid)::text
    AND p.anchor_at>=sqlc.arg(after_anchor_at)::timestamptz AND p.anchor_at<sqlc.arg(acquired_until)::timestamptz
    AND (p.anchor_at,p.artifact_id)>(sqlc.arg(after_anchor_at)::timestamptz,sqlc.arg(after_artifact_id)::uuid)
    AND p.retire_by>sqlc.arg(observed_at)::timestamptz AND a.state<>'deleted'
  ORDER BY p.anchor_at,p.artifact_id
  LIMIT sqlc.arg(scan_limit)::integer
 )
)
SELECT s.artifact_id,s.capture_id,s.attempt_id,s.case_id,s.cluster_id,s.namespace_uid,s.workload_uid,s.pod_uid,
       s.anchor_at,s.delete_by,s.retire_by,s.origin,s.parents,s.state,s.effective_expires_at,s.effective_delete_by,
       COALESCE(e.doc->>'PurposeRef','')::text AS purpose_ref,
       COALESCE(e.doc->>'ActionID','')::text AS action_id,
       COALESCE(e.doc->>'NativeType','')::text AS native_type,
       COALESCE(e.doc->>'DataClass','')::text AS data_class,
       COALESCE(v.audit_acknowledged_at IS NOT NULL AND s.copies_digest=v.copies_digest,false)::boolean AS verified
FROM scanned s
LEFT JOIN context_catalog cat ON cat.root_id=s.root_id AND cat.artifact_id=s.artifact_id AND cat.capture_id=s.capture_id
LEFT JOIN context_verification v ON v.root_id=cat.root_id AND v.capture_id=cat.capture_id
LEFT JOIN context_capture c ON c.root_id=cat.root_id AND c.id=cat.capture_id AND c.attempt_id=s.attempt_id
LEFT JOIN LATERAL (SELECT convert_from(c.expectation_json,'UTF8')::jsonb AS doc) e ON true
ORDER BY CASE WHEN sqlc.narg(case_id)::uuid IS NULL THEN s.anchor_at END,s.artifact_id;
