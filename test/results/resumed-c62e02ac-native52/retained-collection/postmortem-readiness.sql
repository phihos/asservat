BEGIN READ ONLY;
SET LOCAL statement_timeout='5s';
SET LOCAL lock_timeout='2s';
SELECT clock_timestamp() AS collected_at;
SELECT root_id,installation_id,control_cluster_id,accepted_revision,observed_at,fresh_until,suspended,root_configuration->>'ReadyAt' AS root_ready_at FROM capacity_source;
SELECT root_id,cluster_id,namespace_uid,workload_uid,id,allocation_id,initial_observed_at,initial_until,reserved_at,capture_backed_at,ready_at FROM capacity_workload ORDER BY reserved_at LIMIT 20;
SELECT root_id,cluster_id,namespace_uid,workload_uid,observed_at,fresh_until FROM context_storage_binding LIMIT 20;
SELECT id,epoch,sequence,observed_at,fresh_until,lease_until,suspended,initial_audit_id FROM permission_stream;
SELECT b.stream_id,b.basis_key,b.cluster_id,b.namespace_uid,b.workload_uids,b.effect,b.not_after,b.seen_sequence,s.sequence,
 count(a.id) AS assignment_count,count(a.id) FILTER(WHERE a.retired_at IS NULL) AS live_assignments,
 min(a.created_at) AS first_assignment_at,array_agg(DISTINCT a.role) AS roles,
 bool_and(EXISTS(SELECT 1 FROM authority_audit audit WHERE audit.id=a.activation_audit_id AND audit.acknowledged_at IS NOT NULL)) AS activation_audited
FROM permission_basis b JOIN permission_stream s ON s.id=b.stream_id LEFT JOIN permission_assignment a ON a.stream_id=b.stream_id AND a.basis_key=b.basis_key
GROUP BY b.stream_id,b.basis_key,b.cluster_id,b.namespace_uid,b.workload_uids,b.effect,b.not_after,b.seen_sequence,s.sequence ORDER BY b.basis_key LIMIT 50;
SELECT root_id,id,source_name,revision,accounts,namespaces FROM capacity_pool LIMIT 20;
SELECT root_id,pool_id,revision,superseded_at FROM capacity_pool_revision LIMIT 20;
COMMIT;
