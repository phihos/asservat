-- Synthetic disposable fixtures only. Never apply these credentials or grants to an operator installation.
CREATE ROLE browser_runtime LOGIN PASSWORD 'synthetic-browser'; GRANT CONNECT ON DATABASE custody_test TO browser_runtime; GRANT USAGE ON SCHEMA public TO browser_runtime; GRANT SELECT ON goose_db_version TO browser_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON browser_login,browser_session,browser_logout TO browser_runtime;
CREATE ROLE custody_runtime LOGIN PASSWORD 'synthetic-runtime'; GRANT CONNECT ON DATABASE custody_test TO custody_runtime; GRANT USAGE ON SCHEMA public TO custody_runtime; GRANT SELECT ON goose_db_version TO custody_runtime; GRANT SELECT,INSERT,UPDATE ON custody_pool,custody_allocation,custody_attempt,custody_copy,custody_event TO custody_runtime; GRANT SELECT,INSERT,UPDATE ON custody_stream TO custody_runtime;

CREATE ROLE authority_runtime LOGIN PASSWORD 'synthetic-authority'; GRANT CONNECT ON DATABASE custody_test TO authority_runtime; GRANT USAGE ON SCHEMA public TO authority_runtime; GRANT SELECT ON goose_db_version TO authority_runtime; GRANT SELECT ON permission_stream,permission_basis,permission_assignment,permission_review_source,permission_review_assignment,permission_review_decision,permission_acceptance,authority_audit,workload_name TO authority_runtime; GRANT SELECT ON remote_access_binding_delivery TO authority_runtime; GRANT INSERT ON permission_stream,permission_basis,permission_assignment,permission_acceptance,authority_audit,permission_basis_change TO authority_runtime; GRANT UPDATE(id,epoch,sequence,trust_digest,projection_digest,lease_until,observed_at,fresh_until,suspended,unavailable_clusters) ON permission_stream TO authority_runtime; GRANT UPDATE(generation,resource_version,spec_digest,scope_digest,workload_uids,effect,not_after,seen_sequence,observation_version,automation_json,automation_audit_id) ON permission_basis TO authority_runtime; GRANT UPDATE(retired_at,retirement_audit_id) ON permission_assignment TO authority_runtime;
-- ADR-245: the product permission-accept review-source grants and, for the review store tests, the access-review duty's writes.
GRANT INSERT,DELETE ON permission_review_source TO authority_runtime; GRANT UPDATE(uid,epoch,seen_sequence,generation,resource_version,spec_digest,authority_digest,cluster_id,role,source_json,accepted_audit_id) ON permission_review_source TO authority_runtime; GRANT INSERT ON permission_review_assignment TO authority_runtime; GRANT UPDATE(retired_at,retirement_audit_id) ON permission_review_assignment TO authority_runtime; GRANT INSERT,DELETE ON permission_review_decision TO authority_runtime; GRANT UPDATE(decided_at,fresh_until) ON permission_review_decision TO authority_runtime; GRANT SELECT ON context_capture TO authority_runtime; GRANT EXECUTE ON FUNCTION record_permission_review_audit(uuid,uuid,bytea,jsonb) TO authority_runtime;

CREATE ROLE capture_runtime LOGIN PASSWORD 'synthetic-capture'; GRANT CONNECT ON DATABASE custody_test TO capture_runtime; GRANT USAGE ON SCHEMA public TO capture_runtime; GRANT SELECT ON goose_db_version,permission_stream,permission_basis,permission_assignment,permission_review_source,permission_review_assignment,permission_review_decision,authority_audit,context_storage_binding,capture_history_parameter,workload_name TO capture_runtime; GRANT UPDATE(id) ON permission_stream TO capture_runtime; GRANT UPDATE(source_uid) ON context_storage_binding TO capture_runtime; GRANT SELECT,INSERT ON context_capture TO capture_runtime; GRANT SELECT,INSERT,UPDATE ON custody_pool,custody_allocation,custody_attempt,custody_copy,custody_event TO capture_runtime;

CREATE ROLE capture_audit_runtime LOGIN PASSWORD 'synthetic-capture-audit'; GRANT CONNECT ON DATABASE custody_test TO capture_audit_runtime; GRANT USAGE ON SCHEMA public TO capture_audit_runtime; GRANT SELECT ON goose_db_version,permission_stream,context_capture TO capture_audit_runtime; GRANT UPDATE(id) ON permission_stream TO capture_audit_runtime;

CREATE ROLE peer_read_runtime LOGIN PASSWORD 'synthetic-peer-read'; GRANT CONNECT ON DATABASE custody_test TO peer_read_runtime; GRANT USAGE ON SCHEMA public TO peer_read_runtime; GRANT SELECT ON goose_db_version,fleet_trust TO peer_read_runtime;











CREATE ROLE context_catalog_read_runtime LOGIN PASSWORD 'synthetic-context-read'; GRANT CONNECT ON DATABASE custody_test TO context_catalog_read_runtime; GRANT USAGE ON SCHEMA public TO context_catalog_read_runtime;
GRANT SELECT ON goose_db_version,context_capture,custody_attempt,context_catalog TO context_catalog_read_runtime;

CREATE ROLE download_config_runtime LOGIN PASSWORD 'synthetic-download-config'; GRANT CONNECT ON DATABASE custody_test TO download_config_runtime; GRANT USAGE ON SCHEMA public TO download_config_runtime;
GRANT SELECT ON goose_db_version,permission_stream,download_allocation TO download_config_runtime;
GRANT UPDATE(id) ON permission_stream,download_allocation TO download_config_runtime;
GRANT INSERT(id,root_id,cluster_id,namespace_uid,workload_uid,output_limit,read_limit,valid_until) ON download_allocation TO download_config_runtime;

CREATE ROLE download_runtime LOGIN PASSWORD 'synthetic-download'; GRANT CONNECT ON DATABASE custody_test TO download_runtime; GRANT USAGE ON SCHEMA public TO download_runtime;
GRANT SELECT ON goose_db_version,permission_stream,authority_audit,context_catalog,context_capture,custody_attempt,download_allocation,artifact_download,download_batch,download_response TO download_runtime;
GRANT UPDATE(id) ON permission_stream TO download_runtime;
GRANT UPDATE(reserved_output,reserved_read) ON download_allocation TO download_runtime;
GRANT INSERT(id,root_id,allocation_id,artifact_id,principal_key,actor_key,idempotency_digest,request_digest,scope_json,deadline,output_limit,read_limit) ON artifact_download TO download_runtime;
GRANT UPDATE(state,charged_output,charged_read,emitted_bytes,generation,active_batch) ON artifact_download TO download_runtime;
GRANT INSERT(id,session_id,generation,intent_json,lease_until) ON download_batch TO download_runtime;
GRANT UPDATE(outcome_json) ON download_batch TO download_runtime;

CREATE ROLE download_audit_runtime LOGIN PASSWORD 'synthetic-download-audit'; GRANT CONNECT ON DATABASE custody_test TO download_audit_runtime; GRANT USAGE ON SCHEMA public TO download_audit_runtime;
GRANT SELECT ON goose_db_version,artifact_download,download_batch TO download_audit_runtime;
GRANT UPDATE(id,state) ON artifact_download TO download_audit_runtime;
GRANT UPDATE(audit_acknowledged_at,audit_receipt_json,outcome_acknowledged_at,outcome_receipt_json) ON download_batch TO download_audit_runtime;

-- Only the retention worker can shorten the effective dates. Existing custody
-- and capture workers retain their original state/copy/accounting capabilities.
REVOKE UPDATE ON custody_attempt FROM custody_runtime,capture_runtime;
GRANT UPDATE(id,state,copies_digest,deletion_fence,lease_until,deleted_at) ON custody_attempt TO custody_runtime,capture_runtime;
CREATE ROLE retention_runtime LOGIN PASSWORD 'synthetic-retention'; GRANT CONNECT ON DATABASE custody_test TO retention_runtime; GRANT USAGE ON SCHEMA public TO retention_runtime;
GRANT SELECT ON goose_db_version,context_capture,custody_pool,custody_allocation,custody_attempt,retention_decision TO retention_runtime;
GRANT UPDATE(id) ON custody_pool,custody_allocation TO retention_runtime;
GRANT UPDATE(effective_expires_at,effective_delete_by,retention_sequence) ON custody_attempt TO retention_runtime;
GRANT INSERT ON retention_decision TO retention_runtime;
CREATE ROLE retention_audit_runtime LOGIN PASSWORD 'synthetic-retention-audit'; GRANT CONNECT ON DATABASE custody_test TO retention_audit_runtime; GRANT USAGE ON SCHEMA public TO retention_audit_runtime;
GRANT SELECT ON goose_db_version,retention_decision TO retention_audit_runtime;
GRANT UPDATE(audit_acknowledged_at,audit_receipt_json) ON retention_decision TO retention_audit_runtime;

GRANT SELECT ON permission_stream TO retention_runtime; GRANT UPDATE(id) ON permission_stream TO retention_runtime;

-- ADR-330 D12: the retention follower stores the policy set and shortens
-- stored deadlines with one audit row per event.
CREATE ROLE retention_source_runtime LOGIN PASSWORD 'synthetic-retention-source'; GRANT CONNECT ON DATABASE custody_test TO retention_source_runtime; GRANT USAGE ON SCHEMA public TO retention_source_runtime;
GRANT SELECT ON goose_db_version,retention_policy,custody_attempt,context_capture,capture_history_parameter TO retention_source_runtime;
GRANT INSERT,DELETE ON retention_policy TO retention_source_runtime;
GRANT UPDATE(name,generation,digest,policy,effect,updated_at) ON retention_policy TO retention_source_runtime;
GRANT INSERT ON retention_policy_event TO retention_source_runtime;
GRANT UPDATE(effective_expires_at,effective_delete_by) ON custody_attempt TO retention_source_runtime;

-- Effects read the stored policy set and lifecycle decisions only.
GRANT SELECT ON retention_policy,retention_decision TO capture_runtime,download_runtime;
-- The read-only download authorization projection follows original and later
-- applied policy identities; it never records lifecycle or catalog mutations.
GRANT SELECT ON retention_decision TO context_catalog_read_runtime;

-- Effects fence the current installation before permission/capacity locks.
GRANT SELECT ON fleet_trust TO download_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO download_runtime;

-- Context effects share the same read/lock-only recovery fence as downloads.
GRANT SELECT ON fleet_trust TO capture_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO capture_runtime;

-- Policy roles do not author permissions, acknowledge their own acceptance, or
-- allocate evidence. Private factories pin the installation/root association.
CREATE ROLE policy_source_runtime LOGIN PASSWORD 'synthetic-policy-source';
CREATE ROLE policy_accept_runtime LOGIN PASSWORD 'synthetic-policy-accept';
CREATE ROLE policy_audit_runtime LOGIN PASSWORD 'synthetic-policy-audit';
CREATE ROLE policy_read_runtime LOGIN PASSWORD 'synthetic-policy-read';
GRANT CONNECT ON DATABASE custody_test TO policy_source_runtime,policy_accept_runtime,policy_audit_runtime,policy_read_runtime;
GRANT USAGE ON SCHEMA public TO policy_source_runtime,policy_accept_runtime,policy_audit_runtime,policy_read_runtime;
GRANT SELECT ON goose_db_version,permission_stream,policy_source,policy_acceptance TO policy_source_runtime,policy_accept_runtime,policy_audit_runtime,policy_read_runtime;
GRANT UPDATE(id) ON permission_stream TO policy_source_runtime,policy_accept_runtime,policy_audit_runtime,policy_read_runtime;
GRANT INSERT(root_id,policy_uid,installation_id,cluster_id,namespace_uid,name,generation,spec_digest,resource_version,observed_at,fresh_until,deleted,suspended,collection_digest,authored_grant_ref) ON policy_source TO policy_source_runtime;
GRANT UPDATE(generation,spec_digest,resource_version,observed_at,fresh_until,deleted,suspended,collection_digest,intent_version,authored_grant_ref,grant_attachment_id) ON policy_source TO policy_source_runtime;
GRANT UPDATE(creator_json,active_id,grant_attachment_id) ON policy_source TO policy_accept_runtime;
GRANT UPDATE(policy_uid) ON policy_source TO policy_read_runtime;
GRANT SELECT ON fleet_trust,permission_basis,permission_assignment,permission_review_source,permission_review_assignment,permission_review_decision,authority_audit,workload_name TO policy_accept_runtime,policy_read_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO policy_accept_runtime,policy_read_runtime;
GRANT INSERT(id,root_id,policy_uid,generation,nonce,scope_digest,request_digest,record_digest,record,accepted_at) ON policy_acceptance TO policy_accept_runtime;
GRANT UPDATE(acknowledged_at,receipt_json) ON policy_acceptance TO policy_audit_runtime;

-- Exact audited download-batch key bindings: coordinator inserts immutable
-- bindings; key-service consumes slots. Neither role can issue download/audit
-- authority, relax retention/recovery, read root keys or reset a spent slot.
CREATE ROLE download_key_bind_runtime LOGIN PASSWORD 'synthetic-download-key-bind';
CREATE ROLE download_key_read_runtime LOGIN PASSWORD 'synthetic-download-key-read';
GRANT CONNECT ON DATABASE custody_test TO download_key_bind_runtime,download_key_read_runtime;
GRANT USAGE ON SCHEMA public TO download_key_bind_runtime,download_key_read_runtime;
GRANT SELECT ON goose_db_version,fleet_trust,permission_stream,authority_audit,context_catalog,context_capture,custody_attempt,artifact_download,download_batch,download_key_binding,retention_policy,retention_decision TO download_key_bind_runtime,download_key_read_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO download_key_bind_runtime,download_key_read_runtime;
GRANT UPDATE(id) ON permission_stream,artifact_download TO download_key_bind_runtime,download_key_read_runtime;
GRANT INSERT(batch_id,session_id,root_id,installation_id,key_id,peer_id,certificate_sha256,authority_json,valid_until,worker_proof_json) ON download_key_binding TO download_key_bind_runtime;
GRANT UPDATE(used_roles) ON download_key_binding TO download_key_read_runtime;

-- Isolated local-key lifecycle observer, never a consumer or public API role.
CREATE ROLE local_keys_runtime LOGIN PASSWORD 'synthetic-local-keys';
GRANT SELECT ON goose_db_version,fleet_trust,local_key_configuration,local_key_version TO local_keys_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO local_keys_runtime;
GRANT INSERT ON local_key_configuration,local_key_version TO local_keys_runtime;
GRANT UPDATE(snapshot_json) ON local_key_configuration TO local_keys_runtime;

-- Worker dispatch never writes evidence permissions, audit acknowledgement or
-- the parent download counters. Audit and identity lookups are separate roles.
CREATE ROLE download_worker_runtime LOGIN PASSWORD 'synthetic-download-worker';
CREATE ROLE download_worker_audit_runtime LOGIN PASSWORD 'synthetic-download-worker-audit';
CREATE ROLE download_worker_identity_runtime LOGIN PASSWORD 'synthetic-download-worker-identity';
GRANT CONNECT ON DATABASE custody_test TO download_worker_runtime,download_worker_audit_runtime,download_worker_identity_runtime;
GRANT USAGE ON SCHEMA public TO download_worker_runtime,download_worker_audit_runtime,download_worker_identity_runtime;
GRANT SELECT ON goose_db_version,download_worker TO download_worker_runtime,download_worker_audit_runtime,download_worker_identity_runtime;
GRANT SELECT ON artifact_download TO download_worker_identity_runtime;
GRANT SELECT ON fleet_trust,permission_stream,authority_audit,context_catalog,context_capture,custody_attempt,artifact_download,download_batch,retention_policy,retention_decision TO download_worker_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO download_worker_runtime;
GRANT UPDATE(id) ON permission_stream,artifact_download TO download_worker_runtime;
GRANT INSERT(id,session_id,root_id,installation_id,allocation_id,generation,intent_json,run_until) ON download_worker TO download_worker_runtime;
GRANT UPDATE(claimed_at,job_json,binding_json,termination_json,retired_proof_json) ON download_worker TO download_worker_runtime;
-- The shared acquisition capacity count matches workload identity through either purpose parent.
GRANT SELECT ON download_allocation,context_query_allocation TO download_worker_runtime;
GRANT UPDATE(audit_receipt_json) ON download_worker TO download_worker_audit_runtime;

CREATE ROLE worker_configuration_runtime LOGIN PASSWORD 'synthetic-worker-configuration';
CREATE ROLE worker_configuration_audit_runtime LOGIN PASSWORD 'synthetic-worker-configuration-audit';
CREATE ROLE worker_configuration_read_runtime LOGIN PASSWORD 'synthetic-worker-configuration-read';
GRANT CONNECT ON DATABASE custody_test TO worker_configuration_runtime,worker_configuration_audit_runtime,worker_configuration_read_runtime;
GRANT USAGE ON SCHEMA public TO worker_configuration_runtime,worker_configuration_audit_runtime,worker_configuration_read_runtime;
GRANT SELECT ON goose_db_version,download_worker_configuration,download_worker_configuration_revision,fleet_trust TO worker_configuration_runtime,worker_configuration_audit_runtime,worker_configuration_read_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO worker_configuration_runtime,worker_configuration_read_runtime;
GRANT INSERT ON download_worker_configuration TO worker_configuration_runtime;
GRANT INSERT(installation_id,cluster_id,source_uid,generation,snapshot_json) ON download_worker_configuration_revision TO worker_configuration_runtime;
GRANT UPDATE(generation,observed_at) ON download_worker_configuration TO worker_configuration_runtime;
GRANT UPDATE(source_uid) ON download_worker_configuration TO worker_configuration_runtime,worker_configuration_audit_runtime,worker_configuration_read_runtime,download_worker_runtime,download_worker_identity_runtime;
GRANT UPDATE(audit_receipt_json) ON download_worker_configuration_revision TO worker_configuration_audit_runtime;
GRANT SELECT ON download_worker_configuration,download_worker_configuration_revision TO download_worker_runtime,download_worker_identity_runtime;
GRANT SELECT ON fleet_trust TO download_worker_identity_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO download_worker_identity_runtime;

-- Worker enrollment cannot launch Jobs, acknowledge its own audit or alter
-- parent authority/counters. Public certificates contain no private keys.
CREATE ROLE worker_enrollment_runtime LOGIN PASSWORD 'synthetic-worker-enrollment';
CREATE ROLE worker_enrollment_audit_runtime LOGIN PASSWORD 'synthetic-worker-enrollment-audit';
CREATE ROLE worker_enrollment_activate_runtime LOGIN PASSWORD 'synthetic-worker-enrollment-activate';
GRANT CONNECT ON DATABASE custody_test TO worker_enrollment_runtime,worker_enrollment_audit_runtime,worker_enrollment_activate_runtime;
GRANT USAGE ON SCHEMA public TO worker_enrollment_runtime,worker_enrollment_audit_runtime,worker_enrollment_activate_runtime;
GRANT SELECT ON goose_db_version,download_worker,download_worker_enrollment,download_worker_certificate TO worker_enrollment_runtime,worker_enrollment_audit_runtime,worker_enrollment_activate_runtime;
GRANT UPDATE(id) ON download_worker TO worker_enrollment_runtime,worker_enrollment_audit_runtime,worker_enrollment_activate_runtime;
GRANT SELECT ON fleet_trust,permission_stream,authority_audit,context_catalog,context_capture,custody_attempt,artifact_download,download_batch,retention_policy,retention_decision,download_worker_configuration,download_worker_configuration_revision TO worker_enrollment_runtime,worker_enrollment_activate_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO worker_enrollment_runtime,worker_enrollment_activate_runtime;
GRANT UPDATE(id) ON permission_stream,artifact_download TO worker_enrollment_runtime,worker_enrollment_activate_runtime;
GRANT UPDATE(source_uid) ON download_worker_configuration TO worker_enrollment_runtime,worker_enrollment_activate_runtime;
GRANT INSERT(worker_id,enrollment_json) ON download_worker_enrollment TO worker_enrollment_runtime;
GRANT INSERT(id,worker_id,epoch,ordinal,attempt_json) ON download_worker_certificate TO worker_enrollment_runtime;
GRANT UPDATE(certificate_json,certificate_sha256) ON download_worker_certificate TO worker_enrollment_runtime;
GRANT UPDATE(audit_receipt_json) ON download_worker_enrollment,download_worker_certificate TO worker_enrollment_audit_runtime;
GRANT UPDATE(activated_at) ON download_worker_certificate TO worker_enrollment_activate_runtime;
-- Current identity verifies both the retained enrollment and certificate audits.
GRANT SELECT ON download_worker_enrollment,download_worker_certificate TO download_worker_identity_runtime;

-- Active hub request locators have no worker/signing or evidence privileges.
CREATE ROLE worker_owner_runtime LOGIN PASSWORD 'synthetic-worker-owner';
CREATE ROLE worker_owner_read_runtime LOGIN PASSWORD 'synthetic-worker-owner-read';
GRANT CONNECT ON DATABASE custody_test TO worker_owner_runtime,worker_owner_read_runtime;
GRANT USAGE ON SCHEMA public TO worker_owner_runtime,worker_owner_read_runtime;
GRANT SELECT ON goose_db_version,download_worker_owner,download_worker,artifact_download TO worker_owner_runtime,worker_owner_read_runtime;
GRANT SELECT ON fleet_trust,permission_stream,authority_audit,context_catalog,context_capture,custody_attempt,download_batch,retention_policy,retention_decision,download_worker_configuration,download_worker_configuration_revision TO worker_owner_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO worker_owner_runtime;
GRANT UPDATE(id) ON permission_stream,artifact_download,download_worker TO worker_owner_runtime;
GRANT UPDATE(source_uid) ON download_worker_configuration TO worker_owner_runtime;
GRANT INSERT ON download_worker_owner TO worker_owner_runtime;
GRANT UPDATE(request_id,pod_uid,process_epoch,fence,started_at,expires_at,released_at) ON download_worker_owner TO worker_owner_runtime;
-- Hub owner source acceptance, transactional audit and consumers
-- are separate principals. Dummy UPDATE grants permit PostgreSQL row locks;
-- immutable-identity triggers prevent them from changing those identities.
CREATE ROLE owner_configuration_runtime LOGIN PASSWORD 'synthetic-owner-configuration';
CREATE ROLE owner_configuration_read_runtime LOGIN PASSWORD 'synthetic-owner-configuration-read';
GRANT CONNECT ON DATABASE custody_test TO owner_configuration_runtime,owner_configuration_read_runtime;
GRANT USAGE ON SCHEMA public TO owner_configuration_runtime,owner_configuration_read_runtime;
GRANT SELECT ON goose_db_version,fleet_trust,hub_owner_configuration,hub_owner_configuration_revision TO owner_configuration_runtime,owner_configuration_read_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO owner_configuration_runtime,owner_configuration_read_runtime;
GRANT INSERT ON hub_owner_configuration TO owner_configuration_runtime;
GRANT INSERT(installation_id,cluster_id,source_uid,generation,snapshot_json) ON hub_owner_configuration_revision TO owner_configuration_runtime;
GRANT UPDATE(generation,observed_at,fresh_until) ON hub_owner_configuration TO owner_configuration_runtime;
GRANT UPDATE(source_uid) ON hub_owner_configuration TO owner_configuration_runtime,owner_configuration_read_runtime;

-- Hub process ownership: independent enrollment, audit, activation/read and cleanup.
CREATE ROLE owner_enrollment_runtime LOGIN PASSWORD 'synthetic-owner-enrollment';
CREATE ROLE owner_enrollment_audit_runtime LOGIN PASSWORD 'synthetic-owner-enrollment-audit';
CREATE ROLE owner_enrollment_activate_runtime LOGIN PASSWORD 'synthetic-owner-enrollment-activate';
CREATE ROLE owner_enrollment_read_runtime LOGIN PASSWORD 'synthetic-owner-enrollment-read';
CREATE ROLE owner_enrollment_cleanup_runtime LOGIN PASSWORD 'synthetic-owner-enrollment-cleanup';
GRANT CONNECT ON DATABASE custody_test TO owner_enrollment_runtime,owner_enrollment_audit_runtime,owner_enrollment_activate_runtime,owner_enrollment_read_runtime,owner_enrollment_cleanup_runtime;
GRANT USAGE ON SCHEMA public TO owner_enrollment_runtime,owner_enrollment_audit_runtime,owner_enrollment_activate_runtime,owner_enrollment_read_runtime,owner_enrollment_cleanup_runtime;
GRANT SELECT ON goose_db_version,hub_owner_configuration,hub_owner_enrollment,hub_owner_certificate TO owner_enrollment_runtime,owner_enrollment_audit_runtime,owner_enrollment_activate_runtime,owner_enrollment_read_runtime,owner_enrollment_cleanup_runtime;
GRANT UPDATE(source_uid) ON hub_owner_configuration TO owner_enrollment_runtime,owner_enrollment_audit_runtime,owner_enrollment_activate_runtime,owner_enrollment_read_runtime,owner_enrollment_cleanup_runtime;
GRANT SELECT ON fleet_trust,hub_owner_configuration_revision TO owner_enrollment_runtime,owner_enrollment_activate_runtime,owner_enrollment_read_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO owner_enrollment_runtime,owner_enrollment_activate_runtime,owner_enrollment_read_runtime;
GRANT INSERT(id,installation_id,cluster_id,issuer_epoch,pod_uid,process_epoch,usage,enrollment_json,created_at,hold_until) ON hub_owner_enrollment TO owner_enrollment_runtime;
GRANT UPDATE(highest_epoch,hold_until) ON hub_owner_enrollment TO owner_enrollment_runtime;
GRANT INSERT(id,enrollment_id,epoch,ordinal,not_after,attempt_json) ON hub_owner_certificate TO owner_enrollment_runtime;
GRANT UPDATE(certificate_json,certificate_sha256) ON hub_owner_certificate TO owner_enrollment_runtime;
GRANT UPDATE(audit_receipt_json) ON hub_owner_enrollment,hub_owner_certificate TO owner_enrollment_audit_runtime;
GRANT UPDATE(activated_at) ON hub_owner_certificate TO owner_enrollment_activate_runtime;
GRANT UPDATE(retired_at) ON hub_owner_enrollment TO owner_enrollment_cleanup_runtime;
GRANT DELETE ON hub_owner_certificate,hub_owner_enrollment TO owner_enrollment_runtime,owner_enrollment_cleanup_runtime;

-- Hub-wide routing reads current profiles but cannot dispatch, enroll, claim or
-- activate. Identity-column privileges permit locks, not identity replacement.
CREATE ROLE worker_routing_read_runtime LOGIN PASSWORD 'synthetic-worker-routing-read';
GRANT CONNECT ON DATABASE custody_test TO worker_routing_read_runtime;
GRANT USAGE ON SCHEMA public TO worker_routing_read_runtime;
GRANT SELECT ON goose_db_version,download_worker_owner,download_worker,artifact_download,fleet_trust,download_worker_configuration,download_worker_configuration_revision TO worker_routing_read_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO worker_routing_read_runtime;
GRANT UPDATE(source_uid) ON download_worker_configuration TO worker_routing_read_runtime;

-- Effective recovery is computed from this PostgreSQL process/database.
-- Runtime roles cannot set either activation field or mutate the derived flag.
GRANT SELECT ON fleet_current_trust TO capture_runtime,download_key_bind_runtime,download_key_read_runtime,download_runtime,download_worker_identity_runtime,download_worker_runtime,local_keys_runtime,owner_configuration_read_runtime,owner_configuration_runtime,owner_enrollment_activate_runtime,owner_enrollment_read_runtime,owner_enrollment_runtime,peer_read_runtime,policy_accept_runtime,policy_read_runtime,worker_configuration_audit_runtime,worker_configuration_read_runtime,worker_configuration_runtime,worker_enrollment_activate_runtime,worker_enrollment_runtime,worker_owner_runtime,worker_routing_read_runtime;

-- Placement observations confer no reservation or configuration authority.
CREATE ROLE context_storage_read_runtime LOGIN PASSWORD 'synthetic-context-storage-read';
GRANT CONNECT ON DATABASE custody_test TO context_storage_read_runtime;
GRANT USAGE ON SCHEMA public TO context_storage_read_runtime;
GRANT SELECT ON goose_db_version,context_storage_binding,custody_allocation,custody_pool TO context_storage_read_runtime;

-- Capture status reads and elapsed-deadline observations are distinct roles.
CREATE ROLE context_progress_read_runtime LOGIN PASSWORD 'synthetic-context-progress-read';
CREATE ROLE context_deadline_runtime LOGIN PASSWORD 'synthetic-context-deadline';
GRANT CONNECT ON DATABASE custody_test TO context_progress_read_runtime,context_deadline_runtime;
GRANT USAGE ON SCHEMA public TO context_progress_read_runtime,context_deadline_runtime;
GRANT SELECT ON goose_db_version,permission_stream,context_capture,context_catalog TO context_progress_read_runtime,context_deadline_runtime;
GRANT UPDATE(id) ON permission_stream TO context_progress_read_runtime,context_deadline_runtime;
GRANT SELECT ON fleet_current_trust,permission_basis,permission_assignment,permission_review_source,permission_review_assignment,permission_review_decision,authority_audit,custody_attempt,workload_name TO context_progress_read_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO context_progress_read_runtime;
GRANT UPDATE(deadline_observed_at) ON context_capture TO context_deadline_runtime;

-- The regional API execution roles share no installer, hub-owner, acquisition-
-- unwrap or publication authority. Preparation cannot commit a local start;
-- execution cannot insert/replace the prepared execution/process identity.
CREATE ROLE api_execution_read_runtime LOGIN PASSWORD 'synthetic-api-execution-read';
CREATE ROLE api_execution_prepare_runtime LOGIN PASSWORD 'synthetic-api-execution-prepare';
CREATE ROLE api_execution_runtime LOGIN PASSWORD 'synthetic-api-execution';
GRANT CONNECT ON DATABASE custody_test TO api_execution_read_runtime,api_execution_prepare_runtime,api_execution_runtime;
GRANT USAGE ON SCHEMA public TO api_execution_read_runtime,api_execution_prepare_runtime,api_execution_runtime;
GRANT SELECT ON goose_db_version,fleet_current_trust,permission_stream,permission_basis,permission_assignment,permission_review_source,permission_review_assignment,permission_review_decision,authority_audit,context_capture,context_execution,custody_pool,custody_allocation,custody_attempt,retention_policy,retention_decision,workload_name TO api_execution_read_runtime,api_execution_prepare_runtime,api_execution_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO api_execution_read_runtime,api_execution_prepare_runtime,api_execution_runtime;
GRANT UPDATE(id) ON permission_stream TO api_execution_read_runtime,api_execution_prepare_runtime,api_execution_runtime;
GRANT UPDATE(id) ON context_capture,custody_pool,custody_allocation,custody_attempt TO api_execution_prepare_runtime,api_execution_runtime;
GRANT UPDATE(capture_id) ON context_execution TO api_execution_prepare_runtime,api_execution_runtime;
GRANT INSERT(root_id,capture_id,attempt_id,binding_json,process_json,expectation_digest,not_before,not_after) ON context_execution TO api_execution_prepare_runtime;
GRANT UPDATE(object_uid) ON context_execution TO api_execution_runtime;
GRANT UPDATE(phase,started_at,acquired_at,completed_at,copies_json,copies_digest) ON context_execution TO api_execution_runtime;
GRANT SELECT ON context_execution TO context_progress_read_runtime;

-- Migration37: separate protected control backing from immutable capture spend.
CREATE ROLE context_control_config_runtime LOGIN PASSWORD 'synthetic-context-control-config';
GRANT CONNECT ON DATABASE custody_test TO context_control_config_runtime;
GRANT USAGE ON SCHEMA public TO context_control_config_runtime;
GRANT SELECT ON goose_db_version,permission_stream,context_storage_binding,custody_pool,custody_allocation TO context_control_config_runtime;
GRANT UPDATE(id) ON permission_stream,custody_pool,custody_allocation TO context_control_config_runtime;
GRANT UPDATE(source_uid) ON context_storage_binding TO context_control_config_runtime;
CREATE ROLE context_retirement_read_runtime LOGIN PASSWORD 'synthetic-context-retirement-read';
GRANT CONNECT ON DATABASE custody_test TO context_retirement_read_runtime;
GRANT USAGE ON SCHEMA public TO context_retirement_read_runtime;
GRANT SELECT ON goose_db_version,context_capture,custody_attempt,custody_copy,context_execution,artifact_download,retention_decision TO context_retirement_read_runtime;

-- Migration54: mirror the production capture-admit/storage-read function grant.
-- This reads the current managed cutoff; it grants no capacity configuration.
GRANT EXECUTE ON FUNCTION capacity_managed_admission_until(uuid,uuid,text,timestamptz) TO capture_runtime,context_storage_read_runtime;

-- Published-only private case routing. Ordinary metadata uses its separate
-- SELECT-only catalog facet after current scope eligibility.
CREATE ROLE context_case_read_runtime LOGIN PASSWORD 'synthetic-context-case-read';
GRANT CONNECT ON DATABASE custody_test TO context_case_read_runtime;
GRANT USAGE ON SCHEMA public TO context_case_read_runtime;
GRANT SELECT ON goose_db_version,context_case_locator,fleet_current_trust TO context_case_read_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO context_case_read_runtime;
GRANT SELECT(artifact_id,capture_id,root_id,copies_digest) ON context_catalog TO context_case_read_runtime;
-- expectation_json: ReadContextCaseRoutes reports each route's NativeType (PR 150).
GRANT SELECT(id,root_id,attempt_id,expectation_json) ON context_capture TO context_case_read_runtime;
GRANT SELECT(id,artifact_id,state,copies_digest,effective_expires_at) ON custody_attempt TO context_case_read_runtime;

-- Positive writer completion is separate from deletion/audit/finalization.
GRANT INSERT(writer_protocol) ON context_execution TO api_execution_prepare_runtime;
GRANT SELECT,INSERT ON context_writer_completion TO api_execution_runtime;
GRANT SELECT(installation_id,activated_postmaster_at,activated_database_oid) ON fleet_trust TO api_execution_runtime;
-- One-step publication (REQ-EVD-001): the stored outcome's copies, custody
-- event and catalog row commit in the execution transaction.
GRANT SELECT ON custody_copy,context_catalog TO api_execution_runtime;
GRANT UPDATE(state,copies_digest) ON custody_attempt TO api_execution_runtime;
GRANT UPDATE(ciphertext_bytes,ciphertext_sha256,etag,version_id) ON custody_copy TO api_execution_runtime;
GRANT INSERT ON custody_event TO api_execution_runtime;
GRANT INSERT(artifact_id,capture_id,root_id,copies_digest,native_bytes,acquisition_started_at,acquisition_completed_at) ON context_catalog TO api_execution_runtime;
GRANT INSERT ON audit_event TO api_execution_runtime;
CREATE ROLE context_cleanup_runtime LOGIN PASSWORD 'synthetic-context-cleanup';
CREATE ROLE context_cleanup_audit_runtime LOGIN PASSWORD 'synthetic-context-cleanup-audit';
CREATE ROLE context_cleanup_finalize_runtime LOGIN PASSWORD 'synthetic-context-cleanup-finalize';
GRANT CONNECT ON DATABASE custody_test TO context_cleanup_runtime,context_cleanup_audit_runtime,context_cleanup_finalize_runtime;
GRANT USAGE ON SCHEMA public TO context_cleanup_runtime,context_cleanup_audit_runtime,context_cleanup_finalize_runtime;
GRANT SELECT ON goose_db_version,permission_stream,fleet_current_trust,context_execution,context_writer_completion,context_deletion_checkpoint TO context_cleanup_runtime,context_cleanup_audit_runtime,context_cleanup_finalize_runtime;
GRANT SELECT(installation_id,activated_postmaster_at,activated_database_oid) ON fleet_trust TO context_cleanup_runtime,context_cleanup_audit_runtime,context_cleanup_finalize_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO context_cleanup_runtime,context_cleanup_audit_runtime,context_cleanup_finalize_runtime;
GRANT UPDATE(id) ON permission_stream TO context_cleanup_runtime,context_cleanup_audit_runtime,context_cleanup_finalize_runtime;
GRANT SELECT ON custody_pool,custody_allocation,custody_attempt,custody_copy TO context_cleanup_runtime,context_cleanup_finalize_runtime;
GRANT UPDATE(id) ON custody_pool,custody_allocation,custody_attempt TO context_cleanup_runtime,context_cleanup_finalize_runtime;
GRANT UPDATE(state,deletion_fence,lease_until) ON custody_attempt TO context_cleanup_runtime;
GRANT INSERT ON context_deletion_checkpoint TO context_cleanup_runtime;
-- ADR-223: the installed cleaner login also holds context_deadline_runtime's grants.
GRANT SELECT ON context_capture,context_catalog TO context_cleanup_runtime;
GRANT UPDATE(deadline_observed_at) ON context_capture TO context_cleanup_runtime;
GRANT UPDATE(attempt_id) ON context_deletion_checkpoint TO context_cleanup_audit_runtime,context_cleanup_finalize_runtime;
GRANT UPDATE(audit_receipt_json,audit_acknowledged_at) ON context_deletion_checkpoint TO context_cleanup_audit_runtime;
GRANT UPDATE(charged_bytes,charged_objects) ON custody_allocation TO context_cleanup_finalize_runtime;
GRANT UPDATE(state,deleted_at,lease_until) ON custody_attempt TO context_cleanup_finalize_runtime;
GRANT UPDATE(ciphertext_bytes,ciphertext_sha256,etag,version_id) ON custody_copy TO context_cleanup_finalize_runtime;
GRANT INSERT ON custody_event TO context_cleanup_finalize_runtime;

GRANT SELECT(attempt_id,writer_protocol) ON context_execution TO custody_runtime;
GRANT UPDATE(finalization_xid) ON context_deletion_checkpoint TO context_cleanup_finalize_runtime;

-- Operation audit is independent from capture/evidence budgets and authority.

-- Download stop (ADR-330 D6): one transaction fences the session, stores the
-- stop and appends its audit row. No catalog/native metadata permission.
CREATE ROLE download_stop_runtime LOGIN PASSWORD 'synthetic-download-stop';
GRANT CONNECT ON DATABASE custody_test TO download_stop_runtime;
GRANT USAGE ON SCHEMA public TO download_stop_runtime;
GRANT SELECT ON goose_db_version,artifact_download,artifact_download_stop TO download_stop_runtime;
GRANT UPDATE(id,state) ON artifact_download TO download_stop_runtime;
GRANT INSERT ON artifact_download_stop,audit_event TO download_stop_runtime;

-- SQL50 synthetic roles: current processing reads never write completeness or
-- lift restrictions. Protected configuration and exact decision facets differ.
CREATE ROLE processing_config_runtime LOGIN PASSWORD 'synthetic-processing-config';
CREATE ROLE processing_decision_runtime LOGIN PASSWORD 'synthetic-processing-decision';
CREATE ROLE processing_read_runtime LOGIN PASSWORD 'synthetic-processing-read';
GRANT CONNECT ON DATABASE custody_test TO processing_config_runtime,processing_decision_runtime,processing_read_runtime;
GRANT USAGE ON SCHEMA public TO processing_config_runtime,processing_decision_runtime,processing_read_runtime;
GRANT SELECT ON goose_db_version,fleet_current_trust,permission_stream,processing_root TO processing_config_runtime,processing_decision_runtime,processing_read_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO processing_config_runtime,processing_decision_runtime,processing_read_runtime;
GRANT UPDATE(id) ON permission_stream TO processing_config_runtime,processing_decision_runtime;
GRANT INSERT ON processing_root TO processing_config_runtime;
GRANT UPDATE(backing,backing_revision,valid_until,retire_by,max_captures,max_rules,max_root_transitions,root_transitions,sequence) ON processing_root TO processing_config_runtime;
GRANT UPDATE(root_id) ON processing_root TO processing_decision_runtime;
GRANT SELECT ON context_processing,processing_rule,processing_decision,context_catalog,audit_event TO processing_decision_runtime;
GRANT INSERT ON processing_rule,processing_decision,audit_event TO processing_decision_runtime;
GRANT UPDATE(id) ON processing_rule TO processing_decision_runtime;
GRANT UPDATE(id,applied_at) ON processing_decision TO processing_decision_runtime;
GRANT SELECT ON context_processing,processing_rule TO processing_read_runtime;
-- Existing effect consumers run the same current processing fence; these are
-- read-only projections and confer no independent authorization or mutation.
GRANT SELECT ON processing_root,context_processing,processing_rule TO context_catalog_read_runtime,context_case_read_runtime,download_runtime,download_key_bind_runtime,download_key_read_runtime,download_worker_runtime,download_worker_identity_runtime;
-- Enrollment, activation and active-request ownership call the same current
-- download fence before their effects. Audit-only and locator-read facets do not.
GRANT SELECT ON processing_root,context_processing,processing_rule TO worker_enrollment_runtime,worker_enrollment_activate_runtime,worker_owner_runtime;
GRANT SELECT ON fleet_current_trust TO context_catalog_read_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO context_catalog_read_runtime;

-- SQL52 private capture-intent roles. Synthetic credentials only; production
-- provisioning/pinning is a separate accepted installation prerequisite.
CREATE ROLE capture_operation_admit_runtime LOGIN NOINHERIT PASSWORD 'synthetic-capture-operation-admit';
GRANT CONNECT ON DATABASE custody_test TO capture_operation_admit_runtime;
GRANT USAGE ON SCHEMA public TO capture_operation_admit_runtime;
GRANT SELECT ON goose_db_version TO capture_operation_admit_runtime;
GRANT EXECUTE ON FUNCTION capacity_managed_admission_until(uuid,uuid,text,timestamptz) TO capture_operation_admit_runtime;
GRANT INSERT ON audit_event TO capture_runtime,capture_operation_admit_runtime;
-- Admission retains the existing exact authority/custody/control transaction,
-- without inheriting another role or gaining audit/provider acknowledgement.
GRANT SELECT ON permission_stream,permission_basis,permission_assignment,permission_review_source,permission_review_assignment,permission_review_decision,authority_audit,context_storage_binding,workload_name TO capture_operation_admit_runtime;
GRANT UPDATE(id) ON permission_stream TO capture_operation_admit_runtime;
-- Match the existing admission lock-only column grant; no allocation/freshness writes.
GRANT UPDATE(source_uid) ON context_storage_binding TO capture_operation_admit_runtime;
GRANT SELECT,INSERT ON context_capture TO capture_operation_admit_runtime;
GRANT SELECT,INSERT,UPDATE ON custody_pool,custody_allocation,custody_copy,custody_event TO capture_operation_admit_runtime;
GRANT SELECT,INSERT ON custody_attempt TO capture_operation_admit_runtime;
GRANT UPDATE(id,state,copies_digest,deletion_fence,lease_until,deleted_at) ON custody_attempt TO capture_operation_admit_runtime;
GRANT SELECT ON retention_policy,retention_decision TO capture_operation_admit_runtime;
GRANT SELECT ON fleet_trust,fleet_current_trust TO capture_operation_admit_runtime;
GRANT UPDATE(installation_id) ON fleet_trust,fleet_current_trust TO capture_operation_admit_runtime;

-- ADR-206 SQL component fixture only. These are not installed runtime grants.
-- Protected backing and C-14 worker/key bindings are seeded by the owned fixture
-- administrator; query admission cannot provision or replace any of them.
CREATE ROLE context_query_runtime LOGIN NOINHERIT PASSWORD 'synthetic-context-query';
GRANT CONNECT ON DATABASE custody_test TO context_query_runtime;
GRANT USAGE ON SCHEMA public TO context_query_runtime;
GRANT SELECT ON goose_db_version,fleet_trust,fleet_current_trust,permission_stream,authority_audit,
 retention_policy,retention_decision,
 context_catalog,context_capture,custody_attempt,context_case_locator,
 processing_root,context_processing,processing_rule,
 context_query_backing,context_query_allocation,context_query_principal,context_query,context_query_call,context_query_worker,context_query_batch
 TO context_query_runtime;
GRANT UPDATE(installation_id) ON fleet_trust,fleet_current_trust TO context_query_runtime;
GRANT UPDATE(id) ON permission_stream,context_query_allocation,context_query_principal,context_query TO context_query_runtime;
GRANT UPDATE(root_id) ON context_query_backing TO context_query_runtime;
GRANT INSERT ON context_query_principal,context_query,context_query_call,context_query_batch TO context_query_runtime;
GRANT UPDATE(claim_id,closed) ON context_query_batch TO context_query_runtime;
GRANT EXECUTE ON FUNCTION lock_context_query_capacity(uuid,uuid),context_query_capacity_allocation_current(uuid,uuid),context_query_shared_profile_current(uuid,jsonb) TO context_query_runtime;
CREATE ROLE context_query_key_fixture LOGIN NOINHERIT PASSWORD 'synthetic-context-query-key';
GRANT CONNECT ON DATABASE custody_test TO context_query_key_fixture;
GRANT USAGE ON SCHEMA public TO context_query_key_fixture;
GRANT SELECT ON context_query_key_binding TO context_query_key_fixture;
GRANT UPDATE(used_roles) ON context_query_key_binding TO context_query_key_fixture;

-- ADR-240: the retention impact preview reads only tables the production
-- hub-metadata-read union already selects; it holds no effect privilege.
CREATE ROLE retention_preview_read_runtime LOGIN PASSWORD 'synthetic-retention-preview-read'; GRANT CONNECT ON DATABASE custody_test TO retention_preview_read_runtime; GRANT USAGE ON SCHEMA public TO retention_preview_read_runtime;
GRANT SELECT ON goose_db_version,permission_stream,retention_policy,retention_decision,context_capture,custody_attempt TO retention_preview_read_runtime;
GRANT UPDATE(id) ON permission_stream TO retention_preview_read_runtime;

-- ADR-200: mirror the compiled capture-preview duty; wakeup only, no table grant.
GRANT EXECUTE ON FUNCTION lock_approved_context_grant(uuid,uuid,uuid,text,text,text,bytea) TO capture_runtime,api_execution_read_runtime,api_execution_prepare_runtime,api_execution_runtime;

-- ADR-255: existing metadata/retention facets read typed history obligations.
GRANT SELECT ON capture_history_parameter TO retention_runtime,retention_source_runtime,context_progress_read_runtime,retention_preview_read_runtime;

-- ADR-261: existing audited finalization alone retires an expired observation
-- child; cleaner/audit roles cannot delete or refund either observed pool.
GRANT SELECT(root_id,capture_id),DELETE ON policy_observation_session TO context_cleanup_finalize_runtime;

-- ADR-266/00108-00110: recording selections and save groups, as the
-- production capture-admit, capture-history and preview cleanup purposes
-- (public_runtime_role_plan.go).
GRANT SELECT,INSERT ON recording_save_group TO capture_runtime;
-- The audited capture admission's replay lookup reads save groups too
-- (findRecordingGroupRequest, as the production capture-admit purpose).
GRANT SELECT ON recording_save_group TO capture_operation_admit_runtime;
GRANT SELECT ON recording_save_group TO context_progress_read_runtime,context_deadline_runtime;
GRANT UPDATE(id) ON recording_save_group TO context_progress_read_runtime; -- row lock (production hub-metadata-read)

-- S-05: admission precharges a pending multipart obligation; the accepted
-- connector preparation alone binds its immutable process, and the separately
-- audited purge finalizer releases temporary charges after complete inventory.
GRANT SELECT,INSERT ON custody_stream TO capture_runtime;
GRANT UPDATE(attempt_id) ON custody_stream TO capture_runtime;
GRANT SELECT ON custody_stream TO api_execution_prepare_runtime,context_cleanup_finalize_runtime;
GRANT UPDATE(attempt_id,writer_epoch,plan_digest,revision) ON custody_stream TO api_execution_prepare_runtime;
GRANT UPDATE(attempt_id,state,revision,released_at) ON custody_stream TO context_cleanup_finalize_runtime;

GRANT UPDATE(installation_id) ON fleet_current_trust TO capture_runtime,download_key_bind_runtime,download_key_read_runtime,download_runtime,download_worker_identity_runtime,download_worker_runtime,local_keys_runtime,owner_configuration_read_runtime,owner_configuration_runtime,owner_enrollment_activate_runtime,owner_enrollment_read_runtime,owner_enrollment_runtime,policy_accept_runtime,policy_read_runtime,worker_configuration_read_runtime,worker_configuration_runtime,worker_enrollment_activate_runtime,worker_enrollment_runtime,worker_owner_runtime,worker_routing_read_runtime;
-- Migration 00170: account charge/release (SECURITY DEFINER) for every login that charges custody bytes.
GRANT EXECUTE ON FUNCTION capacity_charge(uuid,bigint,bigint),capacity_release(uuid,bigint,bigint) TO custody_runtime,capture_runtime,context_cleanup_finalize_runtime,capture_operation_admit_runtime;
GRANT EXECUTE ON FUNCTION capacity_expensive_admits(uuid) TO capture_runtime,capture_operation_admit_runtime;
