-- Synthetic disposable fixtures only. Never apply these credentials or grants to an operator installation.
CREATE ROLE browser_runtime LOGIN PASSWORD 'synthetic-browser'; GRANT CONNECT ON DATABASE custody_test TO browser_runtime; GRANT USAGE ON SCHEMA public TO browser_runtime; GRANT SELECT ON goose_db_version,browser_session_root TO browser_runtime; GRANT UPDATE(id) ON browser_session_root TO browser_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON browser_login,browser_session,browser_logout TO browser_runtime;
CREATE ROLE browser_cleanup_runtime LOGIN PASSWORD 'synthetic-browser-cleanup'; GRANT CONNECT ON DATABASE custody_test TO browser_cleanup_runtime; GRANT USAGE ON SCHEMA public TO browser_cleanup_runtime; GRANT SELECT ON goose_db_version,browser_session_root TO browser_cleanup_runtime; GRANT UPDATE(id) ON browser_session_root TO browser_cleanup_runtime; GRANT SELECT,DELETE ON browser_login,browser_session,browser_logout TO browser_cleanup_runtime; GRANT UPDATE(id) ON browser_login,browser_session,browser_logout TO browser_cleanup_runtime;
CREATE ROLE browser_settings_runtime LOGIN PASSWORD 'synthetic-browser-settings'; GRANT CONNECT ON DATABASE custody_test TO browser_settings_runtime; GRANT USAGE ON SCHEMA public TO browser_settings_runtime; GRANT SELECT ON goose_db_version,browser_session_root,browser_session_epoch TO browser_settings_runtime; GRANT INSERT,UPDATE ON browser_session_root TO browser_settings_runtime; GRANT INSERT ON browser_session_epoch TO browser_settings_runtime; GRANT DELETE ON browser_login,browser_session TO browser_settings_runtime; GRANT SELECT(root_id) ON browser_login TO browser_settings_runtime; GRANT SELECT(root_id,id,epoch,created_at,expires_at,refresh_at) ON browser_session TO browser_settings_runtime; GRANT UPDATE(expires_at,refresh_at) ON browser_session TO browser_settings_runtime;
CREATE ROLE custody_runtime LOGIN PASSWORD 'synthetic-runtime'; GRANT CONNECT ON DATABASE custody_test TO custody_runtime; GRANT USAGE ON SCHEMA public TO custody_runtime; GRANT SELECT ON goose_db_version TO custody_runtime; GRANT SELECT,INSERT,UPDATE ON custody_pool,custody_allocation,custody_attempt,custody_copy,custody_event TO custody_runtime; GRANT SELECT,INSERT,UPDATE ON custody_stream TO custody_runtime;

CREATE ROLE authority_runtime LOGIN PASSWORD 'synthetic-authority'; GRANT CONNECT ON DATABASE custody_test TO authority_runtime; GRANT USAGE ON SCHEMA public TO authority_runtime; GRANT SELECT ON goose_db_version TO authority_runtime; GRANT SELECT ON permission_stream,permission_basis,permission_assignment,permission_acceptance,authority_audit TO authority_runtime; GRANT INSERT ON permission_stream,permission_basis,permission_assignment,permission_acceptance,authority_audit TO authority_runtime; GRANT UPDATE(id,epoch,sequence,initial_audit_id,trust_digest,projection_digest,lease_until,observed_at,fresh_until,suspended) ON permission_stream TO authority_runtime; GRANT UPDATE(generation,resource_version,spec_digest,scope_digest,workload_uids,effect,not_after,seen_sequence,observation_version,automation_json,automation_audit_id) ON permission_basis TO authority_runtime; GRANT UPDATE(retired_at,retirement_audit_id) ON permission_assignment TO authority_runtime; GRANT UPDATE(acknowledged_at,object_key,object_version,object_etag,object_bytes,object_sha256) ON authority_audit TO authority_runtime; -- ADR-189: the union of the product permission-accept and permission-audit grants.

CREATE ROLE capture_runtime LOGIN PASSWORD 'synthetic-capture'; GRANT CONNECT ON DATABASE custody_test TO capture_runtime; GRANT USAGE ON SCHEMA public TO capture_runtime; GRANT SELECT ON goose_db_version,permission_stream,permission_basis,permission_assignment,authority_audit,context_storage_binding TO capture_runtime; GRANT UPDATE(id) ON permission_stream TO capture_runtime; GRANT UPDATE(source_uid) ON context_storage_binding TO capture_runtime; GRANT SELECT,INSERT ON context_capture TO capture_runtime; GRANT SELECT,INSERT,UPDATE ON custody_pool,custody_allocation,custody_attempt,custody_copy,custody_event TO capture_runtime;

CREATE ROLE capture_audit_runtime LOGIN PASSWORD 'synthetic-capture-audit'; GRANT CONNECT ON DATABASE custody_test TO capture_audit_runtime; GRANT USAGE ON SCHEMA public TO capture_audit_runtime; GRANT SELECT ON goose_db_version,permission_stream,context_capture TO capture_audit_runtime; GRANT UPDATE(id) ON permission_stream TO capture_audit_runtime; GRANT UPDATE(state,intent_acknowledged_at,intent_digest,intent_object_key,intent_object_version,intent_object_etag,intent_object_bytes,intent_object_sha256) ON context_capture TO capture_audit_runtime;

CREATE ROLE peer_read_runtime LOGIN PASSWORD 'synthetic-peer-read'; GRANT CONNECT ON DATABASE custody_test TO peer_read_runtime; GRANT USAGE ON SCHEMA public TO peer_read_runtime; GRANT SELECT ON goose_db_version,fleet_trust,fleet_peer,fleet_peer_certificate TO peer_read_runtime;

CREATE ROLE enrollment_claim_runtime LOGIN PASSWORD 'synthetic-enrollment-claim'; GRANT CONNECT ON DATABASE custody_test TO enrollment_claim_runtime; GRANT USAGE ON SCHEMA public TO enrollment_claim_runtime; GRANT SELECT ON goose_db_version,fleet_trust,fleet_bootstrap TO enrollment_claim_runtime; GRANT UPDATE(installation_id) ON fleet_trust TO enrollment_claim_runtime; GRANT UPDATE(claimed_at,public_key_sha256) ON fleet_bootstrap TO enrollment_claim_runtime;

CREATE ROLE enrollment_audit_runtime LOGIN PASSWORD 'synthetic-enrollment-audit'; GRANT CONNECT ON DATABASE custody_test TO enrollment_audit_runtime; GRANT USAGE ON SCHEMA public TO enrollment_audit_runtime; GRANT SELECT ON goose_db_version,fleet_trust,fleet_bootstrap TO enrollment_audit_runtime; GRANT UPDATE(installation_id) ON fleet_trust TO enrollment_audit_runtime; GRANT UPDATE(id,claim_acknowledged_at,claim_audit_digest,claim_object_key,claim_object_version,claim_object_etag,claim_object_bytes,claim_object_sha256) ON fleet_bootstrap TO enrollment_audit_runtime;

CREATE ROLE enrollment_sign_runtime LOGIN PASSWORD 'synthetic-enrollment-sign'; GRANT CONNECT ON DATABASE custody_test TO enrollment_sign_runtime; GRANT USAGE ON SCHEMA public TO enrollment_sign_runtime; GRANT SELECT ON goose_db_version,fleet_trust,fleet_bootstrap,fleet_certificate_issue TO enrollment_sign_runtime; GRANT UPDATE(installation_id) ON fleet_trust TO enrollment_sign_runtime; GRANT UPDATE(id) ON fleet_bootstrap TO enrollment_sign_runtime; GRANT INSERT ON fleet_certificate_issue TO enrollment_sign_runtime; GRANT UPDATE(signed_at,certificate_json,certificate_sha256,certificate_not_before,certificate_not_after) ON fleet_certificate_issue TO enrollment_sign_runtime;

GRANT SELECT ON fleet_certificate_issue TO enrollment_audit_runtime; GRANT UPDATE(audit_acknowledged_at,audit_digest,audit_object_key,audit_object_version,audit_object_etag,audit_object_bytes,audit_object_sha256) ON fleet_certificate_issue TO enrollment_audit_runtime;

CREATE ROLE enrollment_activate_runtime LOGIN PASSWORD 'synthetic-enrollment-activate'; GRANT CONNECT ON DATABASE custody_test TO enrollment_activate_runtime; GRANT USAGE ON SCHEMA public TO enrollment_activate_runtime; GRANT SELECT ON goose_db_version,fleet_trust,fleet_bootstrap,fleet_certificate_issue,fleet_peer,fleet_peer_certificate TO enrollment_activate_runtime; GRANT UPDATE(installation_id) ON fleet_trust TO enrollment_activate_runtime; GRANT UPDATE(id) ON fleet_bootstrap TO enrollment_activate_runtime; GRANT UPDATE(activated_at) ON fleet_certificate_issue TO enrollment_activate_runtime; GRANT INSERT ON fleet_peer,fleet_peer_certificate TO enrollment_activate_runtime; GRANT UPDATE(installation_id) ON fleet_peer TO enrollment_activate_runtime;

CREATE ROLE bootstrap_reserve_runtime LOGIN PASSWORD 'synthetic-bootstrap-reserve'; GRANT CONNECT ON DATABASE custody_test TO bootstrap_reserve_runtime; GRANT USAGE ON SCHEMA public TO bootstrap_reserve_runtime; GRANT SELECT ON goose_db_version,fleet_trust,fleet_peer,fleet_bootstrap,fleet_bootstrap_intent TO bootstrap_reserve_runtime; GRANT UPDATE(installation_id) ON fleet_trust TO bootstrap_reserve_runtime; GRANT INSERT ON fleet_bootstrap_intent TO bootstrap_reserve_runtime;

CREATE ROLE bootstrap_record_runtime LOGIN PASSWORD 'synthetic-bootstrap-record'; GRANT CONNECT ON DATABASE custody_test TO bootstrap_record_runtime; GRANT USAGE ON SCHEMA public TO bootstrap_record_runtime; GRANT SELECT ON goose_db_version,fleet_trust,fleet_bootstrap_intent TO bootstrap_record_runtime; GRANT UPDATE(installation_id) ON fleet_trust TO bootstrap_record_runtime; GRANT UPDATE(id,credential_recorded_at,credential_sha256,credential_version) ON fleet_bootstrap_intent TO bootstrap_record_runtime;

CREATE ROLE bootstrap_audit_runtime LOGIN PASSWORD 'synthetic-bootstrap-audit'; GRANT CONNECT ON DATABASE custody_test TO bootstrap_audit_runtime; GRANT USAGE ON SCHEMA public TO bootstrap_audit_runtime; GRANT SELECT ON goose_db_version,fleet_trust,fleet_bootstrap_intent TO bootstrap_audit_runtime; GRANT UPDATE(installation_id) ON fleet_trust TO bootstrap_audit_runtime; GRANT UPDATE(id,audit_acknowledged_at,audit_digest,audit_object_key,audit_object_version,audit_object_etag,audit_object_bytes,audit_object_sha256) ON fleet_bootstrap_intent TO bootstrap_audit_runtime;

CREATE ROLE bootstrap_activate_runtime LOGIN PASSWORD 'synthetic-bootstrap-activate'; GRANT CONNECT ON DATABASE custody_test TO bootstrap_activate_runtime; GRANT USAGE ON SCHEMA public TO bootstrap_activate_runtime; GRANT SELECT ON goose_db_version,fleet_trust,fleet_bootstrap_intent,fleet_bootstrap TO bootstrap_activate_runtime; GRANT UPDATE(installation_id) ON fleet_trust TO bootstrap_activate_runtime; GRANT UPDATE(id,issued_at) ON fleet_bootstrap_intent TO bootstrap_activate_runtime; GRANT INSERT ON fleet_bootstrap TO bootstrap_activate_runtime; GRANT UPDATE(id) ON fleet_bootstrap TO bootstrap_activate_runtime;

CREATE ROLE fleet_observe_runtime LOGIN PASSWORD 'synthetic-fleet-observe'; GRANT CONNECT ON DATABASE custody_test TO fleet_observe_runtime; GRANT USAGE ON SCHEMA public TO fleet_observe_runtime; GRANT SELECT ON goose_db_version,fleet_trust TO fleet_observe_runtime; GRANT EXECUTE ON FUNCTION observe_fleet_administration(uuid,bigint,timestamptz,oid,timestamptz,uuid,text,bigint,bytea,boolean,timestamptz,timestamptz),fence_fleet_observation(uuid,bigint,timestamptz,oid,timestamptz) TO fleet_observe_runtime; GRANT EXECUTE ON FUNCTION public.reactivate_restarted_database(uuid) TO fleet_observe_runtime;

CREATE ROLE context_verify_runtime LOGIN PASSWORD 'synthetic-context-verify'; GRANT CONNECT ON DATABASE custody_test TO context_verify_runtime; GRANT USAGE ON SCHEMA public TO context_verify_runtime;
GRANT SELECT ON goose_db_version,permission_stream,authority_audit,context_capture,custody_pool,custody_allocation,custody_attempt,custody_copy,context_verification TO context_verify_runtime;
GRANT UPDATE(id) ON permission_stream,context_capture,custody_pool,custody_allocation TO context_verify_runtime;
GRANT UPDATE(id,state,copies_digest) ON custody_attempt TO context_verify_runtime;
GRANT UPDATE(ciphertext_bytes,ciphertext_sha256,etag,version_id) ON custody_copy TO context_verify_runtime;
GRANT INSERT ON custody_event TO context_verify_runtime;
GRANT INSERT(capture_id,root_id,expectation_digest,copies_digest,intent_digest,authority_digest,permission_epoch,permission_sequence) ON context_verification TO context_verify_runtime;

CREATE ROLE context_verification_audit_runtime LOGIN PASSWORD 'synthetic-context-audit'; GRANT CONNECT ON DATABASE custody_test TO context_verification_audit_runtime; GRANT USAGE ON SCHEMA public TO context_verification_audit_runtime;
GRANT SELECT ON goose_db_version,permission_stream,context_capture,context_verification TO context_verification_audit_runtime;
GRANT UPDATE(id) ON permission_stream,context_capture TO context_verification_audit_runtime;
GRANT UPDATE(capture_id,audit_acknowledged_at,audit_digest,audit_object_key,audit_object_version,audit_object_etag,audit_object_bytes,audit_object_sha256) ON context_verification TO context_verification_audit_runtime;

CREATE ROLE context_publish_runtime LOGIN PASSWORD 'synthetic-context-publish'; GRANT CONNECT ON DATABASE custody_test TO context_publish_runtime; GRANT USAGE ON SCHEMA public TO context_publish_runtime;
GRANT SELECT ON goose_db_version,permission_stream,authority_audit,context_capture,custody_pool,custody_allocation,custody_attempt,custody_copy,context_verification,context_catalog TO context_publish_runtime;
GRANT UPDATE(id) ON permission_stream,context_capture,custody_pool,custody_allocation,custody_attempt TO context_publish_runtime;
GRANT INSERT(artifact_id,capture_id,root_id) ON context_catalog TO context_publish_runtime;

CREATE ROLE context_catalog_read_runtime LOGIN PASSWORD 'synthetic-context-read'; GRANT CONNECT ON DATABASE custody_test TO context_catalog_read_runtime; GRANT USAGE ON SCHEMA public TO context_catalog_read_runtime;
GRANT SELECT ON goose_db_version,context_capture,custody_attempt,context_verification,context_catalog TO context_catalog_read_runtime;

CREATE ROLE download_config_runtime LOGIN PASSWORD 'synthetic-download-config'; GRANT CONNECT ON DATABASE custody_test TO download_config_runtime; GRANT USAGE ON SCHEMA public TO download_config_runtime;
GRANT SELECT ON goose_db_version,permission_stream,download_allocation TO download_config_runtime;
GRANT UPDATE(id) ON permission_stream,download_allocation TO download_config_runtime;
GRANT INSERT(id,root_id,cluster_id,namespace_uid,workload_uid,output_limit,read_limit,session_limit,valid_until) ON download_allocation TO download_config_runtime;

CREATE ROLE download_runtime LOGIN PASSWORD 'synthetic-download'; GRANT CONNECT ON DATABASE custody_test TO download_runtime; GRANT USAGE ON SCHEMA public TO download_runtime;
GRANT SELECT ON goose_db_version,permission_stream,authority_audit,context_catalog,context_capture,context_verification,custody_attempt,download_allocation,artifact_download,download_batch,download_response TO download_runtime;
GRANT UPDATE(id) ON permission_stream TO download_runtime;
GRANT UPDATE(reserved_output,reserved_read,reserved_sessions) ON download_allocation TO download_runtime;
GRANT INSERT(id,root_id,allocation_id,artifact_id,principal_key,actor_key,idempotency_digest,request_digest,scope_json,deadline,output_limit,read_limit,request_limit) ON artifact_download TO download_runtime;
GRANT UPDATE(state,charged_output,charged_read,requests,emitted_bytes,generation,active_batch) ON artifact_download TO download_runtime;
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

CREATE ROLE retention_source_runtime LOGIN PASSWORD 'synthetic-retention-source'; GRANT CONNECT ON DATABASE custody_test TO retention_source_runtime; GRANT USAGE ON SCHEMA public TO retention_source_runtime;
GRANT SELECT ON goose_db_version,permission_stream,retention_source,retention_checkpoint,retention_source_epoch TO retention_source_runtime;
GRANT UPDATE(id) ON permission_stream TO retention_source_runtime;
GRANT INSERT ON retention_source,retention_checkpoint,retention_source_epoch TO retention_source_runtime;
GRANT UPDATE(epoch,sequence,lease_until,suspended) ON retention_source TO retention_source_runtime;
CREATE ROLE retention_source_audit_runtime LOGIN PASSWORD 'synthetic-retention-source-audit'; GRANT CONNECT ON DATABASE custody_test TO retention_source_audit_runtime; GRANT USAGE ON SCHEMA public TO retention_source_audit_runtime;
GRANT SELECT ON goose_db_version,retention_checkpoint TO retention_source_audit_runtime;
GRANT UPDATE(audit_acknowledged_at,audit_receipt) ON retention_checkpoint TO retention_source_audit_runtime;

GRANT INSERT(checkpoint_id) ON retention_catchup TO retention_source_runtime;
GRANT UPDATE(watch_cursor) ON retention_source TO retention_source_runtime;
GRANT UPDATE(observed_sequence,observed_at,fresh_until,list_cursor) ON retention_source TO retention_source_runtime;
CREATE ROLE retention_catchup_runtime LOGIN PASSWORD 'synthetic-retention-catchup'; GRANT CONNECT ON DATABASE custody_test TO retention_catchup_runtime; GRANT USAGE ON SCHEMA public TO retention_catchup_runtime;
GRANT SELECT ON goose_db_version,permission_stream,retention_source,retention_checkpoint,retention_catchup,retention_catchup_effect,context_capture,custody_pool,custody_allocation,custody_attempt,retention_decision TO retention_catchup_runtime;
GRANT UPDATE(id) ON permission_stream,custody_pool,custody_allocation TO retention_catchup_runtime;
GRANT UPDATE(root_id) ON retention_source TO retention_catchup_runtime;
GRANT UPDATE(effective_expires_at,effective_delete_by,retention_sequence) ON custody_attempt TO retention_catchup_runtime;
GRANT UPDATE(after_attempt,visited,shortened,completed_at) ON retention_catchup TO retention_catchup_runtime;
GRANT INSERT ON retention_decision,retention_catchup_effect TO retention_catchup_runtime;

CREATE ROLE retention_source_read_runtime LOGIN PASSWORD 'synthetic-retention-source-read'; GRANT CONNECT ON DATABASE custody_test TO retention_source_read_runtime; GRANT USAGE ON SCHEMA public TO retention_source_read_runtime;
GRANT SELECT ON goose_db_version,permission_stream,retention_source,retention_checkpoint,retention_catchup,retention_catchup_effect,retention_decision TO retention_source_read_runtime;
GRANT UPDATE(id) ON permission_stream TO retention_source_read_runtime;
GRANT UPDATE(root_id) ON retention_source TO retention_source_read_runtime;

-- Final effects share current accepted retention sources. These facets cannot
-- acknowledge audits, advance history, freshen observations or mark catch-up.
GRANT SELECT ON retention_source,retention_checkpoint,retention_catchup,retention_catchup_effect,retention_decision TO capture_runtime,context_verify_runtime,context_publish_runtime,download_runtime;
GRANT UPDATE(root_id) ON retention_source TO capture_runtime,context_verify_runtime,context_publish_runtime,download_runtime;
-- The read-only download authorization projection follows original and later
-- applied policy identities; it never records lifecycle or catalog mutations.
GRANT SELECT ON retention_decision TO context_catalog_read_runtime;

-- Effects fence the current installation before permission/capacity locks.
GRANT SELECT ON fleet_trust TO download_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO download_runtime;

-- Context effects share the same read/lock-only recovery fence as downloads.
GRANT SELECT ON fleet_trust TO capture_runtime,context_verify_runtime,context_publish_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO capture_runtime,context_verify_runtime,context_publish_runtime;

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
GRANT INSERT(root_id,policy_uid,installation_id,cluster_id,namespace_uid,name,generation,spec_digest,resource_version,observed_at,fresh_until,deleted,suspended,collection_digest) ON policy_source TO policy_source_runtime;
GRANT UPDATE(generation,spec_digest,resource_version,observed_at,fresh_until,deleted,suspended,collection_digest,intent_version) ON policy_source TO policy_source_runtime;
GRANT UPDATE(creator_json,active_id) ON policy_source TO policy_accept_runtime;
GRANT UPDATE(policy_uid) ON policy_source TO policy_read_runtime;
GRANT SELECT ON fleet_trust,permission_basis,permission_assignment,authority_audit TO policy_accept_runtime,policy_read_runtime;
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
GRANT SELECT ON goose_db_version,fleet_trust,permission_stream,authority_audit,context_catalog,context_capture,context_verification,custody_attempt,artifact_download,download_batch,download_key_binding,retention_source,retention_checkpoint,retention_catchup,retention_catchup_effect,retention_decision TO download_key_bind_runtime,download_key_read_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO download_key_bind_runtime,download_key_read_runtime;
GRANT UPDATE(id) ON permission_stream,artifact_download TO download_key_bind_runtime,download_key_read_runtime;
GRANT UPDATE(root_id) ON retention_source TO download_key_bind_runtime,download_key_read_runtime;
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
GRANT SELECT ON fleet_trust,permission_stream,authority_audit,context_catalog,context_capture,context_verification,custody_attempt,artifact_download,download_batch,retention_source,retention_checkpoint,retention_catchup,retention_catchup_effect,retention_decision TO download_worker_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO download_worker_runtime;
GRANT UPDATE(id) ON permission_stream,artifact_download TO download_worker_runtime;
GRANT UPDATE(root_id) ON retention_source TO download_worker_runtime;
GRANT INSERT(id,session_id,root_id,installation_id,allocation_id,principal_key,generation,intent_json,run_until) ON download_worker TO download_worker_runtime;
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
GRANT UPDATE(generation,observed_at,fresh_until) ON download_worker_configuration TO worker_configuration_runtime;
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
GRANT SELECT ON fleet_trust,permission_stream,authority_audit,context_catalog,context_capture,context_verification,custody_attempt,artifact_download,download_batch,retention_source,retention_checkpoint,retention_catchup,retention_catchup_effect,retention_decision,download_worker_configuration,download_worker_configuration_revision TO worker_enrollment_runtime,worker_enrollment_activate_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO worker_enrollment_runtime,worker_enrollment_activate_runtime;
GRANT UPDATE(id) ON permission_stream,artifact_download TO worker_enrollment_runtime,worker_enrollment_activate_runtime;
GRANT UPDATE(root_id) ON retention_source TO worker_enrollment_runtime,worker_enrollment_activate_runtime;
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
GRANT SELECT ON fleet_trust,permission_stream,authority_audit,context_catalog,context_capture,context_verification,custody_attempt,download_batch,retention_source,retention_checkpoint,retention_catchup,retention_catchup_effect,retention_decision,download_worker_configuration,download_worker_configuration_revision TO worker_owner_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO worker_owner_runtime;
GRANT UPDATE(id) ON permission_stream,artifact_download,download_worker TO worker_owner_runtime;
GRANT UPDATE(root_id) ON retention_source TO worker_owner_runtime;
GRANT UPDATE(source_uid) ON download_worker_configuration TO worker_owner_runtime;
GRANT INSERT ON download_worker_owner TO worker_owner_runtime;
GRANT UPDATE(request_id,pod_uid,process_epoch,fence,started_at,expires_at,released_at) ON download_worker_owner TO worker_owner_runtime;
-- Hub owner source acceptance, encrypted audit acknowledgement and consumers
-- are separate principals. Dummy UPDATE grants permit PostgreSQL row locks;
-- immutable-identity triggers prevent them from changing those identities.
CREATE ROLE owner_configuration_runtime LOGIN PASSWORD 'synthetic-owner-configuration';
CREATE ROLE owner_configuration_audit_runtime LOGIN PASSWORD 'synthetic-owner-configuration-audit';
CREATE ROLE owner_configuration_read_runtime LOGIN PASSWORD 'synthetic-owner-configuration-read';
GRANT CONNECT ON DATABASE custody_test TO owner_configuration_runtime,owner_configuration_audit_runtime,owner_configuration_read_runtime;
GRANT USAGE ON SCHEMA public TO owner_configuration_runtime,owner_configuration_audit_runtime,owner_configuration_read_runtime;
GRANT SELECT ON goose_db_version,fleet_trust,hub_owner_configuration,hub_owner_configuration_revision TO owner_configuration_runtime,owner_configuration_audit_runtime,owner_configuration_read_runtime;
GRANT UPDATE(installation_id) ON fleet_trust TO owner_configuration_runtime,owner_configuration_read_runtime;
GRANT INSERT ON hub_owner_configuration TO owner_configuration_runtime;
GRANT INSERT(installation_id,cluster_id,source_uid,generation,snapshot_json) ON hub_owner_configuration_revision TO owner_configuration_runtime;
GRANT UPDATE(generation,observed_at,fresh_until) ON hub_owner_configuration TO owner_configuration_runtime;
GRANT UPDATE(source_uid) ON hub_owner_configuration TO owner_configuration_runtime,owner_configuration_audit_runtime,owner_configuration_read_runtime;
GRANT UPDATE(audit_receipt_json) ON hub_owner_configuration_revision TO owner_configuration_audit_runtime;

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
GRANT UPDATE(installation_id) ON fleet_current_trust TO fleet_observe_runtime;
GRANT SELECT ON fleet_current_trust TO bootstrap_activate_runtime,bootstrap_audit_runtime,bootstrap_record_runtime,bootstrap_reserve_runtime,capture_runtime,context_publish_runtime,context_verify_runtime,download_key_bind_runtime,download_key_read_runtime,download_runtime,download_worker_identity_runtime,download_worker_runtime,enrollment_activate_runtime,enrollment_audit_runtime,enrollment_claim_runtime,enrollment_sign_runtime,fleet_observe_runtime,local_keys_runtime,owner_configuration_audit_runtime,owner_configuration_read_runtime,owner_configuration_runtime,owner_enrollment_activate_runtime,owner_enrollment_read_runtime,owner_enrollment_runtime,peer_read_runtime,policy_accept_runtime,policy_read_runtime,worker_configuration_audit_runtime,worker_configuration_read_runtime,worker_configuration_runtime,worker_enrollment_activate_runtime,worker_enrollment_runtime,worker_owner_runtime,worker_routing_read_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO bootstrap_activate_runtime,bootstrap_audit_runtime,bootstrap_record_runtime,bootstrap_reserve_runtime,capture_runtime,context_publish_runtime,context_verify_runtime,download_key_bind_runtime,download_key_read_runtime,download_runtime,download_worker_identity_runtime,download_worker_runtime,enrollment_activate_runtime,enrollment_audit_runtime,enrollment_claim_runtime,enrollment_sign_runtime,local_keys_runtime,owner_configuration_read_runtime,owner_configuration_runtime,owner_enrollment_activate_runtime,owner_enrollment_read_runtime,owner_enrollment_runtime,policy_accept_runtime,policy_read_runtime,worker_configuration_read_runtime,worker_configuration_runtime,worker_enrollment_activate_runtime,worker_enrollment_runtime,worker_owner_runtime,worker_routing_read_runtime;

-- Private passive previews: no evidence, admission, audit or key authority.
CREATE ROLE context_preview_runtime LOGIN PASSWORD 'synthetic-context-preview';
CREATE ROLE context_preview_cleanup_runtime LOGIN PASSWORD 'synthetic-context-preview-cleanup';
GRANT CONNECT ON DATABASE custody_test TO context_preview_runtime,context_preview_cleanup_runtime;
GRANT USAGE ON SCHEMA public TO context_preview_runtime,context_preview_cleanup_runtime;
GRANT SELECT ON goose_db_version,permission_stream,context_preview TO context_preview_runtime,context_preview_cleanup_runtime;
GRANT UPDATE(id) ON permission_stream TO context_preview_runtime,context_preview_cleanup_runtime;
GRANT INSERT ON context_preview TO context_preview_runtime;
GRANT DELETE ON context_preview TO context_preview_runtime,context_preview_cleanup_runtime;

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
GRANT SELECT ON fleet_current_trust,permission_basis,permission_assignment,authority_audit,custody_attempt,context_verification TO context_progress_read_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO context_progress_read_runtime;
GRANT UPDATE(deadline_observed_at) ON context_capture TO context_deadline_runtime;

-- The regional API execution roles share no installer, hub-owner, acquisition-
-- unwrap or publication authority. Preparation cannot commit a local start;
-- execution cannot insert/replace the prepared execution/process identity.
CREATE ROLE api_execution_read_runtime LOGIN PASSWORD 'synthetic-api-execution-read';
CREATE ROLE api_execution_prepare_runtime LOGIN PASSWORD 'synthetic-api-execution-prepare';
CREATE ROLE api_execution_runtime LOGIN PASSWORD 'synthetic-api-execution';
CREATE ROLE api_publication_gate_runtime LOGIN PASSWORD 'synthetic-api-publication-gate';
GRANT CONNECT ON DATABASE custody_test TO api_execution_read_runtime,api_execution_prepare_runtime,api_execution_runtime,api_publication_gate_runtime;
GRANT USAGE ON SCHEMA public TO api_execution_read_runtime,api_execution_prepare_runtime,api_execution_runtime,api_publication_gate_runtime;
GRANT SELECT ON goose_db_version,fleet_current_trust,permission_stream,permission_basis,permission_assignment,authority_audit,context_capture,context_execution,custody_pool,custody_allocation,custody_attempt,retention_source,retention_checkpoint,retention_catchup,retention_catchup_effect,retention_decision TO api_execution_read_runtime,api_execution_prepare_runtime,api_execution_runtime,api_publication_gate_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO api_execution_read_runtime,api_execution_prepare_runtime,api_execution_runtime,api_publication_gate_runtime;
GRANT UPDATE(id) ON permission_stream TO api_execution_read_runtime,api_execution_prepare_runtime,api_execution_runtime,api_publication_gate_runtime;
GRANT UPDATE(root_id) ON retention_source TO api_execution_prepare_runtime,api_execution_runtime,api_publication_gate_runtime;
GRANT UPDATE(id) ON context_capture,custody_pool,custody_allocation,custody_attempt TO api_execution_prepare_runtime,api_execution_runtime;
GRANT UPDATE(capture_id) ON context_execution TO api_execution_prepare_runtime,api_execution_runtime;
GRANT INSERT(root_id,capture_id,attempt_id,binding_json,process_json,expectation_digest,not_before,not_after) ON context_execution TO api_execution_prepare_runtime;
GRANT UPDATE(object_uid) ON context_execution TO api_execution_prepare_runtime;
GRANT UPDATE(phase,started_at,acquired_at,completed_at,copies_json,copies_digest) ON context_execution TO api_execution_runtime;
GRANT SELECT ON context_execution TO context_verify_runtime,context_verification_audit_runtime,context_publish_runtime,context_progress_read_runtime;

-- Resolve-or-close is a passive request facet: no accepted capture/custody writes.
CREATE ROLE context_request_resolution_runtime LOGIN PASSWORD 'synthetic-context-request-resolution';
GRANT CONNECT ON DATABASE custody_test TO context_request_resolution_runtime;
GRANT USAGE ON SCHEMA public TO context_request_resolution_runtime;
GRANT SELECT ON goose_db_version,permission_stream,permission_basis,permission_assignment,authority_audit,fleet_current_trust,context_capture,context_preview,context_preview_fence TO context_request_resolution_runtime;
GRANT UPDATE(id) ON permission_stream TO context_request_resolution_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO context_request_resolution_runtime;
GRANT UPDATE(closed_at,closed_request_key,closed_submission_digest) ON context_preview TO context_request_resolution_runtime;
GRANT INSERT,DELETE ON context_preview_fence TO context_request_resolution_runtime;
GRANT DELETE ON context_preview TO context_request_resolution_runtime;
GRANT SELECT ON context_preview,context_preview_fence TO capture_runtime;
GRANT SELECT,DELETE ON context_preview_fence TO context_preview_runtime,context_preview_cleanup_runtime;

-- Migration37: separate protected control backing from immutable capture spend.
CREATE ROLE context_control_config_runtime LOGIN PASSWORD 'synthetic-context-control-config';
GRANT CONNECT ON DATABASE custody_test TO context_control_config_runtime;
GRANT USAGE ON SCHEMA public TO context_control_config_runtime;
GRANT SELECT ON goose_db_version,permission_stream,context_storage_binding,custody_pool,custody_allocation,context_control_pool,context_control_account TO context_control_config_runtime;
GRANT UPDATE(id) ON permission_stream,custody_pool,custody_allocation TO context_control_config_runtime;
GRANT UPDATE(source_uid) ON context_storage_binding TO context_control_config_runtime;
GRANT INSERT ON context_control_pool,context_control_account TO context_control_config_runtime;
GRANT UPDATE(root_id,configured,paused,revision,valid_until,full_limit,replay_limit) ON context_control_pool,context_control_account TO context_control_config_runtime;
GRANT SELECT ON context_control_pool,context_control_account,context_control_charge TO capture_runtime;
GRANT UPDATE(root_id) ON context_control_pool,context_control_account TO capture_runtime;
GRANT INSERT ON context_control_charge TO capture_runtime;
CREATE ROLE context_retirement_read_runtime LOGIN PASSWORD 'synthetic-context-retirement-read';
GRANT CONNECT ON DATABASE custody_test TO context_retirement_read_runtime;
GRANT USAGE ON SCHEMA public TO context_retirement_read_runtime;
GRANT SELECT ON goose_db_version,context_capture,custody_attempt,custody_copy,context_verification,context_execution,artifact_download,retention_decision,retention_checkpoint,retention_catchup TO context_retirement_read_runtime;

GRANT SELECT ON context_control_pool,context_control_account TO context_storage_read_runtime;

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
GRANT SELECT(artifact_id,capture_id,root_id) ON context_catalog TO context_case_read_runtime;
GRANT SELECT(id,root_id,attempt_id) ON context_capture TO context_case_read_runtime;
GRANT SELECT(capture_id,root_id,audit_acknowledged_at,copies_digest) ON context_verification TO context_case_read_runtime;
GRANT SELECT(id,artifact_id,state,copies_digest,effective_expires_at) ON custody_attempt TO context_case_read_runtime;

-- Positive writer completion is separate from deletion/audit/finalization.
GRANT INSERT(writer_protocol) ON context_execution TO api_execution_prepare_runtime;
GRANT SELECT,INSERT ON context_writer_completion TO api_execution_runtime;
GRANT SELECT(installation_id,activated_postmaster_at,activated_database_oid) ON fleet_trust TO api_execution_runtime;
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
CREATE ROLE operation_audit_config_runtime LOGIN PASSWORD 'synthetic-operation-config';
CREATE ROLE operation_audit_runtime LOGIN PASSWORD 'synthetic-operation-journal';
CREATE ROLE operation_audit_ack_runtime LOGIN PASSWORD 'synthetic-operation-ack';
GRANT CONNECT ON DATABASE custody_test TO operation_audit_config_runtime,operation_audit_runtime,operation_audit_ack_runtime;
GRANT USAGE ON SCHEMA public TO operation_audit_config_runtime,operation_audit_runtime,operation_audit_ack_runtime;
GRANT SELECT ON goose_db_version,operation_audit_pool TO operation_audit_config_runtime,operation_audit_runtime,operation_audit_ack_runtime;
GRANT SELECT ON operation_audit_account TO operation_audit_config_runtime;
GRANT SELECT ON permission_stream TO operation_audit_config_runtime;
GRANT UPDATE(id) ON permission_stream TO operation_audit_config_runtime;
GRANT INSERT ON operation_audit_pool TO operation_audit_config_runtime;
GRANT UPDATE(root_id,revision,paused,valid_until,account_limit,records_per_account,retained_seconds) ON operation_audit_pool TO operation_audit_config_runtime;
GRANT SELECT ON operation_audit,operation_audit_account,fleet_current_trust TO operation_audit_runtime,operation_audit_ack_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO operation_audit_runtime,operation_audit_ack_runtime;
GRANT UPDATE(root_id) ON operation_audit_pool TO operation_audit_runtime;
GRANT INSERT ON operation_audit TO operation_audit_runtime;
GRANT UPDATE(id,intent_started,outcome,outcome_started) ON operation_audit TO operation_audit_runtime;
GRANT UPDATE(id,intent_receipt,outcome_receipt) ON operation_audit TO operation_audit_ack_runtime;

-- Positive audit completion and terminal retirement are separate capabilities.
CREATE ROLE operation_audit_cleanup_runtime LOGIN PASSWORD 'synthetic-operation-cleanup';
CREATE ROLE operation_audit_retire_runtime LOGIN PASSWORD 'synthetic-operation-retire';
GRANT CONNECT ON DATABASE custody_test TO operation_audit_cleanup_runtime,operation_audit_retire_runtime;
GRANT USAGE ON SCHEMA public TO operation_audit_cleanup_runtime,operation_audit_retire_runtime;
GRANT SELECT ON goose_db_version,operation_audit_pool,operation_audit_account,operation_audit,operation_audit_lifecycle,fleet_current_trust TO operation_audit_cleanup_runtime,operation_audit_retire_runtime;
GRANT SELECT ON operation_audit_lifecycle TO operation_audit_runtime,operation_audit_ack_runtime;
GRANT SELECT(installation_id,activated_postmaster_at,activated_database_oid) ON fleet_trust TO operation_audit_runtime,operation_audit_ack_runtime,operation_audit_cleanup_runtime,operation_audit_retire_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO operation_audit_cleanup_runtime,operation_audit_retire_runtime;
GRANT UPDATE(root_id) ON operation_audit_pool TO operation_audit_ack_runtime,operation_audit_cleanup_runtime,operation_audit_retire_runtime;
GRANT UPDATE(root_id) ON operation_audit_account TO operation_audit_runtime,operation_audit_ack_runtime,operation_audit_cleanup_runtime,operation_audit_retire_runtime;
GRANT UPDATE(id) ON operation_audit TO operation_audit_cleanup_runtime,operation_audit_retire_runtime;
GRANT UPDATE(operation_id) ON operation_audit_lifecycle TO operation_audit_runtime,operation_audit_ack_runtime,operation_audit_cleanup_runtime,operation_audit_retire_runtime;
GRANT UPDATE(intent_completion,outcome_completion) ON operation_audit_lifecycle TO operation_audit_runtime;
GRANT UPDATE(lease_fence,lease,retirement,certificate_started,certificate_completion,terminal_purge) ON operation_audit_lifecycle TO operation_audit_cleanup_runtime;
GRANT UPDATE(certificate_receipt,certificate_acknowledged_at,terminal_acknowledged_at) ON operation_audit_lifecycle TO operation_audit_ack_runtime;
GRANT EXECUTE ON FUNCTION finish_operation_audit_retirement(uuid,uuid,uuid) TO operation_audit_retire_runtime;

GRANT SELECT ON operation_audit_history TO operation_audit_runtime,operation_audit_cleanup_runtime,operation_audit_ack_runtime,operation_audit_retire_runtime;
GRANT EXECUTE ON FUNCTION finish_operation_audit_history(uuid,text,bytea,timestamptz,timestamptz,uuid) TO operation_audit_retire_runtime;

-- Overdue cleanup can fence certificate creation and record a result only.
GRANT UPDATE(overdue_selected_at,overdue_purge) ON operation_audit_lifecycle TO operation_audit_cleanup_runtime;
-- No runtime role can reset or directly increment proof_window_missed.

-- Prepaid native stop: fixture identities represent independently wired roles.
-- The public stop writer has no ordinary catalog/native metadata permission.
GRANT SELECT ON download_stop_pool,download_stop_backing TO download_config_runtime;
GRANT INSERT ON download_stop_pool,download_stop_backing TO download_config_runtime;
GRANT UPDATE(revision,valid_until) ON download_stop_pool TO download_config_runtime;
GRANT INSERT(stop_protocol) ON artifact_download TO download_runtime;
CREATE ROLE download_stop_runtime LOGIN PASSWORD 'synthetic-download-stop';
CREATE ROLE download_stop_writer_runtime LOGIN PASSWORD 'synthetic-download-stop-writer';
CREATE ROLE download_stop_ack_runtime LOGIN PASSWORD 'synthetic-download-stop-ack';
GRANT CONNECT ON DATABASE custody_test TO download_stop_runtime,download_stop_writer_runtime,download_stop_ack_runtime;
GRANT USAGE ON SCHEMA public TO download_stop_runtime,download_stop_writer_runtime,download_stop_ack_runtime;
GRANT SELECT ON goose_db_version,download_stop TO download_stop_runtime,download_stop_writer_runtime,download_stop_ack_runtime;
GRANT SELECT ON artifact_download TO download_stop_runtime;
GRANT UPDATE(id,state) ON artifact_download TO download_stop_runtime;
GRANT UPDATE(download_id,key_digest,request_id,requested_at,write_until,decision) ON download_stop TO download_stop_runtime;
GRANT UPDATE(download_id,write_started,lookup_attempts) ON download_stop TO download_stop_writer_runtime;
GRANT UPDATE(download_id,receipt) ON download_stop TO download_stop_ack_runtime;

GRANT SELECT ON fleet_current_trust TO download_stop_writer_runtime,download_stop_ack_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO download_stop_writer_runtime,download_stop_ack_runtime;

-- Stop lifecycle uses independent producer, cleanup, verification and retirement
-- facets. Immutable-column UPDATE only permits the necessary row locks.
CREATE ROLE download_stop_lifecycle_config_runtime LOGIN PASSWORD 'synthetic-stop-lifecycle-config';
CREATE ROLE download_stop_cleanup_runtime LOGIN PASSWORD 'synthetic-stop-cleanup';
CREATE ROLE download_stop_verify_runtime LOGIN PASSWORD 'synthetic-stop-verify';
CREATE ROLE download_stop_retire_runtime LOGIN PASSWORD 'synthetic-stop-retire';
GRANT CONNECT ON DATABASE custody_test TO download_stop_lifecycle_config_runtime,download_stop_cleanup_runtime,download_stop_verify_runtime,download_stop_retire_runtime;
GRANT USAGE ON SCHEMA public TO download_stop_lifecycle_config_runtime,download_stop_cleanup_runtime,download_stop_verify_runtime,download_stop_retire_runtime;
GRANT SELECT ON goose_db_version,fleet_current_trust,download_stop_pool,download_stop_backing,download_stop,download_stop_lifecycle,download_stop_history TO download_stop_writer_runtime,download_stop_lifecycle_config_runtime,download_stop_cleanup_runtime,download_stop_verify_runtime,download_stop_retire_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO download_stop_lifecycle_config_runtime,download_stop_cleanup_runtime,download_stop_verify_runtime,download_stop_retire_runtime;
GRANT UPDATE(root_id) ON download_stop_pool TO download_stop_writer_runtime,download_stop_lifecycle_config_runtime,download_stop_cleanup_runtime,download_stop_verify_runtime,download_stop_retire_runtime;
GRANT UPDATE(allocation_id) ON download_stop_backing TO download_stop_writer_runtime,download_stop_cleanup_runtime,download_stop_verify_runtime,download_stop_retire_runtime;
GRANT UPDATE(download_id) ON download_stop TO download_stop_cleanup_runtime,download_stop_verify_runtime,download_stop_retire_runtime;
GRANT UPDATE(download_id) ON download_stop_lifecycle TO download_stop_writer_runtime,download_stop_cleanup_runtime,download_stop_verify_runtime,download_stop_retire_runtime;
GRANT UPDATE(lifecycle_policy) ON download_stop_pool TO download_stop_lifecycle_config_runtime;
GRANT UPDATE(original_completion) ON download_stop_lifecycle TO download_stop_writer_runtime;
GRANT UPDATE(closed_at,mode,overdue_selected_at,lease,lease_fence,retirement,certificate_started,certificate_completion,terminal_purge) ON download_stop_lifecycle TO download_stop_cleanup_runtime;
-- Cleanup can only clear a terminal acknowledgement while advancing an exact
-- finite lease; the guard forbids it from installing an acknowledgement.
GRANT UPDATE(certificate_verify_attempts,certificate_receipt,certificate_acknowledged_at,terminal_acknowledged_at) ON download_stop_lifecycle TO download_stop_verify_runtime;
GRANT EXECUTE ON FUNCTION finish_download_stop_retirement(uuid,uuid,uuid),finish_download_stop_history(uuid,uuid,bytea,timestamptz,timestamptz,uuid) TO download_stop_retire_runtime;

-- Independently credentialed pre-provider verification spend. Neither the
-- producer nor cleanup may acquire, reset or erase these attempts.
GRANT UPDATE(certificate_verify_attempts) ON operation_audit_lifecycle TO operation_audit_ack_runtime;

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
GRANT UPDATE(backing,release_policy,backing_revision,valid_until,retire_by,max_captures,max_rules,max_root_transitions,root_transitions,sequence) ON processing_root TO processing_config_runtime;
GRANT UPDATE(root_id) ON processing_root TO processing_decision_runtime;
GRANT SELECT ON context_processing,processing_rule,processing_decision,context_catalog,operation_audit TO processing_decision_runtime;
GRANT INSERT ON processing_rule,processing_decision TO processing_decision_runtime;
GRANT UPDATE(id) ON processing_rule TO processing_decision_runtime;
GRANT UPDATE(id,applied_at,audit_digest) ON processing_decision TO processing_decision_runtime;
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
CREATE ROLE capture_operation_source_runtime LOGIN NOINHERIT PASSWORD 'synthetic-capture-operation-source';
CREATE ROLE capture_operation_admit_runtime LOGIN NOINHERIT PASSWORD 'synthetic-capture-operation-admit';
CREATE ROLE capture_operation_journal_runtime LOGIN NOINHERIT PASSWORD 'synthetic-capture-operation-journal';
CREATE ROLE capture_operation_ack_runtime LOGIN NOINHERIT PASSWORD 'synthetic-capture-operation-ack';
CREATE ROLE capture_operation_cleanup_runtime LOGIN NOINHERIT PASSWORD 'synthetic-capture-operation-cleanup';
CREATE ROLE capture_operation_verify_runtime LOGIN NOINHERIT PASSWORD 'synthetic-capture-operation-verify';
CREATE ROLE capture_operation_retire_runtime LOGIN NOINHERIT PASSWORD 'synthetic-capture-operation-retire';
CREATE ROLE capture_operation_read_runtime LOGIN NOINHERIT PASSWORD 'synthetic-capture-operation-read';
GRANT CONNECT ON DATABASE custody_test TO capture_operation_source_runtime,capture_operation_admit_runtime,capture_operation_journal_runtime,capture_operation_ack_runtime,capture_operation_cleanup_runtime,capture_operation_verify_runtime,capture_operation_retire_runtime,capture_operation_read_runtime;
GRANT USAGE ON SCHEMA public TO capture_operation_source_runtime,capture_operation_admit_runtime,capture_operation_journal_runtime,capture_operation_ack_runtime,capture_operation_cleanup_runtime,capture_operation_verify_runtime,capture_operation_retire_runtime,capture_operation_read_runtime;
GRANT SELECT ON goose_db_version TO capture_operation_source_runtime,capture_operation_admit_runtime,capture_operation_journal_runtime,capture_operation_ack_runtime,capture_operation_cleanup_runtime,capture_operation_verify_runtime,capture_operation_retire_runtime,capture_operation_read_runtime;
GRANT EXECUTE ON FUNCTION configure_capture_audit_backing(uuid,jsonb,jsonb,timestamptz,timestamptz) TO capture_operation_source_runtime;
GRANT EXECUTE ON FUNCTION lock_capture_audit_admission(uuid,uuid),reserve_capture_audit(uuid,uuid,jsonb,bytea,timestamptz),capacity_managed_admission_until(uuid,uuid,text,timestamptz) TO capture_operation_admit_runtime;
GRANT EXECUTE ON FUNCTION read_capture_operation(uuid,uuid),capture_audit_journal(uuid,jsonb,text,jsonb),claim_capture_reconciliation(uuid,jsonb,text) TO capture_operation_journal_runtime;
GRANT EXECUTE ON FUNCTION capture_audit_acknowledge(uuid,jsonb,text,jsonb,jsonb,jsonb),acknowledge_capture_pair(uuid,jsonb) TO capture_operation_ack_runtime;
-- Admission retains the existing exact authority/custody/control transaction,
-- without inheriting another role or gaining audit/provider acknowledgement.
GRANT SELECT ON permission_stream,permission_basis,permission_assignment,authority_audit,context_storage_binding,context_preview,context_preview_fence,context_control_pool,context_control_account,context_control_charge TO capture_operation_admit_runtime;
GRANT UPDATE(id) ON permission_stream TO capture_operation_admit_runtime;
-- Match the existing admission lock-only column grant; no allocation/freshness writes.
GRANT UPDATE(source_uid) ON context_storage_binding TO capture_operation_admit_runtime;
GRANT SELECT,INSERT ON context_capture TO capture_operation_admit_runtime;
GRANT SELECT,INSERT,UPDATE ON custody_pool,custody_allocation,custody_copy,custody_event TO capture_operation_admit_runtime;
GRANT SELECT,INSERT ON custody_attempt TO capture_operation_admit_runtime;
GRANT UPDATE(id,state,copies_digest,deletion_fence,lease_until,deleted_at) ON custody_attempt TO capture_operation_admit_runtime;
GRANT SELECT ON retention_source,retention_checkpoint,retention_catchup,retention_catchup_effect,retention_decision TO capture_operation_admit_runtime;
GRANT UPDATE(root_id) ON retention_source,context_control_pool,context_control_account TO capture_operation_admit_runtime;
GRANT INSERT ON context_control_charge TO capture_operation_admit_runtime;
GRANT SELECT ON fleet_trust,fleet_current_trust TO capture_operation_admit_runtime;
GRANT UPDATE(installation_id) ON fleet_trust,fleet_current_trust TO capture_operation_admit_runtime;
-- Fixed filtered cleanup views; no SELECT or UPDATE on human/other lanes.
GRANT EXECUTE ON FUNCTION capture_audit_role_ok(uuid,text) TO capture_operation_cleanup_runtime,capture_operation_verify_runtime,capture_operation_retire_runtime;
GRANT SELECT ON capture_operation_pool,capture_operation_account,capture_operation_audit,capture_operation_lifecycle,capture_operation_history,fleet_current_trust TO capture_operation_cleanup_runtime,capture_operation_verify_runtime,capture_operation_retire_runtime;
GRANT SELECT(installation_id,activated_postmaster_at,activated_database_oid) ON fleet_trust TO capture_operation_cleanup_runtime,capture_operation_verify_runtime,capture_operation_retire_runtime;
GRANT UPDATE(installation_id) ON fleet_current_trust TO capture_operation_cleanup_runtime,capture_operation_verify_runtime,capture_operation_retire_runtime;
GRANT UPDATE(root_id) ON capture_operation_pool,capture_operation_account TO capture_operation_cleanup_runtime,capture_operation_verify_runtime,capture_operation_retire_runtime;
GRANT UPDATE(id) ON capture_operation_audit TO capture_operation_cleanup_runtime,capture_operation_verify_runtime,capture_operation_retire_runtime;
GRANT UPDATE(operation_id) ON capture_operation_lifecycle TO capture_operation_cleanup_runtime,capture_operation_verify_runtime,capture_operation_retire_runtime;
GRANT UPDATE(lease_fence,lease,retirement,certificate_started,certificate_completion,terminal_purge,overdue_selected_at,overdue_purge) ON capture_operation_lifecycle TO capture_operation_cleanup_runtime;
GRANT UPDATE(certificate_verify_attempts,certificate_receipt,certificate_acknowledged_at,terminal_acknowledged_at) ON capture_operation_lifecycle TO capture_operation_verify_runtime;
GRANT EXECUTE ON FUNCTION finish_capture_operation_retirement(uuid,uuid,uuid),finish_capture_operation_history(uuid,text,bytea,timestamptz,timestamptz,uuid) TO capture_operation_retire_runtime;

-- Passive retained acknowledgement: no base-table read or write privilege.
GRANT EXECUTE ON FUNCTION capture_audit_role_ok(uuid,text) TO capture_operation_read_runtime;
GRANT SELECT ON capture_operation_intents TO capture_operation_read_runtime;
CREATE ROLE cluster_credential_runtime LOGIN PASSWORD 'synthetic-cluster-credential'; GRANT CONNECT ON DATABASE custody_test TO cluster_credential_runtime; GRANT USAGE ON SCHEMA public TO cluster_credential_runtime; GRANT SELECT ON goose_db_version TO cluster_credential_runtime; GRANT SELECT(root_id,peer_id,installation_id,cluster_id) ON connector_identity_profile TO cluster_credential_runtime; GRANT SELECT,UPDATE ON cluster_enrollment_lineage,cluster_enrollment_credential TO cluster_credential_runtime; GRANT INSERT ON cluster_enrollment_credential TO cluster_credential_runtime; GRANT EXECUTE ON FUNCTION reserve_cluster_bootstrap(uuid,uuid,uuid,bytea,uuid,bigint,bytea,bigint,bigint),acknowledge_cluster_bootstrap(uuid,uuid,text,text,text,bigint,bytea),activate_cluster_bootstrap(uuid,uuid,bytea,bytea) TO cluster_credential_runtime;

-- ADR-206 SQL component fixture only. These are not installed runtime grants.
-- Protected backing and C-14 worker/key bindings are seeded by the owned fixture
-- administrator; query admission cannot provision or replace any of them.
CREATE ROLE context_query_runtime LOGIN NOINHERIT PASSWORD 'synthetic-context-query';
GRANT CONNECT ON DATABASE custody_test TO context_query_runtime;
GRANT USAGE ON SCHEMA public TO context_query_runtime;
GRANT SELECT ON goose_db_version,fleet_trust,fleet_current_trust,permission_stream,authority_audit,
 retention_source,retention_source_epoch,retention_checkpoint,retention_catchup,retention_catchup_effect,retention_decision,
 context_catalog,context_capture,context_verification,custody_attempt,context_case_locator,
 processing_root,context_processing,processing_rule,operation_audit,operation_audit_lifecycle,
 context_query_backing,context_query_allocation,context_query_principal,context_query,context_query_call,context_query_worker,context_query_batch
 TO context_query_runtime;
GRANT UPDATE(installation_id) ON fleet_trust,fleet_current_trust TO context_query_runtime;
GRANT UPDATE(id) ON permission_stream,operation_audit,context_query_allocation,context_query_principal,context_query TO context_query_runtime;
GRANT UPDATE(root_id) ON retention_source,context_query_backing TO context_query_runtime;
GRANT UPDATE(operation_id) ON operation_audit_lifecycle TO context_query_runtime;
GRANT INSERT ON context_query_principal,context_query,context_query_call,context_query_batch TO context_query_runtime;
GRANT UPDATE(claim_id,closed) ON context_query_batch TO context_query_runtime;
GRANT EXECUTE ON FUNCTION lock_context_query_capacity(uuid,uuid),context_query_capacity_allocation_current(uuid,uuid),context_query_shared_profile_current(uuid,jsonb) TO context_query_runtime;
CREATE ROLE context_query_key_fixture LOGIN NOINHERIT PASSWORD 'synthetic-context-query-key';
GRANT CONNECT ON DATABASE custody_test TO context_query_key_fixture;
GRANT USAGE ON SCHEMA public TO context_query_key_fixture;
GRANT SELECT ON context_query_key_binding TO context_query_key_fixture;
GRANT UPDATE(used_roles) ON context_query_key_binding TO context_query_key_fixture;
