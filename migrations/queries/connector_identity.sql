-- name: StageConnectorIdentity :one
SELECT stage_connector_identity(sqlc.arg(root_id)::uuid,sqlc.arg(configuration_value)::jsonb,sqlc.arg(qualification_value)::jsonb)::boolean;
-- name: FenceConnectorIdentity :exec
SELECT fence_connector_identity(sqlc.arg(root_id)::uuid,sqlc.arg(peer_id)::uuid,sqlc.arg(observed_at)::timestamptz);
-- name: ReadConnectorProcessAdmission :one
SELECT read_connector_process_admission(sqlc.arg(root_id)::uuid,sqlc.arg(operation_id)::uuid,sqlc.arg(current_value)::jsonb)::jsonb;
-- name: AdmitConnectorProcess :one
SELECT admit_connector_process(sqlc.arg(root_id)::uuid,sqlc.arg(current_value)::jsonb,sqlc.arg(intent_value)::jsonb,sqlc.arg(process_value)::jsonb)::jsonb;
-- name: StoreConnectorProcessOutcome :exec
SELECT store_connector_process_outcome(sqlc.arg(root_id)::uuid,sqlc.arg(operation_id)::uuid,sqlc.arg(intent_value)::jsonb,sqlc.arg(outcome_value)::jsonb);
-- name: AcceptConnectorProcess :one
SELECT accept_connector_process(sqlc.arg(root_id)::uuid,sqlc.arg(operation_id)::uuid,sqlc.arg(current_value)::jsonb)::jsonb;
-- name: ReadConnectorCredentialProcess :one
SELECT read_connector_credential_process(sqlc.arg(root_id)::uuid,sqlc.arg(candidate_value)::jsonb)::jsonb;
-- name: ReadConnectorCredentialAttempt :one
SELECT read_connector_credential_attempt(sqlc.arg(root_id)::uuid,sqlc.arg(operation_id)::uuid,sqlc.arg(candidate_value)::jsonb)::jsonb;
-- name: AdmitConnectorCredential :one
SELECT admit_connector_credential(sqlc.arg(root_id)::uuid,sqlc.arg(candidate_value)::jsonb,sqlc.arg(intent_value)::jsonb,sqlc.arg(permit_value)::jsonb)::jsonb;
-- name: ClaimConnectorCredential :one
SELECT claim_connector_credential(sqlc.arg(root_id)::uuid,sqlc.arg(operation_id)::uuid,sqlc.arg(candidate_value)::jsonb,sqlc.arg(permit_value)::jsonb)::boolean;
-- name: StoreConnectorCredential :exec
SELECT store_connector_credential(sqlc.arg(root_id)::uuid,sqlc.arg(operation_id)::uuid,sqlc.arg(permit_value)::jsonb,sqlc.arg(issued_value)::jsonb,sqlc.arg(outcome_value)::jsonb);
-- name: ActivateConnectorCredential :one
SELECT activate_connector_credential(sqlc.arg(root_id)::uuid,sqlc.arg(operation_id)::uuid,sqlc.arg(candidate_value)::jsonb,sqlc.arg(permit_value)::jsonb)::jsonb;
-- name: ConnectorAuditJournal :one
SELECT connector_audit_journal(sqlc.arg(root_id)::uuid,sqlc.arg(intent_value)::jsonb,sqlc.arg(verb)::text,sqlc.narg(outcome_value)::jsonb)::jsonb;
-- name: ConnectorAuditAcknowledge :one
SELECT connector_audit_acknowledge(sqlc.arg(root_id)::uuid,sqlc.arg(intent_value)::jsonb,sqlc.arg(phase)::text,sqlc.narg(completion_value)::jsonb,sqlc.narg(receipt_value)::jsonb)::jsonb;

-- name: ReadConnectorActivatedLeaf :one
SELECT read_connector_activated_leaf(sqlc.arg(root_id)::uuid,sqlc.arg(peer_id)::uuid,sqlc.arg(usage_value)::text,sqlc.arg(digest_value)::bytea,sqlc.arg(source_value)::jsonb)::jsonb;

-- name: ReadConnectorBackingCandidate :one
SELECT read_connector_backing_candidate(sqlc.arg(root_id)::uuid,sqlc.arg(current_value)::jsonb)::jsonb;
-- name: ReadConnectorBackingAdmission :one
SELECT read_connector_backing_admission(sqlc.arg(root_id)::uuid,sqlc.arg(operation_id)::uuid,sqlc.arg(current_value)::jsonb)::jsonb;
-- name: AdmitConnectorBacking :one
SELECT admit_connector_backing(sqlc.arg(root_id)::uuid,sqlc.arg(current_value)::jsonb,sqlc.arg(intent_value)::jsonb)::jsonb;
-- name: StoreConnectorBackingOutcome :exec
SELECT store_connector_backing_outcome(sqlc.arg(root_id)::uuid,sqlc.arg(operation_id)::uuid,sqlc.arg(intent_value)::jsonb,sqlc.arg(outcome_value)::jsonb);
-- name: PromoteConnectorBacking :one
SELECT promote_connector_backing(sqlc.arg(root_id)::uuid,sqlc.arg(operation_id)::uuid,sqlc.arg(current_value)::jsonb)::jsonb;

-- name: ReadConnectorProcessBacking :one
SELECT read_connector_process_backing(sqlc.arg(root_id)::uuid,sqlc.arg(current_value)::jsonb)::jsonb;
