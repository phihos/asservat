-- name: ReadProcessingRoot :one
SELECT * FROM processing_root WHERE root_id=$1;
-- name: LockProcessingRoot :one
SELECT * FROM processing_root WHERE root_id=$1 FOR UPDATE;
-- name: InsertProcessingRoot :exec
INSERT INTO processing_root(root_id,installation_id,issuer_epoch,epoch,source_uid,protection_digest,backing,release_policy,backing_revision,valid_until,retire_by,max_captures,max_rules,max_root_transitions)
VALUES($1,$2,$3,$4,$5,$6,$7,sqlc.arg(release_policy),1,$8,$9,$10,$11,$12);
-- name: UpdateProcessingBacking :execrows
UPDATE processing_root SET backing=$3,release_policy=sqlc.arg(release_policy),backing_revision=backing_revision+1,valid_until=$4,retire_by=$5,max_captures=$6,max_rules=$7,max_root_transitions=$8,root_transitions=root_transitions+1,sequence=sequence+1
WHERE root_id=$1 AND backing_revision=$2;
-- name: ReadProcessingNode :one
SELECT * FROM context_processing WHERE root_id=$1 AND artifact_id=$2;
-- name: ReadProcessingRules :many
SELECT * FROM processing_rule WHERE root_id=$1 AND state<>'reserved' ORDER BY id LIMIT 1025;
-- name: LockProcessingRule :one
SELECT * FROM processing_rule WHERE root_id=$1 AND id=$2 FOR UPDATE;
-- name: InsertProcessingRule :exec
INSERT INTO processing_rule(root_id,id,scope,release_account) VALUES($1,$2,$3,$4);
-- name: ReadProcessingDecision :one
SELECT * FROM processing_decision WHERE root_id=$1 AND id=$2 AND actor_digest=sha256(convert_to(sqlc.arg(actor)::jsonb::text,'UTF8'));
-- name: LockProcessingDecision :one
SELECT * FROM processing_decision WHERE root_id=$1 AND id=$2 AND actor_digest=sha256(convert_to(sqlc.arg(actor)::jsonb::text,'UTF8')) FOR UPDATE;
-- name: InsertProcessingDecision :one
INSERT INTO processing_decision(id,root_id,rule_id,expected_revision,release_account,actor_digest,request_digest,scope,action,intent_seed,decision_digest,created_at,request_until,outcome_json)
VALUES($1,$2,$3,$4,sqlc.narg(release_account),sha256(convert_to(sqlc.arg(actor)::jsonb::text,'UTF8')),$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *;
-- name: ApplyProcessingDecision :one
UPDATE processing_decision SET applied_at=clock_timestamp(),audit_digest=(SELECT sha256(convert_to(a.outcome_receipt::text,'UTF8')) FROM operation_audit a WHERE a.root_id=processing_decision.root_id AND a.id=processing_decision.id)
WHERE processing_decision.root_id=$1 AND processing_decision.id=$2 AND processing_decision.applied_at IS NULL RETURNING processing_decision.*;
-- name: ProcessingCatalogEmpty :one
SELECT NOT EXISTS(SELECT 1 FROM context_catalog WHERE root_id=$1) AS empty;
