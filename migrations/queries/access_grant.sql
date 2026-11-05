-- ADR-249 adHocCapture AccessGrants, exact child grants and pool spend.

-- name: ReadGrantByKey :one
SELECT * FROM access_grant WHERE root_id=$1 AND requester_issuer=$2 AND requester_subject=$3 AND idempotency_key=$4 AND kind='adHocCapture';

-- name: ReadGrantByCapture :one
SELECT parent.* FROM access_grant parent WHERE parent.root_id=$1 AND (parent.capture_id=$2 OR parent.capture_id=(SELECT c.group_id FROM context_capture c JOIN recording_save_group g ON g.id=c.group_id AND g.root_id=c.root_id AND g.group_kind='composition' WHERE c.root_id=$1 AND c.id=$2 AND g.child_ids[c.group_ordinal+1]=c.id)) ORDER BY CASE WHEN parent.capture_id=$2 THEN 0 ELSE 1 END LIMIT 1;

-- name: InsertGrant :one
-- The review window starts at the database clock; the caller never names it.
INSERT INTO access_grant(id,root_id,kind,preview_id,capture_id,cluster_id,namespace_uid,workload_uid,pod_uid,execution_digest,result_access_digest,review_digest,data_class,reasons,review,scope,
 requester_issuer,requester_subject,requester_client,lifetime_seconds,result_access,not_after,max_artifacts,max_bytes,max_operations,idempotency_key,request_digest,requested_at,review_until)
SELECT @id::uuid, @root_id::uuid, 'adHocCapture', @preview_id::uuid, @capture_id::uuid, @cluster_id::uuid, @namespace_uid::text, @workload_uid::text, @pod_uid::text,
 @execution_digest::bytea, sqlc.narg(result_access_digest)::bytea, @review_digest::bytea, @data_class::text, @reasons::jsonb, @review::bytea, @scope::bytea,
 @requester_issuer::text, @requester_subject::text, @requester_client::text, @lifetime_seconds::integer, sqlc.narg(result_access)::jsonb, sqlc.narg(not_after)::timestamptz,
 @max_artifacts::integer, @max_bytes::bigint, @max_operations::bigint, @idempotency_key::text, @request_digest::bytea, t.n, t.n+interval '1 hour'
FROM (SELECT clock_timestamp() AS n) t
RETURNING *;

-- name: ReadGrant :one
SELECT * FROM access_grant WHERE root_id=$1 AND id=$2;

-- name: ReadGrantForUpdate :one
SELECT * FROM access_grant WHERE root_id=$1 AND id=$2 FOR UPDATE;

-- name: DecideGrant :one
-- One decision by a distinct human while the request is reviewable. The
-- expiry starts at the decision, from the lifetime pinned at request time.
UPDATE access_grant g SET decision= @decision::text, approver_issuer= @approver_issuer::text, approver_subject= @approver_subject::text, approver_client= @approver_client::text,
 decision_reason= @decision_reason::text, decision_acr=sqlc.narg(decision_acr)::text, decision_auth_time=sqlc.narg(decision_auth_time)::timestamptz, decided_at=t.n, decision_key= @decision_key::text,
 expires_at=CASE WHEN @decision::text='approved' THEN CASE WHEN g.kind='policy' THEN g.policy_not_after ELSE LEAST(t.n+make_interval(secs => g.lifetime_seconds),COALESCE(g.not_after,'infinity'::timestamptz)) END END, revision=g.revision+1
FROM (SELECT clock_timestamp() AS n) t
WHERE t.n< @effect_until::timestamptz AND g.root_id= @root_id::uuid AND g.id= @id::uuid AND g.decision IS NULL AND g.revoked_at IS NULL AND g.review_until>t.n AND g.revision=1
 AND (g.kind<>'policy' OR g.policy_not_after>t.n) AND (g.kind<>'rawQuery' OR g.not_after>t.n)
 AND NOT (g.requester_issuer= @approver_issuer::text AND g.requester_subject= @approver_subject::text)
RETURNING g.*;

-- name: RevokeGrant :one
UPDATE access_grant SET revoked_at=clock_timestamp(), revoker_issuer= @revoker_issuer::text, revoker_subject= @revoker_subject::text, revoker_client= @revoker_client::text, revoke_key= @revoke_key::text, revision=revision+1
WHERE root_id= @root_id::uuid AND id= @id::uuid AND revoked_at IS NULL AND revision= @expected_revision::smallint RETURNING *;

-- name: ListPendingGrants :many
-- The approver inbox: reviewable requests newest first. Candidates only; the
-- service lists a row only while the caller is a current approver for it.
SELECT * FROM access_grant WHERE root_id=$1 AND decision IS NULL AND revoked_at IS NULL AND review_until>clock_timestamp()
 AND (kind<>'policy' OR policy_not_after>clock_timestamp()) AND (kind<>'rawQuery' OR not_after>clock_timestamp())
ORDER BY requested_at DESC, id LIMIT @row_limit;

-- name: ListRequestedGrants :many
SELECT * FROM access_grant WHERE root_id=sqlc.arg(root_id)::uuid AND requester_issuer=sqlc.arg(requester_issuer)::text AND requester_subject=sqlc.arg(requester_subject)::text
 AND requester_kind=sqlc.arg(requester_kind)::text
 AND (requester_kind='human' OR requester_client=sqlc.arg(requester_client)::text)
ORDER BY requested_at DESC, id LIMIT @row_limit;

-- name: ReadGrantChild :one
SELECT sqlc.embed(child),c.scope_digest AS source_scope_digest,(CASE WHEN rg.group_kind='composition' AND c.group_ordinal>=0 AND cardinality(rg.child_ids) BETWEEN 2 AND 16 AND rg.child_ids[c.group_ordinal+1]=c.id AND
 c.created_at=rg.accepted_at AND c.deadline<=rg.deadline AND sha256(c.scope_json)=c.scope_digest AND sha256(rg.scope_json)=rg.scope_digest AND
 convert_from(rg.scope_json,'UTF8')::jsonb->>'schemaVersion'='recorder-group/v1' AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->c.group_ordinal->>'captureID'=c.id::text AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->c.group_ordinal->>'scopeDigest'=encode(c.scope_digest,'hex') AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->c.group_ordinal->>'actionID'=convert_from(c.expectation_json,'UTF8')::jsonb->>'ActionID' AND
 convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,Location,ArtifactID}'=l.artifact_id::text AND
 convert_from(c.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ParentCaptureID}'=rg.id::text AND
 (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildIndex}')::integer=c.group_ordinal AND
 (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildCount}')::integer=cardinality(rg.child_ids) THEN jsonb_build_object('RootID',c.root_id,'ParentCaptureID',rg.id,'CaptureID',c.id,'ArtifactID',l.artifact_id,
 'ActionID',convert_from(c.expectation_json,'UTF8')::jsonb->>'ActionID',
 'ParentExecutionDigest',to_jsonb(ARRAY(SELECT get_byte(rg.scope_digest,byte_index) FROM generate_series(0,31) AS bytes(byte_index))),
 'ExecutionDigest',to_jsonb(ARRAY(SELECT get_byte(c.scope_digest,byte_index) FROM generate_series(0,31) AS bytes(byte_index))),
 'ArtifactDigest',to_jsonb(ARRAY(SELECT get_byte(l.version,byte_index) FROM generate_series(0,31) AS bytes(byte_index))),
 'ChildIndex',c.group_ordinal,'ChildCount',cardinality(rg.child_ids)) END)::jsonb AS group_association
FROM access_grant_child child
LEFT JOIN context_capture c ON c.root_id=child.root_id AND c.id=child.capture_id
LEFT JOIN context_case_locator l ON l.root_id=c.root_id AND l.capture_id=c.id AND l.artifact_id=child.artifact_id AND l.version=child.artifact_digest
LEFT JOIN recording_save_group rg ON rg.root_id=c.root_id AND rg.id=c.group_id
WHERE child.parent_id=$1 AND child.artifact_id=$2 AND child.client_id=$3;

-- name: ReadGrantChildByID :one
SELECT sqlc.embed(child),c.scope_digest AS source_scope_digest,(CASE WHEN rg.group_kind='composition' AND c.group_ordinal>=0 AND cardinality(rg.child_ids) BETWEEN 2 AND 16 AND rg.child_ids[c.group_ordinal+1]=c.id AND
 c.created_at=rg.accepted_at AND c.deadline<=rg.deadline AND sha256(c.scope_json)=c.scope_digest AND sha256(rg.scope_json)=rg.scope_digest AND
 convert_from(rg.scope_json,'UTF8')::jsonb->>'schemaVersion'='recorder-group/v1' AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->c.group_ordinal->>'captureID'=c.id::text AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->c.group_ordinal->>'scopeDigest'=encode(c.scope_digest,'hex') AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->c.group_ordinal->>'actionID'=convert_from(c.expectation_json,'UTF8')::jsonb->>'ActionID' AND
 convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,Location,ArtifactID}'=l.artifact_id::text AND
 convert_from(c.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ParentCaptureID}'=rg.id::text AND
 (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildIndex}')::integer=c.group_ordinal AND
 (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildCount}')::integer=cardinality(rg.child_ids) THEN jsonb_build_object('RootID',c.root_id,'ParentCaptureID',rg.id,'CaptureID',c.id,'ArtifactID',l.artifact_id,
 'ActionID',convert_from(c.expectation_json,'UTF8')::jsonb->>'ActionID',
 'ParentExecutionDigest',to_jsonb(ARRAY(SELECT get_byte(rg.scope_digest,byte_index) FROM generate_series(0,31) AS bytes(byte_index))),
 'ExecutionDigest',to_jsonb(ARRAY(SELECT get_byte(c.scope_digest,byte_index) FROM generate_series(0,31) AS bytes(byte_index))),
 'ArtifactDigest',to_jsonb(ARRAY(SELECT get_byte(l.version,byte_index) FROM generate_series(0,31) AS bytes(byte_index))),
 'ChildIndex',c.group_ordinal,'ChildCount',cardinality(rg.child_ids)) END)::jsonb AS group_association
FROM access_grant_child child
LEFT JOIN context_capture c ON c.root_id=child.root_id AND c.id=child.capture_id
LEFT JOIN context_case_locator l ON l.root_id=c.root_id AND l.capture_id=c.id AND l.artifact_id=child.artifact_id AND l.version=child.artifact_digest
LEFT JOIN recording_save_group rg ON rg.root_id=c.root_id AND rg.id=c.group_id
WHERE child.root_id=$1 AND child.id=$2;

-- name: GrantArtifactRegistered :one
SELECT EXISTS(SELECT 1 FROM access_grant_child WHERE parent_id=$1 AND artifact_id=$2);

-- name: ReadGrantOutputLocator :one
-- Only an existing published artifact of exactly this capture and target can
-- become a child target; an unknown future artifact never can.
SELECT artifact_id FROM context_case_locator WHERE root_id= @root_id::uuid AND artifact_id= @artifact_id::uuid AND capture_id= @capture_id::uuid
 AND cluster_id= @cluster_id::uuid AND namespace_uid= @namespace_uid::text AND workload_uid= @workload_uid::text AND pod_uid= @pod_uid::text;

-- name: ChargeGrantArtifact :one
UPDATE access_grant SET artifacts_spent=artifacts_spent+1
WHERE root_id=$1 AND id=$2 AND decision='approved' AND revoked_at IS NULL AND expires_at>clock_timestamp() AND artifacts_spent<max_artifacts RETURNING *;

-- name: InsertGrantChild :one
INSERT INTO access_grant_child(id,root_id,parent_id,capture_id,action_id,artifact_id,artifact_digest,client_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *;

-- name: ReadGrantUse :one
SELECT * FROM access_grant_use WHERE root_id=$1 AND id=$2;

-- name: ChargeGrantUse :one
-- Reserves before delivery against the shared pool of every child and
-- client; never refunded.
UPDATE access_grant SET bytes_spent=bytes_spent+ @bytes::bigint, operations_spent=operations_spent+ @operations::bigint
WHERE root_id= @root_id::uuid AND id= @id::uuid AND decision='approved' AND revoked_at IS NULL AND expires_at>clock_timestamp()
 AND @bytes::bigint<=max_bytes-bytes_spent AND @operations::bigint<=max_operations-operations_spent RETURNING *;

-- name: InsertGrantUse :one
INSERT INTO access_grant_use(id,root_id,parent_id,child_id,operation,bytes,operations) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *;

-- name: ReadRawQueryByKey :one
SELECT * FROM access_grant WHERE root_id=$1 AND requester_key=$2 AND request_operation='requestRawAccess' AND idempotency_key=$3 AND kind='rawQuery';

-- name: InsertRawQueryGrant :one
INSERT INTO access_grant(id,root_id,kind,execution_digest,review_digest,data_class,reasons,review,scope,
 requester_issuer,requester_subject,requester_client,requester_kind,requester_key,request_operation,lifetime_seconds,raw_query,not_after,max_artifacts,max_bytes,max_operations,idempotency_key,request_digest,requested_at,review_until)
SELECT @id::uuid,@root_id::uuid,'rawQuery',@execution_digest::bytea,@review_digest::bytea,'raw',@reasons::jsonb,@review::bytea,@scope::bytea,
 @requester_issuer::text,@requester_subject::text,@requester_client::text,'human',@requester_key::bytea,'requestRawAccess',@lifetime_seconds::integer,@raw_query::jsonb,@not_after::timestamptz,
 @max_artifacts::integer,@max_bytes::bigint,@max_operations::bigint,@idempotency_key::text,@request_digest::bytea,t.n,LEAST(t.n+interval '1 hour',@not_after::timestamptz)
FROM (SELECT clock_timestamp() AS n) t
ON CONFLICT(root_id,requester_key,request_operation,idempotency_key) WHERE kind='rawQuery' DO NOTHING
RETURNING *;

-- name: ReadRawQueryCandidates :many
SELECT g.* FROM access_grant g
WHERE g.root_id= @root_id::uuid AND g.kind='rawQuery' AND g.requester_key= @requester_key::bytea
 AND g.requester_issuer= @requester_issuer::text AND g.requester_subject= @requester_subject::text AND g.requester_client= @requester_client::text AND g.requester_kind='human'
 AND g.decision='approved' AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp()
 AND g.raw_query @> @member::jsonb
 AND (@operation::text='' OR (g.raw_query->'Operations') ? @operation::text)
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(g.raw_query->'Artifacts') a WHERE a#>>'{Output,ArtifactID}'= (@artifact_id::uuid)::text AND a#>'{Output,ArtifactDigest}'= sqlc.arg(version)::jsonb AND (a->>'ExpiresAt')::timestamptz>clock_timestamp())
 AND @bytes::bigint<=g.max_bytes-g.bytes_spent AND @operations::bigint<=g.max_operations-g.operations_spent
ORDER BY EXISTS(SELECT 1 FROM access_grant_child c WHERE c.root_id=g.root_id AND c.parent_id=g.id AND c.artifact_id= @artifact_id::uuid AND c.client_id=g.requester_client) DESC,g.requested_at,g.id
LIMIT 64;

-- name: CountRegisteredGrantArtifacts :one
-- One bounded selection, not the parent's unrelated/hidden registered outputs.
-- Artifact capacity is shared across the parent's reviewed clients.
SELECT count(DISTINCT c.artifact_id)::bigint FROM access_grant_child c
JOIN access_grant g ON g.root_id=c.root_id AND g.id=c.parent_id
WHERE g.root_id=sqlc.arg(root_id)::uuid AND g.id=sqlc.arg(parent_id)::uuid AND g.kind='adHocCapture'
 AND c.artifact_id=ANY(sqlc.arg(artifact_ids)::uuid[])
 AND (g.result_access->'clientIDs') ? c.client_id;

-- name: ResolveGrantedGroupOutput :one
-- Immutable accepted association only; current caller/recovery/grant/retention
-- checks remain mandatory before effects. No log bytes or grant JSON returned.
SELECT c.id AS capture_id,(convert_from(c.expectation_json,'UTF8')::jsonb->>'ActionID')::text AS action_id,
 c.scope_digest AS execution_digest,(CASE WHEN rg.group_kind='composition' AND c.group_ordinal>=0 AND cardinality(rg.child_ids) BETWEEN 2 AND 16 AND rg.child_ids[c.group_ordinal+1]=c.id AND
 c.created_at=rg.accepted_at AND c.deadline<=rg.deadline AND sha256(c.scope_json)=c.scope_digest AND sha256(rg.scope_json)=rg.scope_digest AND
 convert_from(rg.scope_json,'UTF8')::jsonb->>'schemaVersion'='recorder-group/v1' AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->c.group_ordinal->>'captureID'=c.id::text AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->c.group_ordinal->>'scopeDigest'=encode(c.scope_digest,'hex') AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->c.group_ordinal->>'actionID'=convert_from(c.expectation_json,'UTF8')::jsonb->>'ActionID' AND
 convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,Location,ArtifactID}'=l.artifact_id::text AND
 convert_from(c.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ParentCaptureID}'=rg.id::text AND
 (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildIndex}')::integer=c.group_ordinal AND
 (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildCount}')::integer=cardinality(rg.child_ids) THEN jsonb_build_object('RootID',c.root_id,'ParentCaptureID',rg.id,'CaptureID',c.id,'ArtifactID',l.artifact_id,
 'ActionID',convert_from(c.expectation_json,'UTF8')::jsonb->>'ActionID',
 'ParentExecutionDigest',to_jsonb(ARRAY(SELECT get_byte(rg.scope_digest,byte_index) FROM generate_series(0,31) AS bytes(byte_index))),
 'ExecutionDigest',to_jsonb(ARRAY(SELECT get_byte(c.scope_digest,byte_index) FROM generate_series(0,31) AS bytes(byte_index))),
 'ArtifactDigest',to_jsonb(ARRAY(SELECT get_byte(l.version,byte_index) FROM generate_series(0,31) AS bytes(byte_index))),
 'ChildIndex',c.group_ordinal,'ChildCount',cardinality(rg.child_ids)) END)::jsonb AS group_association
FROM context_case_locator l
JOIN context_capture c ON c.root_id=l.root_id AND c.id=l.capture_id
JOIN recording_save_group rg ON rg.root_id=c.root_id AND rg.id=c.group_id
JOIN access_grant parent ON parent.root_id=c.root_id AND parent.capture_id=rg.id AND parent.id=sqlc.arg(parent_id)::uuid
WHERE l.root_id=sqlc.arg(root_id)::uuid AND l.artifact_id=sqlc.arg(artifact_id)::uuid AND l.capture_id=sqlc.arg(capture_id)::uuid AND l.version=sqlc.arg(version)::bytea
 AND l.cluster_id=sqlc.arg(cluster_id)::uuid AND l.namespace_uid=sqlc.arg(namespace_uid)::text AND l.workload_uid=sqlc.arg(workload_uid)::text AND l.pod_uid=sqlc.arg(pod_uid)::text
 AND (sqlc.arg(action_id)::text='' OR convert_from(c.expectation_json,'UTF8')::jsonb->>'ActionID'=sqlc.arg(action_id)::text)
 AND parent.kind='adHocCapture' AND rg.group_kind='composition' AND c.group_ordinal>=0 AND cardinality(rg.child_ids) BETWEEN 2 AND 16 AND rg.child_ids[c.group_ordinal+1]=c.id AND
 c.created_at=rg.accepted_at AND c.deadline<=rg.deadline AND sha256(c.scope_json)=c.scope_digest AND sha256(rg.scope_json)=rg.scope_digest AND
 convert_from(rg.scope_json,'UTF8')::jsonb->>'schemaVersion'='recorder-group/v1' AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->c.group_ordinal->>'captureID'=c.id::text AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->c.group_ordinal->>'scopeDigest'=encode(c.scope_digest,'hex') AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->c.group_ordinal->>'actionID'=convert_from(c.expectation_json,'UTF8')::jsonb->>'ActionID' AND
 convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,Location,ArtifactID}'=l.artifact_id::text AND
 convert_from(c.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ParentCaptureID}'=rg.id::text AND
 (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildIndex}')::integer=c.group_ordinal AND
 (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildCount}')::integer=cardinality(rg.child_ids);
