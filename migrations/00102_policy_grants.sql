-- +goose Up
-- ADR-259: distinct team-policy review, request-anchored periods and prepaid
-- observation. Existing ad hoc rows retain their original contract.
LOCK TABLE access_grant IN ACCESS EXCLUSIVE MODE;

ALTER TABLE access_grant ADD COLUMN requester_kind text NOT NULL DEFAULT 'human';
ALTER TABLE access_grant ADD COLUMN request_operation text NOT NULL DEFAULT 'requestGrant';
ALTER TABLE access_grant ADD COLUMN requester_key bytea;
ALTER TABLE access_grant ALTER COLUMN preview_id DROP NOT NULL;
ALTER TABLE access_grant ALTER COLUMN capture_id DROP NOT NULL;
ALTER TABLE access_grant ALTER COLUMN pod_uid DROP NOT NULL;
ALTER TABLE access_grant ADD COLUMN policy_uid text;
ALTER TABLE access_grant ADD COLUMN policy_acceptance_id uuid REFERENCES policy_acceptance(id);
ALTER TABLE access_grant ADD COLUMN policy_scope jsonb;
ALTER TABLE access_grant ADD COLUMN policy_not_after timestamptz;
ALTER TABLE access_grant ADD COLUMN policy_max_executions bigint GENERATED ALWAYS AS ((policy_scope#>>'{Limits,MaxExecutions}')::bigint) STORED;
ALTER TABLE access_grant ADD COLUMN policy_max_bytes bigint GENERATED ALWAYS AS ((policy_scope#>>'{Limits,MaxBytes}')::bigint) STORED;
ALTER TABLE access_grant ADD COLUMN policy_max_observed_bytes bigint GENERATED ALWAYS AS ((policy_scope#>>'{Limits,MaxObservedBytes}')::bigint) STORED;
ALTER TABLE access_grant ADD COLUMN policy_executions_spent bigint NOT NULL DEFAULT 0;
ALTER TABLE access_grant ADD COLUMN policy_bytes_spent bigint NOT NULL DEFAULT 0;
ALTER TABLE access_grant ADD COLUMN policy_observed_bytes_spent bigint NOT NULL DEFAULT 0;

-- Only the old kind/lifetime/expiry and requester-key constraints change.
-- The original target/digest/decision/revocation/disclosure checks remain.
-- +goose StatementBegin
DO $$ DECLARE c record; BEGIN
 FOR c IN SELECT conname FROM pg_constraint
  WHERE conrelid='public.access_grant'::regclass
   AND ((contype='c' AND (pg_get_constraintdef(oid) LIKE '%kind = ''adHocCapture''%'
         OR pg_get_constraintdef(oid) LIKE '%lifetime_seconds%'))
    OR (contype='u' AND pg_get_constraintdef(oid) LIKE '%requester_issuer, requester_subject, idempotency_key%'))
 LOOP EXECUTE format('ALTER TABLE public.access_grant DROP CONSTRAINT %I',c.conname); END LOOP;
END $$;
-- +goose StatementEnd
ALTER TABLE access_grant ADD CONSTRAINT access_grant_kind CHECK(kind IN('adHocCapture','policy'));
ALTER TABLE access_grant ADD CONSTRAINT access_grant_requester_kind CHECK(requester_kind IN('human','workload'));
ALTER TABLE access_grant ADD CONSTRAINT access_grant_scope_kind CHECK((
 (kind='adHocCapture' AND requester_kind='human' AND request_operation='requestGrant' AND requester_key IS NULL
  AND preview_id IS NOT NULL AND capture_id IS NOT NULL AND pod_uid IS NOT NULL
  AND policy_uid IS NULL AND policy_acceptance_id IS NULL AND policy_scope IS NULL AND policy_not_after IS NULL
  AND lifetime_seconds BETWEEN 60 AND 28800
  AND policy_executions_spent=0 AND policy_bytes_spent=0 AND policy_observed_bytes_spent=0)
 OR
 (kind='policy' AND request_operation='requestPolicyGrant'
  AND requester_key IS NOT NULL AND octet_length(requester_key)=32
  AND requester_key=sha256(int4send(octet_length(convert_to(requester_issuer,'UTF8'))) || convert_to(requester_issuer,'UTF8') || int4send(octet_length(convert_to(requester_subject,'UTF8'))) || convert_to(requester_subject,'UTF8') || int4send(octet_length(convert_to(requester_client,'UTF8'))) || convert_to(requester_client,'UTF8') || int4send(octet_length(convert_to(requester_kind,'UTF8'))) || convert_to(requester_kind,'UTF8'))
  AND preview_id IS NULL AND capture_id IS NULL AND pod_uid IS NULL
  AND policy_uid IS NOT NULL AND octet_length(policy_uid) BETWEEN 1 AND 64
  AND policy_acceptance_id IS NOT NULL AND policy_scope IS NOT NULL
  AND jsonb_typeof(policy_scope)='object' AND octet_length(policy_scope::text)<=65536
  AND policy_scope ?& ARRAY['Authority','Limits','ApprovalPolicyRef','ApprovalMaxAge','RecipeDigest']
  AND policy_scope#>>'{Authority,PolicyUID}'=policy_uid
  AND policy_scope#>>'{Authority,ClusterID}'=cluster_id::text
  AND policy_scope#>>'{Authority,NamespaceUID}'=namespace_uid
  AND policy_scope#>>'{Authority,WorkloadUID}'=workload_uid
  AND lifetime_seconds BETWEEN 1 AND 31536000
  AND (policy_scope->>'ApprovalMaxAge')::bigint BETWEEN lifetime_seconds::bigint*1000000000 AND 31536000000000000
  AND policy_not_after IS NOT NULL AND policy_not_after>requested_at
  AND policy_not_after<=requested_at+make_interval(secs=>lifetime_seconds)
  AND policy_not_after<=(policy_scope#>>'{Authority,NotAfter}')::timestamptz
  AND result_access IS NULL AND result_access_digest IS NULL AND not_after IS NULL
  AND max_artifacts=0 AND max_bytes=0 AND max_operations=0
  AND artifacts_spent=0 AND bytes_spent=0 AND operations_spent=0
  AND policy_max_executions IS NOT NULL AND policy_max_executions>0
  AND policy_max_bytes IS NOT NULL AND policy_max_bytes>0
  AND policy_max_observed_bytes IS NOT NULL AND policy_max_observed_bytes>=0)
) IS TRUE);
ALTER TABLE access_grant ADD CONSTRAINT access_grant_policy_pool CHECK(
 policy_executions_spent>=0 AND policy_bytes_spent>=0 AND policy_observed_bytes_spent>=0
 AND (kind<>'policy' OR (policy_executions_spent<=policy_max_executions
  AND policy_bytes_spent<=policy_max_bytes AND policy_observed_bytes_spent<=policy_max_observed_bytes
  AND (decision IS NOT DISTINCT FROM 'approved' OR (policy_executions_spent=0 AND policy_bytes_spent=0 AND policy_observed_bytes_spent=0))))
);
ALTER TABLE access_grant ADD CONSTRAINT access_grant_expiry_kind CHECK(
 decision IS DISTINCT FROM 'approved' OR
 (decision_acr IS NOT NULL AND decision_auth_time IS NOT NULL AND decision_auth_time<=decided_at
 AND ((kind='adHocCapture' AND expires_at=LEAST(decided_at+make_interval(secs=>lifetime_seconds),COALESCE(not_after,'infinity'::timestamptz)))
   OR (kind='policy' AND expires_at=policy_not_after)))
);
CREATE UNIQUE INDEX access_grant_legacy_request ON access_grant(root_id,requester_issuer,requester_subject,idempotency_key) WHERE kind='adHocCapture';
CREATE UNIQUE INDEX access_grant_policy_request ON access_grant(root_id,requester_key,request_operation,idempotency_key) WHERE kind='policy';
CREATE INDEX access_grant_policy_deadline ON access_grant(root_id,policy_not_after) WHERE kind='policy' AND (decision IS NULL OR decision='approved');

-- Policy grants have no capture identity and therefore cannot parent personal
-- artifact children. Preserve the exact original root/capture of legacy rows.
ALTER TABLE access_grant ADD CONSTRAINT access_grant_child_scope UNIQUE(root_id,id,capture_id);
ALTER TABLE access_grant_child ADD CONSTRAINT access_grant_child_exact_parent FOREIGN KEY(root_id,parent_id,capture_id) REFERENCES access_grant(root_id,id,capture_id);
ALTER TABLE policy_acceptance ADD CONSTRAINT policy_acceptance_grant_scope UNIQUE(root_id,id,policy_uid);
ALTER TABLE access_grant ADD CONSTRAINT access_grant_exact_policy_acceptance
 FOREIGN KEY(root_id,policy_acceptance_id,policy_uid) REFERENCES policy_acceptance(root_id,id,policy_uid);
ALTER TABLE access_grant ADD CONSTRAINT access_grant_policy_parent UNIQUE(root_id,id,policy_acceptance_id,policy_uid);

-- Separate from browser session settings. Original bounded observations and
-- accepted lower maxima are published atomically with the monotonic clamp.
CREATE TABLE policy_grant_settings (
 root_id uuid PRIMARY KEY REFERENCES permission_stream(id),
 installation_id uuid NOT NULL,
 issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
 source_uid text NOT NULL CHECK(octet_length(source_uid) BETWEEN 1 AND 64),
 source_generation bigint NOT NULL CHECK(source_generation BETWEEN 1 AND 2147483647),
 source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 observed_at timestamptz NOT NULL,
 fresh_until timestamptz NOT NULL,
 default_age_seconds integer NOT NULL CHECK(default_age_seconds BETWEEN 1 AND 31536000),
 max_age_seconds integer NOT NULL CHECK(max_age_seconds BETWEEN default_age_seconds AND 31536000),
 renewal_notice_seconds integer NOT NULL CHECK(renewal_notice_seconds BETWEEN 1 AND max_age_seconds),
 CHECK(fresh_until>observed_at AND fresh_until<=observed_at+interval '30 seconds')
);

-- Immutable original authority is separate from these cumulative counters.
-- Replacing/reattaching a grant never replaces the acceptance's spent pool.
ALTER TABLE policy_acceptance ADD COLUMN collected_bytes_spent bigint NOT NULL DEFAULT 0;
ALTER TABLE policy_acceptance ADD COLUMN observed_bytes_spent bigint NOT NULL DEFAULT 0;
ALTER TABLE policy_acceptance ADD CONSTRAINT policy_acceptance_byte_pools CHECK (
 collected_bytes_spent BETWEEN 0 AND COALESCE((record#>>'{Authority,Limits,MaxBytes}')::bigint,0)
 AND observed_bytes_spent BETWEEN 0 AND COALESCE((record#>>'{Authority,Limits,MaxObservedBytes}')::bigint,0)
);

ALTER TABLE policy_source ADD COLUMN authored_grant_ref text NOT NULL DEFAULT ''
 CHECK(authored_grant_ref='' OR authored_grant_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');

-- An explicit activate_policy receipt, never a newest-grant index or new
-- authority. The transport acknowledges its encrypted intent before mutation.
CREATE TABLE policy_grant_attachment (
 id uuid PRIMARY KEY,
 root_id uuid NOT NULL,
 installation_id uuid NOT NULL,
 policy_uid text NOT NULL,
 acceptance_id uuid NOT NULL REFERENCES policy_acceptance(id),
 grant_id uuid NOT NULL REFERENCES access_grant(id),
 authority_digest bytea NOT NULL CHECK(octet_length(authority_digest)=32),
 authored_grant_ref text NOT NULL CHECK(authored_grant_ref='' OR authored_grant_ref=grant_id::text),
 actor_issuer text NOT NULL CHECK(octet_length(actor_issuer) BETWEEN 1 AND 2048),
 actor_subject text NOT NULL CHECK(octet_length(actor_subject) BETWEEN 1 AND 256),
 actor_client text NOT NULL CHECK(octet_length(actor_client) BETWEEN 1 AND 256),
 actor_key bytea NOT NULL CHECK(octet_length(actor_key)=32 AND actor_key=sha256(int4send(octet_length(convert_to(actor_issuer,'UTF8'))) || convert_to(actor_issuer,'UTF8') || int4send(octet_length(convert_to(actor_subject,'UTF8'))) || convert_to(actor_subject,'UTF8') || int4send(octet_length(convert_to(actor_client,'UTF8'))) || convert_to(actor_client,'UTF8') || int4send(5) || convert_to('human','UTF8'))),
 idempotency_key text NOT NULL CHECK(octet_length(idempotency_key) BETWEEN 1 AND 128),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 attached_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(root_id,policy_uid) REFERENCES policy_source(root_id,policy_uid),
 FOREIGN KEY(root_id,grant_id,acceptance_id,policy_uid) REFERENCES access_grant(root_id,id,policy_acceptance_id,policy_uid),
 UNIQUE(root_id,actor_key,idempotency_key),
 UNIQUE(root_id,policy_uid,id)
);
CREATE TRIGGER policy_grant_attachment_immutable BEFORE UPDATE OR DELETE ON policy_grant_attachment
 FOR EACH ROW EXECUTE FUNCTION protect_access_grant_history();
ALTER TABLE policy_source ADD COLUMN grant_attachment_id uuid;
ALTER TABLE policy_source ADD CONSTRAINT policy_source_exact_grant_attachment
 FOREIGN KEY(root_id,policy_uid,grant_attachment_id) REFERENCES policy_grant_attachment(root_id,policy_uid,id);

-- One original recorder session/fence. Credit is cumulative and already spent
-- in both grant and acceptance pools, including an uncertain start/reply.
-- Authority renewal extends this same row; there is no refund or quota poller.
CREATE TABLE policy_observation_session (
 id uuid PRIMARY KEY,
 root_id uuid NOT NULL,
 policy_uid text NOT NULL,
 acceptance_id uuid NOT NULL,
 grant_id uuid NOT NULL,
 capture_id uuid NOT NULL UNIQUE REFERENCES context_capture(id),
 fence uuid NOT NULL,
 started_at timestamptz NOT NULL,
 session_until timestamptz NOT NULL,
 lease_until timestamptz NOT NULL,
 sequence bigint NOT NULL CHECK(sequence>0),
 credit bigint NOT NULL CHECK(credit BETWEEN 1 AND 1099511627776),
 max_bytes_per_second bigint NOT NULL CHECK(max_bytes_per_second BETWEEN 1 AND 1073741824),
 ended_at timestamptz,
 FOREIGN KEY(root_id,grant_id,acceptance_id,policy_uid) REFERENCES access_grant(root_id,id,policy_acceptance_id,policy_uid),
 CHECK(session_until>started_at AND session_until<=started_at+interval '1 hour'),
 CHECK(lease_until>started_at AND lease_until<=session_until),
 CHECK(ended_at IS NULL OR ended_at>=started_at)
);
CREATE INDEX policy_observation_active ON policy_observation_session(root_id,acceptance_id,lease_until) WHERE ended_at IS NULL;
-- +goose StatementBegin
CREATE FUNCTION protect_policy_observation_session() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.sequence<>1 OR NEW.ended_at IS NOT NULL OR clock_timestamp()>=NEW.lease_until
   OR NEW.lease_until>clock_timestamp()+interval '1 minute' THEN
   RAISE EXCEPTION 'invalid original observation session' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-ARRAY['sequence','credit','lease_until','ended_at'])<>(to_jsonb(OLD)-ARRAY['sequence','credit','lease_until','ended_at'])
  OR OLD.ended_at IS NOT NULL THEN
  RAISE EXCEPTION 'original observation session is immutable' USING ERRCODE='23514';
 END IF;
 IF NEW.ended_at IS NOT NULL THEN
  IF (to_jsonb(NEW)-'ended_at')<>(to_jsonb(OLD)-'ended_at') THEN
   RAISE EXCEPTION 'closing observation does not change credit' USING ERRCODE='23514';
  END IF;
 ELSIF clock_timestamp()>=OLD.lease_until OR clock_timestamp()>=OLD.session_until
  OR OLD.sequence=9223372036854775807 OR NEW.sequence<>OLD.sequence+1
  OR NEW.credit<OLD.credit OR NEW.lease_until<OLD.lease_until OR NEW.lease_until>clock_timestamp()+interval '1 minute' THEN
  RAISE EXCEPTION 'observation renewal cannot revive or refund' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_policy_observation_session() FROM PUBLIC;
CREATE TRIGGER policy_observation_session_monotonic BEFORE INSERT OR UPDATE OR DELETE ON policy_observation_session
 FOR EACH ROW EXECUTE FUNCTION protect_policy_observation_session();

-- +goose StatementBegin
CREATE FUNCTION protect_policy_collection_spend() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.executions_spent<OLD.executions_spent
  OR NEW.collected_bytes_spent<OLD.collected_bytes_spent
  OR NEW.observed_bytes_spent<OLD.observed_bytes_spent THEN
  RAISE EXCEPTION 'policy collection spend never decreases' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_policy_collection_spend() FROM PUBLIC;
CREATE TRIGGER policy_acceptance_collection_monotonic BEFORE UPDATE ON policy_acceptance
 FOR EACH ROW EXECUTE FUNCTION protect_policy_collection_spend();

-- A restrictive settings overlay is the only non-spend edit to a reviewed
-- lifetime. It does not change revision, decision time or original review.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_access_grant() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 counters text[] := ARRAY['artifacts_spent','bytes_spent','operations_spent',
  'policy_executions_spent','policy_bytes_spent','policy_observed_bytes_spent'];
 mutable text[] := ARRAY['decision','approver_issuer','approver_subject','approver_client','decision_reason','decision_acr','decision_auth_time','decided_at','decision_key','expires_at',
  'revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision','policy_not_after',
  'artifacts_spent','bytes_spent','operations_spent','policy_executions_spent','policy_bytes_spent','policy_observed_bytes_spent'];
 spent boolean;
 before_row jsonb;
 after_row jsonb;
BEGIN
 -- Stored generated values are computed after BEFORE triggers. Compare the
 -- immutable source columns, never NEW's not-yet-computed generated fields.
 before_row := to_jsonb(OLD)-ARRAY['policy_max_executions','policy_max_bytes','policy_max_observed_bytes'];
 after_row := to_jsonb(NEW)-ARRAY['policy_max_executions','policy_max_bytes','policy_max_observed_bytes'];
 IF TG_OP='DELETE' OR (after_row-mutable)<>(before_row-mutable) THEN
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 spent := ROW(NEW.artifacts_spent,NEW.bytes_spent,NEW.operations_spent,NEW.policy_executions_spent,NEW.policy_bytes_spent,NEW.policy_observed_bytes_spent)
   IS DISTINCT FROM ROW(OLD.artifacts_spent,OLD.bytes_spent,OLD.operations_spent,OLD.policy_executions_spent,OLD.policy_bytes_spent,OLD.policy_observed_bytes_spent);
 IF NEW.artifacts_spent<OLD.artifacts_spent OR NEW.bytes_spent<OLD.bytes_spent OR NEW.operations_spent<OLD.operations_spent
  OR NEW.policy_executions_spent<OLD.policy_executions_spent OR NEW.policy_bytes_spent<OLD.policy_bytes_spent OR NEW.policy_observed_bytes_spent<OLD.policy_observed_bytes_spent THEN
  RAISE EXCEPTION 'access grant spend never decreases' USING ERRCODE='23514';
 END IF;
 IF OLD.decision IS NULL AND NEW.decision IS NOT NULL THEN
  IF spent OR NEW.policy_not_after IS DISTINCT FROM OLD.policy_not_after
   OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1
   OR clock_timestamp()>=OLD.review_until OR (OLD.kind='policy' AND clock_timestamp()>=OLD.policy_not_after) THEN
   RAISE EXCEPTION 'access grant decision refused' USING ERRCODE='23514';
  END IF;
 ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
  IF spent OR NEW.revision<>OLD.revision+1 OR (after_row-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision'])<>(before_row-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision']) THEN
   RAISE EXCEPTION 'access grant revocation refused' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.policy_not_after IS DISTINCT FROM OLD.policy_not_after THEN
  IF OLD.kind<>'policy' OR NEW.policy_not_after IS NULL OR NEW.policy_not_after>=OLD.policy_not_after
   OR (after_row-ARRAY['policy_not_after','expires_at'])<>(before_row-ARRAY['policy_not_after','expires_at'])
   OR NEW.expires_at IS DISTINCT FROM CASE WHEN OLD.decision='approved' THEN NEW.policy_not_after ELSE NULL END THEN
   RAISE EXCEPTION 'access grant deadline only shortens' USING ERRCODE='23514';
  END IF;
 ELSIF spent THEN
  IF OLD.decision IS DISTINCT FROM 'approved' OR OLD.revoked_at IS NOT NULL OR clock_timestamp()>=OLD.expires_at
   OR (after_row-counters)<>(before_row-counters) THEN
   RAISE EXCEPTION 'access grant pool is not usable' USING ERRCODE='23514';
  END IF;
 ELSE
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ BEGIN
 EXECUTE 'COMMENT ON TABLE public.goose_db_version IS ''asservat:oldest-binary-schema=102''';
END $$;
-- +goose StatementEnd

-- +goose Down
-- Refuse incompatible survivors rather than destroy authority or spent state.
LOCK TABLE access_grant IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM access_grant WHERE kind<>'adHocCapture')
  OR EXISTS(SELECT 1 FROM policy_grant_attachment)
  OR EXISTS(SELECT 1 FROM policy_observation_session)
  OR EXISTS(SELECT 1 FROM policy_acceptance WHERE collected_bytes_spent<>0 OR observed_bytes_spent<>0)
  OR EXISTS(SELECT 1 FROM access_grant GROUP BY root_id,requester_issuer,requester_subject,idempotency_key HAVING count(*)>1) THEN
  RAISE EXCEPTION 'policy grant state prevents rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TABLE policy_observation_session;
DROP FUNCTION protect_policy_observation_session();
ALTER TABLE policy_source DROP CONSTRAINT policy_source_exact_grant_attachment;
ALTER TABLE policy_source DROP COLUMN grant_attachment_id, DROP COLUMN authored_grant_ref;
DROP TABLE policy_grant_attachment;
DROP TRIGGER policy_acceptance_collection_monotonic ON policy_acceptance;
DROP FUNCTION protect_policy_collection_spend();
ALTER TABLE policy_acceptance DROP CONSTRAINT policy_acceptance_byte_pools;
ALTER TABLE policy_acceptance DROP COLUMN collected_bytes_spent, DROP COLUMN observed_bytes_spent;
DROP TABLE policy_grant_settings;
ALTER TABLE access_grant_child DROP CONSTRAINT access_grant_child_exact_parent;
ALTER TABLE access_grant DROP CONSTRAINT access_grant_child_scope;
ALTER TABLE access_grant DROP CONSTRAINT access_grant_policy_parent, DROP CONSTRAINT access_grant_exact_policy_acceptance;
ALTER TABLE policy_acceptance DROP CONSTRAINT policy_acceptance_grant_scope;
DROP INDEX access_grant_policy_deadline;
DROP INDEX access_grant_policy_request;
DROP INDEX access_grant_legacy_request;
ALTER TABLE access_grant DROP CONSTRAINT access_grant_kind, DROP CONSTRAINT access_grant_requester_kind,
 DROP CONSTRAINT access_grant_scope_kind, DROP CONSTRAINT access_grant_policy_pool, DROP CONSTRAINT access_grant_expiry_kind;
ALTER TABLE access_grant DROP COLUMN requester_key, DROP COLUMN requester_kind, DROP COLUMN request_operation,
 DROP COLUMN policy_uid, DROP COLUMN policy_acceptance_id, DROP COLUMN policy_max_executions,
 DROP COLUMN policy_max_bytes, DROP COLUMN policy_max_observed_bytes, DROP COLUMN policy_scope,
 DROP COLUMN policy_not_after, DROP COLUMN policy_executions_spent, DROP COLUMN policy_bytes_spent,
 DROP COLUMN policy_observed_bytes_spent;
ALTER TABLE access_grant ALTER COLUMN preview_id SET NOT NULL, ALTER COLUMN capture_id SET NOT NULL, ALTER COLUMN pod_uid SET NOT NULL;
ALTER TABLE access_grant ADD CHECK(kind='adHocCapture'), ADD CHECK(lifetime_seconds BETWEEN 60 AND 28800),
 ADD UNIQUE(root_id,requester_issuer,requester_subject,idempotency_key),
 ADD CHECK (decision IS DISTINCT FROM 'approved' OR (expires_at=LEAST(decided_at+make_interval(secs => lifetime_seconds),COALESCE(not_after,'infinity'::timestamptz)) AND decision_acr IS NOT NULL AND decision_auth_time IS NOT NULL AND decision_auth_time<=decided_at));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_access_grant() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 mutable text[] := ARRAY['decision','approver_issuer','approver_subject','approver_client','decision_reason','decision_acr','decision_auth_time','decided_at','decision_key','expires_at',
  'revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision','artifacts_spent','bytes_spent','operations_spent'];
 spent boolean;
BEGIN
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-mutable)<>(to_jsonb(OLD)-mutable) THEN
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 spent := NEW.artifacts_spent<>OLD.artifacts_spent OR NEW.bytes_spent<>OLD.bytes_spent OR NEW.operations_spent<>OLD.operations_spent;
 IF NEW.artifacts_spent<OLD.artifacts_spent OR NEW.bytes_spent<OLD.bytes_spent OR NEW.operations_spent<OLD.operations_spent THEN
  RAISE EXCEPTION 'access grant spend never decreases' USING ERRCODE='23514';
 END IF;
 IF OLD.decision IS NULL AND NEW.decision IS NOT NULL THEN
  IF spent OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1 OR clock_timestamp()>=OLD.review_until THEN
   RAISE EXCEPTION 'access grant decision refused' USING ERRCODE='23514';
  END IF;
 ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
  IF spent OR NEW.revision<>OLD.revision+1 OR (to_jsonb(NEW)-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision'])<>(to_jsonb(OLD)-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision']) THEN
   RAISE EXCEPTION 'access grant revocation refused' USING ERRCODE='23514';
  END IF;
 ELSIF spent THEN
  IF OLD.decision IS DISTINCT FROM 'approved' OR OLD.revoked_at IS NOT NULL OR clock_timestamp()>=OLD.expires_at
   OR (to_jsonb(NEW)-ARRAY['artifacts_spent','bytes_spent','operations_spent'])<>(to_jsonb(OLD)-ARRAY['artifacts_spent','bytes_spent','operations_spent']) THEN
   RAISE EXCEPTION 'access grant pool is not usable' USING ERRCODE='23514';
  END IF;
 ELSE
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ BEGIN
 EXECUTE 'COMMENT ON TABLE public.goose_db_version IS ''asservat:oldest-binary-schema=81''';
END $$;
-- +goose StatementEnd
