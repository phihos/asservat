-- +goose Up
-- ADR-266: one real parent operation; every member retains its own custody.
ALTER TABLE context_preview ADD COLUMN preview_kind text NOT NULL DEFAULT 'context'
 CHECK(preview_kind IN ('context','recordingSaveGroup'));
ALTER TABLE context_preview ALTER COLUMN attempt_id DROP NOT NULL;
ALTER TABLE context_preview ADD CONSTRAINT context_preview_kind_attempt CHECK
 ((preview_kind='context' AND attempt_id IS NOT NULL) OR
  (preview_kind='recordingSaveGroup' AND attempt_id IS NULL));

CREATE TABLE recording_save_group (
 id uuid PRIMARY KEY,
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 preview_id uuid NOT NULL,
 request_key bytea NOT NULL CHECK(octet_length(request_key)=32),
 submission_digest bytea NOT NULL CHECK(octet_length(submission_digest)=32),
 scope_digest bytea NOT NULL CHECK(octet_length(scope_digest)=32),
 scope_json bytea NOT NULL CHECK(octet_length(scope_json) BETWEEN 1 AND 65536),
 policy_uid text NOT NULL CHECK(octet_length(policy_uid) BETWEEN 1 AND 64),
 acceptance_id uuid NOT NULL REFERENCES policy_acceptance(id),
 allocation_id uuid NOT NULL REFERENCES custody_allocation(id),
 child_ids uuid[] NOT NULL CHECK(cardinality(child_ids) BETWEEN 2 AND 16 AND array_position(child_ids,NULL) IS NULL),
 accepted_at timestamptz NOT NULL,
 deadline timestamptz NOT NULL,
 progress_revision bigint NOT NULL DEFAULT 1 CHECK(progress_revision BETWEEN 1 AND 1000000000),
 cancel_requested_at timestamptz,
 cancel_request_key bytea CHECK(octet_length(cancel_request_key)=32),
 UNIQUE(root_id,id), UNIQUE(root_id,request_key), UNIQUE(root_id,preview_id),
 CHECK(sha256(scope_json)=scope_digest),
 CHECK(isfinite(accepted_at) AND isfinite(deadline) AND deadline>accepted_at),
 CHECK((cancel_requested_at IS NULL)=(cancel_request_key IS NULL))
);
ALTER TABLE context_capture ADD COLUMN group_id uuid;
ALTER TABLE context_capture ADD COLUMN group_ordinal smallint;
ALTER TABLE context_capture ADD CONSTRAINT context_capture_group_link
 FOREIGN KEY(root_id,group_id) REFERENCES recording_save_group(root_id,id);
ALTER TABLE context_capture ADD CONSTRAINT context_capture_group_position
 CHECK((group_id IS NULL AND group_ordinal IS NULL) OR
       (group_id IS NOT NULL AND group_ordinal BETWEEN 0 AND 15));
CREATE UNIQUE INDEX context_capture_group_ordinal ON context_capture(group_id,group_ordinal) WHERE group_id IS NOT NULL;

-- The extra parent metadata consumes one existing full/replay record unit.
-- Like existing context charges, this is monotonic: no speculative refund.
-- +goose StatementBegin
CREATE FUNCTION guard_recording_save_group() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE pool public.context_control_pool; account public.context_control_account;
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'group control retirement requires protocol' USING ERRCODE='23514';
 ELSIF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-ARRAY['progress_revision','cancel_requested_at','cancel_request_key']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['progress_revision','cancel_requested_at','cancel_request_key']) OR
     NEW.progress_revision<>OLD.progress_revision+1 THEN
   RAISE EXCEPTION 'immutable save group' USING ERRCODE='23514';
  END IF;
  IF ROW(NEW.cancel_requested_at,NEW.cancel_request_key) IS DISTINCT FROM ROW(OLD.cancel_requested_at,OLD.cancel_request_key) THEN
   IF OLD.cancel_requested_at IS NOT NULL OR NEW.cancel_requested_at IS NULL OR NEW.cancel_request_key IS NULL THEN
    RAISE EXCEPTION 'immutable group cancellation' USING ERRCODE='23514';
   END IF;
   NEW.cancel_requested_at:=clock_timestamp();
  ELSIF pg_trigger_depth()<2 THEN
   RAISE EXCEPTION 'group progress derives from children' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF NEW.progress_revision<>1 OR NEW.cancel_requested_at IS NOT NULL OR NEW.cancel_request_key IS NOT NULL OR
    EXISTS(SELECT 1 FROM public.context_capture WHERE id=NEW.id OR (root_id=NEW.root_id AND request_key=NEW.request_key)) OR
    (SELECT count(DISTINCT x) FROM unnest(NEW.child_ids) x)<>cardinality(NEW.child_ids) OR NEW.id=ANY(NEW.child_ids) THEN
  RAISE EXCEPTION 'invalid new save group' USING ERRCODE='23514';
 END IF;
 SELECT * INTO STRICT pool FROM public.context_control_pool WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT account FROM public.context_control_account WHERE root_id=NEW.root_id AND allocation_id=NEW.allocation_id FOR UPDATE;
 IF NOT pool.configured OR NOT account.configured OR pool.paused OR account.paused OR
    clock_timestamp()>=pool.valid_until OR clock_timestamp()>=account.valid_until OR
    account.charged_full>=account.full_limit OR account.charged_replay>=account.replay_limit THEN
  RAISE EXCEPTION 'group control capacity unavailable' USING ERRCODE='23514';
 END IF;
 UPDATE public.context_control_account SET charged_full=charged_full+1,charged_replay=charged_replay+1
 WHERE root_id=NEW.root_id AND allocation_id=NEW.allocation_id;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER recording_save_group_guard BEFORE INSERT OR UPDATE OR DELETE ON recording_save_group
 FOR EACH ROW EXECUTE FUNCTION guard_recording_save_group();

-- A deferred check sees the complete atomic group, not an intermediate child.
-- +goose StatementBegin
CREATE FUNCTION require_recording_save_group_members() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE g public.recording_save_group; member record; n integer:=0; e jsonb; s jsonb;
BEGIN
 SELECT * INTO STRICT g FROM public.recording_save_group WHERE id=NEW.id;
 s:=convert_from(g.scope_json,'UTF8')::jsonb;
 IF s->>'schemaVersion' IS DISTINCT FROM 'recording-save/v1' OR s->>'captureID' IS DISTINCT FROM g.id::text OR
    jsonb_typeof(s->'sources') IS DISTINCT FROM 'array' OR jsonb_array_length(s->'sources')<>cardinality(g.child_ids) THEN
  RAISE EXCEPTION 'group selection differs from accepted scope' USING ERRCODE='23514';
 END IF;
 FOR member IN SELECT c.*,a.allocation_id AS actual_allocation FROM public.context_capture c
  JOIN public.custody_attempt a ON a.id=c.attempt_id WHERE c.group_id=g.id ORDER BY c.group_ordinal LOOP
  e:=convert_from(member.expectation_json,'UTF8')::jsonb;
  IF member.root_id<>g.root_id OR member.group_ordinal<>n OR member.id<>g.child_ids[n+1] OR
     member.scope_digest<>g.scope_digest OR member.scope_json<>g.scope_json OR member.created_at<>g.accepted_at OR
     member.deadline>g.deadline OR member.actual_allocation<>g.allocation_id OR
     (e#>>'{Snapshot,T0}')::timestamptz IS DISTINCT FROM g.accepted_at OR
     e#>>'{Snapshot,SourceID}' IS DISTINCT FROM s->'sources'->n->>'sourceSessionID' OR
     NOT EXISTS(SELECT 1 FROM public.recording_save_reservation r WHERE r.capture_id=member.id AND
       r.root_id=g.root_id AND r.acceptance_id=g.acceptance_id AND r.policy_uid=g.policy_uid AND r.accepted_at=g.accepted_at) THEN
   RAISE EXCEPTION 'incomplete or substituted group member' USING ERRCODE='23514';
  END IF;
  n:=n+1;
 END LOOP;
 IF n<>cardinality(g.child_ids) THEN RAISE EXCEPTION 'incomplete save group' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER recording_save_group_complete AFTER INSERT ON recording_save_group
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_recording_save_group_members();

-- +goose StatementBegin
CREATE FUNCTION guard_context_capture_group() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.group_id,NEW.group_ordinal) IS DISTINCT FROM ROW(OLD.group_id,OLD.group_ordinal) THEN
   RAISE EXCEPTION 'immutable group membership' USING ERRCODE='23514';
  END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM public.recording_save_group WHERE id=NEW.id OR (root_id=NEW.root_id AND request_key=NEW.request_key)) THEN
   RAISE EXCEPTION 'request key already belongs to a group' USING ERRCODE='23514';
  END IF;
  IF NEW.group_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.recording_save_group g WHERE
    g.root_id=NEW.root_id AND g.id=NEW.group_id AND g.child_ids[NEW.group_ordinal+1]=NEW.id AND
    g.scope_digest=NEW.scope_digest AND g.scope_json=NEW.scope_json AND g.accepted_at=NEW.created_at) THEN
   RAISE EXCEPTION 'unlisted group member' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER context_capture_group_guard BEFORE INSERT OR UPDATE ON context_capture
 FOR EACH ROW EXECUTE FUNCTION guard_context_capture_group();
-- +goose StatementBegin
CREATE FUNCTION project_recording_save_group_revision() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.group_id IS NOT NULL AND NEW.progress_revision<>OLD.progress_revision THEN
  UPDATE public.recording_save_group SET progress_revision=progress_revision+1 WHERE id=NEW.group_id;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER context_capture_group_revision AFTER UPDATE OF progress_revision ON context_capture
 FOR EACH ROW EXECUTE FUNCTION project_recording_save_group_revision();
REVOKE ALL ON FUNCTION guard_recording_save_group(),require_recording_save_group_members(),guard_context_capture_group(),project_recording_save_group_revision() FROM PUBLIC;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_preview_read_until(p_root uuid,p_preview uuid) RETURNS timestamptz
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT GREATEST(p.deadline,COALESCE((SELECT GREATEST(g.review_until,g.expires_at)
 FROM public.access_grant g WHERE p.preview_kind='context' AND g.root_id=p.root_id AND g.preview_id=p.id
 AND g.capture_id=p.capture_id
 AND g.scope=decode(convert_from(p.blueprint_json,'UTF8')::jsonb->>'CanonicalScope','base64')
 AND g.requester_issuer=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'Issuer'
 AND g.requester_subject=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'Subject'
 AND g.requester_client=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'ClientID'),p.deadline))
 FROM public.context_preview p WHERE p.root_id=p_root AND p.id=p_preview
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capture_audit_payload_matches(c public.context_capture,i jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE v jsonb:=i->'Capture';e jsonb:=convert_from(c.expectation_json,'UTF8')::jsonb;s jsonb:=convert_from(c.scope_json,'UTF8')::jsonb;a public.custody_attempt;
BEGIN
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=c.attempt_id;
 RETURN COALESCE(i->>'Name'='persist_capture_intent' AND i->>'InputFormat'='capture-intent/v2' AND NOT(i ? 'Peer') AND NOT(i ? 'Process') AND
  jsonb_typeof(v)='object' AND (v-ARRAY['RootID','CaptureID','CaseID','OccurrenceID','ArtifactID','AttemptID','Actor','Initiator','Group','Target','ScopeDigest','SubmissionDigest','ExpectationDigest','PermissionEpoch','PermissionSequence','IdentityRevision','CreatedAt','Deadline','ExpiresAt','DeleteBy','ReservedBytes'])='{}'::jsonb AND
  (i->>'ID')::uuid=c.id AND (i->>'RootID')::uuid=c.root_id AND (i->>'TraceID')::uuid=(e->>'OccurrenceID')::uuid AND
  (v->>'RootID')::uuid=c.root_id AND (v->>'CaptureID')::uuid=c.id AND (v->>'AttemptID')::uuid=c.attempt_id AND
  v->>'CaseID'=e->>'CaseID' AND v->>'OccurrenceID'=e->>'OccurrenceID' AND v->>'ArtifactID'=e->'Registration'->'Location'->>'ArtifactID' AND
  ((s->>'schemaVersion' IS DISTINCT FROM 'recording-save/v1' AND NOT v ? 'Initiator' AND v->'Actor'=i->'Actor') OR
   (s->>'schemaVersion'='recording-save/v1' AND s->>'operation'='recordingSave' AND jsonb_typeof(e->'Snapshot')='object' AND
    jsonb_typeof(v->'Initiator')='object' AND v->'Initiator'=i->'Actor' AND v->'Initiator'->>'Kind' IN ('human','workload') AND
    v->'Initiator'=jsonb_build_object('Issuer',s#>>'{requester,issuer}','Subject',s#>>'{requester,subject}','ClientID',s#>>'{requester,clientID}','Kind',s#>>'{requester,identityType}'))) AND
  ((c.group_id IS NULL AND NOT v ? 'Group') OR (c.group_id IS NOT NULL AND
   v->'Group'->>'ParentCaptureID'=c.group_id::text AND public.connector_digest(v->'Group'->'SelectionDigest')=c.scope_digest AND
   (v->'Group'->>'ChildIndex')::smallint=c.group_ordinal AND
   (v->'Group'->>'ChildCount')::integer=jsonb_array_length(s->'sources') AND
   (v->'Group')-ARRAY['ParentCaptureID','SelectionDigest','ChildIndex','ChildCount']='{}'::jsonb)) AND
  v->'Actor'=jsonb_build_object('Issuer',s#>>'{executor,issuer}','Subject',s#>>'{executor,subject}','ClientID',s#>>'{executor,clientID}','Kind',s#>>'{executor,identityType}') AND public.capture_audit_actor_valid(v->'Actor') AND
  v->'Target'=jsonb_build_object('ClusterID',e#>>'{Registration,Location,ClusterID}','NamespaceUID',e->>'NamespaceUID','WorkloadUID',e->>'WorkloadUID','PodUID',e->>'PodUID') AND
  public.connector_digest(v->'ScopeDigest')=c.scope_digest AND public.connector_digest(v->'SubmissionDigest')=c.submission_digest AND public.connector_digest(v->'ExpectationDigest')=sha256(c.expectation_json) AND sha256(c.scope_json)=c.scope_digest AND
  (v->>'PermissionEpoch')::uuid=c.permission_epoch AND (v->>'PermissionSequence')::bigint=c.permission_sequence AND
  v->'IdentityRevision'->>'UID'=c.identity_policy_uid AND (v->'IdentityRevision'->>'Generation')::bigint=c.identity_policy_generation AND public.connector_digest(v->'IdentityRevision'->'Digest')=c.identity_policy_digest AND
  (v->>'CreatedAt')::timestamptz=c.created_at AND (i->>'CreatedAt')::timestamptz=c.created_at AND (v->>'Deadline')::timestamptz=c.deadline AND
  (v->>'ExpiresAt')::timestamptz=(e->'Registration'->>'ExpiresAt')::timestamptz AND (v->>'DeleteBy')::timestamptz=(e->'Registration'->>'DeleteBy')::timestamptz AND (v->>'ReservedBytes')::bigint=a.reserved_bytes AND
  (i->>'WriteUntil')::timestamptz<=c.deadline,false);
END $$;
-- +goose StatementEnd

ALTER TABLE capture_history_parameter DROP CONSTRAINT capture_history_parameter_capture_id_fkey;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_capture_history_parameter() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c public.context_capture;g public.recording_save_group;e jsonb;a public.custody_attempt;
 owner_root uuid;owner_id uuid;owner_scope bytea;owner_created timestamptz;owner_allocation uuid;owner_cluster uuid;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=OLD.attempt_id;
  IF a.state<>'deleted' OR clock_timestamp()<OLD.summary_expires_at THEN RAISE EXCEPTION 'retained history obligation' USING ERRCODE='23514';END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.root_id,NEW.capture_id,NEW.attempt_id,NEW.selector_key,NEW.settings_key,NEW.mac_version,NEW.expectation_json,NEW.retention_json,NEW.summary_expires_at,NEW.created_at)
   IS DISTINCT FROM ROW(OLD.root_id,OLD.capture_id,OLD.attempt_id,OLD.selector_key,OLD.settings_key,OLD.mac_version,OLD.expectation_json,OLD.retention_json,OLD.summary_expires_at,OLD.created_at) OR (NOT OLD.visible AND NEW.visible) OR
   (OLD.write_id IS NOT NULL AND ROW(NEW.write_id,NEW.write_digest,NEW.write_started_at,NEW.write_until,NEW.write_executor_epoch) IS DISTINCT FROM ROW(OLD.write_id,OLD.write_digest,OLD.write_started_at,OLD.write_until,OLD.write_executor_epoch)) OR
   (OLD.writer_completion_json IS NOT NULL AND ROW(NEW.writer_completion_json,NEW.copies_digest) IS DISTINCT FROM ROW(OLD.writer_completion_json,OLD.copies_digest)) THEN
    RAISE EXCEPTION 'immutable history parameters' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO c FROM public.context_capture WHERE id=NEW.capture_id;
 IF FOUND THEN
  owner_root:=c.root_id;owner_id:=c.id;owner_scope:=c.scope_digest;owner_created:=c.created_at;
  owner_allocation:=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,AllocationID}')::uuid;
  owner_cluster:=c.history_cluster_id;
 ELSE
  SELECT * INTO STRICT g FROM public.recording_save_group WHERE id=NEW.capture_id;
  owner_root:=g.root_id;owner_id:=g.id;owner_scope:=g.scope_digest;owner_created:=g.accepted_at;owner_allocation:=g.allocation_id;
  owner_cluster:=(convert_from(g.scope_json,'UTF8')::jsonb#>>'{policy,clusterID}')::uuid;
 END IF;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;
 e:=convert_from(NEW.expectation_json,'UTF8')::jsonb;
 IF NEW.root_id<>owner_root OR (e->>'RootID')::uuid<>owner_root OR (e->>'CaptureID')::uuid<>owner_id OR
   (e#>>'{Registration,Location,AttemptID}')::uuid<>a.id OR (e#>>'{Registration,Location,ArtifactID}')::uuid<>a.artifact_id OR
   (e#>>'{Registration,Location,ClusterID}')::uuid<>a.cluster_id OR (e#>>'{Registration,AllocationID}')::uuid<>a.allocation_id OR a.native_limit<>131072 OR
   public.connector_digest(e->'OriginalExecutionDigest')<>owner_scope OR
   (e#>>'{Registration,StoreID}')::uuid<>(SELECT p.store_id FROM public.custody_pool p JOIN public.custody_allocation x ON x.pool_id=p.id WHERE x.id=a.allocation_id) OR
   (e#>>'{Registration,PoolRevision}')::bigint<>a.pool_revision OR (e#>>'{Registration,AllocationRevision}')::bigint<>a.allocation_revision OR
   (e#>>'{Registration,AnchorAt}')::timestamptz<>a.anchor_at OR (e#>>'{Registration,WriteUntil}')::timestamptz<>a.write_until OR
   (e#>>'{Registration,ExpiresAt}')::timestamptz<>a.expires_at OR (e#>>'{Registration,DeleteBy}')::timestamptz<>a.delete_by OR
   a.allocation_id<>owner_allocation OR
   a.cluster_id<>owner_cluster OR NEW.summary_expires_at>owner_created+interval '3650 days' THEN
  RAISE EXCEPTION 'history parameter scope changed' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM recording_save_group) OR EXISTS(SELECT 1 FROM context_preview WHERE preview_kind='recordingSaveGroup') THEN
  RAISE EXCEPTION 'retained save groups prevent downgrade';
 END IF;
END $$;
-- +goose StatementEnd
-- Refuse populated groups in migration109 Down BEFORE this fragment.
ALTER TABLE capture_history_parameter ADD CONSTRAINT capture_history_parameter_capture_id_fkey FOREIGN KEY(capture_id) REFERENCES context_capture(id);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_capture_history_parameter() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c public.context_capture;e jsonb;a public.custody_attempt;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=OLD.attempt_id;
  IF a.state<>'deleted' OR clock_timestamp()<OLD.summary_expires_at THEN RAISE EXCEPTION 'retained history obligation' USING ERRCODE='23514';END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.root_id,NEW.capture_id,NEW.attempt_id,NEW.selector_key,NEW.settings_key,NEW.mac_version,NEW.expectation_json,NEW.retention_json,NEW.summary_expires_at,NEW.created_at)
   IS DISTINCT FROM ROW(OLD.root_id,OLD.capture_id,OLD.attempt_id,OLD.selector_key,OLD.settings_key,OLD.mac_version,OLD.expectation_json,OLD.retention_json,OLD.summary_expires_at,OLD.created_at) OR (NOT OLD.visible AND NEW.visible) OR
   (OLD.write_id IS NOT NULL AND ROW(NEW.write_id,NEW.write_digest,NEW.write_started_at,NEW.write_until,NEW.write_executor_epoch) IS DISTINCT FROM ROW(OLD.write_id,OLD.write_digest,OLD.write_started_at,OLD.write_until,OLD.write_executor_epoch)) OR
   (OLD.writer_completion_json IS NOT NULL AND ROW(NEW.writer_completion_json,NEW.copies_digest) IS DISTINCT FROM ROW(OLD.writer_completion_json,OLD.copies_digest)) THEN
    RAISE EXCEPTION 'immutable history parameters' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT c FROM public.context_capture WHERE id=NEW.capture_id;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;
 e:=convert_from(NEW.expectation_json,'UTF8')::jsonb;
 IF NEW.root_id<>c.root_id OR (e->>'RootID')::uuid<>c.root_id OR (e->>'CaptureID')::uuid<>c.id OR
   (e#>>'{Registration,Location,AttemptID}')::uuid<>a.id OR (e#>>'{Registration,Location,ArtifactID}')::uuid<>a.artifact_id OR
   (e#>>'{Registration,Location,ClusterID}')::uuid<>a.cluster_id OR (e#>>'{Registration,AllocationID}')::uuid<>a.allocation_id OR a.native_limit<>131072 OR
   public.connector_digest(e->'OriginalExecutionDigest')<>c.scope_digest OR
   (e#>>'{Registration,StoreID}')::uuid<>(SELECT p.store_id FROM public.custody_pool p JOIN public.custody_allocation x ON x.pool_id=p.id WHERE x.id=a.allocation_id) OR
   (e#>>'{Registration,PoolRevision}')::bigint<>a.pool_revision OR (e#>>'{Registration,AllocationRevision}')::bigint<>a.allocation_revision OR
   (e#>>'{Registration,AnchorAt}')::timestamptz<>a.anchor_at OR (e#>>'{Registration,WriteUntil}')::timestamptz<>a.write_until OR
   (e#>>'{Registration,ExpiresAt}')::timestamptz<>a.expires_at OR (e#>>'{Registration,DeleteBy}')::timestamptz<>a.delete_by OR
   a.allocation_id<>(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,AllocationID}')::uuid OR
   a.cluster_id<>c.history_cluster_id OR NEW.summary_expires_at>c.created_at+interval '3650 days' THEN
  RAISE EXCEPTION 'history parameter scope changed' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

DROP TRIGGER context_capture_group_revision ON context_capture;
DROP FUNCTION project_recording_save_group_revision();
DROP TRIGGER context_capture_group_guard ON context_capture;
DROP FUNCTION guard_context_capture_group();
DROP TRIGGER recording_save_group_complete ON recording_save_group;
DROP FUNCTION require_recording_save_group_members();
ALTER TABLE context_capture DROP CONSTRAINT context_capture_group_link;
ALTER TABLE context_capture DROP CONSTRAINT context_capture_group_position;
DROP INDEX context_capture_group_ordinal;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capture_audit_payload_matches(c public.context_capture,i jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE v jsonb:=i->'Capture';e jsonb:=convert_from(c.expectation_json,'UTF8')::jsonb;s jsonb:=convert_from(c.scope_json,'UTF8')::jsonb;a public.custody_attempt;
BEGIN
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=c.attempt_id;
 RETURN COALESCE(i->>'Name'='persist_capture_intent' AND i->>'InputFormat'='capture-intent/v2' AND NOT(i ? 'Peer') AND NOT(i ? 'Process') AND
  jsonb_typeof(v)='object' AND (v-ARRAY['RootID','CaptureID','CaseID','OccurrenceID','ArtifactID','AttemptID','Actor','Initiator','Target','ScopeDigest','SubmissionDigest','ExpectationDigest','PermissionEpoch','PermissionSequence','IdentityRevision','CreatedAt','Deadline','ExpiresAt','DeleteBy','ReservedBytes'])='{}'::jsonb AND
  (i->>'ID')::uuid=c.id AND (i->>'RootID')::uuid=c.root_id AND (i->>'TraceID')::uuid=(e->>'OccurrenceID')::uuid AND
  (v->>'RootID')::uuid=c.root_id AND (v->>'CaptureID')::uuid=c.id AND (v->>'AttemptID')::uuid=c.attempt_id AND
  v->>'CaseID'=e->>'CaseID' AND v->>'OccurrenceID'=e->>'OccurrenceID' AND v->>'ArtifactID'=e->'Registration'->'Location'->>'ArtifactID' AND
  ((s->>'schemaVersion' IS DISTINCT FROM 'recording-save/v1' AND NOT v ? 'Initiator' AND v->'Actor'=i->'Actor') OR
   (s->>'schemaVersion'='recording-save/v1' AND s->>'operation'='recordingSave' AND jsonb_typeof(e->'Snapshot')='object' AND
    jsonb_typeof(v->'Initiator')='object' AND v->'Initiator'=i->'Actor' AND v->'Initiator'->>'Kind' IN ('human','workload') AND
    v->'Initiator'=jsonb_build_object('Issuer',s#>>'{requester,issuer}','Subject',s#>>'{requester,subject}','ClientID',s#>>'{requester,clientID}','Kind',s#>>'{requester,identityType}'))) AND
  v->'Actor'=jsonb_build_object('Issuer',s#>>'{executor,issuer}','Subject',s#>>'{executor,subject}','ClientID',s#>>'{executor,clientID}','Kind',s#>>'{executor,identityType}') AND public.capture_audit_actor_valid(v->'Actor') AND
  v->'Target'=jsonb_build_object('ClusterID',e#>>'{Registration,Location,ClusterID}','NamespaceUID',e->>'NamespaceUID','WorkloadUID',e->>'WorkloadUID','PodUID',e->>'PodUID') AND
  public.connector_digest(v->'ScopeDigest')=c.scope_digest AND public.connector_digest(v->'SubmissionDigest')=c.submission_digest AND public.connector_digest(v->'ExpectationDigest')=sha256(c.expectation_json) AND sha256(c.scope_json)=c.scope_digest AND
  (v->>'PermissionEpoch')::uuid=c.permission_epoch AND (v->>'PermissionSequence')::bigint=c.permission_sequence AND
  v->'IdentityRevision'->>'UID'=c.identity_policy_uid AND (v->'IdentityRevision'->>'Generation')::bigint=c.identity_policy_generation AND public.connector_digest(v->'IdentityRevision'->'Digest')=c.identity_policy_digest AND
  (v->>'CreatedAt')::timestamptz=c.created_at AND (i->>'CreatedAt')::timestamptz=c.created_at AND (v->>'Deadline')::timestamptz=c.deadline AND
  (v->>'ExpiresAt')::timestamptz=(e->'Registration'->>'ExpiresAt')::timestamptz AND (v->>'DeleteBy')::timestamptz=(e->'Registration'->>'DeleteBy')::timestamptz AND (v->>'ReservedBytes')::bigint=a.reserved_bytes AND
  (i->>'WriteUntil')::timestamptz<=c.deadline,false);
END $$;
-- +goose StatementEnd
ALTER TABLE context_capture DROP COLUMN group_id;
ALTER TABLE context_capture DROP COLUMN group_ordinal;
DROP TABLE recording_save_group;
DROP FUNCTION guard_recording_save_group();
ALTER TABLE context_preview DROP CONSTRAINT context_preview_kind_attempt;
ALTER TABLE context_preview ALTER COLUMN attempt_id SET NOT NULL;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_preview_read_until(p_root uuid,p_preview uuid) RETURNS timestamptz
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT GREATEST(p.deadline,COALESCE((SELECT GREATEST(g.review_until,g.expires_at)
 FROM public.access_grant g WHERE g.root_id=p.root_id AND g.preview_id=p.id
 AND g.capture_id=p.capture_id
 AND g.scope=decode(convert_from(p.blueprint_json,'UTF8')::jsonb->>'CanonicalScope','base64')
 AND g.requester_issuer=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'Issuer'
 AND g.requester_subject=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'Subject'
 AND g.requester_client=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'ClientID'),p.deadline))
 FROM public.context_preview p WHERE p.root_id=p_root AND p.id=p_preview
$$;
-- +goose StatementEnd
ALTER TABLE context_preview DROP COLUMN preview_kind;
