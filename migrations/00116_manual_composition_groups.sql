-- +goose Up
-- ADR-276: a manual packet + syscall composition is a reviewed group of single
-- manual recordings. The ADR-266 group gains a kind; a composition group has
-- no policy, and each member keeps its own scope, listed in the parent's
-- recorder-group/v1 scope. Every recordingSave path is unchanged.
ALTER TABLE context_preview DROP CONSTRAINT context_preview_preview_kind_check;
ALTER TABLE context_preview ADD CONSTRAINT context_preview_preview_kind_check CHECK(preview_kind IN ('context','recordingSaveGroup','compositionGroup'));
ALTER TABLE context_preview DROP CONSTRAINT context_preview_kind_attempt;
ALTER TABLE context_preview ADD CONSTRAINT context_preview_kind_attempt CHECK
 ((preview_kind='context' AND attempt_id IS NOT NULL) OR
  (preview_kind IN ('recordingSaveGroup','compositionGroup') AND attempt_id IS NULL));
ALTER TABLE recording_save_group ADD COLUMN group_kind text NOT NULL DEFAULT 'recordingSave' CHECK(group_kind IN ('recordingSave','composition'));
ALTER TABLE recording_save_group ALTER COLUMN policy_uid DROP NOT NULL;
ALTER TABLE recording_save_group ALTER COLUMN acceptance_id DROP NOT NULL;
ALTER TABLE recording_save_group ADD CONSTRAINT recording_save_group_kind_policy CHECK
 ((group_kind='recordingSave' AND policy_uid IS NOT NULL AND acceptance_id IS NOT NULL) OR
  (group_kind='composition' AND policy_uid IS NULL AND acceptance_id IS NULL));

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION require_recording_save_group_members() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE g public.recording_save_group; member record; n integer:=0; e jsonb; s jsonb;
BEGIN
 SELECT * INTO STRICT g FROM public.recording_save_group WHERE id=NEW.id;
 s:=convert_from(g.scope_json,'UTF8')::jsonb;
 IF g.group_kind='composition' THEN
  -- ADR-276: each member is one single manual recording under its own scope,
  -- listed with that scope's digest in the recorder-group/v1 parent.
  IF s->>'schemaVersion' IS DISTINCT FROM 'recorder-group/v1' OR s->>'captureID' IS DISTINCT FROM g.id::text OR
     jsonb_typeof(s->'children') IS DISTINCT FROM 'array' OR jsonb_array_length(s->'children')<>cardinality(g.child_ids) THEN
   RAISE EXCEPTION 'group selection differs from accepted scope' USING ERRCODE='23514';
  END IF;
  FOR member IN SELECT c.*,a.allocation_id AS actual_allocation FROM public.context_capture c
   JOIN public.custody_attempt a ON a.id=c.attempt_id WHERE c.group_id=g.id ORDER BY c.group_ordinal LOOP
   e:=convert_from(member.expectation_json,'UTF8')::jsonb;
   IF member.root_id<>g.root_id OR member.group_ordinal<>n OR member.id<>g.child_ids[n+1] OR
      s->'children'->n->>'captureID' IS DISTINCT FROM member.id::text OR
      s->'children'->n->>'scopeDigest' IS DISTINCT FROM encode(member.scope_digest,'hex') OR
      sha256(member.scope_json)<>member.scope_digest OR member.created_at<>g.accepted_at OR
      member.deadline>g.deadline OR member.actual_allocation<>g.allocation_id OR jsonb_typeof(e->'Recording') IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'incomplete or substituted group member' USING ERRCODE='23514';
   END IF;
   n:=n+1;
  END LOOP;
  IF n<>cardinality(g.child_ids) THEN RAISE EXCEPTION 'incomplete composition group' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_capture_group() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE g public.recording_save_group;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.group_id,NEW.group_ordinal) IS DISTINCT FROM ROW(OLD.group_id,OLD.group_ordinal) THEN
   RAISE EXCEPTION 'immutable group membership' USING ERRCODE='23514';
  END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM public.recording_save_group WHERE id=NEW.id OR (root_id=NEW.root_id AND request_key=NEW.request_key)) THEN
   RAISE EXCEPTION 'request key already belongs to a group' USING ERRCODE='23514';
  END IF;
  IF NEW.group_id IS NOT NULL THEN
   SELECT * INTO g FROM public.recording_save_group WHERE root_id=NEW.root_id AND id=NEW.group_id;
   IF NOT FOUND OR g.child_ids[NEW.group_ordinal+1] IS DISTINCT FROM NEW.id OR g.accepted_at IS DISTINCT FROM NEW.created_at OR
      (g.group_kind='recordingSave' AND (g.scope_digest IS DISTINCT FROM NEW.scope_digest OR g.scope_json IS DISTINCT FROM NEW.scope_json)) OR
      (g.group_kind='composition' AND convert_from(g.scope_json,'UTF8')::jsonb->'children'->NEW.group_ordinal->>'scopeDigest' IS DISTINCT FROM encode(NEW.scope_digest,'hex')) THEN
    RAISE EXCEPTION 'unlisted group member' USING ERRCODE='23514';
   END IF;
  END IF;
  IF convert_from(NEW.expectation_json,'UTF8')::jsonb ? 'Snapshot' AND (convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz>NEW.created_at+interval '5 seconds' AND NOT public.recording_save_group_window_valid(NEW,g,(convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz) THEN
   RAISE EXCEPTION 'long snapshot window requires exact protected manual group' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capture_audit_payload_matches_without_reason(c public.context_capture,i jsonb) RETURNS boolean
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
   (v->'Group'->>'ChildCount')::integer=(SELECT cardinality(g.child_ids) FROM public.recording_save_group g WHERE g.id=c.group_id AND g.root_id=c.root_id) AND
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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_preview_read_until(p_root uuid,p_preview uuid) RETURNS timestamptz
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT GREATEST(p.deadline,COALESCE((SELECT GREATEST(g.review_until,g.expires_at)
 FROM public.access_grant g WHERE p.preview_kind IN ('context','compositionGroup') AND g.root_id=p.root_id AND g.preview_id=p.id
 AND g.capture_id=p.capture_id
 AND g.scope=decode(convert_from(p.blueprint_json,'UTF8')::jsonb->>'CanonicalScope','base64')
 AND g.requester_issuer=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'Issuer'
 AND g.requester_subject=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'Subject'
 AND g.requester_client=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'ClientID'),p.deadline))
 FROM public.context_preview p WHERE p.root_id=p_root AND p.id=p_preview
$$;
-- +goose StatementEnd

-- +goose Down
-- Refuse while composition groups exist; then restore the 00109/00110/00112 definitions.
-- +goose StatementBegin
DO $$ BEGIN IF EXISTS(SELECT 1 FROM recording_save_group WHERE group_kind='composition') OR EXISTS(SELECT 1 FROM context_preview WHERE preview_kind='compositionGroup') THEN RAISE EXCEPTION 'composition groups must be retired before downgrade'; END IF; END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION require_recording_save_group_members() RETURNS trigger LANGUAGE plpgsql
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
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_capture_group() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE g public.recording_save_group;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.group_id,NEW.group_ordinal) IS DISTINCT FROM ROW(OLD.group_id,OLD.group_ordinal) THEN
   RAISE EXCEPTION 'immutable group membership' USING ERRCODE='23514';
  END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM public.recording_save_group WHERE id=NEW.id OR (root_id=NEW.root_id AND request_key=NEW.request_key)) THEN
   RAISE EXCEPTION 'request key already belongs to a group' USING ERRCODE='23514';
  END IF;
  IF NEW.group_id IS NOT NULL THEN
   SELECT * INTO g FROM public.recording_save_group WHERE root_id=NEW.root_id AND id=NEW.group_id;
   IF NOT FOUND OR g.child_ids[NEW.group_ordinal+1] IS DISTINCT FROM NEW.id OR
      g.scope_digest IS DISTINCT FROM NEW.scope_digest OR g.scope_json IS DISTINCT FROM NEW.scope_json OR g.accepted_at IS DISTINCT FROM NEW.created_at THEN
    RAISE EXCEPTION 'unlisted group member' USING ERRCODE='23514';
   END IF;
  END IF;
  IF convert_from(NEW.expectation_json,'UTF8')::jsonb ? 'Snapshot' AND (convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz>NEW.created_at+interval '5 seconds' AND NOT public.recording_save_group_window_valid(NEW,g,(convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz) THEN
   RAISE EXCEPTION 'long snapshot window requires exact protected manual group' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capture_audit_payload_matches_without_reason(c public.context_capture,i jsonb) RETURNS boolean
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
ALTER TABLE recording_save_group DROP CONSTRAINT recording_save_group_kind_policy;
ALTER TABLE recording_save_group ALTER COLUMN acceptance_id SET NOT NULL;
ALTER TABLE recording_save_group ALTER COLUMN policy_uid SET NOT NULL;
ALTER TABLE recording_save_group DROP COLUMN group_kind;
ALTER TABLE context_preview DROP CONSTRAINT context_preview_kind_attempt;
ALTER TABLE context_preview ADD CONSTRAINT context_preview_kind_attempt CHECK
 ((preview_kind='context' AND attempt_id IS NOT NULL) OR
  (preview_kind='recordingSaveGroup' AND attempt_id IS NULL));
ALTER TABLE context_preview DROP CONSTRAINT context_preview_preview_kind_check;
ALTER TABLE context_preview ADD CONSTRAINT context_preview_preview_kind_check CHECK(preview_kind IN ('context','recordingSaveGroup'));
