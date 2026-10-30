-- +goose Up
-- Passive opaque selection sets share the existing preview root/principal
-- counts and credential. One bounded row covers up to100 recording references.
CREATE TABLE recording_selection_set (
 id uuid PRIMARY KEY,
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 actor_key bytea NOT NULL CHECK(octet_length(actor_key)=32),
 principal_key bytea NOT NULL CHECK(octet_length(principal_key)=32),
 cluster_id uuid NOT NULL,
 namespace_uid text NOT NULL CHECK(length(namespace_uid) BETWEEN 1 AND 64),
 workload_uid text NOT NULL CHECK(length(workload_uid) BETWEEN 1 AND 64),
 policy_uid text NOT NULL DEFAULT '' CHECK(length(policy_uid)<=64),
 after_source_id uuid,
 has_more boolean NOT NULL DEFAULT false,
 CHECK(NOT has_more OR after_source_id IS NOT NULL),
 references_json bytea NOT NULL CHECK(octet_length(references_json) BETWEEN 2 AND 65536),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 CHECK(isfinite(created_at) AND isfinite(expires_at) AND created_at>='2020-01-01' AND expires_at<'10000-01-01'),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '60 seconds')
);
CREATE INDEX recording_selection_expiry ON recording_selection_set(root_id,expires_at,id);
CREATE INDEX recording_selection_principal ON recording_selection_set(root_id,principal_key,expires_at);
-- +goose StatementBegin
CREATE FUNCTION guard_recording_selection_set() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' OR OLD.expires_at>clock_timestamp() THEN
  RAISE EXCEPTION 'live recording selection is immutable' USING ERRCODE='23514';
 END IF;
 RETURN OLD;
END $$;
-- +goose StatementEnd
CREATE TRIGGER recording_selection_guard BEFORE UPDATE OR DELETE ON recording_selection_set FOR EACH ROW EXECUTE FUNCTION guard_recording_selection_set();
REVOKE ALL ON FUNCTION guard_recording_selection_set() FROM PUBLIC;

-- One charged manual save uses a capture-linked reservation, not a fake
-- detector occurrence. Counter spend remains in the existing accepted policy
-- and grant accounts; deleting this metadata cannot refund those accounts.
CREATE TABLE recording_save_reservation (
 capture_id uuid PRIMARY KEY REFERENCES context_capture(id) ON DELETE CASCADE,
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 policy_uid text NOT NULL CHECK(octet_length(policy_uid) BETWEEN 1 AND 64),
 acceptance_id uuid NOT NULL REFERENCES policy_acceptance(id),
 grant_id uuid REFERENCES access_grant(id),
 reserved_bytes bigint NOT NULL CHECK(reserved_bytes BETWEEN 65536 AND 8388608),
 accepted_at timestamptz NOT NULL,
 processing_until timestamptz NOT NULL,
 CHECK(isfinite(accepted_at) AND isfinite(processing_until) AND processing_until>accepted_at)
);
-- +goose StatementBegin
CREATE FUNCTION guard_recording_save_reservation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'manual save reservation is immutable' USING ERRCODE='23514'; END $$;
-- +goose StatementEnd
CREATE TRIGGER recording_save_reservation_immutable BEFORE UPDATE ON recording_save_reservation FOR EACH ROW EXECUTE FUNCTION guard_recording_save_reservation();
REVOKE ALL ON FUNCTION guard_recording_save_reservation() FROM PUBLIC;

-- Manual initiation is independently bound without changing acquisition identity.
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
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION claim_policy_capture_share() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s jsonb; policy text; src public.policy_source; acc public.policy_acceptance; i jsonb; at timestamptz:=clock_timestamp();
BEGIN
 IF TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_capture'::regclass THEN
  RAISE EXCEPTION 'invalid policy share source' USING ERRCODE='23514';
 END IF;
 IF NEW.share_instruction IS NOT NULL THEN
  RETURN NEW;
 END IF;
 s:=convert_from(NEW.scope_json,'UTF8')::jsonb;
 -- Manual saves never inherit/debit an automatic recurring sharing intent.
 IF s->>'schemaVersion'='recording-save/v1' AND s->>'operation'='recordingSave' THEN RETURN NEW; END IF;
 IF s#>>'{executor,identityType}' IS DISTINCT FROM 'workload' OR s#>>'{executor,clientID}' IS DISTINCT FROM 'policy-executor' OR s#>>'{executor,subject}' NOT LIKE 'policy:%' THEN
  RETURN NEW;
 END IF;
 policy:=substr(s#>>'{executor,subject}',8);
 SELECT * INTO src FROM public.policy_source WHERE root_id=NEW.root_id AND policy_uid=policy;
 IF NOT FOUND OR src.active_id IS NULL OR src.deleted OR src.suspended THEN
  RETURN NEW;
 END IF;
 UPDATE public.policy_acceptance a SET shares_spent=a.shares_spent+1
 WHERE a.id=src.active_id AND a.root_id=NEW.root_id AND a.policy_uid=policy AND a.record ? 'Sharing' AND a.sharing_revoked_at IS NULL AND a.sharing_stopped_at IS NULL
  AND a.generation=src.generation AND a.shares_spent<(a.record#>>'{Sharing,MaxCaptures}')::integer AND (a.record#>>'{Sharing,NotAfter}')::timestamptz>at
 RETURNING * INTO acc;
 IF NOT FOUND THEN
  RETURN NEW;
 END IF;
 i:=acc.record->'Sharing';
 NEW.share_instruction:=jsonb_build_object(
  'share_id',gen_random_uuid(),
  'creator',jsonb_build_object('issuer',i#>>'{Creator,Issuer}','subject',i#>>'{Creator,Subject}','client',i#>>'{Creator,ClientID}'),
  'management',i->'Management',
  'recipients',(SELECT jsonb_agg(jsonb_build_object('kind',r->>'Kind','issuer',r->>'Issuer','id',r->>'ID') ORDER BY n) FROM jsonb_array_elements(i->'Recipients') WITH ORDINALITY x(r,n)),
  'recipient_keys',(SELECT jsonb_agg((r->>'Kind')||E'\n'||(r->>'Issuer')||E'\n'||(r->>'ID') ORDER BY n) FROM jsonb_array_elements(i->'Recipients') WITH ORDINALITY x(r,n)),
  'not_after',i->'NotAfter',
  'request_digest',encode(sha256(convert_to('policy-share/v1:'||acc.id::text||':'||NEW.id::text,'UTF8')),'hex'),
  'policy_acceptance_id',acc.id);
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION fill_context_capture_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE e jsonb;s jsonb;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.history_cluster_id,NEW.history_namespace_uid,NEW.history_workload_uid,NEW.history_origin) IS DISTINCT FROM ROW(OLD.history_cluster_id,OLD.history_namespace_uid,OLD.history_workload_uid,OLD.history_origin) THEN
   RAISE EXCEPTION 'capture history identity is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 -- Caller-supplied values are ignored: the accepted record is the only source.
 e:=convert_from(NEW.expectation_json,'UTF8')::jsonb;
 s:=convert_from(NEW.scope_json,'UTF8')::jsonb;
 NEW.history_cluster_id:=(e#>>'{Registration,Location,ClusterID}')::uuid;
 NEW.history_namespace_uid:=e->>'NamespaceUID';
 NEW.history_workload_uid:=e->>'WorkloadUID';
 -- capture_audit_actor_valid admits only a human or the policy executor.
 NEW.history_origin:=CASE WHEN s->>'schemaVersion'='recording-save/v1' AND s->>'operation'='recordingSave' THEN 'manual' WHEN s#>>'{executor,identityType}'='human' THEN 'manual' ELSE 'policy' END;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- Two existing-source operations reuse the normal bounded context audit lane.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant') THEN 'normal' ELSE NULL END
$$;
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format='capture-intent/v2'
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd

-- Restrictive capture-only cancellation is retained on the existing capture.
-- It neither stops its source nor refunds uncertain acquisition/storage spend.
ALTER TABLE context_capture ADD COLUMN snapshot_cancel_key bytea;
ALTER TABLE context_capture ADD COLUMN snapshot_cancel_actor bytea;
ALTER TABLE context_capture ADD COLUMN snapshot_cancel_requested_at timestamptz;
ALTER TABLE context_capture ADD COLUMN snapshot_cancel_joined_at timestamptz;
ALTER TABLE context_capture ADD COLUMN snapshot_cancel_proof bytea;
ALTER TABLE context_capture ADD COLUMN snapshot_cancel_proof_digest bytea;
ALTER TABLE context_capture ADD CONSTRAINT snapshot_cancel_shape CHECK (
 (snapshot_cancel_key IS NULL AND snapshot_cancel_actor IS NULL AND snapshot_cancel_requested_at IS NULL AND snapshot_cancel_joined_at IS NULL AND snapshot_cancel_proof IS NULL AND snapshot_cancel_proof_digest IS NULL) OR
 (snapshot_cancel_key IS NOT NULL AND octet_length(snapshot_cancel_key)=32 AND snapshot_cancel_actor IS NOT NULL AND octet_length(snapshot_cancel_actor) BETWEEN 1 AND 8192 AND snapshot_cancel_requested_at IS NOT NULL AND isfinite(snapshot_cancel_requested_at) AND
 (snapshot_cancel_joined_at IS NULL AND snapshot_cancel_proof IS NULL AND snapshot_cancel_proof_digest IS NULL OR snapshot_cancel_joined_at IS NOT NULL AND isfinite(snapshot_cancel_joined_at) AND
  (snapshot_cancel_proof IS NULL AND snapshot_cancel_proof_digest IS NULL OR snapshot_cancel_proof IS NOT NULL AND octet_length(snapshot_cancel_proof) BETWEEN 1 AND 8192 AND snapshot_cancel_proof_digest IS NOT NULL AND octet_length(snapshot_cancel_proof_digest)=32))));
-- +goose StatementBegin
CREATE FUNCTION guard_snapshot_cancel() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.snapshot_cancel_key IS NOT NULL THEN RAISE EXCEPTION 'cancellation follows committed acceptance' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.snapshot_cancel_key,NEW.snapshot_cancel_actor,NEW.snapshot_cancel_requested_at) IS DISTINCT FROM ROW(OLD.snapshot_cancel_key,OLD.snapshot_cancel_actor,OLD.snapshot_cancel_requested_at) THEN
  IF OLD.snapshot_cancel_key IS NOT NULL OR NEW.snapshot_cancel_key IS NULL OR jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Snapshot') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'immutable cancellation request' USING ERRCODE='23514';END IF;
  NEW.snapshot_cancel_requested_at:=clock_timestamp();
 END IF;
 IF ROW(NEW.snapshot_cancel_joined_at,NEW.snapshot_cancel_proof,NEW.snapshot_cancel_proof_digest) IS DISTINCT FROM ROW(OLD.snapshot_cancel_joined_at,OLD.snapshot_cancel_proof,OLD.snapshot_cancel_proof_digest) THEN
  IF OLD.snapshot_cancel_joined_at IS NOT NULL OR NEW.snapshot_cancel_joined_at IS NULL OR NEW.snapshot_cancel_joined_at>clock_timestamp() THEN RAISE EXCEPTION 'immutable cancellation completion' USING ERRCODE='23514';END IF;
  IF NEW.snapshot_cancel_proof IS NULL THEN
   IF EXISTS(SELECT 1 FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id AND started_at IS NOT NULL) THEN RAISE EXCEPTION 'started cancellation needs joined proof' USING ERRCODE='23514';END IF;
  ELSIF NOT EXISTS(SELECT 1 FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id AND phase='cancelled') THEN RAISE EXCEPTION 'cancellation lacks joined execution' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION bump_snapshot_cancel_progress() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'UPDATE' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_capture'::regclass THEN RAISE EXCEPTION 'invalid cancellation progress source' USING ERRCODE='23514';END IF;
 IF ROW(NEW.snapshot_cancel_requested_at,NEW.snapshot_cancel_joined_at) IS DISTINCT FROM ROW(OLD.snapshot_cancel_requested_at,OLD.snapshot_cancel_joined_at) THEN
  UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE root_id=NEW.root_id AND id=NEW.id;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_snapshot_cancel(),bump_snapshot_cancel_progress() FROM PUBLIC;
CREATE TRIGGER snapshot_cancel_guard BEFORE INSERT OR UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION guard_snapshot_cancel();
CREATE TRIGGER snapshot_cancel_progress AFTER UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION bump_snapshot_cancel_progress();

ALTER TABLE context_execution DROP CONSTRAINT context_execution_phase_check,
 ADD CONSTRAINT context_execution_phase_check CHECK(phase IN ('prepared','started','stored','captureFailed','targetGone','denied','storeUnconfirmed','cancelled'));
-- context_execution_check is the not_after bound (it also names not_before);
-- the row-shape rule is the second unnamed check.
ALTER TABLE context_execution DROP CONSTRAINT context_execution_check1,
 ADD CONSTRAINT context_execution_check1 CHECK(COALESCE((phase='prepared' AND started_at IS NULL AND acquired_at IS NULL AND completed_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR phase='started' AND object_uid IS NOT NULL AND started_at>=not_before AND started_at<not_after AND acquired_at IS NULL AND completed_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR phase IN ('stored','captureFailed','targetGone','denied','storeUnconfirmed','cancelled') AND object_uid IS NOT NULL AND started_at>=not_before AND started_at<not_after AND isfinite(completed_at) AND completed_at>=started_at AND
 (phase IN ('captureFailed','targetGone','denied','cancelled') AND acquired_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR acquired_at>=started_at AND acquired_at<not_after AND completed_at>=acquired_at AND
 (phase='stored' AND copies_json IS NOT NULL AND copies_digest IS NOT NULL OR phase='storeUnconfirmed' AND copies_json IS NULL AND copies_digest IS NULL))),false));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_execution() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'context execution deletion requires retention protocol' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF EXISTS(SELECT 1 FROM public.context_capture WHERE root_id=NEW.root_id AND id=NEW.capture_id AND snapshot_cancel_requested_at IS NOT NULL) THEN RAISE EXCEPTION 'capture cancellation fences preparation' USING ERRCODE='23514';END IF;
  IF NEW.phase<>'prepared' OR NEW.object_uid IS NOT NULL OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL OR clock_timestamp()>=NEW.not_after THEN
   RAISE EXCEPTION 'invalid first context preparation' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.capture_id,NEW.root_id,NEW.attempt_id,NEW.binding_json,NEW.process_json,NEW.expectation_digest,NEW.created_at,NEW.not_before,NEW.not_after)
 IS DISTINCT FROM ROW(OLD.capture_id,OLD.root_id,OLD.attempt_id,OLD.binding_json,OLD.process_json,OLD.expectation_digest,OLD.created_at,OLD.not_before,OLD.not_after) THEN
  RAISE EXCEPTION 'immutable context execution identity' USING ERRCODE='23514';
 END IF;
 IF OLD.object_uid IS NOT NULL AND NEW.object_uid IS DISTINCT FROM OLD.object_uid OR OLD.object_uid IS NULL AND NEW.object_uid IS NOT NULL AND (OLD.phase<>'prepared' OR NEW.phase<>'prepared' OR clock_timestamp()>=OLD.not_after) THEN
  RAISE EXCEPTION 'immutable context start object' USING ERRCODE='23514';
 END IF;
 IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 IF OLD.phase='prepared' AND NEW.phase='prepared' AND OLD.object_uid IS NULL AND NEW.object_uid IS NOT NULL THEN RETURN NEW; END IF;
 IF OLD.phase='prepared' AND NEW.phase='started' AND EXISTS(SELECT 1 FROM public.context_capture WHERE root_id=NEW.root_id AND id=NEW.capture_id AND snapshot_cancel_requested_at IS NOT NULL) THEN RAISE EXCEPTION 'capture cancellation fences start' USING ERRCODE='23514';END IF;
 IF OLD.phase='prepared' AND NEW.phase='started' AND OLD.object_uid IS NOT NULL AND NEW.started_at<=clock_timestamp() AND clock_timestamp()<OLD.not_after THEN RETURN NEW; END IF;
 IF OLD.phase='started' AND NEW.phase IN ('stored','captureFailed','targetGone','denied','storeUnconfirmed','cancelled') AND NEW.started_at=OLD.started_at AND NEW.completed_at<=clock_timestamp() THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'context execution cannot repeat or rewrite result' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd

-- Cancellation completion is a separate positive join, never a plain failure.
-- +goose StatementBegin
CREATE FUNCTION require_snapshot_cancel_proof() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'UPDATE' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_execution'::regclass THEN RAISE EXCEPTION 'invalid cancellation execution source' USING ERRCODE='23514';END IF;
 IF NEW.phase='cancelled' AND NOT EXISTS(SELECT 1 FROM public.context_capture c WHERE c.root_id=NEW.root_id AND c.id=NEW.capture_id AND c.snapshot_cancel_requested_at IS NOT NULL AND c.snapshot_cancel_joined_at IS NOT NULL AND c.snapshot_cancel_proof IS NOT NULL AND c.snapshot_cancel_proof_digest=sha256(c.snapshot_cancel_proof)) THEN RAISE EXCEPTION 'cancelled execution lacks exact joined proof' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_snapshot_cancel_proof() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER snapshot_cancel_execution_proof AFTER UPDATE ON context_execution DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_snapshot_cancel_proof();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN IF EXISTS(SELECT 1 FROM context_capture WHERE snapshot_cancel_requested_at IS NOT NULL) OR EXISTS(SELECT 1 FROM context_execution WHERE phase='cancelled') OR EXISTS(SELECT 1 FROM recording_save_reservation) OR EXISTS(SELECT 1 FROM recording_selection_set WHERE expires_at>clock_timestamp()) THEN RAISE EXCEPTION 'live manual save control prevents downgrade'; END IF; END $$;
-- +goose StatementEnd
DROP TRIGGER snapshot_cancel_execution_proof ON context_execution;
DROP FUNCTION require_snapshot_cancel_proof();
DROP TRIGGER snapshot_cancel_progress ON context_capture;
DROP TRIGGER snapshot_cancel_guard ON context_capture;
DROP FUNCTION bump_snapshot_cancel_progress(),guard_snapshot_cancel();
ALTER TABLE context_capture DROP CONSTRAINT snapshot_cancel_shape;
ALTER TABLE context_capture DROP COLUMN snapshot_cancel_key,DROP COLUMN snapshot_cancel_actor,DROP COLUMN snapshot_cancel_requested_at,DROP COLUMN snapshot_cancel_joined_at,DROP COLUMN snapshot_cancel_proof,DROP COLUMN snapshot_cancel_proof_digest;
DROP TABLE recording_save_reservation;
DROP FUNCTION guard_recording_save_reservation();
DROP TABLE recording_selection_set;
DROP FUNCTION guard_recording_selection_set();

-- Restore the prior exact payload/share rules only after manual rows retire.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capture_audit_payload_matches(c public.context_capture,i jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE v jsonb:=i->'Capture';e jsonb:=convert_from(c.expectation_json,'UTF8')::jsonb;s jsonb:=convert_from(c.scope_json,'UTF8')::jsonb;a public.custody_attempt;
BEGIN
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=c.attempt_id;
 RETURN COALESCE(i->>'Name'='persist_capture_intent' AND i->>'InputFormat'='capture-intent/v2' AND NOT(i ? 'Peer') AND NOT(i ? 'Process') AND
  jsonb_typeof(v)='object' AND (v-ARRAY['RootID','CaptureID','CaseID','OccurrenceID','ArtifactID','AttemptID','Actor','Target','ScopeDigest','SubmissionDigest','ExpectationDigest','PermissionEpoch','PermissionSequence','IdentityRevision','CreatedAt','Deadline','ExpiresAt','DeleteBy','ReservedBytes'])='{}'::jsonb AND
  (i->>'ID')::uuid=c.id AND (i->>'RootID')::uuid=c.root_id AND (i->>'TraceID')::uuid=(e->>'OccurrenceID')::uuid AND
  (v->>'RootID')::uuid=c.root_id AND (v->>'CaptureID')::uuid=c.id AND (v->>'AttemptID')::uuid=c.attempt_id AND
  v->>'CaseID'=e->>'CaseID' AND v->>'OccurrenceID'=e->>'OccurrenceID' AND v->>'ArtifactID'=e->'Registration'->'Location'->>'ArtifactID' AND
  v->'Actor'=i->'Actor' AND v->'Actor'=jsonb_build_object('Issuer',s#>>'{executor,issuer}','Subject',s#>>'{executor,subject}','ClientID',s#>>'{executor,clientID}','Kind',s#>>'{executor,identityType}') AND public.capture_audit_actor_valid(v->'Actor') AND
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
CREATE OR REPLACE FUNCTION claim_policy_capture_share() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s jsonb; policy text; src public.policy_source; acc public.policy_acceptance; i jsonb; at timestamptz:=clock_timestamp();
BEGIN
 IF TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_capture'::regclass THEN
  RAISE EXCEPTION 'invalid policy share source' USING ERRCODE='23514';
 END IF;
 IF NEW.share_instruction IS NOT NULL THEN
  RETURN NEW;
 END IF;
 s:=convert_from(NEW.scope_json,'UTF8')::jsonb;
 IF s#>>'{executor,identityType}' IS DISTINCT FROM 'workload' OR s#>>'{executor,clientID}' IS DISTINCT FROM 'policy-executor' OR s#>>'{executor,subject}' NOT LIKE 'policy:%' THEN
  RETURN NEW;
 END IF;
 policy:=substr(s#>>'{executor,subject}',8);
 SELECT * INTO src FROM public.policy_source WHERE root_id=NEW.root_id AND policy_uid=policy;
 IF NOT FOUND OR src.active_id IS NULL OR src.deleted OR src.suspended THEN
  RETURN NEW;
 END IF;
 UPDATE public.policy_acceptance a SET shares_spent=a.shares_spent+1
 WHERE a.id=src.active_id AND a.root_id=NEW.root_id AND a.policy_uid=policy AND a.record ? 'Sharing' AND a.sharing_revoked_at IS NULL AND a.sharing_stopped_at IS NULL
  AND a.generation=src.generation AND a.shares_spent<(a.record#>>'{Sharing,MaxCaptures}')::integer AND (a.record#>>'{Sharing,NotAfter}')::timestamptz>at
 RETURNING * INTO acc;
 IF NOT FOUND THEN
  RETURN NEW;
 END IF;
 i:=acc.record->'Sharing';
 NEW.share_instruction:=jsonb_build_object(
  'share_id',gen_random_uuid(),
  'creator',jsonb_build_object('issuer',i#>>'{Creator,Issuer}','subject',i#>>'{Creator,Subject}','client',i#>>'{Creator,ClientID}'),
  'management',i->'Management',
  'recipients',(SELECT jsonb_agg(jsonb_build_object('kind',r->>'Kind','issuer',r->>'Issuer','id',r->>'ID') ORDER BY n) FROM jsonb_array_elements(i->'Recipients') WITH ORDINALITY x(r,n)),
  'recipient_keys',(SELECT jsonb_agg((r->>'Kind')||E'\n'||(r->>'Issuer')||E'\n'||(r->>'ID') ORDER BY n) FROM jsonb_array_elements(i->'Recipients') WITH ORDINALITY x(r,n)),
  'not_after',i->'NotAfter',
  'request_digest',encode(sha256(convert_to('policy-share/v1:'||acc.id::text||':'||NEW.id::text,'UTF8')),'hex'),
  'policy_acceptance_id',acc.id);
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION fill_context_capture_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE e jsonb;s jsonb;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.history_cluster_id,NEW.history_namespace_uid,NEW.history_workload_uid,NEW.history_origin) IS DISTINCT FROM ROW(OLD.history_cluster_id,OLD.history_namespace_uid,OLD.history_workload_uid,OLD.history_origin) THEN
   RAISE EXCEPTION 'capture history identity is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 -- Caller-supplied values are ignored: the accepted record is the only source.
 e:=convert_from(NEW.expectation_json,'UTF8')::jsonb;
 s:=convert_from(NEW.scope_json,'UTF8')::jsonb;
 NEW.history_cluster_id:=(e#>>'{Registration,Location,ClusterID}')::uuid;
 NEW.history_namespace_uid:=e->>'NamespaceUID';
 NEW.history_workload_uid:=e->>'WorkloadUID';
 -- capture_audit_actor_valid admits only a human or the policy executor.
 NEW.history_origin:=CASE WHEN s#>>'{executor,identityType}'='human' THEN 'manual' ELSE 'policy' END;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- Restore the exact latest pre-manual operation union.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant') THEN 'normal' ELSE NULL END
$$;
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format='capture-intent/v2'
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd

ALTER TABLE context_execution DROP CONSTRAINT context_execution_phase_check,
 ADD CONSTRAINT context_execution_phase_check CHECK(phase IN ('prepared','started','stored','captureFailed','targetGone','denied','storeUnconfirmed'));
-- context_execution_check is the not_after bound (it also names not_before);
-- the row-shape rule is the second unnamed check.
ALTER TABLE context_execution DROP CONSTRAINT context_execution_check1,
 ADD CONSTRAINT context_execution_check1 CHECK(COALESCE((phase='prepared' AND started_at IS NULL AND acquired_at IS NULL AND completed_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR phase='started' AND object_uid IS NOT NULL AND started_at>=not_before AND started_at<not_after AND acquired_at IS NULL AND completed_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR phase IN ('stored','captureFailed','targetGone','denied','storeUnconfirmed') AND object_uid IS NOT NULL AND started_at>=not_before AND started_at<not_after AND isfinite(completed_at) AND completed_at>=started_at AND
 (phase IN ('captureFailed','targetGone','denied') AND acquired_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR acquired_at>=started_at AND acquired_at<not_after AND completed_at>=acquired_at AND
 (phase='stored' AND copies_json IS NOT NULL AND copies_digest IS NOT NULL OR phase='storeUnconfirmed' AND copies_json IS NULL AND copies_digest IS NULL))),false));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_execution() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'context execution deletion requires retention protocol' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.phase<>'prepared' OR NEW.object_uid IS NOT NULL OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL OR clock_timestamp()>=NEW.not_after THEN
   RAISE EXCEPTION 'invalid first context preparation' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.capture_id,NEW.root_id,NEW.attempt_id,NEW.binding_json,NEW.process_json,NEW.expectation_digest,NEW.created_at,NEW.not_before,NEW.not_after)
 IS DISTINCT FROM ROW(OLD.capture_id,OLD.root_id,OLD.attempt_id,OLD.binding_json,OLD.process_json,OLD.expectation_digest,OLD.created_at,OLD.not_before,OLD.not_after) THEN
  RAISE EXCEPTION 'immutable context execution identity' USING ERRCODE='23514';
 END IF;
 IF OLD.object_uid IS NOT NULL AND NEW.object_uid IS DISTINCT FROM OLD.object_uid OR OLD.object_uid IS NULL AND NEW.object_uid IS NOT NULL AND (OLD.phase<>'prepared' OR NEW.phase<>'prepared' OR clock_timestamp()>=OLD.not_after) THEN
  RAISE EXCEPTION 'immutable context start object' USING ERRCODE='23514';
 END IF;
 IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 IF OLD.phase='prepared' AND NEW.phase='prepared' AND OLD.object_uid IS NULL AND NEW.object_uid IS NOT NULL THEN RETURN NEW; END IF;
 IF OLD.phase='prepared' AND NEW.phase='started' AND OLD.object_uid IS NOT NULL AND NEW.started_at<=clock_timestamp() AND clock_timestamp()<OLD.not_after THEN RETURN NEW; END IF;
 IF OLD.phase='started' AND NEW.phase IN ('stored','captureFailed','targetGone','denied','storeUnconfirmed') AND NEW.started_at=OLD.started_at AND NEW.completed_at<=clock_timestamp() THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'context execution cannot repeat or rewrite result' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd

