-- +goose Up
-- New explicitly opted-in captures only. No historical receipt or GET is a
-- positive original-writer completion, and no migration adopts old obligations.
ALTER TABLE operation_audit_pool DROP CONSTRAINT operation_audit_pool_lane_check;
ALTER TABLE operation_audit_pool ADD CHECK(lane IN ('normal','resolution','identity','processing','capture'));
ALTER TABLE operation_audit_lifecycle DROP CONSTRAINT operation_audit_lifecycle_lane_check;
ALTER TABLE operation_audit_lifecycle ADD CHECK(lane IN ('normal','resolution','identity','processing','capture'));
ALTER TABLE operation_audit_history DROP CONSTRAINT operation_audit_history_lane_check;
ALTER TABLE operation_audit_history ADD CHECK(lane IN ('normal','resolution','identity','processing','capture'));
ALTER TABLE operation_audit DROP CONSTRAINT operation_audit_intent_check;
ALTER TABLE operation_audit ADD CHECK(jsonb_typeof(intent)='object' AND octet_length(intent::text)<=CASE WHEN lane='capture' THEN 16384 ELSE 8192 END);
ALTER TABLE operation_audit DROP CONSTRAINT operation_audit_outcome_check;
ALTER TABLE operation_audit ADD CHECK(outcome IS NULL OR (jsonb_typeof(outcome)='object' AND octet_length(outcome::text)<=CASE WHEN lane='capture' THEN 24576 ELSE 16384 END));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture'
 WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','initialize_processing','restrict_processing') THEN 'normal' ELSE NULL END
$$;
CREATE OR REPLACE FUNCTION operation_audit_history_layout_valid(lane text,layout text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE((lane IN ('normal','resolution') AND layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3')) OR (lane='identity' AND layout IN ('connector-operation-history/v1','connector-operation-history/v2')) OR (lane='processing' AND layout='processing-release-history/v1') OR (lane='capture' AND layout='capture-intent-history/v1'),false)
$$;
CREATE OR REPLACE FUNCTION operation_audit_history_fixed_transitions(layout text) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE layout WHEN 'operation-audit-history/v1' THEN 16 WHEN 'operation-audit-history/v2' THEN 19 WHEN 'operation-audit-history/v3' THEN 21 WHEN 'connector-operation-history/v1' THEN 32 WHEN 'connector-operation-history/v2' THEN 40 WHEN 'processing-release-history/v1' THEN 32 WHEN 'capture-intent-history/v1' THEN 32 ELSE NULL END::bigint
$$;
CREATE OR REPLACE FUNCTION operation_audit_history_verifier_backed(layout text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(layout IN ('operation-audit-history/v3','connector-operation-history/v1','connector-operation-history/v2','processing-release-history/v1','capture-intent-history/v1'),false)
$$;
CREATE OR REPLACE FUNCTION operation_audit_history_minimum_row(layout text) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN layout IN ('connector-operation-history/v1','connector-operation-history/v2') THEN 1048576 WHEN layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3','processing-release-history/v1','capture-intent-history/v1') THEN 131072 ELSE NULL END::bigint
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION operation_audit_lane(text),operation_audit_history_layout_valid(text,text),operation_audit_history_fixed_transitions(text),operation_audit_history_verifier_backed(text),operation_audit_history_minimum_row(text) FROM PUBLIC;


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name='persist_capture_intent' THEN input_format='capture-intent/v2'
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION operation_audit_human_input_valid(text,text) FROM PUBLIC;

-- Installation source acceptance owns this finite root and its exact login
-- identities. Runtime facets have no direct table write privileges. The role
-- identity is administrative provenance, never human permission or recovery.
CREATE TABLE capture_audit_root (
 root_id uuid PRIMARY KEY REFERENCES permission_stream(id),
 installation_id uuid NOT NULL,
 source_role oid NOT NULL, admission_role oid NOT NULL, journal_role oid NOT NULL,
 acknowledge_role oid NOT NULL, cleanup_role oid NOT NULL, verifier_role oid NOT NULL,
 finalizer_role oid NOT NULL, reader_role oid NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1152921504606846976),
 paused boolean NOT NULL, valid_until timestamptz NOT NULL CHECK(isfinite(valid_until)),
 CHECK(source_role<>admission_role AND source_role<>journal_role AND source_role<>acknowledge_role AND source_role<>cleanup_role AND source_role<>verifier_role AND source_role<>finalizer_role AND source_role<>reader_role)
);
CREATE TABLE capture_audit_allocation (
 root_id uuid NOT NULL REFERENCES capture_audit_root(root_id),
 allocation_id uuid NOT NULL,
 account_version text NOT NULL CHECK(length(account_version) BETWEEN 1 AND 64),
 account_digest bytea NOT NULL CHECK(octet_length(account_digest)=32),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1152921504606846976),
 paused boolean NOT NULL, valid_until timestamptz NOT NULL CHECK(isfinite(valid_until)),
 guaranteed_records bigint NOT NULL CHECK(guaranteed_records BETWEEN 1 AND 1000000),
 policy jsonb NOT NULL CHECK(jsonb_typeof(policy)='object' AND octet_length(policy::text)<=4096),
 PRIMARY KEY(root_id,allocation_id), UNIQUE(root_id,account_digest),
 FOREIGN KEY(root_id,allocation_id) REFERENCES context_control_account(root_id,allocation_id)
);
-- Equal IDs deliberately reuse the immutable server-generated capture UUID.
-- A collision with any other audit operation is an error, never adoption.
ALTER TABLE context_capture ADD COLUMN intent_operation_id uuid;
ALTER TABLE context_capture ADD CHECK(intent_operation_id IS NULL OR intent_operation_id=id);
CREATE TABLE capture_audit_binding (
 capture_id uuid PRIMARY KEY, root_id uuid NOT NULL, allocation_id uuid NOT NULL,
 operation_id uuid NOT NULL UNIQUE REFERENCES operation_audit(id) DEFERRABLE INITIALLY DEFERRED,
 capture_digest bytea NOT NULL CHECK(octet_length(capture_digest)=32),
 intent_reads smallint NOT NULL DEFAULT 0 CHECK(intent_reads BETWEEN 0 AND 2),
 outcome_reads smallint NOT NULL DEFAULT 0 CHECK(outcome_reads BETWEEN 0 AND 2),
 intent_first_until timestamptz CHECK(intent_first_until IS NULL OR isfinite(intent_first_until)),
 intent_second_until timestamptz CHECK(intent_second_until IS NULL OR isfinite(intent_second_until)),
 outcome_first_until timestamptz CHECK(outcome_first_until IS NULL OR isfinite(outcome_first_until)),
 outcome_second_until timestamptz CHECK(outcome_second_until IS NULL OR isfinite(outcome_second_until)),
 CHECK(capture_id=operation_id),
 CHECK((intent_reads=0)=(intent_first_until IS NULL)),CHECK((intent_reads<2)=(intent_second_until IS NULL)),
 CHECK((outcome_reads=0)=(outcome_first_until IS NULL)),CHECK((outcome_reads<2)=(outcome_second_until IS NULL)),
 FOREIGN KEY(capture_id,root_id) REFERENCES context_capture(id,root_id),
 FOREIGN KEY(root_id,allocation_id) REFERENCES capture_audit_allocation(root_id,allocation_id)
);
CREATE INDEX capture_audit_binding_allocation ON capture_audit_binding(root_id,allocation_id,capture_id);

-- +goose StatementBegin
CREATE FUNCTION capture_audit_role_ok(r uuid,purpose text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM public.capture_audit_root b JOIN pg_catalog.pg_roles u ON u.rolname=session_user
 WHERE b.root_id=r AND u.rolcanlogin AND NOT u.rolsuper AND NOT u.rolinherit AND NOT u.rolcreaterole AND NOT u.rolcreatedb AND NOT u.rolreplication AND NOT u.rolbypassrls
 AND u.oid=CASE purpose WHEN 'source' THEN b.source_role WHEN 'admission' THEN b.admission_role WHEN 'journal' THEN b.journal_role WHEN 'acknowledge' THEN b.acknowledge_role WHEN 'cleanup' THEN b.cleanup_role WHEN 'verifier' THEN b.verifier_role WHEN 'finalizer' THEN b.finalizer_role WHEN 'reader' THEN b.reader_role ELSE 0::oid END
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=u.oid))
$$;
CREATE FUNCTION capture_audit_login_private() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM public.capture_audit_root b JOIN pg_catalog.pg_roles u ON u.rolname=session_user
 WHERE u.oid IN(b.source_role,b.admission_role,b.journal_role,b.acknowledge_role,b.cleanup_role,b.verifier_role,b.finalizer_role,b.reader_role))
$$;
CREATE FUNCTION guard_capture_audit_root() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE roles oid[]; member_count bigint;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'capture audit root retirement unavailable' USING ERRCODE='23514';END IF;
 roles:=ARRAY[NEW.source_role,NEW.admission_role,NEW.journal_role,NEW.acknowledge_role,NEW.cleanup_role,NEW.verifier_role,NEW.finalizer_role,NEW.reader_role];
 SELECT count(DISTINCT u.oid) INTO member_count FROM pg_catalog.pg_roles u WHERE u.oid=ANY(roles) AND u.rolcanlogin AND NOT u.rolsuper AND NOT u.rolinherit AND NOT u.rolcreaterole AND NOT u.rolcreatedb AND NOT u.rolreplication AND NOT u.rolbypassrls AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=u.oid);
 IF member_count<>8 THEN RAISE EXCEPTION 'capture audit role pins unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 THEN RAISE EXCEPTION 'capture audit initial revision unavailable' USING ERRCODE='23514';END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['revision','paused','valid_until']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['revision','paused','valid_until']) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'capture audit root mutation unavailable' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capture_audit_role_ok(uuid,text),capture_audit_login_private(),guard_capture_audit_root() FROM PUBLIC;
CREATE TRIGGER capture_audit_root_guard BEFORE INSERT OR UPDATE OR DELETE ON capture_audit_root FOR EACH ROW EXECUTE FUNCTION guard_capture_audit_root();

-- +goose StatementBegin
CREATE FUNCTION guard_capture_audit_allocation() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE pool public.operation_audit_pool; control public.context_control_account; root public.capture_audit_root; n timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'capture audit allocation retirement unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=NEW.root_id;
 IF NOT public.capture_audit_role_ok(NEW.root_id,'source') THEN RAISE EXCEPTION 'capture audit source unavailable' USING ERRCODE='23514';END IF;
 -- Caller holds recovery and permission first. This guard does not acquire
 -- storage/control locks in reverse order; their accepted rows are immutable
 -- identities, and the common permission lock serializes configuration.
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='capture' FOR UPDATE;
 SELECT * INTO STRICT control FROM public.context_control_account WHERE root_id=NEW.root_id AND allocation_id=NEW.allocation_id;
 n:=clock_timestamp();
 IF n>=root.valid_until OR n>=pool.valid_until OR n>=NEW.valid_until OR NOT control.configured OR NEW.guaranteed_records<control.full_limit OR NEW.guaranteed_records>pool.records_per_account OR NEW.account_version<>pool.account_version OR
  NEW.policy->>'Lane' IS DISTINCT FROM 'capture' OR NEW.policy->'History'->>'Layout' IS DISTINCT FROM 'capture-intent-history/v1' OR (NEW.policy->>'RootID')::uuid<>NEW.root_id OR (NEW.policy->>'InstallationID')::uuid<>root.installation_id OR (NEW.policy->>'BackingRevision')::bigint<>pool.revision OR n>=(NEW.policy->>'ValidUntil')::timestamptz THEN
  RAISE EXCEPTION 'capture audit backing unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 OR (SELECT count(*) FROM public.capture_audit_allocation WHERE root_id=NEW.root_id)>=pool.account_limit THEN RAISE EXCEPTION 'capture audit account reservation exhausted' USING ERRCODE='23514';END IF;
 ELSE
  IF ROW(NEW.root_id,NEW.allocation_id,NEW.account_version,NEW.account_digest) IS DISTINCT FROM ROW(OLD.root_id,OLD.allocation_id,OLD.account_version,OLD.account_digest) OR NEW.revision<>OLD.revision+1 OR NEW.guaranteed_records<OLD.guaranteed_records THEN RAISE EXCEPTION 'capture audit account cannot reset or shrink' USING ERRCODE='23514';END IF;
  IF ((NEW.policy-ARRAY['PolicyID','PolicyDigest','BackingRevision','ValidUntil']) IS DISTINCT FROM (OLD.policy-ARRAY['PolicyID','PolicyDigest','BackingRevision','ValidUntil'])) THEN RAISE EXCEPTION 'capture audit account qualification changed' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION preserve_capture_audit_guarantees() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.lane<>'capture' THEN RETURN NEW;END IF;
 IF (SELECT count(*) FROM public.capture_audit_allocation WHERE root_id=NEW.root_id)>NEW.account_limit OR EXISTS(SELECT 1 FROM public.capture_audit_allocation WHERE root_id=NEW.root_id AND (guaranteed_records>NEW.records_per_account OR account_version<>NEW.account_version)) THEN RAISE EXCEPTION 'capture audit workload guarantees remain backed' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION guard_capture_audit_access() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r uuid;l text;source_role boolean;admit_role boolean;journal_role boolean;ack_role boolean;cleanup_role boolean;verifier_role boolean;finalizer_role boolean;completion jsonb;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_TABLE_NAME NOT IN('operation_audit_pool','operation_audit_account','operation_audit','operation_audit_lifecycle','operation_audit_history') THEN RAISE EXCEPTION 'invalid capture audit boundary' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN r:=OLD.root_id;l:=OLD.lane;ELSE r:=NEW.root_id;l:=NEW.lane;END IF;
 IF l<>'capture' THEN
  IF public.capture_audit_login_private() THEN RAISE EXCEPTION 'capture audit role cannot use other lanes' USING ERRCODE='23514';END IF;
  IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 source_role:=public.capture_audit_role_ok(r,'source');admit_role:=public.capture_audit_role_ok(r,'admission');journal_role:=public.capture_audit_role_ok(r,'journal');ack_role:=public.capture_audit_role_ok(r,'acknowledge');cleanup_role:=public.capture_audit_role_ok(r,'cleanup');verifier_role:=public.capture_audit_role_ok(r,'verifier');finalizer_role:=public.capture_audit_role_ok(r,'finalizer');
 IF TG_TABLE_NAME='operation_audit_pool' THEN
  IF NOT source_role AND NOT(pg_trigger_depth()>1 AND (admit_role OR finalizer_role)) THEN RAISE EXCEPTION 'capture audit backing role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit_account' THEN
  IF pg_trigger_depth()<2 OR NOT(admit_role OR finalizer_role) THEN RAISE EXCEPTION 'capture audit account role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit_history' THEN
  IF NOT finalizer_role THEN RAISE EXCEPTION 'capture audit history role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit' THEN
  IF TG_OP='DELETE' THEN
   IF NOT finalizer_role THEN RAISE EXCEPTION 'capture audit retirement role unavailable' USING ERRCODE='23514';END IF;
  ELSIF TG_OP='INSERT' THEN
   IF NOT admit_role OR NEW.intent->'Lifecycle'->'Policy'->'History'->>'Layout' IS DISTINCT FROM 'capture-intent-history/v1' OR NEW.intent->>'Name' IS DISTINCT FROM 'persist_capture_intent' THEN RAISE EXCEPTION 'capture audit admission role unavailable' USING ERRCODE='23514';END IF;
  ELSIF ack_role THEN
   IF (to_jsonb(NEW)-ARRAY['intent_receipt','outcome_receipt']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['intent_receipt','outcome_receipt']) THEN RAISE EXCEPTION 'capture audit acknowledgement cannot create work' USING ERRCODE='23514';END IF;
  ELSIF NOT journal_role OR ROW(NEW.intent_receipt,NEW.outcome_receipt) IS DISTINCT FROM ROW(OLD.intent_receipt,OLD.outcome_receipt) THEN RAISE EXCEPTION 'capture audit writer cannot acknowledge itself' USING ERRCODE='23514';END IF;
 ELSE
  IF TG_OP='UPDATE' THEN
   FOREACH completion IN ARRAY ARRAY[NEW.intent_completion,NEW.outcome_completion,NEW.certificate_completion] LOOP
    IF completion IS NOT NULL THEN
     PERFORM public.connector_digest(completion->'RecordDigest');
     PERFORM public.connector_digest(completion->'Receipt'->'SHA256');
    END IF;
   END LOOP;
  END IF;
  IF TG_OP='INSERT' THEN
   IF NOT admit_role OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'capture audit lifecycle admission unavailable' USING ERRCODE='23514';END IF;
  ELSIF TG_OP='DELETE' THEN
   IF NOT finalizer_role THEN RAISE EXCEPTION 'capture audit lifecycle retirement unavailable' USING ERRCODE='23514';END IF;
  ELSIF ack_role THEN
   IF (to_jsonb(NEW)-ARRAY['intent_completion','outcome_completion']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['intent_completion','outcome_completion']) THEN RAISE EXCEPTION 'capture writer acknowledgement scope unavailable' USING ERRCODE='23514';END IF;
  ELSIF verifier_role THEN
   IF (to_jsonb(NEW)-ARRAY['certificate_verify_attempts','certificate_receipt','certificate_acknowledged_at','terminal_acknowledged_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['certificate_verify_attempts','certificate_receipt','certificate_acknowledged_at','terminal_acknowledged_at']) THEN RAISE EXCEPTION 'capture verifier cannot create cleanup work' USING ERRCODE='23514';END IF;
  ELSIF finalizer_role THEN
   IF (to_jsonb(NEW)-'finalization_xid') IS DISTINCT FROM (to_jsonb(OLD)-'finalization_xid') THEN RAISE EXCEPTION 'capture finalizer cannot acknowledge cleanup' USING ERRCODE='23514';END IF;
  ELSIF cleanup_role THEN
   IF ROW(NEW.intent_completion,NEW.outcome_completion,NEW.certificate_verify_attempts,NEW.certificate_receipt,NEW.certificate_acknowledged_at,NEW.terminal_acknowledged_at,NEW.finalization_xid) IS DISTINCT FROM ROW(OLD.intent_completion,OLD.outcome_completion,OLD.certificate_verify_attempts,OLD.certificate_receipt,OLD.certificate_acknowledged_at,OLD.terminal_acknowledged_at,OLD.finalization_xid) THEN RAISE EXCEPTION 'capture cleanup cannot acknowledge itself' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'capture lifecycle role unavailable' USING ERRCODE='23514';END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_capture_audit_allocation(),preserve_capture_audit_guarantees(),guard_capture_audit_access() FROM PUBLIC;
CREATE TRIGGER capture_audit_allocation_guard BEFORE INSERT OR UPDATE OR DELETE ON capture_audit_allocation FOR EACH ROW EXECUTE FUNCTION guard_capture_audit_allocation();
CREATE TRIGGER operation_audit_pool_00_capture_reserve BEFORE UPDATE ON operation_audit_pool FOR EACH ROW EXECUTE FUNCTION preserve_capture_audit_guarantees();
CREATE TRIGGER aaa_capture_audit_access BEFORE INSERT OR UPDATE OR DELETE ON operation_audit_pool FOR EACH ROW EXECUTE FUNCTION guard_capture_audit_access();
CREATE TRIGGER aaa_capture_audit_access BEFORE INSERT OR UPDATE OR DELETE ON operation_audit_account FOR EACH ROW EXECUTE FUNCTION guard_capture_audit_access();
CREATE TRIGGER aaa_capture_audit_access BEFORE INSERT OR UPDATE OR DELETE ON operation_audit FOR EACH ROW EXECUTE FUNCTION guard_capture_audit_access();
CREATE TRIGGER aaa_capture_audit_access BEFORE INSERT OR UPDATE OR DELETE ON operation_audit_lifecycle FOR EACH ROW EXECUTE FUNCTION guard_capture_audit_access();
CREATE TRIGGER aaa_capture_audit_access BEFORE INSERT OR UPDATE OR DELETE ON operation_audit_history FOR EACH ROW EXECUTE FUNCTION guard_capture_audit_access();

-- +goose StatementBegin
CREATE FUNCTION capture_audit_payload_matches(c public.context_capture,i jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE v jsonb:=i->'Capture';e jsonb:=convert_from(c.expectation_json,'UTF8')::jsonb;s jsonb:=convert_from(c.scope_json,'UTF8')::jsonb;a public.custody_attempt;
BEGIN
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=c.attempt_id;
 RETURN COALESCE(i->>'Name'='persist_capture_intent' AND i->>'InputFormat'='capture-intent/v2' AND NOT(i ? 'Peer') AND NOT(i ? 'Process') AND
  jsonb_typeof(v)='object' AND (v-ARRAY['RootID','CaptureID','CaseID','OccurrenceID','ArtifactID','AttemptID','Actor','Target','ScopeDigest','SubmissionDigest','ExpectationDigest','PermissionEpoch','PermissionSequence','IdentityRevision','CreatedAt','Deadline','ExpiresAt','DeleteBy','ReservedBytes'])='{}'::jsonb AND
  (i->>'ID')::uuid=c.id AND (i->>'RootID')::uuid=c.root_id AND (i->>'TraceID')::uuid=(e->>'OccurrenceID')::uuid AND
  (v->>'RootID')::uuid=c.root_id AND (v->>'CaptureID')::uuid=c.id AND (v->>'AttemptID')::uuid=c.attempt_id AND
  v->>'CaseID'=e->>'CaseID' AND v->>'OccurrenceID'=e->>'OccurrenceID' AND v->>'ArtifactID'=e->'Registration'->'Location'->>'ArtifactID' AND
  v->'Actor'=i->'Actor' AND v->'Actor'=jsonb_build_object('Issuer',s#>>'{executor,issuer}','Subject',s#>>'{executor,subject}','ClientID',s#>>'{executor,clientID}','Kind',s#>>'{executor,identityType}') AND v->'Actor'->>'Kind'='human' AND
  v->'Target'=jsonb_build_object('ClusterID',e#>>'{Registration,Location,ClusterID}','NamespaceUID',e->>'NamespaceUID','WorkloadUID',e->>'WorkloadUID','PodUID',e->>'PodUID') AND
  public.connector_digest(v->'ScopeDigest')=c.scope_digest AND public.connector_digest(v->'SubmissionDigest')=c.submission_digest AND public.connector_digest(v->'ExpectationDigest')=sha256(c.expectation_json) AND sha256(c.scope_json)=c.scope_digest AND
  (v->>'PermissionEpoch')::uuid=c.permission_epoch AND (v->>'PermissionSequence')::bigint=c.permission_sequence AND
  v->'IdentityRevision'->>'UID'=c.identity_policy_uid AND (v->'IdentityRevision'->>'Generation')::bigint=c.identity_policy_generation AND public.connector_digest(v->'IdentityRevision'->'Digest')=c.identity_policy_digest AND
  (v->>'CreatedAt')::timestamptz=c.created_at AND (i->>'CreatedAt')::timestamptz=c.created_at AND (v->>'Deadline')::timestamptz=c.deadline AND
  (v->>'ExpiresAt')::timestamptz=(e->'Registration'->>'ExpiresAt')::timestamptz AND (v->>'DeleteBy')::timestamptz=(e->'Registration'->>'DeleteBy')::timestamptz AND (v->>'ReservedBytes')::bigint=a.reserved_bytes AND
  (i->>'WriteUntil')::timestamptz<=c.deadline,false);
END $$;
CREATE FUNCTION lock_capture_audit_admission(r uuid,allocation uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE started timestamptz:=clock_timestamp();n timestamptz;until_at timestamptz;root public.capture_audit_root;trust public.fleet_current_trust;pool public.operation_audit_pool;a public.capture_audit_allocation;control public.context_control_account;
BEGIN
 IF NOT public.capture_audit_role_ok(r,'admission') THEN RAISE EXCEPTION 'capture audit admission unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=root.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=r AND lane='capture' FOR UPDATE;
 SELECT * INTO STRICT a FROM public.capture_audit_allocation WHERE root_id=r AND allocation_id=allocation FOR UPDATE;
 SELECT * INTO STRICT control FROM public.context_control_account WHERE root_id=r AND allocation_id=allocation;
 n:=clock_timestamp();until_at:=LEAST(started+interval '5 seconds',root.valid_until,trust.fresh_until,pool.valid_until,a.valid_until,(a.policy->>'ValidUntil')::timestamptz);
 IF NOT COALESCE(n<until_at AND trust.observed_at<=n AND NOT trust.recovery_blocked AND NOT trust.suspended AND NOT root.paused AND NOT pool.paused AND NOT a.paused AND a.account_version=pool.account_version AND a.guaranteed_records>=control.full_limit AND a.guaranteed_records<=pool.records_per_account AND (a.policy->>'BackingRevision')::bigint=pool.revision,false) THEN RAISE EXCEPTION 'capture audit backing unavailable' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('RootID',r,'AllocationID',allocation,'AccountVersion',a.account_version,'AccountDigest',to_jsonb(ARRAY(SELECT get_byte(a.account_digest,k) FROM generate_series(0,31) k)),'Revision',a.revision,'Records',a.guaranteed_records,'RetainedSeconds',pool.retained_seconds,'Policy',a.policy,'ValidUntil',until_at);
END $$;
CREATE FUNCTION reserve_capture_audit(r uuid,capture uuid,i jsonb,capture_digest bytea,original_until timestamptz) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c public.context_capture;a public.capture_audit_allocation;trust public.fleet_current_trust;root public.capture_audit_root;allocation uuid;observed jsonb;n timestamptz;
BEGIN
 IF octet_length(i::text)>16384 OR octet_length(capture_digest)<>32 OR NOT public.capture_audit_role_ok(r,'admission') THEN RAISE EXCEPTION 'capture audit admission unavailable' USING ERRCODE='23514';END IF;
 -- Immutable own INSERT identifies allocation before reacquiring the agreed
 -- prefix. It cannot use a legacy capture or repair a committed missing pair.
 SELECT * INTO STRICT c FROM public.context_capture WHERE id=capture AND root_id=r;
 allocation:=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,AllocationID}')::uuid;
 observed:=public.lock_capture_audit_admission(r,allocation);
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=root.installation_id FOR SHARE;
 SELECT * INTO STRICT a FROM public.capture_audit_allocation WHERE root_id=r AND allocation_id=allocation;
 n:=clock_timestamp();
 IF NOT COALESCE(c.intent_operation_id=c.id AND c.state='accepted_pending_audit' AND c.intent_acknowledged_at IS NULL AND public.capture_audit_payload_matches(c,i) AND
   i->'Lifecycle'->'Policy'=a.policy AND public.connector_digest(i->'PrincipalDigest')=a.account_digest AND i->>'AccountVersion'=a.account_version AND
   n<original_until AND n<(observed->>'ValidUntil')::timestamptz AND n<(i->>'RequestUntil')::timestamptz AND (i->>'RequestUntil')::timestamptz<=original_until,false) THEN RAISE EXCEPTION 'capture audit binding mismatch' USING ERRCODE='23514';END IF;
 INSERT INTO public.operation_audit(id,root_id,lane,issuer_epoch,principal_digest,intent,request_until,write_until,retain_until)
 VALUES(c.id,r,'capture',trust.issuer_epoch,a.account_digest,i,(i->>'RequestUntil')::timestamptz,(i->>'WriteUntil')::timestamptz,(i->>'RetainUntil')::timestamptz);
 INSERT INTO public.capture_audit_binding(capture_id,root_id,allocation_id,operation_id,capture_digest) VALUES(c.id,r,allocation,c.id,capture_digest);
 IF clock_timestamp()>=LEAST(original_until,(observed->>'ValidUntil')::timestamptz,(i->>'RequestUntil')::timestamptz) THEN RAISE EXCEPTION 'capture audit admission expired' USING ERRCODE='23514';END IF;
END $$;
CREATE FUNCTION require_capture_audit_pair() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE allocation uuid;
BEGIN
 allocation:=(convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Registration,AllocationID}')::uuid;
 IF NEW.intent_operation_id IS NULL THEN
  IF EXISTS(SELECT 1 FROM public.capture_audit_allocation WHERE root_id=NEW.root_id AND allocation_id=allocation) THEN RAISE EXCEPTION 'capture admission requires its backed pair' USING ERRCODE='23514';END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM public.capture_audit_binding b JOIN public.operation_audit a ON a.id=b.operation_id AND a.root_id=b.root_id WHERE b.capture_id=NEW.id AND b.root_id=NEW.root_id AND b.allocation_id=allocation AND a.lane='capture' AND a.id=NEW.intent_operation_id AND public.capture_audit_payload_matches(NEW,a.intent)) THEN RAISE EXCEPTION 'capture audit pair missing' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capture_audit_payload_matches(public.context_capture,jsonb),lock_capture_audit_admission(uuid,uuid),reserve_capture_audit(uuid,uuid,jsonb,bytea,timestamptz),require_capture_audit_pair() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER context_capture_audit_pair AFTER INSERT ON context_capture DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_capture_audit_pair();

-- +goose StatementBegin
CREATE FUNCTION capture_audit_receipts_current(a public.operation_audit) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(a.lane='capture' AND a.intent->>'Name'='persist_capture_intent' AND EXISTS(
  SELECT 1 FROM public.capture_audit_binding b JOIN public.operation_audit_lifecycle d ON d.operation_id=b.operation_id AND d.root_id=b.root_id
  WHERE b.operation_id=a.id AND b.root_id=a.root_id AND
   (a.intent_receipt IS NULL OR a.intent_started AND (d.intent_completion->'Receipt'=a.intent_receipt OR b.intent_reads>0)) AND
   (a.outcome_receipt IS NULL OR a.outcome_started AND (d.outcome_completion->'Receipt'=a.outcome_receipt OR b.outcome_reads>0))),false)
$$;
CREATE FUNCTION capture_audit_current(r uuid,operation uuid) RETURNS public.operation_audit
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE root public.capture_audit_root;trust public.fleet_current_trust;a public.operation_audit;d public.operation_audit_lifecycle;n timestamptz;started timestamptz:=clock_timestamp();
BEGIN
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=root.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_pool WHERE root_id=r AND lane='capture' FOR UPDATE;
 SELECT * INTO STRICT a FROM public.operation_audit WHERE id=operation AND root_id=r AND lane='capture' FOR UPDATE;
 SELECT * INTO STRICT d FROM public.operation_audit_lifecycle WHERE operation_id=operation AND root_id=r FOR UPDATE;
 n:=clock_timestamp();
 IF NOT COALESCE(NOT trust.recovery_blocked AND NOT trust.suspended AND trust.observed_at<=n AND n<trust.fresh_until AND n<started+interval '5 seconds' AND n<a.write_until AND trust.issuer_epoch=a.issuer_epoch AND d.issuer_epoch=a.issuer_epoch AND public.incarnation_current(d.postmaster_at) AND d.database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AND d.installation_id=root.installation_id AND EXISTS(SELECT 1 FROM public.capture_audit_binding WHERE capture_id=operation AND root_id=r),false) THEN RAISE EXCEPTION 'capture audit original interval unavailable' USING ERRCODE='23514';END IF;
 RETURN a;
END $$;
CREATE FUNCTION capture_audit_original_until(r uuid,a public.operation_audit,started timestamptz) RETURNS timestamptz
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT LEAST(started+interval '5 seconds',a.write_until,t.fresh_until)
 FROM public.capture_audit_root root JOIN public.fleet_current_trust t ON t.installation_id=root.installation_id
 WHERE root.root_id=r AND a.root_id=r AND a.lane='capture'
$$;
CREATE FUNCTION capture_audit_snapshot(a public.operation_audit) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object('Intent',a.intent,'IntentStarted',a.intent_started,'OutcomeStarted',a.outcome_started,'IntentReceipt',a.intent_receipt,'OutcomeReceipt',a.outcome_receipt,'Outcome',a.outcome)
$$;
CREATE FUNCTION read_capture_operation(r uuid,operation uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit;started timestamptz:=clock_timestamp();until_at timestamptz;result jsonb;
BEGIN
 IF NOT(public.capture_audit_role_ok(r,'journal') OR public.capture_audit_role_ok(r,'acknowledge') OR public.capture_audit_role_ok(r,'reader')) THEN RAISE EXCEPTION 'capture audit reader unavailable' USING ERRCODE='23514';END IF;
 a:=public.capture_audit_current(r,operation);
 until_at:=public.capture_audit_original_until(r,a,started);result:=jsonb_build_object('Snapshot',public.capture_audit_snapshot(a),'ValidUntil',until_at);
 IF until_at IS NULL OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capture read expired' USING ERRCODE='23514';END IF;
 RETURN result;
END $$;
CREATE FUNCTION capture_audit_journal(r uuid,i jsonb,verb text,o jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit;fresh boolean:=false;n timestamptz;started timestamptz:=clock_timestamp();until_at timestamptz;
BEGIN
 IF NOT public.capture_audit_role_ok(r,'journal') OR octet_length(i::text)>16384 OR verb NOT IN('reserve','claim-intent','claim-outcome','freeze-outcome') THEN RAISE EXCEPTION 'capture audit writer unavailable' USING ERRCODE='23514';END IF;
 a:=public.capture_audit_current(r,(i->>'ID')::uuid);
 until_at:=public.capture_audit_original_until(r,a,started);
 IF until_at IS NULL OR clock_timestamp()>=until_at OR a.intent IS DISTINCT FROM i THEN RAISE EXCEPTION 'capture audit record mismatch' USING ERRCODE='23514';END IF;
 n:=clock_timestamp();
 IF verb='claim-intent' AND NOT a.intent_started THEN
  IF n>=a.request_until THEN RAISE EXCEPTION 'capture original create interval expired' USING ERRCODE='23514';END IF;
  UPDATE public.operation_audit SET intent_started=true WHERE id=a.id RETURNING * INTO a;fresh:=true;
 ELSIF verb='claim-outcome' AND NOT a.outcome_started THEN
  IF a.outcome IS NULL OR a.intent_receipt IS NULL THEN RAISE EXCEPTION 'capture outcome not frozen' USING ERRCODE='23514';END IF;
  UPDATE public.operation_audit SET outcome_started=true WHERE id=a.id RETURNING * INTO a;fresh:=true;
 ELSIF verb='freeze-outcome' THEN
  IF octet_length(o::text)>24576 OR NOT COALESCE(o->'Intent'=i AND o->>'Status'='success' AND o->>'Reason'='prepared' AND o->>'Effect'='accepted' AND o->>'ClientReceipt'='unknown' AND o->'CaptureIDs'=jsonb_build_array(a.id::text) AND (o->'CaseIDs'='null'::jsonb OR o->'CaseIDs'='[]'::jsonb) AND (o->'ArtifactIDs'='null'::jsonb OR o->'ArtifactIDs'='[]'::jsonb) AND (o->>'OutputBytes')::bigint=0 AND NOT(o ? 'Credential') AND public.connector_digest(o->'OutputDigest') IS NOT NULL AND (o->>'MetadataUntil')::timestamptz=a.request_until AND (o->>'RecordedAt')::timestamptz>=((i->>'CreatedAt')::timestamptz) AND (o->>'RecordedAt')::timestamptz<=n AND (o->>'RecordedAt')::timestamptz<a.write_until,false) THEN RAISE EXCEPTION 'capture persistence outcome invalid' USING ERRCODE='23514';END IF;
  IF a.outcome IS NULL THEN
   IF a.intent_receipt IS NULL THEN RAISE EXCEPTION 'capture intent not acknowledged' USING ERRCODE='23514';END IF;
   UPDATE public.operation_audit SET outcome=o WHERE id=a.id RETURNING * INTO a;
  ELSIF a.outcome IS DISTINCT FROM o THEN RAISE EXCEPTION 'capture outcome already frozen' USING ERRCODE='23514';END IF;
 END IF;
 IF clock_timestamp()>=until_at OR fresh AND verb='claim-intent' AND clock_timestamp()>=a.request_until THEN RAISE EXCEPTION 'capture write claim expired' USING ERRCODE='23514';END IF;
 IF fresh AND verb='claim-intent' THEN until_at:=LEAST(until_at,a.request_until);END IF;
 RETURN jsonb_build_object('Snapshot',public.capture_audit_snapshot(a),'Fresh',fresh,'ValidUntil',until_at);
END $$;
CREATE FUNCTION claim_capture_reconciliation(r uuid,i jsonb,phase text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit;b public.capture_audit_binding;started timestamptz:=clock_timestamp();n timestamptz;until_at timestamptz;trust_until timestamptz;attempt bigint;
BEGIN
 IF NOT public.capture_audit_role_ok(r,'journal') OR phase NOT IN('intent','outcome') OR octet_length(i::text)>16384 THEN RAISE EXCEPTION 'capture reconciliation unavailable' USING ERRCODE='23514';END IF;
 a:=public.capture_audit_current(r,(i->>'ID')::uuid);
 SELECT * INTO STRICT b FROM public.capture_audit_binding WHERE operation_id=a.id AND root_id=r FOR UPDATE;
 SELECT t.fresh_until INTO STRICT trust_until FROM public.capture_audit_root root JOIN public.fleet_current_trust t ON t.installation_id=root.installation_id WHERE root.root_id=r;
 n:=clock_timestamp();until_at:=LEAST(started+interval '5 seconds',a.write_until,trust_until);
 IF a.intent IS DISTINCT FROM i OR n>=until_at THEN RAISE EXCEPTION 'capture reconciliation original interval unavailable' USING ERRCODE='23514';END IF;
 IF phase='intent' THEN
  IF NOT a.intent_started OR a.intent_receipt IS NOT NULL OR b.intent_reads>=2 THEN RAISE EXCEPTION 'capture intent reconciliation exhausted' USING ERRCODE='23514';END IF;
  attempt:=b.intent_reads+1;
  UPDATE public.capture_audit_binding SET intent_reads=intent_reads+1,intent_first_until=CASE WHEN intent_reads=0 THEN until_at ELSE intent_first_until END,intent_second_until=CASE WHEN intent_reads=1 THEN until_at ELSE intent_second_until END WHERE capture_id=a.id;
 ELSE
  IF NOT a.outcome_started OR a.outcome IS NULL OR a.outcome_receipt IS NOT NULL OR b.outcome_reads>=2 THEN RAISE EXCEPTION 'capture outcome reconciliation exhausted' USING ERRCODE='23514';END IF;
  attempt:=b.outcome_reads+1;
  UPDATE public.capture_audit_binding SET outcome_reads=outcome_reads+1,outcome_first_until=CASE WHEN outcome_reads=0 THEN until_at ELSE outcome_first_until END,outcome_second_until=CASE WHEN outcome_reads=1 THEN until_at ELSE outcome_second_until END WHERE capture_id=a.id;
 END IF;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capture reconciliation claim expired' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Attempt',attempt,'Until',until_at);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capture_audit_receipts_current(public.operation_audit),capture_audit_current(uuid,uuid),capture_audit_original_until(uuid,public.operation_audit,timestamptz),capture_audit_snapshot(public.operation_audit),read_capture_operation(uuid,uuid),capture_audit_journal(uuid,jsonb,text,jsonb),claim_capture_reconciliation(uuid,jsonb,text) FROM PUBLIC;

-- All preexisting lanes retain their original positive-completion requirement.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_operation_audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.operation_audit_pool; a public.operation_audit_account; n timestamptz; prepaid boolean:=false;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN
  RAISE EXCEPTION 'invalid operation audit source' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN
  IF NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d JOIN public.fleet_current_trust t ON t.installation_id=d.installation_id
   WHERE d.operation_id=OLD.id AND d.root_id=OLD.root_id AND d.finalization_xid=pg_current_xact_id() AND d.terminal_acknowledged_at IS NOT NULL AND
    NOT t.recovery_blocked AND NOT t.suspended AND clock_timestamp()<t.fresh_until AND t.issuer_epoch=d.issuer_epoch AND public.incarnation_current(d.postmaster_at) AND (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())=d.database_oid AND clock_timestamp()<(d.lease->>'Until')::timestamptz)
   THEN RAISE EXCEPTION 'audit retirement unavailable' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT p FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane=NEW.lane FOR UPDATE;
  n:=clock_timestamp();
  prepaid:=public.connector_retirement_prepaid(NEW);
  IF NEW.intent->>'Name'='connector_retirement' AND NOT prepaid THEN RAISE EXCEPTION 'connector retirement has no paid original ticket' USING ERRCODE='23514';END IF;
  IF (NOT prepaid AND (p.paused OR n>=p.valid_until)) OR n>=NEW.request_until OR n<(NEW.intent->>'CreatedAt')::timestamptz OR NEW.intent_started OR NEW.intent_receipt IS NOT NULL OR NEW.outcome IS NOT NULL OR NEW.outcome_started OR NEW.outcome_receipt IS NOT NULL OR
   NOT (NEW.intent ?& ARRAY['ID','RootID','MACVersion','AccountVersion','Name','CreatedAt','RequestUntil','WriteUntil','RetainUntil']) OR public.operation_audit_lane(NEW.intent->>'Name') IS NULL OR NOT public.connector_operation_actor_valid(NEW.intent) OR
   ((NEW.intent ? 'Capture') IS DISTINCT FROM (NEW.lane='capture')) OR
   (NEW.intent->>'ID')::uuid<>NEW.id OR (NEW.intent->>'RootID')::uuid<>NEW.root_id OR NEW.intent->>'AccountVersion'<>p.account_version OR
   NEW.request_until<>(NEW.intent->>'RequestUntil')::timestamptz OR NEW.write_until<>(NEW.intent->>'WriteUntil')::timestamptz OR NEW.retain_until<>(NEW.intent->>'RetainUntil')::timestamptz OR
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '5 seconds' OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
   NEW.retain_until>(NEW.intent->>'CreatedAt')::timestamptz+make_interval(secs=>p.retained_seconds::double precision) OR
   NEW.lane IS DISTINCT FROM public.operation_audit_lane(NEW.intent->>'Name') THEN
   RAISE EXCEPTION 'operation audit unavailable' USING ERRCODE='23514'; END IF;
  SELECT * INTO a FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest FOR UPDATE;
  IF NOT FOUND THEN
   IF p.accounts>=p.account_limit THEN RAISE EXCEPTION 'audit accounts exhausted' USING ERRCODE='23514'; END IF;
   UPDATE public.operation_audit_pool SET accounts=accounts+1 WHERE root_id=NEW.root_id AND lane=NEW.lane;
   INSERT INTO public.operation_audit_account(root_id,lane,principal_digest) VALUES(NEW.root_id,NEW.lane,NEW.principal_digest) RETURNING * INTO a;
  END IF;
  IF a.charged>=p.records_per_account THEN RAISE EXCEPTION 'audit records exhausted' USING ERRCODE='23514'; END IF;
  UPDATE public.operation_audit_account SET charged=charged+1 WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest;
 ELSE
  IF ROW(NEW.id,NEW.root_id,NEW.lane,NEW.issuer_epoch,NEW.principal_digest,NEW.intent,NEW.request_until,NEW.write_until,NEW.retain_until) IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.lane,OLD.issuer_epoch,OLD.principal_digest,OLD.intent,OLD.request_until,OLD.write_until,OLD.retain_until) OR
   (OLD.intent_started AND NOT NEW.intent_started) OR (OLD.outcome_started AND NOT NEW.outcome_started) OR
   (OLD.intent_receipt IS NOT NULL AND NEW.intent_receipt IS DISTINCT FROM OLD.intent_receipt) OR
   (OLD.outcome IS NOT NULL AND NEW.outcome IS DISTINCT FROM OLD.outcome) OR
   (OLD.outcome_receipt IS NOT NULL AND NEW.outcome_receipt IS DISTINCT FROM OLD.outcome_receipt) THEN
   RAISE EXCEPTION 'immutable operation audit' USING ERRCODE='23514'; END IF;
  IF NEW.intent ? 'Lifecycle' AND NOT public.capture_audit_receipts_current(NEW) AND NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.operation_id=NEW.id AND
    (NEW.intent_receipt IS NULL OR d.intent_completion->'Receipt'=NEW.intent_receipt) AND (NEW.outcome_receipt IS NULL OR d.outcome_completion->'Receipt'=NEW.outcome_receipt)) THEN
   RAISE EXCEPTION 'receipt lacks positive writer completion' USING ERRCODE='23514'; END IF;
  n:=clock_timestamp();
  IF n>=NEW.write_until OR (NOT OLD.intent_started AND NEW.intent_started AND n>=NEW.request_until) THEN
   RAISE EXCEPTION 'operation audit interval expired' USING ERRCODE='23514'; END IF;
  IF NEW.outcome IS NOT NULL AND NEW.outcome->'Intent' IS DISTINCT FROM NEW.intent THEN
   RAISE EXCEPTION 'outcome intent mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;

-- +goose StatementEnd

-- One finite child per newly accepted capture. Read claims never refill; exact
-- GET is an acknowledgement source, not completion of the original writer.
-- +goose StatementBegin
CREATE FUNCTION capture_audit_read_step(old_count smallint,new_count smallint,old_first timestamptz,new_first timestamptz,old_second timestamptz,new_second timestamptz,n timestamptz,write_until timestamptz) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(new_count=old_count+1 AND (
  old_count=0 AND old_first IS NULL AND old_second IS NULL AND new_second IS NULL AND new_first>n AND new_first<=LEAST(n+interval '5 seconds',write_until) OR
  old_count=1 AND old_second IS NULL AND new_first=old_first AND new_second>n AND new_second<=LEAST(n+interval '5 seconds',write_until)),false)
$$;
CREATE FUNCTION guard_capture_audit_binding() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit;d public.operation_audit_lifecycle;n timestamptz:=clock_timestamp();
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT d FROM public.operation_audit_lifecycle WHERE operation_id=OLD.operation_id AND root_id=OLD.root_id;
  IF NOT public.capture_audit_role_ok(OLD.root_id,'finalizer') OR d.finalization_xid IS DISTINCT FROM pg_current_xact_id() OR d.terminal_acknowledged_at IS NULL OR EXISTS(SELECT 1 FROM public.operation_audit WHERE id=OLD.operation_id) THEN RAISE EXCEPTION 'capture audit dependency remains live' USING ERRCODE='23514';END IF;
  RETURN OLD;
 END IF;
 SELECT * INTO STRICT a FROM public.operation_audit WHERE id=NEW.operation_id AND root_id=NEW.root_id AND lane='capture';
 IF TG_OP='INSERT' THEN
  IF NOT public.capture_audit_role_ok(NEW.root_id,'admission') OR NEW.intent_reads<>0 OR NEW.outcome_reads<>0 OR NOT EXISTS(SELECT 1 FROM public.context_capture c WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id AND c.intent_operation_id=NEW.operation_id AND public.capture_audit_payload_matches(c,a.intent)) THEN RAISE EXCEPTION 'capture audit binding admission unavailable' USING ERRCODE='23514';END IF;
 ELSE
  IF NOT public.capture_audit_role_ok(NEW.root_id,'journal') OR (to_jsonb(NEW)-ARRAY['intent_reads','outcome_reads','intent_first_until','intent_second_until','outcome_first_until','outcome_second_until']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['intent_reads','outcome_reads','intent_first_until','intent_second_until','outcome_first_until','outcome_second_until']) THEN RAISE EXCEPTION 'immutable capture audit binding' USING ERRCODE='23514';END IF;
  IF NOT COALESCE(
   (ROW(NEW.outcome_reads,NEW.outcome_first_until,NEW.outcome_second_until) IS NOT DISTINCT FROM ROW(OLD.outcome_reads,OLD.outcome_first_until,OLD.outcome_second_until) AND a.intent_started AND a.intent_receipt IS NULL AND public.capture_audit_read_step(OLD.intent_reads,NEW.intent_reads,OLD.intent_first_until,NEW.intent_first_until,OLD.intent_second_until,NEW.intent_second_until,n,a.write_until)) OR
   (ROW(NEW.intent_reads,NEW.intent_first_until,NEW.intent_second_until) IS NOT DISTINCT FROM ROW(OLD.intent_reads,OLD.intent_first_until,OLD.intent_second_until) AND a.outcome_started AND a.outcome_receipt IS NULL AND public.capture_audit_read_step(OLD.outcome_reads,NEW.outcome_reads,OLD.outcome_first_until,NEW.outcome_first_until,OLD.outcome_second_until,NEW.outcome_second_until,n,a.write_until)),false) THEN RAISE EXCEPTION 'capture reconciliation cannot refill' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION guard_context_capture_audit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit;b public.capture_audit_binding;
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.intent_operation_id IS NOT NULL AND (NOT public.capture_audit_role_ok(NEW.root_id,'admission') OR NEW.intent_acknowledged_at IS NOT NULL) THEN RAISE EXCEPTION 'capture private admission unavailable' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF NEW.intent_operation_id IS DISTINCT FROM OLD.intent_operation_id THEN RAISE EXCEPTION 'capture protocol cannot change' USING ERRCODE='23514';END IF;
 IF OLD.intent_operation_id IS NULL THEN RETURN NEW;END IF;
 IF ROW(NEW.state,NEW.intent_acknowledged_at,NEW.intent_digest,NEW.intent_object_key,NEW.intent_object_version,NEW.intent_object_etag,NEW.intent_object_bytes,NEW.intent_object_sha256) IS DISTINCT FROM ROW(OLD.state,OLD.intent_acknowledged_at,OLD.intent_digest,OLD.intent_object_key,OLD.intent_object_version,OLD.intent_object_etag,OLD.intent_object_bytes,OLD.intent_object_sha256) THEN
  IF NOT public.capture_audit_role_ok(NEW.root_id,'acknowledge') THEN RAISE EXCEPTION 'legacy capture audit cannot acknowledge private pair' USING ERRCODE='23514';END IF;
  SELECT * INTO STRICT a FROM public.operation_audit WHERE id=NEW.intent_operation_id AND root_id=NEW.root_id AND lane='capture';
  SELECT * INTO STRICT b FROM public.capture_audit_binding WHERE capture_id=NEW.id AND root_id=NEW.root_id;
  IF NOT COALESCE(OLD.intent_acknowledged_at IS NULL AND NEW.state='intent_audited' AND NEW.intent_acknowledged_at IS NOT NULL AND clock_timestamp()<a.write_until AND a.intent_receipt IS NOT NULL AND a.outcome_receipt IS NOT NULL AND public.capture_audit_payload_matches(NEW,a.intent) AND NEW.intent_digest=b.capture_digest AND NEW.intent_object_key=a.intent_receipt->>'Key' AND NEW.intent_object_version=COALESCE(a.intent_receipt->>'Version','') AND NEW.intent_object_etag=a.intent_receipt->>'ETag' AND NEW.intent_object_bytes=(a.intent_receipt->>'Bytes')::bigint AND NEW.intent_object_sha256=public.connector_digest(a.intent_receipt->'SHA256'),false) THEN RAISE EXCEPTION 'capture pair acknowledgement mismatch' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION capture_audit_acknowledge(r uuid,i jsonb,phase text,completion jsonb,receipt jsonb,read_claim jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit;d public.operation_audit_lifecycle;b public.capture_audit_binding;existing jsonb;old_receipt jsonb;started boolean;read_until timestamptz;until_at timestamptz;begin_at timestamptz:=clock_timestamp();
BEGIN
 IF NOT public.capture_audit_role_ok(r,'acknowledge') OR phase NOT IN('intent','outcome') OR octet_length(i::text)>16384 OR completion IS NOT NULL AND octet_length(completion::text)>8192 OR receipt IS NOT NULL AND octet_length(receipt::text)>4096 THEN RAISE EXCEPTION 'capture acknowledgement unavailable' USING ERRCODE='23514';END IF;
 a:=public.capture_audit_current(r,(i->>'ID')::uuid);until_at:=public.capture_audit_original_until(r,a,begin_at);
 SELECT * INTO STRICT d FROM public.operation_audit_lifecycle WHERE root_id=r AND operation_id=a.id FOR UPDATE;
 SELECT * INTO STRICT b FROM public.capture_audit_binding WHERE root_id=r AND operation_id=a.id FOR UPDATE;
 IF a.intent IS DISTINCT FROM i OR until_at IS NULL OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capture acknowledgement expired' USING ERRCODE='23514';END IF;
 IF phase='intent' THEN existing:=d.intent_completion;old_receipt:=a.intent_receipt;started:=a.intent_started;read_until:=CASE WHEN (read_claim->>'Attempt')::bigint=1 THEN b.intent_first_until WHEN (read_claim->>'Attempt')::bigint=2 THEN b.intent_second_until END;
 ELSE existing:=d.outcome_completion;old_receipt:=a.outcome_receipt;started:=a.outcome_started;read_until:=CASE WHEN (read_claim->>'Attempt')::bigint=1 THEN b.outcome_first_until WHEN (read_claim->>'Attempt')::bigint=2 THEN b.outcome_second_until END;END IF;
 IF NOT started THEN RAISE EXCEPTION 'capture writer never claimed' USING ERRCODE='23514';END IF;
 IF completion IS NOT NULL THEN
  IF existing IS NOT NULL AND existing IS DISTINCT FROM completion OR old_receipt IS NOT NULL AND old_receipt IS DISTINCT FROM completion->'Receipt' THEN RAISE EXCEPTION 'immutable capture writer completion' USING ERRCODE='23514';END IF;
  -- SQL's existing lifecycle guard checks the original phase, key, dates and
  -- already-spent writer claim. The independent adapter also verifies the exact
  -- typed-record digest; this role cannot originate or refill the write claim.
  IF existing IS NULL THEN
   IF phase='intent' THEN UPDATE public.operation_audit_lifecycle SET intent_completion=completion WHERE root_id=r AND operation_id=a.id;
   ELSE UPDATE public.operation_audit_lifecycle SET outcome_completion=completion WHERE root_id=r AND operation_id=a.id;END IF;
   existing:=completion;
  END IF;
 END IF;
 IF receipt IS NOT NULL THEN
  IF NOT COALESCE(receipt->>'Key'='operation-audit/v1/'||r::text||'/'||a.id::text||'/'||phase AND length(COALESCE(receipt->>'Version',''))<=1024 AND length(receipt->>'ETag') BETWEEN 1 AND 256 AND (receipt->>'Bytes')::bigint BETWEEN 1 AND 65536 AND public.connector_digest(receipt->'SHA256') IS NOT NULL,false) THEN RAISE EXCEPTION 'capture receipt invalid' USING ERRCODE='23514';END IF;
  IF old_receipt IS NOT NULL AND old_receipt IS DISTINCT FROM receipt THEN RAISE EXCEPTION 'immutable capture receipt' USING ERRCODE='23514';END IF;
  IF old_receipt IS NULL THEN
   IF existing IS NOT NULL THEN
    IF existing->'Receipt' IS DISTINCT FROM receipt THEN RAISE EXCEPTION 'capture completion receipt mismatch' USING ERRCODE='23514';END IF;
   ELSE
    -- Exact unknown-result lookup can acknowledge persistence only within its
    -- original prepaid read interval. It does not fill either completion field.
    IF read_claim IS NULL OR octet_length(read_claim::text)>256 OR (read_claim-ARRAY['Attempt','Until'])<>'{}'::jsonb OR read_until IS NULL OR (read_claim->>'Until')::timestamptz IS DISTINCT FROM read_until OR clock_timestamp()>=read_until THEN RAISE EXCEPTION 'capture reconciliation acknowledgement expired' USING ERRCODE='23514';END IF;
    until_at:=LEAST(until_at,read_until);
   END IF;
   IF phase='intent' THEN UPDATE public.operation_audit SET intent_receipt=receipt WHERE root_id=r AND id=a.id RETURNING * INTO a;
   ELSE UPDATE public.operation_audit SET outcome_receipt=receipt WHERE root_id=r AND id=a.id RETURNING * INTO a;END IF;
  END IF;
 END IF;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capture acknowledgement expired' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Snapshot',public.capture_audit_snapshot(a),'Completion',existing,'ValidUntil',until_at);
END $$;
CREATE FUNCTION acknowledge_capture_pair(r uuid,i jsonb) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit;b public.capture_audit_binding;c public.context_capture;begin_at timestamptz:=clock_timestamp();until_at timestamptz;
BEGIN
 IF NOT public.capture_audit_role_ok(r,'acknowledge') OR octet_length(i::text)>16384 THEN RAISE EXCEPTION 'capture pair acknowledgement unavailable' USING ERRCODE='23514';END IF;
 a:=public.capture_audit_current(r,(i->>'ID')::uuid);until_at:=public.capture_audit_original_until(r,a,begin_at);
 SELECT * INTO STRICT b FROM public.capture_audit_binding WHERE root_id=r AND operation_id=a.id FOR UPDATE;
 SELECT * INTO STRICT c FROM public.context_capture WHERE root_id=r AND id=a.id FOR UPDATE;
 IF NOT COALESCE(a.intent=i AND a.intent_receipt IS NOT NULL AND a.outcome_receipt IS NOT NULL AND a.outcome->>'Status'='success' AND a.outcome->>'Effect'='accepted' AND a.outcome->>'Reason'='prepared' AND public.capture_audit_payload_matches(c,i) AND clock_timestamp()<until_at,false) THEN RAISE EXCEPTION 'capture pair not acknowledged' USING ERRCODE='23514';END IF;
 IF c.intent_acknowledged_at IS NULL THEN
  UPDATE public.context_capture SET state='intent_audited',intent_acknowledged_at=clock_timestamp(),intent_digest=b.capture_digest,intent_object_key=a.intent_receipt->>'Key',intent_object_version=COALESCE(a.intent_receipt->>'Version',''),intent_object_etag=a.intent_receipt->>'ETag',intent_object_bytes=(a.intent_receipt->>'Bytes')::bigint,intent_object_sha256=public.connector_digest(a.intent_receipt->'SHA256') WHERE id=c.id AND root_id=r;
 ELSIF c.state<>'intent_audited' OR c.intent_digest IS DISTINCT FROM b.capture_digest OR c.intent_object_key IS DISTINCT FROM a.intent_receipt->>'Key' OR c.intent_object_sha256 IS DISTINCT FROM public.connector_digest(a.intent_receipt->'SHA256') THEN RAISE EXCEPTION 'capture acknowledgement changed' USING ERRCODE='23514';END IF;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capture pair acknowledgement expired' USING ERRCODE='23514';END IF;
 RETURN until_at;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capture_audit_read_step(smallint,smallint,timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,timestamptz),guard_capture_audit_binding(),guard_context_capture_audit(),capture_audit_acknowledge(uuid,jsonb,text,jsonb,jsonb,jsonb),acknowledge_capture_pair(uuid,jsonb) FROM PUBLIC;
CREATE TRIGGER capture_audit_binding_guard BEFORE INSERT OR UPDATE OR DELETE ON capture_audit_binding FOR EACH ROW EXECUTE FUNCTION guard_capture_audit_binding();
CREATE TRIGGER context_capture_private_audit_guard BEFORE INSERT OR UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION guard_context_capture_audit();

-- Private cleanup reuses the existing state machine through purpose-fixed views.
CREATE VIEW capture_operation_pool WITH (security_barrier=true) AS
SELECT root_id, lane, account_version, revision, paused, valid_until, account_limit, records_per_account, accounts, retained_seconds, history_profile, history_backing_until, proof_window_missed FROM public.operation_audit_pool
WHERE lane='capture' AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;
REVOKE ALL ON capture_operation_pool FROM PUBLIC;
CREATE VIEW capture_operation_account WITH (security_barrier=true) AS
SELECT root_id, lane, principal_digest, charged FROM public.operation_audit_account
WHERE lane='capture' AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;
REVOKE ALL ON capture_operation_account FROM PUBLIC;
CREATE VIEW capture_operation_audit WITH (security_barrier=true) AS
SELECT id, root_id, lane, issuer_epoch, principal_digest, intent, request_until, write_until, retain_until, intent_started, intent_receipt, outcome, outcome_started, outcome_receipt FROM public.operation_audit
WHERE lane='capture' AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;
REVOKE ALL ON capture_operation_audit FROM PUBLIC;
CREATE VIEW capture_operation_lifecycle WITH (security_barrier=true) AS
SELECT operation_id, root_id, lane, principal_digest, installation_id, issuer_epoch, postmaster_at, database_oid, binding, original_purge_at, certificate_purge_at, live_retire_by, intent_completion, outcome_completion, lease_fence, lease, retirement, certificate_started, certificate_completion, certificate_receipt, certificate_acknowledged_at, terminal_purge, terminal_acknowledged_at, finalization_xid, overdue_selected_at, overdue_purge, certificate_verify_attempts FROM public.operation_audit_lifecycle
WHERE lane='capture' AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;
REVOKE ALL ON capture_operation_lifecycle FROM PUBLIC;
CREATE VIEW capture_operation_history WITH (security_barrier=true) AS
SELECT root_id,lane,principal_digest,release_at,delete_by,hard_delete_by,eligible_at,installation_id,issuer_epoch,postmaster_at,database_oid,horizon_seconds,history_policy,records,overdue,drain_xid FROM public.operation_audit_history
WHERE lane='capture' AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;
REVOKE ALL ON capture_operation_history FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION retire_capture_audit_binding() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF OLD.lane='capture' THEN
  IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.operation_audit'::regclass OR TG_OP<>'DELETE' OR TG_WHEN<>'AFTER' OR NOT public.capture_audit_role_ok(OLD.root_id,'finalizer') THEN RAISE EXCEPTION 'capture dependency retirement unavailable' USING ERRCODE='23514';END IF;
  DELETE FROM public.capture_audit_binding WHERE root_id=OLD.root_id AND operation_id=OLD.id;
  IF NOT FOUND THEN RAISE EXCEPTION 'capture audit dependency missing' USING ERRCODE='23514';END IF;
 END IF;
 RETURN OLD;
END $$;
CREATE FUNCTION finish_capture_operation_retirement(r uuid,i uuid,installation uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NOT public.capture_audit_role_ok(r,'finalizer') OR NOT EXISTS(SELECT 1 FROM public.capture_audit_root p WHERE p.root_id=r AND p.installation_id=installation) THEN RAISE EXCEPTION 'capture finalizer unavailable' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.operation_audit a WHERE a.root_id=r AND a.id=i AND a.lane='capture') THEN RETURN false;END IF;
 RETURN public.finish_operation_audit_retirement(r,i,installation);
END $$;
CREATE FUNCTION finish_capture_operation_history(r uuid,l text,p bytea,releases timestamptz,deletes timestamptz,installation uuid) RETURNS TABLE(records bigint,overdue boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF l IS DISTINCT FROM 'capture' OR NOT public.capture_audit_role_ok(r,'finalizer') OR NOT EXISTS(SELECT 1 FROM public.capture_audit_root x WHERE x.root_id=r AND x.installation_id=installation) THEN RAISE EXCEPTION 'capture history finalizer unavailable' USING ERRCODE='23514';END IF;
 RETURN QUERY SELECT h.records,h.overdue FROM public.finish_operation_audit_history(r,'capture',p,releases,deletes,installation) h;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION retire_capture_audit_binding(),finish_capture_operation_retirement(uuid,uuid,uuid),finish_capture_operation_history(uuid,text,bytea,timestamptz,timestamptz,uuid) FROM PUBLIC;
CREATE TRIGGER operation_audit_capture_dependency AFTER DELETE ON operation_audit FOR EACH ROW EXECUTE FUNCTION retire_capture_audit_binding();
REVOKE ALL ON capture_audit_root,capture_audit_allocation,capture_audit_binding FROM PUBLIC;

-- Accepted private composition supplies these finite backing observations. This
-- is not a Kubernetes source-acceptance producer or a public administrator API.
-- The separate root provisioning credential pins the exact source login first.
-- +goose StatementBegin
CREATE FUNCTION configure_capture_audit_backing(r uuid,p jsonb,a jsonb,observed timestamptz,fresh_until timestamptz) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE root public.capture_audit_root;trust public.fleet_current_trust;pool public.operation_audit_pool;account public.capture_audit_allocation;n timestamptz;started timestamptz:=clock_timestamp();until_at timestamptz;pool_missing boolean;account_missing boolean;pool_revision bigint:=(p->>'ExpectedRevision')::bigint;account_revision bigint:=(a->>'ExpectedRevision')::bigint;allocation uuid:=(a->'Account'->>'AllocationID')::uuid;desired jsonb:=a->'Account';pol jsonb:=desired->'Policy';
BEGIN
 IF NOT public.capture_audit_role_ok(r,'source') OR octet_length(p::text)>4096 OR octet_length(a::text)>8192 THEN RAISE EXCEPTION 'capture backing source unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=root.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO pool FROM public.operation_audit_pool WHERE root_id=r AND lane='capture' FOR UPDATE;pool_missing:=NOT FOUND;
 SELECT * INTO account FROM public.capture_audit_allocation WHERE root_id=r AND allocation_id=allocation FOR UPDATE;account_missing:=NOT FOUND;
 n:=clock_timestamp();until_at:=LEAST(started+interval '5 seconds',fresh_until,trust.fresh_until,root.valid_until,(p->>'ValidUntil')::timestamptz,(a->>'ValidUntil')::timestamptz,(pol->>'ValidUntil')::timestamptz);
 IF NOT COALESCE(observed<=n AND fresh_until>observed AND fresh_until<=observed+interval '5 seconds' AND n<until_at AND NOT trust.recovery_blocked AND NOT trust.suspended AND trust.observed_at<=n AND (p->>'RootID')::uuid=r AND p->>'Lane'='capture' AND pool_revision BETWEEN 0 AND 1152921504606846975 AND account_revision BETWEEN 0 AND 1152921504606846975 AND (desired->>'RootID')::uuid=r AND (desired->>'Revision')::bigint=account_revision+1 AND desired->>'AccountVersion'=p->>'AccountVersion' AND (desired->>'RetainedSeconds')::bigint=(p->>'RetainedSeconds')::bigint AND (pol->>'BackingRevision')::bigint=pool_revision+1 AND (pol->>'InstallationID')::uuid=root.installation_id AND (pol->>'RootID')::uuid=r AND pol->>'Lane'='capture' AND pol->'History'->>'Layout'='capture-intent-history/v1' AND (pol->>'MetadataSlots')::bigint>=(p->>'Accounts')::bigint*(p->>'RecordsPerAccount')::bigint AND public.connector_digest(desired->'AccountDigest') IS NOT NULL,false) THEN RAISE EXCEPTION 'capture backing current observation unavailable' USING ERRCODE='23514';END IF;
 IF pool_missing THEN
  IF pool_revision<>0 THEN RAISE EXCEPTION 'capture backing pool missing' USING ERRCODE='23514';END IF;
  INSERT INTO public.operation_audit_pool(root_id,lane,account_version,revision,paused,valid_until,account_limit,records_per_account,retained_seconds)
  VALUES(r,'capture',p->>'AccountVersion',1,(p->>'Paused')::boolean,(p->>'ValidUntil')::timestamptz,(p->>'Accounts')::bigint,(p->>'RecordsPerAccount')::bigint,(p->>'RetainedSeconds')::bigint);
 ELSIF pool.revision=pool_revision+1 THEN
  IF ROW(pool.account_version,pool.paused,pool.valid_until,pool.account_limit,pool.records_per_account,pool.retained_seconds) IS DISTINCT FROM ROW(p->>'AccountVersion',(p->>'Paused')::boolean,(p->>'ValidUntil')::timestamptz,(p->>'Accounts')::bigint,(p->>'RecordsPerAccount')::bigint,(p->>'RetainedSeconds')::bigint) THEN RAISE EXCEPTION 'capture backing pool replay mismatch' USING ERRCODE='23514';END IF;
 ELSE
  IF pool.revision<>pool_revision OR pool.account_version<>p->>'AccountVersion' THEN RAISE EXCEPTION 'capture backing pool revision mismatch' USING ERRCODE='23514';END IF;
  UPDATE public.operation_audit_pool SET revision=revision+1,paused=(p->>'Paused')::boolean,valid_until=(p->>'ValidUntil')::timestamptz,account_limit=(p->>'Accounts')::bigint,records_per_account=(p->>'RecordsPerAccount')::bigint,retained_seconds=(p->>'RetainedSeconds')::bigint WHERE root_id=r AND lane='capture';
 END IF;
 IF account_missing THEN
  IF account_revision<>0 THEN RAISE EXCEPTION 'capture backing account missing' USING ERRCODE='23514';END IF;
  INSERT INTO public.capture_audit_allocation(root_id,allocation_id,account_version,account_digest,revision,paused,valid_until,guaranteed_records,policy)
  VALUES(r,allocation,desired->>'AccountVersion',public.connector_digest(desired->'AccountDigest'),1,(a->>'Paused')::boolean,(a->>'ValidUntil')::timestamptz,(desired->>'Records')::bigint,pol);
 ELSIF account.revision=account_revision+1 THEN
  IF ROW(account.account_version,account.account_digest,account.paused,account.valid_until,account.guaranteed_records,account.policy) IS DISTINCT FROM ROW(desired->>'AccountVersion',public.connector_digest(desired->'AccountDigest'),(a->>'Paused')::boolean,(a->>'ValidUntil')::timestamptz,(desired->>'Records')::bigint,pol) THEN RAISE EXCEPTION 'capture backing account replay mismatch' USING ERRCODE='23514';END IF;
 ELSE
  IF account.revision<>account_revision THEN RAISE EXCEPTION 'capture backing account revision mismatch' USING ERRCODE='23514';END IF;
  UPDATE public.capture_audit_allocation SET revision=revision+1,paused=(a->>'Paused')::boolean,valid_until=(a->>'ValidUntil')::timestamptz,guaranteed_records=(desired->>'Records')::bigint,policy=pol WHERE root_id=r AND allocation_id=allocation;
 END IF;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capture backing expired after lock' USING ERRCODE='23514';END IF;
 RETURN until_at;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION configure_capture_audit_backing(uuid,jsonb,jsonb,timestamptz,timestamptz) FROM PUBLIC;

-- Retained provenance is separate from active journal timing and survives the
-- independently qualified retirement of the audit pair. No effect is granted.
CREATE VIEW capture_operation_intents WITH(security_barrier=true) AS
SELECT c.* FROM public.context_capture c WHERE c.intent_operation_id=c.id AND
 public.capture_audit_role_ok(c.root_id,'reader');
REVOKE ALL ON capture_operation_intents FROM PUBLIC;
