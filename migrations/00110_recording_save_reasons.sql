-- +goose Up
-- ADR-267: descriptive encrypted reason, never collection authority.
ALTER TABLE context_capture ADD COLUMN reason_ref jsonb CHECK(reason_ref IS NULL OR (jsonb_typeof(reason_ref)='object' AND octet_length(reason_ref::text)<=1024));
ALTER TABLE context_preview ADD COLUMN reason_envelope bytea CHECK(reason_envelope IS NULL OR octet_length(reason_envelope) BETWEEN 1 AND 16384);
ALTER TABLE context_preview ADD CONSTRAINT context_preview_reason_total_bytes CHECK(reason_envelope IS NULL OR octet_length(blueprint_json)+octet_length(reason_envelope)<=131072);
CREATE OR REPLACE VIEW capture_operation_intents WITH(security_barrier=true) AS SELECT c.id,c.root_id,c.request_key,c.submission_digest,c.scope_digest,c.scope_json,c.expectation_json,c.pod_pin_json,c.attempt_id,c.permission_epoch,c.permission_sequence,c.identity_policy_uid,c.identity_policy_generation,c.identity_policy_digest,c.created_at,c.deadline,c.state,c.intent_acknowledged_at,c.intent_digest,c.intent_object_key,c.intent_object_version,c.intent_object_etag,c.intent_object_bytes,c.intent_object_sha256,c.progress_revision,c.deadline_observed_at,c.preview_id,c.intent_operation_id,c.share_instruction,c.history_cluster_id,c.history_namespace_uid,c.history_workload_uid,c.history_origin,c.history_parameters_required,c.repeated_from_capture_id,c.repeated_from_expires_at,c.reason_ref FROM public.context_capture c WHERE c.intent_operation_id=c.id AND public.capture_audit_role_ok(c.root_id,'reader');

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
CREATE FUNCTION capture_reason_preview_id(c public.context_capture) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(c.preview_id,(SELECT g.preview_id FROM public.recording_save_group g WHERE g.id=c.group_id AND g.root_id=c.root_id))
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capture_audit_payload_matches(c public.context_capture,i jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE base jsonb; p public.context_preview; e jsonb:=i->'ReasonEnvelope'; ref jsonb:=i->'Capture'->'ReasonRef';
BEGIN
 IF c.reason_ref IS NULL THEN
  RETURN NOT(i ? 'ReasonEnvelope') AND NOT(i->'Capture' ? 'ReasonRef') AND public.capture_audit_payload_matches_without_reason(c,i);
 END IF;
 IF i->>'InputFormat' IS DISTINCT FROM 'capture-intent-reason/v1' OR ref IS DISTINCT FROM c.reason_ref OR
  jsonb_typeof(ref) IS DISTINCT FROM 'object' OR (ref-ARRAY['ID','CiphertextDigest','ExpiresAt'])<>'{}'::jsonb OR public.connector_digest(ref->'CiphertextDigest') IS NULL OR
  jsonb_typeof(e) IS DISTINCT FROM 'object' OR (e-ARRAY['format','keyReference','wrappedKey','ciphertext'])<>'{}'::jsonb OR e->>'format' IS DISTINCT FROM 'asservat-recording-save-reason/v1' OR
  octet_length(decode(e->>'keyReference','base64')) NOT BETWEEN 1 AND 256 OR octet_length(decode(e->>'wrappedKey','base64')) NOT BETWEEN 1 AND 8192 OR octet_length(decode(e->>'ciphertext','base64')) NOT BETWEEN 34 AND 2081 THEN RETURN false;END IF;
 SELECT * INTO p FROM public.context_preview WHERE root_id=c.root_id AND id=public.capture_reason_preview_id(c);
 IF FOUND AND p.reason_envelope IS NOT NULL THEN
  IF ref->>'ID' IS DISTINCT FROM p.id::text OR convert_from(p.blueprint_json,'UTF8')::jsonb#>'{Intent,Reason}' IS DISTINCT FROM ref THEN RETURN false;END IF;
  IF convert_from(p.reason_envelope,'UTF8')::jsonb IS DISTINCT FROM e OR sha256(p.reason_envelope) IS DISTINCT FROM public.connector_digest(ref->'CiphertextDigest') THEN RETURN false;END IF;
 ELSIF NOT EXISTS(SELECT 1 FROM public.operation_audit a WHERE a.id=c.id AND a.root_id=c.root_id AND a.intent->'ReasonEnvelope'=e AND a.intent->'Capture'->'ReasonRef'=ref) THEN RETURN false;
 END IF;
 base:=jsonb_set(jsonb_set(i-'ReasonEnvelope','{InputFormat}','"capture-intent/v2"'::jsonb),'{Capture}',i->'Capture'-'ReasonRef');
 RETURN public.capture_audit_payload_matches_without_reason(c,base);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION capture_audit_intent_limit(i jsonb) RETURNS integer LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN i->>'Name'='persist_capture_intent' AND i->>'InputFormat'='capture-intent-reason/v1' AND jsonb_typeof(i->'ReasonEnvelope')='object' AND jsonb_typeof(i->'Capture'->'ReasonRef')='object' THEN 32768 ELSE 16384 END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
-- The SQL52 checks were unnamed. Select the exact authored predicate, never
-- an assumed auto-generated name or a fragment of another constraint.
DO $$
DECLARE matches integer; selected_name text;
BEGIN
 SELECT count(*),min(c.conname::text) INTO matches,selected_name
 FROM pg_catalog.pg_constraint c
 WHERE c.conrelid='public.operation_audit'::regclass AND c.contype='c'
  AND c.convalidated AND c.conislocal AND c.coninhcount=0
  AND cardinality(c.conkey)=2
  AND ARRAY(SELECT k.attnum FROM unnest(c.conkey) AS k(attnum) ORDER BY k.attnum)=
      ARRAY(SELECT a.attnum FROM pg_catalog.pg_attribute a
       WHERE a.attrelid=c.conrelid AND NOT a.attisdropped AND a.attname IN ('intent','lane') ORDER BY a.attnum)
  AND lower(regexp_replace(replace(replace(replace(pg_catalog.pg_get_expr(c.conbin,c.conrelid),'::text',''),'public.',''),'pg_catalog.',''),'[[:space:]()]','','g'))=
      'jsonb_typeofintent=''object''andoctet_lengthintent<=casewhenlane=''capture''then16384else8192end';
 IF matches<>1 THEN
  RAISE EXCEPTION 'expected one exact legacy intent audit constraint, found %',matches USING ERRCODE='23514';
 END IF;
 EXECUTE format('ALTER TABLE public.operation_audit DROP CONSTRAINT %I',selected_name);
END $$;
-- +goose StatementEnd
ALTER TABLE operation_audit ADD CONSTRAINT operation_audit_intent_check CHECK(jsonb_typeof(intent)='object' AND octet_length(intent::text)<=CASE WHEN lane='capture' THEN public.capture_audit_intent_limit(intent) ELSE 8192 END);
-- +goose StatementBegin
-- The SQL52 checks were unnamed. Select the exact authored predicate, never
-- an assumed auto-generated name or a fragment of another constraint.
DO $$
DECLARE matches integer; selected_name text;
BEGIN
 SELECT count(*),min(c.conname::text) INTO matches,selected_name
 FROM pg_catalog.pg_constraint c
 WHERE c.conrelid='public.operation_audit'::regclass AND c.contype='c'
  AND c.convalidated AND c.conislocal AND c.coninhcount=0
  AND cardinality(c.conkey)=2
  AND ARRAY(SELECT k.attnum FROM unnest(c.conkey) AS k(attnum) ORDER BY k.attnum)=
      ARRAY(SELECT a.attnum FROM pg_catalog.pg_attribute a
       WHERE a.attrelid=c.conrelid AND NOT a.attisdropped AND a.attname IN ('outcome','lane') ORDER BY a.attnum)
  AND lower(regexp_replace(replace(replace(replace(pg_catalog.pg_get_expr(c.conbin,c.conrelid),'::text',''),'public.',''),'pg_catalog.',''),'[[:space:]()]','','g'))=
      'outcomeisnullorjsonb_typeofoutcome=''object''andoctet_lengthoutcome<=casewhenlane=''capture''then24576else16384end';
 IF matches<>1 THEN
  RAISE EXCEPTION 'expected one exact legacy outcome audit constraint, found %',matches USING ERRCODE='23514';
 END IF;
 EXECUTE format('ALTER TABLE public.operation_audit DROP CONSTRAINT %I',selected_name);
END $$;
-- +goose StatementEnd
ALTER TABLE operation_audit ADD CONSTRAINT operation_audit_outcome_check CHECK(outcome IS NULL OR (jsonb_typeof(outcome)='object' AND octet_length(outcome::text)<=CASE WHEN lane='capture' THEN CASE WHEN public.capture_audit_intent_limit(intent)=32768 THEN 32768 ELSE 24576 END ELSE 16384 END));

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reserve_capture_audit(r uuid,capture uuid,i jsonb,capture_digest bytea,original_until timestamptz) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c public.context_capture;a public.capture_audit_allocation;trust public.fleet_current_trust;root public.capture_audit_root;allocation uuid;observed jsonb;n timestamptz;
BEGIN
 IF octet_length(i::text)>public.capture_audit_intent_limit(i) OR octet_length(capture_digest)<>32 OR NOT public.capture_audit_role_ok(r,'admission') THEN RAISE EXCEPTION 'capture audit admission unavailable' USING ERRCODE='23514';END IF;
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
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capture_audit_journal(r uuid,i jsonb,verb text,o jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit;fresh boolean:=false;n timestamptz;started timestamptz:=clock_timestamp();until_at timestamptz;
BEGIN
 IF NOT public.capture_audit_role_ok(r,'journal') OR octet_length(i::text)>public.capture_audit_intent_limit(i) OR verb NOT IN('reserve','claim-intent','claim-outcome','freeze-outcome') THEN RAISE EXCEPTION 'capture audit writer unavailable' USING ERRCODE='23514';END IF;
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
  IF octet_length(o::text)>CASE WHEN public.capture_audit_intent_limit(i)=32768 THEN 32768 ELSE 24576 END OR NOT COALESCE(o->'Intent'=i AND o->>'Status'='success' AND o->>'Reason'='prepared' AND o->>'Effect'='accepted' AND o->>'ClientReceipt'='unknown' AND o->'CaptureIDs'=jsonb_build_array(a.id::text) AND (o->'CaseIDs'='null'::jsonb OR o->'CaseIDs'='[]'::jsonb) AND (o->'ArtifactIDs'='null'::jsonb OR o->'ArtifactIDs'='[]'::jsonb) AND (o->>'OutputBytes')::bigint=0 AND NOT(o ? 'Credential') AND public.connector_digest(o->'OutputDigest') IS NOT NULL AND (o->>'MetadataUntil')::timestamptz=a.request_until AND (o->>'RecordedAt')::timestamptz>=((i->>'CreatedAt')::timestamptz) AND (o->>'RecordedAt')::timestamptz<=n AND (o->>'RecordedAt')::timestamptz<a.write_until,false) THEN RAISE EXCEPTION 'capture persistence outcome invalid' USING ERRCODE='23514';END IF;
  IF a.outcome IS NULL THEN
   IF a.intent_receipt IS NULL THEN RAISE EXCEPTION 'capture intent not acknowledged' USING ERRCODE='23514';END IF;
   UPDATE public.operation_audit SET outcome=o WHERE id=a.id RETURNING * INTO a;
  ELSIF a.outcome IS DISTINCT FROM o THEN RAISE EXCEPTION 'capture outcome already frozen' USING ERRCODE='23514';END IF;
 END IF;
 IF clock_timestamp()>=until_at OR fresh AND verb='claim-intent' AND clock_timestamp()>=a.request_until THEN RAISE EXCEPTION 'capture write claim expired' USING ERRCODE='23514';END IF;
 IF fresh AND verb='claim-intent' THEN until_at:=LEAST(until_at,a.request_until);END IF;
 RETURN jsonb_build_object('Snapshot',public.capture_audit_snapshot(a),'Fresh',fresh,'ValidUntil',until_at);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION claim_capture_reconciliation(r uuid,i jsonb,phase text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit;b public.capture_audit_binding;started timestamptz:=clock_timestamp();n timestamptz;until_at timestamptz;trust_until timestamptz;attempt bigint;
BEGIN
 IF NOT public.capture_audit_role_ok(r,'journal') OR phase NOT IN('intent','outcome') OR octet_length(i::text)>public.capture_audit_intent_limit(i) THEN RAISE EXCEPTION 'capture reconciliation unavailable' USING ERRCODE='23514';END IF;
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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capture_audit_acknowledge(r uuid,i jsonb,phase text,completion jsonb,receipt jsonb,read_claim jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit;d public.operation_audit_lifecycle;b public.capture_audit_binding;existing jsonb;old_receipt jsonb;started boolean;read_until timestamptz;until_at timestamptz;begin_at timestamptz:=clock_timestamp();
BEGIN
 IF NOT public.capture_audit_role_ok(r,'acknowledge') OR phase NOT IN('intent','outcome') OR octet_length(i::text)>public.capture_audit_intent_limit(i) OR completion IS NOT NULL AND octet_length(completion::text)>8192 OR receipt IS NOT NULL AND octet_length(receipt::text)>4096 THEN RAISE EXCEPTION 'capture acknowledgement unavailable' USING ERRCODE='23514';END IF;
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
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION acknowledge_capture_pair(r uuid,i jsonb) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit;b public.capture_audit_binding;c public.context_capture;begin_at timestamptz:=clock_timestamp();until_at timestamptz;
BEGIN
 IF NOT public.capture_audit_role_ok(r,'acknowledge') OR octet_length(i::text)>public.capture_audit_intent_limit(i) THEN RAISE EXCEPTION 'capture pair acknowledgement unavailable' USING ERRCODE='23514';END IF;
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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format IN ('capture-intent/v2','capture-intent-reason/v1')
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION capture_preview_reason_copied(p public.context_preview) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM public.context_capture c JOIN public.capture_audit_binding b ON b.capture_id=c.id AND b.root_id=c.root_id JOIN public.operation_audit a ON a.id=b.operation_id AND a.root_id=b.root_id
 WHERE c.root_id=p.root_id AND public.capture_reason_preview_id(c)=p.id AND c.reason_ref=convert_from(p.blueprint_json,'UTF8')::jsonb#>'{Intent,Reason}' AND a.intent->'ReasonEnvelope'=convert_from(p.reason_envelope,'UTF8')::jsonb)
 AND NOT EXISTS(SELECT 1 FROM public.recording_save_group g WHERE g.root_id=p.root_id AND g.preview_id=p.id AND EXISTS(SELECT 1 FROM unnest(g.child_ids) member(id) LEFT JOIN public.capture_audit_binding b ON b.root_id=g.root_id AND b.capture_id=member.id LEFT JOIN public.operation_audit a ON a.id=b.operation_id AND a.root_id=b.root_id WHERE a.id IS NULL OR a.intent->'ReasonEnvelope' IS DISTINCT FROM convert_from(p.reason_envelope,'UTF8')::jsonb))
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_preview_immutable() RETURNS trigger LANGUAGE plpgsql
 SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.closed_at IS NOT NULL OR NEW.closed_request_key IS NOT NULL OR NEW.closed_submission_digest IS NOT NULL THEN
   RAISE EXCEPTION 'preview cannot begin closed' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 ELSIF TG_OP='UPDATE' THEN
  IF NEW.reason_envelope IS DISTINCT FROM OLD.reason_envelope AND NOT(OLD.reason_envelope IS NOT NULL AND NEW.reason_envelope IS NULL AND public.capture_preview_reason_copied(OLD)) THEN RAISE EXCEPTION 'preview reason is immutable' USING ERRCODE='23514';END IF;
  IF (to_jsonb(NEW)-ARRAY['closed_at','closed_request_key','closed_submission_digest','reason_envelope']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['closed_at','closed_request_key','closed_submission_digest','reason_envelope']) THEN
   RAISE EXCEPTION 'context preview is immutable' USING ERRCODE='23514';
  END IF;
  IF OLD.closed_at IS NOT NULL THEN
   IF (to_jsonb(NEW)-'reason_envelope') IS DISTINCT FROM (to_jsonb(OLD)-'reason_envelope') THEN RAISE EXCEPTION 'context preview closure is immutable' USING ERRCODE='23514'; END IF;
  ELSIF NEW.closed_at IS NOT NULL THEN
   NEW.closed_at:=clock_timestamp();
  END IF;
  RETURN NEW;
 END IF;
 IF public.context_preview_read_until(OLD.root_id,OLD.id)>clock_timestamp() THEN
  RAISE EXCEPTION 'context preview is not expired' USING ERRCODE='23514';
 END IF;
 RETURN OLD;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION erase_copied_preview_reason() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c public.context_capture; p public.context_preview;
BEGIN
 SELECT * INTO STRICT c FROM public.context_capture WHERE id=NEW.capture_id AND root_id=NEW.root_id;
 IF c.reason_ref IS NULL THEN RETURN NEW;END IF;
 SELECT * INTO STRICT p FROM public.context_preview WHERE id=public.capture_reason_preview_id(c) AND root_id=c.root_id FOR UPDATE;
 IF p.reason_envelope IS NOT NULL AND public.capture_preview_reason_copied(p) THEN UPDATE public.context_preview SET reason_envelope=NULL WHERE id=p.id AND root_id=p.root_id;END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

CREATE CONSTRAINT TRIGGER capture_reason_preview_transfer AFTER INSERT ON capture_audit_binding DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION erase_copied_preview_reason();

-- +goose StatementBegin
CREATE FUNCTION guard_capture_reason_ref() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.context_preview;
BEGIN
 IF TG_OP='UPDATE' AND NEW.reason_ref IS DISTINCT FROM OLD.reason_ref THEN RAISE EXCEPTION 'capture reason reference is immutable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO p FROM public.context_preview WHERE id=public.capture_reason_preview_id(NEW) AND root_id=NEW.root_id;
  IF (NEW.reason_ref IS NOT NULL OR (FOUND AND jsonb_typeof(convert_from(p.blueprint_json,'UTF8')::jsonb#>'{Intent,Reason}')='object')) AND (p.reason_envelope IS NULL OR NEW.reason_ref IS DISTINCT FROM convert_from(p.blueprint_json,'UTF8')::jsonb#>'{Intent,Reason}' OR sha256(p.reason_envelope) IS DISTINCT FROM public.connector_digest(NEW.reason_ref->'CiphertextDigest')) THEN RAISE EXCEPTION 'capture reason provenance mismatch' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

CREATE TRIGGER capture_reason_ref_guard BEFORE INSERT OR UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION guard_capture_reason_ref();
REVOKE ALL ON FUNCTION capture_reason_preview_id(public.context_capture),capture_audit_payload_matches_without_reason(public.context_capture,jsonb),capture_audit_intent_limit(jsonb),capture_preview_reason_copied(public.context_preview),erase_copied_preview_reason(),guard_capture_reason_ref() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION read_capture_reason(r uuid,capture uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE root public.capture_audit_root;trust public.fleet_current_trust;a public.operation_audit;d public.operation_audit_lifecycle;c public.context_capture;started timestamptz:=clock_timestamp();n timestamptz;until_at timestamptz;
BEGIN
 IF NOT public.capture_audit_role_ok(r,'journal') THEN RAISE EXCEPTION 'capture reason reader unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=root.installation_id;
 SELECT * INTO STRICT a FROM public.operation_audit WHERE id=capture AND root_id=r AND lane='capture';
 SELECT * INTO STRICT d FROM public.operation_audit_lifecycle WHERE operation_id=capture AND root_id=r;
 SELECT * INTO STRICT c FROM public.context_capture WHERE id=capture AND root_id=r;
 n:=clock_timestamp();until_at:=LEAST(started+interval '5 seconds',trust.fresh_until,d.original_purge_at);
 IF NOT COALESCE(NOT trust.recovery_blocked AND NOT trust.suspended AND trust.observed_at<=n AND n<until_at AND trust.issuer_epoch=a.issuer_epoch AND d.issuer_epoch=a.issuer_epoch AND public.incarnation_current(d.postmaster_at) AND d.database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AND d.installation_id=root.installation_id AND c.reason_ref IS NOT NULL AND a.intent->>'InputFormat'='capture-intent-reason/v1' AND public.capture_audit_payload_matches(c,a.intent) AND EXISTS(SELECT 1 FROM public.capture_audit_binding b WHERE b.capture_id=capture AND b.root_id=r),false) THEN RAISE EXCEPTION 'capture reason is unavailable' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Capture',a.intent->'Capture','Envelope',a.intent->'ReasonEnvelope','ValidUntil',until_at);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_capture_reason(uuid,uuid) FROM PUBLIC;

-- +goose Down

-- +goose StatementBegin
DO $$ BEGIN IF EXISTS(SELECT 1 FROM public.context_capture WHERE reason_ref IS NOT NULL) OR EXISTS(SELECT 1 FROM public.context_preview WHERE reason_envelope IS NOT NULL) OR EXISTS(SELECT 1 FROM public.operation_audit WHERE intent->>'InputFormat'='capture-intent-reason/v1') THEN RAISE EXCEPTION 'populated recording reasons cannot downgrade';END IF;END $$;
-- +goose StatementEnd

DROP FUNCTION read_capture_reason(uuid,uuid);
DROP TRIGGER capture_reason_preview_transfer ON capture_audit_binding;
DROP TRIGGER capture_reason_ref_guard ON context_capture;
DROP FUNCTION erase_copied_preview_reason(),guard_capture_reason_ref();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_preview_immutable() RETURNS trigger LANGUAGE plpgsql
 SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.closed_at IS NOT NULL OR NEW.closed_request_key IS NOT NULL OR NEW.closed_submission_digest IS NOT NULL THEN
   RAISE EXCEPTION 'preview cannot begin closed' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 ELSIF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-ARRAY['closed_at','closed_request_key','closed_submission_digest']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['closed_at','closed_request_key','closed_submission_digest']) THEN
   RAISE EXCEPTION 'context preview is immutable' USING ERRCODE='23514';
  END IF;
  IF OLD.closed_at IS NOT NULL THEN
   IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'context preview closure is immutable' USING ERRCODE='23514'; END IF;
  ELSIF NEW.closed_at IS NOT NULL THEN
   NEW.closed_at:=clock_timestamp();
  END IF;
  RETURN NEW;
 END IF;
 IF public.context_preview_read_until(OLD.root_id,OLD.id)>clock_timestamp() THEN
  RAISE EXCEPTION 'context preview is not expired' USING ERRCODE='23514';
 END IF;
 RETURN OLD;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format='capture-intent/v2'
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reserve_capture_audit(r uuid,capture uuid,i jsonb,capture_digest bytea,original_until timestamptz) RETURNS void
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
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capture_audit_journal(r uuid,i jsonb,verb text,o jsonb) RETURNS jsonb
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
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION claim_capture_reconciliation(r uuid,i jsonb,phase text) RETURNS jsonb
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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capture_audit_acknowledge(r uuid,i jsonb,phase text,completion jsonb,receipt jsonb,read_claim jsonb) RETURNS jsonb
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
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION acknowledge_capture_pair(r uuid,i jsonb) RETURNS timestamptz
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

-- +goose StatementBegin
-- The SQL52 checks were unnamed. Select the exact authored predicate, never
-- an assumed auto-generated name or a fragment of another constraint.
DO $$
DECLARE matches integer; selected_name text;
BEGIN
 SELECT count(*),min(c.conname::text) INTO matches,selected_name
 FROM pg_catalog.pg_constraint c
 WHERE c.conrelid='public.operation_audit'::regclass AND c.contype='c'
  AND c.convalidated AND c.conislocal AND c.coninhcount=0
  AND cardinality(c.conkey)=2
  AND ARRAY(SELECT k.attnum FROM unnest(c.conkey) AS k(attnum) ORDER BY k.attnum)=
      ARRAY(SELECT a.attnum FROM pg_catalog.pg_attribute a
       WHERE a.attrelid=c.conrelid AND NOT a.attisdropped AND a.attname IN ('intent','lane') ORDER BY a.attnum)
  AND lower(regexp_replace(replace(replace(replace(pg_catalog.pg_get_expr(c.conbin,c.conrelid),'::text',''),'public.',''),'pg_catalog.',''),'[[:space:]()]','','g'))=
      'jsonb_typeofintent=''object''andoctet_lengthintent<=casewhenlane=''capture''thencapture_audit_intent_limitintentelse8192end';
 IF matches<>1 THEN
  RAISE EXCEPTION 'expected one exact reason intent audit constraint, found %',matches USING ERRCODE='23514';
 END IF;
 EXECUTE format('ALTER TABLE public.operation_audit DROP CONSTRAINT %I',selected_name);
END $$;
-- +goose StatementEnd
ALTER TABLE operation_audit ADD CHECK(jsonb_typeof(intent)='object' AND octet_length(intent::text)<=CASE WHEN lane='capture' THEN 16384 ELSE 8192 END);
-- +goose StatementBegin
-- The SQL52 checks were unnamed. Select the exact authored predicate, never
-- an assumed auto-generated name or a fragment of another constraint.
DO $$
DECLARE matches integer; selected_name text;
BEGIN
 SELECT count(*),min(c.conname::text) INTO matches,selected_name
 FROM pg_catalog.pg_constraint c
 WHERE c.conrelid='public.operation_audit'::regclass AND c.contype='c'
  AND c.convalidated AND c.conislocal AND c.coninhcount=0
  AND cardinality(c.conkey)=3
  AND ARRAY(SELECT k.attnum FROM unnest(c.conkey) AS k(attnum) ORDER BY k.attnum)=
      ARRAY(SELECT a.attnum FROM pg_catalog.pg_attribute a
       WHERE a.attrelid=c.conrelid AND NOT a.attisdropped AND a.attname IN ('outcome','lane','intent') ORDER BY a.attnum)
  AND lower(regexp_replace(replace(replace(replace(pg_catalog.pg_get_expr(c.conbin,c.conrelid),'::text',''),'public.',''),'pg_catalog.',''),'[[:space:]()]','','g'))=
      'outcomeisnullorjsonb_typeofoutcome=''object''andoctet_lengthoutcome<=casewhenlane=''capture''thencasewhencapture_audit_intent_limitintent=32768then32768else24576endelse16384end';
 IF matches<>1 THEN
  RAISE EXCEPTION 'expected one exact reason outcome audit constraint, found %',matches USING ERRCODE='23514';
 END IF;
 EXECUTE format('ALTER TABLE public.operation_audit DROP CONSTRAINT %I',selected_name);
END $$;
-- +goose StatementEnd
ALTER TABLE operation_audit ADD CHECK(outcome IS NULL OR (jsonb_typeof(outcome)='object' AND octet_length(outcome::text)<=CASE WHEN lane='capture' THEN 24576 ELSE 16384 END));
DROP FUNCTION capture_preview_reason_copied(public.context_preview),capture_reason_preview_id(public.context_capture),capture_audit_payload_matches_without_reason(public.context_capture,jsonb),capture_audit_intent_limit(jsonb);

-- +goose StatementBegin
DO $$ DECLARE roles text[]; grant_role text;
BEGIN
 SELECT array_agg(pg_get_userbyid(x.grantee)) INTO roles FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) x WHERE c.oid='public.capture_operation_intents'::regclass AND x.privilege_type='SELECT' AND x.grantee<>0;
 DROP VIEW public.capture_operation_intents;
 ALTER TABLE public.context_capture DROP COLUMN reason_ref;
 CREATE VIEW public.capture_operation_intents WITH(security_barrier=true) AS SELECT c.id,c.root_id,c.request_key,c.submission_digest,c.scope_digest,c.scope_json,c.expectation_json,c.pod_pin_json,c.attempt_id,c.permission_epoch,c.permission_sequence,c.identity_policy_uid,c.identity_policy_generation,c.identity_policy_digest,c.created_at,c.deadline,c.state,c.intent_acknowledged_at,c.intent_digest,c.intent_object_key,c.intent_object_version,c.intent_object_etag,c.intent_object_bytes,c.intent_object_sha256,c.progress_revision,c.deadline_observed_at,c.preview_id,c.intent_operation_id,c.share_instruction,c.history_cluster_id,c.history_namespace_uid,c.history_workload_uid,c.history_origin,c.history_parameters_required,c.repeated_from_capture_id,c.repeated_from_expires_at FROM public.context_capture c WHERE c.intent_operation_id=c.id AND public.capture_audit_role_ok(c.root_id,'reader');
 REVOKE ALL ON public.capture_operation_intents FROM PUBLIC;
 FOREACH grant_role IN ARRAY COALESCE(roles,ARRAY[]::text[]) LOOP EXECUTE format('GRANT SELECT ON public.capture_operation_intents TO %I',grant_role);END LOOP;
END $$;
-- +goose StatementEnd

ALTER TABLE context_preview DROP COLUMN reason_envelope;
