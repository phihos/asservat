-- +goose Up
-- REQ-EVD-001 / ADR-330: one-step publication. The hub inserts the catalog
-- row in the transaction that records the collector's stored outcome, from
-- its admitted facts plus the collector-reported copy digest, native size and
-- profile acquisition window. There is no verification stage, verification
-- audit acknowledgement or verifier key unwrap any more. Reads authenticate
-- the manifest and compare it with this row.
ALTER TABLE context_catalog
 ADD COLUMN IF NOT EXISTS copies_digest bytea CHECK(octet_length(copies_digest)=32),
 ADD COLUMN IF NOT EXISTS native_bytes bigint CHECK(native_bytes>=0 AND native_bytes<=1099511627776),
 ADD COLUMN IF NOT EXISTS acquisition_started_at timestamptz,
 ADD COLUMN IF NOT EXISTS acquisition_completed_at timestamptz;
ALTER TABLE context_catalog DROP CONSTRAINT IF EXISTS context_catalog_acquisition_window;
ALTER TABLE context_catalog ADD CONSTRAINT context_catalog_acquisition_window CHECK (
 (acquisition_started_at IS NULL AND acquisition_completed_at IS NULL) OR
 (acquisition_started_at IS NOT NULL AND acquisition_completed_at IS NOT NULL
  AND isfinite(acquisition_started_at) AND isfinite(acquisition_completed_at)
  AND acquisition_started_at<=acquisition_completed_at));
UPDATE context_catalog cat SET copies_digest=a.copies_digest
 FROM context_capture c JOIN custody_attempt a ON a.id=c.attempt_id
 WHERE c.id=cat.capture_id AND c.root_id=cat.root_id AND cat.copies_digest IS NULL;
ALTER TABLE context_catalog ALTER COLUMN copies_digest SET NOT NULL;
ALTER TABLE context_catalog DROP CONSTRAINT IF EXISTS context_catalog_capture_id_fkey;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.advance_context_progress()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_TABLE_SCHEMA<>'public' THEN RAISE EXCEPTION 'invalid context progress source' USING ERRCODE='23514'; END IF;
 IF TG_RELID='public.custody_attempt'::regclass AND TG_OP='UPDATE' THEN
  IF ROW(NEW.state,NEW.copies_digest,NEW.effective_expires_at,NEW.effective_delete_by,NEW.retention_sequence,NEW.deleted_at) IS DISTINCT FROM ROW(OLD.state,OLD.copies_digest,OLD.effective_expires_at,OLD.effective_delete_by,OLD.retention_sequence,OLD.deleted_at) THEN
   UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE attempt_id=NEW.id;
  END IF;
 ELSIF TG_RELID='public.context_catalog'::regclass AND TG_OP='INSERT' THEN
  UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE id=NEW.capture_id AND root_id=NEW.root_id;
 ELSIF TG_RELID='public.context_execution'::regclass AND TG_OP IN ('INSERT','UPDATE') THEN
  IF TG_OP='INSERT' OR NEW IS DISTINCT FROM OLD THEN UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE id=NEW.capture_id AND root_id=NEW.root_id; END IF;
 ELSE RAISE EXCEPTION 'invalid context progress source' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $function$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.protect_evidence_share()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE n timestamptz:=clock_timestamp();
BEGIN
 IF TG_OP='DELETE' THEN
  IF n<OLD.expires_at THEN RAISE EXCEPTION 'an unexpired share is revoked, not deleted' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  IF NOT EXISTS(SELECT 1 FROM public.context_case_locator r JOIN public.context_capture source ON source.root_id=r.root_id AND source.id=r.capture_id
   JOIN public.context_catalog v ON v.root_id=r.root_id AND v.capture_id=r.capture_id
   JOIN public.custody_attempt attempt ON attempt.id=source.attempt_id
   WHERE r.root_id=NEW.root_id AND r.artifact_id=NEW.artifact_id AND r.case_id=NEW.case_id AND r.cluster_id=NEW.cluster_id
    AND r.namespace_uid=NEW.namespace_uid AND r.workload_uid=NEW.workload_uid AND r.pod_uid=NEW.pod_uid
    AND v.copies_digest=NEW.version AND NEW.expires_at<=attempt.effective_expires_at) THEN
   RAISE EXCEPTION 'share differs from exact published source' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF OLD.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1 THEN
  RAISE EXCEPTION 'share mutation is unavailable or already spent' USING ERRCODE='23514';
 END IF;
 IF ROW(NEW.id,NEW.root_id,NEW.artifact_id,NEW.case_id,NEW.cluster_id,NEW.namespace_uid,NEW.workload_uid,NEW.pod_uid,
   NEW.version,NEW.creator_issuer,NEW.creator_subject,NEW.creator_client,NEW.recipients,NEW.recipient_keys,NEW.idempotency_key,
   NEW.request_digest,NEW.created_at,NEW.expires_at,NEW.policy_acceptance_id)
  IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.artifact_id,OLD.case_id,OLD.cluster_id,OLD.namespace_uid,OLD.workload_uid,OLD.pod_uid,
   OLD.version,OLD.creator_issuer,OLD.creator_subject,OLD.creator_client,OLD.recipients,OLD.recipient_keys,OLD.idempotency_key,
   OLD.request_digest,OLD.created_at,OLD.expires_at,OLD.policy_acceptance_id) THEN
  RAISE EXCEPTION 'share mutation changes immutable source or original bounds' USING ERRCODE='23514';
 END IF;
 IF NEW.revoked_at IS NOT NULL THEN
  IF ROW(NEW.management,NEW.transfer_key,NEW.transfer_digest) IS DISTINCT FROM ROW(OLD.management,OLD.transfer_key,OLD.transfer_digest) THEN
   RAISE EXCEPTION 'share revocation changes only the revocation' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.transfer_key IS NULL OR OLD.expires_at<=n THEN
  RAISE EXCEPTION 'share transfer changes only live management' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $function$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.materialize_capture_share()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE s jsonb; access_until timestamptz; version bytea; ends timestamptz; acceptance uuid; share uuid; at timestamptz:=clock_timestamp();
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_case_locator'::regclass THEN
  RAISE EXCEPTION 'invalid capture share source' USING ERRCODE='23514';
 END IF;
 SELECT c.share_instruction,a.effective_expires_at INTO s,access_until FROM public.context_capture c JOIN public.custody_attempt a ON a.id=c.attempt_id
 WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF s IS NULL THEN
  RETURN NEW;
 END IF;
 BEGIN
  acceptance:=(s->>'policy_acceptance_id')::uuid;
 EXCEPTION WHEN invalid_text_representation THEN
  RETURN NEW;
 END;
 IF acceptance IS NOT NULL THEN
  PERFORM 1 FROM public.policy_acceptance p WHERE p.id=acceptance AND p.root_id=NEW.root_id AND p.sharing_revoked_at IS NULL FOR KEY SHARE;
  IF NOT FOUND THEN
   RETURN NEW;
  END IF;
 END IF;
 SELECT v.copies_digest INTO version FROM public.context_catalog v WHERE v.capture_id=NEW.capture_id AND v.root_id=NEW.root_id;
 ends:=LEAST(COALESCE((s->>'not_after')::timestamptz,access_until),access_until);
 IF version IS NULL OR ends IS NULL OR ends<=at THEN
  RETURN NEW;
 END IF;
 BEGIN
  INSERT INTO public.evidence_share(id,root_id,artifact_id,case_id,cluster_id,namespace_uid,workload_uid,pod_uid,version,creator_issuer,creator_subject,creator_client,
   management,recipients,recipient_keys,idempotency_key,request_digest,created_at,expires_at,policy_acceptance_id)
  VALUES((s->>'share_id')::uuid,NEW.root_id,NEW.artifact_id,NEW.case_id,NEW.cluster_id,NEW.namespace_uid,NEW.workload_uid,NEW.pod_uid,version,
   s#>>'{creator,issuer}',s#>>'{creator,subject}',s#>>'{creator,client}',s->'management',s->'recipients',
   ARRAY(SELECT jsonb_array_elements_text(s->'recipient_keys')),'capture:'||NEW.capture_id::text,decode(s->>'request_digest','hex'),at,ends,acceptance)
  ON CONFLICT DO NOTHING RETURNING id INTO share;
 EXCEPTION WHEN check_violation OR not_null_violation OR invalid_text_representation OR foreign_key_violation THEN
  -- A malformed instruction never blocks publication; the share is
  -- reported unavailable instead.
  RETURN NEW;
 END;
 IF share IS NOT NULL THEN
  INSERT INTO public.audit_event(event_id,operation_id,kind,operation,issuer,subject,client_id,identity_type,status,effect,case_ids,artifact_ids,capture_ids,share_ids)
  VALUES(gen_random_uuid(),NEW.capture_id,'share.create','publish_capture',s#>>'{creator,issuer}',s#>>'{creator,subject}',s#>>'{creator,client}','human','success','accepted',
   ARRAY[NEW.case_id::text],ARRAY[NEW.artifact_id::text],ARRAY[NEW.capture_id::text],ARRAY[share::text]);
 END IF;
 RETURN NEW;
END $function$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.context_packet_query_scope_grant_current(r uuid, actor jsonb, s jsonb, binding jsonb)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE g public.access_grant; c public.access_grant_child; item jsonb; matched boolean:=false; n timestamptz; grant_operation text;
BEGIN
 grant_operation:=CASE WHEN s->>'DisplayVersion'='approved-pcap-query/v1' AND s->>'NativeType'='rawPcapng' THEN 'pcap_query'
  WHEN s->>'DisplayVersion'='approved-syscall-query/v1' AND s->>'NativeType'='syscallArguments' THEN 'syscall_query'
  WHEN s->>'DisplayVersion'='approved-logs/v1' AND s->>'NativeType'='logs' THEN 'get_logs' END;
 IF grant_operation IS NULL THEN RETURN binding IS NULL AND NOT(s ? 'RawGrantID'); END IF;
 IF NOT public.context_query_scope_source_valid(s) THEN RETURN false; END IF;
 IF NOT public.capacity_json_fields(binding,ARRAY['ParentID','ChildID']) OR NOT public.context_packet_query_uuid(binding->>'ParentID') OR NOT public.context_packet_query_uuid(binding->>'ChildID') OR binding->>'ParentID' IS DISTINCT FROM s->>'RawGrantID' OR actor->>'Kind' IS DISTINCT FROM 'human' THEN RETURN false; END IF;
 SELECT * INTO g FROM public.access_grant WHERE root_id=r AND id=(binding->>'ParentID')::uuid FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO c FROM public.access_grant_child WHERE root_id=r AND id=(binding->>'ChildID')::uuid;
 n:=clock_timestamp();
 IF NOT FOUND OR c.parent_id<>g.id OR c.artifact_id::text IS DISTINCT FROM s->>'ArtifactID' OR c.capture_id::text IS DISTINCT FROM s->>'CaptureID' OR
  to_jsonb(ARRAY(SELECT get_byte(c.artifact_digest,i) FROM generate_series(0,31)i)) IS DISTINCT FROM s->'Version' OR
  g.decision IS DISTINCT FROM 'approved' OR g.revoked_at IS NOT NULL OR NOT COALESCE(n<g.expires_at,false) OR
  g.requester_kind<>'human' OR g.requester_issuer IS DISTINCT FROM actor->>'Issuer' OR g.requester_subject IS DISTINCT FROM actor->>'Subject' OR
  NOT EXISTS(SELECT 1 FROM public.context_case_locator l WHERE l.root_id=r AND l.case_id::text=s->>'CaseID' AND l.capture_id=c.capture_id AND l.artifact_id=c.artifact_id AND l.cluster_id::text=s->>'ClusterID' AND l.namespace_uid=s->>'NamespaceUID' AND l.workload_uid=s->>'WorkloadUID' AND l.pod_uid=s->>'PodUID') THEN RETURN false; END IF;
 IF g.kind='adHocCapture' THEN
  RETURN COALESCE((g.capture_id=c.capture_id OR EXISTS(
   SELECT 1 FROM public.context_capture member
   JOIN public.context_case_locator l ON l.root_id=member.root_id AND l.capture_id=member.id AND l.artifact_id=c.artifact_id
   JOIN public.context_catalog verified ON verified.root_id=member.root_id AND verified.capture_id=member.id AND verified.copies_digest=c.artifact_digest
   JOIN public.recording_save_group rg ON rg.root_id=member.root_id AND rg.id=member.group_id
   WHERE member.root_id=r AND member.id=c.capture_id AND rg.id=g.capture_id AND rg.scope_digest=g.execution_digest AND
   convert_from(member.expectation_json,'UTF8')::jsonb->>'ActionID'=c.action_id AND rg.group_kind='composition' AND member.group_ordinal>=0 AND cardinality(rg.child_ids) BETWEEN 2 AND 16 AND rg.child_ids[member.group_ordinal+1]=member.id AND
 member.created_at=rg.accepted_at AND member.deadline<=rg.deadline AND sha256(member.scope_json)=member.scope_digest AND sha256(rg.scope_json)=rg.scope_digest AND
 convert_from(rg.scope_json,'UTF8')::jsonb->>'schemaVersion'='recorder-group/v1' AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->member.group_ordinal->>'captureID'=member.id::text AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->member.group_ordinal->>'scopeDigest'=encode(member.scope_digest,'hex') AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->member.group_ordinal->>'actionID'=convert_from(member.expectation_json,'UTF8')::jsonb->>'ActionID' AND
 convert_from(member.expectation_json,'UTF8')::jsonb#>>'{Registration,Location,ArtifactID}'=l.artifact_id::text AND
 convert_from(member.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ParentCaptureID}'=rg.id::text AND
 (convert_from(member.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildIndex}')::integer=member.group_ordinal AND
 (convert_from(member.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildCount}')::integer=cardinality(rg.child_ids))) AND g.result_access->'operations' ? grant_operation AND g.result_access->'actionIDs' ? c.action_id AND g.cluster_id::text=s->>'ClusterID' AND g.namespace_uid=s->>'NamespaceUID' AND g.workload_uid=s->>'WorkloadUID' AND g.pod_uid=s->>'PodUID',false);
 ELSIF g.kind='rawQuery' THEN
  IF g.raw_query->>'CaseID' IS DISTINCT FROM s->>'CaseID' OR NOT(g.raw_query->'Operations' ? grant_operation) THEN RETURN false; END IF;
  FOR item IN SELECT jsonb_array_elements(g.raw_query->'Artifacts') LOOP
   IF COALESCE(item#>>'{Output,ArtifactID}'=c.artifact_id::text AND item#>>'{Output,CaptureID}'=c.capture_id::text AND item#>>'{Output,ActionID}'=c.action_id AND item#>'{Output,ArtifactDigest}'=s->'Version' AND
     item#>>'{Output,Target,ClusterID}'=s->>'ClusterID' AND item#>>'{Output,Target,NamespaceUID}'=s->>'NamespaceUID' AND item#>>'{Output,Target,WorkloadUID}'=s->>'WorkloadUID' AND item#>>'{Output,Target,PodUID}'=s->>'PodUID' AND n<(item->>'ExpiresAt')::timestamptz,false) THEN matched:=true; END IF;
  END LOOP;
  RETURN matched;
 END IF;
 RETURN false;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN RETURN false;
END $function$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.processing_erasure_attempt(d processing_decision, p processing_root)
 RETURNS custody_attempt
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE a public.custody_attempt; l public.context_processing; doc jsonb; origins jsonb; storage_pool_id uuid; n timestamptz;
BEGIN
 IF d.action IS DISTINCT FROM 'request_early_erasure' OR d.root_id IS DISTINCT FROM p.root_id OR p.initialized_at IS NULL OR
    d.rule_id IS NOT NULL OR d.expected_revision<>0 OR
    d.scope->>'Kind' IS DISTINCT FROM 'artifact' OR NOT public.processing_scope_valid(d.scope) THEN
  RAISE EXCEPTION 'invalid processing erasure scope' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT l FROM public.context_processing WHERE root_id=d.root_id AND
  cluster_id=(d.scope#>>'{Location,ClusterID}')::uuid AND artifact_id=(d.scope#>>'{Location,ArtifactID}')::uuid AND attempt_id=(d.scope#>>'{Location,AttemptID}')::uuid;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=l.attempt_id;
 SELECT ca.pool_id INTO STRICT storage_pool_id FROM public.custody_allocation ca WHERE ca.id=a.allocation_id;
 PERFORM 1 FROM public.custody_pool cp WHERE cp.id=storage_pool_id FOR UPDATE;
 PERFORM 1 FROM public.custody_allocation ca WHERE ca.id=a.allocation_id AND ca.pool_id=storage_pool_id FOR UPDATE;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=l.attempt_id FOR UPDATE;
 n:=clock_timestamp();
 IF n>=d.request_until OR n>=p.valid_until OR d.request_until>=l.retire_by OR
    a.artifact_id<>l.artifact_id OR a.cluster_id<>l.cluster_id OR a.anchor_at<>l.anchor_at OR a.delete_by<>l.delete_by OR
    a.state<>'stored_unpublished' OR n>=a.effective_expires_at OR a.effective_expires_at<=a.anchor_at OR
    NOT EXISTS(SELECT 1 FROM public.context_catalog cat
     JOIN public.context_capture c ON c.root_id=cat.root_id AND c.id=cat.capture_id
     JOIN public.context_writer_completion w ON w.root_id=c.root_id AND w.capture_id=c.id AND w.attempt_id=c.attempt_id
     JOIN public.context_execution x ON x.root_id=w.root_id AND x.capture_id=w.capture_id AND x.attempt_id=w.attempt_id
     JOIN public.fleet_trust f ON f.installation_id=w.installation_id AND f.activated_postmaster_at=w.postmaster_at AND f.activated_database_oid=w.database_oid
     JOIN public.fleet_current_trust t ON t.installation_id=f.installation_id AND t.issuer_epoch=w.issuer_epoch
     WHERE cat.root_id=l.root_id AND cat.artifact_id=l.artifact_id AND cat.capture_id=l.capture_id AND c.attempt_id=a.id
      AND cat.copies_digest=a.copies_digest
      AND x.writer_protocol='closed-small-context/v1' AND x.phase='stored' AND x.copies_digest=w.copies_digest
      AND w.copies_digest=a.copies_digest AND w.registration_digest=a.request_digest AND w.installation_id=p.installation_id AND w.issuer_epoch=p.issuer_epoch
      AND w.closed_at<=n AND public.incarnation_current(w.postmaster_at) AND w.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database())
      AND NOT t.suspended AND t.observed_at<=n AND n<t.fresh_until) THEN
  RAISE EXCEPTION 'processing erasure needs current verified closed writer' USING ERRCODE='23514'; END IF;
 IF a.retention_sequence=0 THEN
  SELECT convert_from(c.expectation_json,'UTF8')::jsonb->'RetentionRules' INTO STRICT origins FROM public.context_capture c WHERE c.root_id=l.root_id AND c.id=l.capture_id;
 ELSE
  SELECT convert_from(r.decision_json,'UTF8')::jsonb->'Origins' INTO STRICT origins FROM public.retention_decision r
   WHERE r.root_id=l.root_id AND r.attempt_id=a.id AND r.sequence=a.retention_sequence;
 END IF;
 doc:=convert_from(d.erasure_decision,'UTF8')::jsonb;
 IF NOT public.capacity_json_fields(doc,ARRAY['ID','RootID','Location','Target','Sequence','RegistrationDigest','PolicyRevision','Policies','Origins','Previous','Effective','ObservedAt','ValidUntil']) OR
    doc->>'ID' IS DISTINCT FROM d.id::text OR doc->>'RootID' IS DISTINCT FROM d.root_id::text OR doc->'Location' IS DISTINCT FROM d.scope->'Location' OR
    doc->'Target' IS DISTINCT FROM jsonb_build_object('ClusterID',l.cluster_id,'NamespaceUID',l.namespace_uid,'WorkloadUID',l.workload_uid,'PodUID',l.pod_uid) OR
    (doc->>'Sequence')::bigint IS DISTINCT FROM a.retention_sequence+1 OR public.connector_digest(doc->'RegistrationDigest') IS DISTINCT FROM a.request_digest OR
    NOT public.capacity_json_fields(doc->'PolicyRevision',ARRAY['UID','Generation','Digest']) OR
    doc#>>'{PolicyRevision,UID}' IS DISTINCT FROM 'erasure:'||d.id::text OR doc#>'{PolicyRevision,Generation}' IS DISTINCT FROM '1'::jsonb OR
    public.connector_digest(doc#>'{PolicyRevision,Digest}') IS DISTINCT FROM d.request_digest OR
    jsonb_typeof(origins) IS DISTINCT FROM 'array' OR jsonb_array_length(origins) NOT BETWEEN 1 AND 64 OR
    doc->'Policies' IS DISTINCT FROM origins OR doc->'Origins' IS DISTINCT FROM origins OR
    NOT public.capacity_json_fields(doc->'Previous',ARRAY['AnchorAt','ExpiresAt','DeleteBy']) OR
    NOT public.capacity_json_fields(doc->'Effective',ARRAY['AnchorAt','ExpiresAt','DeleteBy']) OR
    (doc#>>'{Previous,AnchorAt}')::timestamptz IS DISTINCT FROM a.anchor_at OR (doc#>>'{Previous,ExpiresAt}')::timestamptz IS DISTINCT FROM a.effective_expires_at OR
    (doc#>>'{Previous,DeleteBy}')::timestamptz IS DISTINCT FROM a.effective_delete_by OR
    (doc#>>'{Effective,AnchorAt}')::timestamptz IS DISTINCT FROM a.anchor_at OR (doc#>>'{Effective,ExpiresAt}')::timestamptz IS DISTINCT FROM a.anchor_at OR
    (doc#>>'{Effective,DeleteBy}')::timestamptz IS DISTINCT FROM a.effective_delete_by OR
    (doc->>'ObservedAt')::timestamptz IS DISTINCT FROM d.created_at OR (doc->>'ValidUntil')::timestamptz IS DISTINCT FROM d.request_until THEN
  RAISE EXCEPTION 'processing erasure payload does not match retained custody' USING ERRCODE='23514'; END IF;
 RETURN a;
END $function$;
-- +goose StatementEnd
DROP TABLE IF EXISTS context_verification;
DROP FUNCTION IF EXISTS protect_context_verification();
DROP TABLE IF EXISTS context_key_unwrap;
DROP FUNCTION IF EXISTS guard_context_key_unwrap();

-- +goose Down
-- No Down: the verification and unwrap tables are not restored. Up uses
-- IF EXISTS / IF NOT EXISTS, so reapplying after a rollback works.
