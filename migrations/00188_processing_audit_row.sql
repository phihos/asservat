-- +goose Up
-- REQ-PRV-006 / REQ-AUT-005 (ADR-330 D6): a processing decision commits its
-- own audit_event row in the transaction that applies it. The decision no
-- longer waits for an encrypted operation audit or a prepaid release lane,
-- and capacity no longer creates the normal, resolution and processing audit
-- pools. The capture pool stays until capture audit moves to audit_event.
DROP TRIGGER IF EXISTS operation_audit_00_processing_release ON operation_audit;
DROP TRIGGER IF EXISTS operation_audit_pool_00_processing_reserve ON operation_audit_pool;
DROP FUNCTION IF EXISTS guard_processing_release_audit();
DROP FUNCTION IF EXISTS preserve_processing_release_backing();
DROP FUNCTION IF EXISTS read_capacity_audit_profiles(uuid,uuid,uuid,bytea,text,timestamptz,timestamptz);

ALTER TABLE processing_decision DROP COLUMN IF EXISTS intent_seed, DROP COLUMN IF EXISTS outcome_json,
 DROP COLUMN IF EXISTS audit_digest, DROP COLUMN IF EXISTS decision_digest, DROP COLUMN IF EXISTS release_account;
ALTER TABLE processing_decision DROP CONSTRAINT IF EXISTS processing_decision_rule_action,
 DROP CONSTRAINT IF EXISTS processing_decision_applied_result;
ALTER TABLE processing_decision ADD CONSTRAINT processing_decision_rule_action
  CHECK ((rule_id IS NULL) = (action IN ('initialize_processing','request_early_erasure'))),
 ADD CONSTRAINT processing_decision_applied_result
  CHECK ((applied_at IS NULL) = (result_revision IS NULL) AND (applied_at IS NULL) = (result_sequence IS NULL));
ALTER TABLE processing_rule DROP COLUMN IF EXISTS release_account;
ALTER TABLE processing_root DROP COLUMN IF EXISTS release_policy;
DROP FUNCTION IF EXISTS processing_release_policy_valid(jsonb,uuid,uuid,bigint);

CREATE OR REPLACE FUNCTION public.guard_processing_root() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE n timestamptz; q jsonb; rows numeric; transitions numeric; h bigint; b bigint;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'processing retirement requires independent completion' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp(); q:=NEW.backing->'History';
 IF NOT (NEW.backing ?& ARRAY['RootID','InstallationID','PolicyID','BackupIdentity','PolicyDigest','BackupDigest','History','MaxCaptures','MaxRules','MaxRootTransitions','BackupBytes','WALBytes','BackupHorizonSeconds','CleanupSeconds','ValidUntil','RetireBy']) OR
    jsonb_typeof(q) IS DISTINCT FROM 'object' OR NOT (q ?& ARRAY['Format','ID','Digest','RowBytes','TransitionWALBytes','BackupCopies','WALCopies']) OR
    NEW.backing->>'RootID' IS DISTINCT FROM NEW.root_id::text OR NEW.backing->>'InstallationID' IS DISTINCT FROM NEW.installation_id::text OR
    q->>'Format' IS DISTINCT FROM 'context-processing-history/v1' OR
    (q->>'ID')::uuid IS NULL OR (NEW.backing->>'PolicyID')::uuid IS NULL OR (NEW.backing->>'BackupIdentity')::uuid IS NULL OR
    jsonb_array_length(q->'Digest')<>32 OR jsonb_array_length(NEW.backing->'PolicyDigest')<>32 OR jsonb_array_length(NEW.backing->'BackupDigest')<>32 OR
    coalesce((q->>'RowBytes')::bigint,0) NOT BETWEEN 16384 AND 16777216 OR
    coalesce((q->>'TransitionWALBytes')::bigint,0) NOT BETWEEN 65536 AND 67108864 OR
    coalesce((q->>'BackupCopies')::bigint,0) NOT BETWEEN 1 AND 64 OR coalesce((q->>'WALCopies')::bigint,0) NOT BETWEEN 1 AND 64 THEN
  RAISE EXCEPTION 'unqualified processing backing' USING ERRCODE='23514'; END IF;
 h:=(NEW.backing->>'BackupHorizonSeconds')::bigint; b:=(NEW.backing->>'CleanupSeconds')::bigint;
 rows:=1+NEW.max_root_transitions+NEW.max_captures+17*NEW.max_rules;
 transitions:=4*NEW.max_root_transitions+2*NEW.max_captures+130*NEW.max_rules;
 IF h IS NULL OR h NOT BETWEEN 0 AND 316224000 OR b IS NULL OR b NOT BETWEEN 1 AND 86400 OR
    (NEW.backing->>'MaxCaptures')::bigint IS DISTINCT FROM NEW.max_captures OR (NEW.backing->>'MaxRules')::bigint IS DISTINCT FROM NEW.max_rules OR
    (NEW.backing->>'MaxRootTransitions')::bigint IS DISTINCT FROM NEW.max_root_transitions OR
    (NEW.backing->>'ValidUntil')::timestamptz IS DISTINCT FROM NEW.valid_until OR (NEW.backing->>'RetireBy')::timestamptz IS DISTINCT FROM NEW.retire_by OR
    NEW.retire_by<>NEW.valid_until+make_interval(secs=>(2*h+b)::double precision) OR
    coalesce((NEW.backing->>'BackupBytes')::numeric,0)<2*rows*(q->>'RowBytes')::numeric*(q->>'BackupCopies')::numeric OR
    coalesce((NEW.backing->>'WALBytes')::numeric,0)<transitions*(q->>'TransitionWALBytes')::numeric*(q->>'WALCopies')::numeric THEN
  RAISE EXCEPTION 'processing backing below complete history' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.backing_revision<>1 OR NEW.captures<>0 OR NEW.rules<>0 OR NEW.root_transitions<>0 OR NEW.sequence<>1 OR NEW.initialized_at IS NOT NULL OR n>=NEW.valid_until THEN
   RAISE EXCEPTION 'invalid initial processing root' USING ERRCODE='23514'; END IF;
 ELSE
  IF ROW(NEW.root_id,NEW.installation_id,NEW.issuer_epoch,NEW.epoch,NEW.source_uid,NEW.protection_digest) IS DISTINCT FROM ROW(OLD.root_id,OLD.installation_id,OLD.issuer_epoch,OLD.epoch,OLD.source_uid,OLD.protection_digest) OR
     NEW.captures<OLD.captures OR NEW.rules<OLD.rules OR NEW.root_transitions<OLD.root_transitions OR NEW.sequence<OLD.sequence OR
     OLD.initialized_at IS NOT NULL AND ROW(NEW.initialized_at,NEW.initialization_id) IS DISTINCT FROM ROW(OLD.initialized_at,OLD.initialization_id) THEN
   RAISE EXCEPTION 'immutable processing history' USING ERRCODE='23514'; END IF;
  IF NEW.backing IS DISTINCT FROM OLD.backing THEN
   IF NEW.backing_revision<>OLD.backing_revision+1 OR NEW.root_transitions<>OLD.root_transitions+1 OR NEW.sequence<>OLD.sequence+1 OR
      ROW(NEW.captures,NEW.rules,NEW.initialized_at,NEW.initialization_id) IS DISTINCT FROM ROW(OLD.captures,OLD.rules,OLD.initialized_at,OLD.initialization_id) OR
      NEW.max_captures<OLD.max_captures OR NEW.max_rules<OLD.max_rules OR NEW.max_root_transitions<OLD.max_root_transitions OR NEW.valid_until<OLD.valid_until OR
      NEW.backing->'History' IS DISTINCT FROM OLD.backing->'History' OR NEW.backing->'PolicyID' IS DISTINCT FROM OLD.backing->'PolicyID' OR
      NEW.backing->'PolicyDigest' IS DISTINCT FROM OLD.backing->'PolicyDigest' OR NEW.backing->'BackupIdentity' IS DISTINCT FROM OLD.backing->'BackupIdentity' OR
      NEW.backing->'BackupDigest' IS DISTINCT FROM OLD.backing->'BackupDigest' OR NEW.backing->'BackupHorizonSeconds' IS DISTINCT FROM OLD.backing->'BackupHorizonSeconds' OR
      NEW.backing->'CleanupSeconds' IS DISTINCT FROM OLD.backing->'CleanupSeconds' OR
      n>=NEW.valid_until THEN
    RAISE EXCEPTION 'processing backing update does not cover history' USING ERRCODE='23514'; END IF;
  ELSE
   IF NEW.backing_revision<>OLD.backing_revision OR ROW(NEW.valid_until,NEW.retire_by,NEW.max_captures,NEW.max_rules,NEW.max_root_transitions) IS DISTINCT FROM ROW(OLD.valid_until,OLD.retire_by,OLD.max_captures,OLD.max_rules,OLD.max_root_transitions) OR pg_trigger_depth()<2 THEN
    RAISE EXCEPTION 'processing counters are source managed' USING ERRCODE='23514'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;


CREATE OR REPLACE FUNCTION public.guard_processing_rule() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE p public.processing_root;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'restriction history cannot be erased' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 IF NOT public.processing_scope_valid(NEW.scope) THEN RAISE EXCEPTION 'invalid processing scope' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.valid_until IS NOT NULL OR NEW.retire_by IS NOT NULL THEN RAISE EXCEPTION 'processing rule dates are source owned' USING ERRCODE='23514'; END IF;
  NEW.valid_until:=p.valid_until; NEW.retire_by:=p.retire_by;
  IF NEW.scope->>'Kind'='workloadInterval' AND (NEW.scope->>'AcquiredUntil')::timestamptz>p.valid_until OR
     NEW.scope->>'Kind'='artifact' AND NOT EXISTS(SELECT 1 FROM public.context_processing n WHERE n.root_id=NEW.root_id AND n.artifact_id=(NEW.scope#>>'{Location,ArtifactID}')::uuid AND n.attempt_id=(NEW.scope#>>'{Location,AttemptID}')::uuid AND n.cluster_id=(NEW.scope#>>'{Location,ClusterID}')::uuid) OR
     p.initialized_at IS NULL OR clock_timestamp()>=p.valid_until OR p.rules>=p.max_rules OR NEW.revision<>0 OR NEW.decisions<>0 OR NEW.state<>'reserved' OR NEW.current_decision IS NOT NULL THEN
   RAISE EXCEPTION 'processing rule capacity unavailable' USING ERRCODE='23514'; END IF;
  UPDATE public.processing_root SET rules=rules+1 WHERE root_id=NEW.root_id;
 ELSE
  IF ROW(NEW.root_id,NEW.id,NEW.scope,NEW.valid_until,NEW.retire_by) IS DISTINCT FROM ROW(OLD.root_id,OLD.id,OLD.scope,OLD.valid_until,OLD.retire_by) OR pg_trigger_depth()<2 THEN
   RAISE EXCEPTION 'processing rule is decision owned' USING ERRCODE='23514'; END IF;
  IF NOT (NEW.decisions=OLD.decisions+1 AND ROW(NEW.revision,NEW.state,NEW.current_decision) IS NOT DISTINCT FROM ROW(OLD.revision,OLD.state,OLD.current_decision)) AND
     NOT (NEW.decisions=OLD.decisions AND NEW.revision=OLD.revision+1 AND NEW.current_decision IS DISTINCT FROM OLD.current_decision AND NEW.state=(CASE WHEN NEW.revision%2=1 THEN 'restricted' ELSE 'released' END)) THEN
   RAISE EXCEPTION 'invalid processing transition' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;


CREATE OR REPLACE FUNCTION public.processing_erasure_attempt(d public.processing_decision, p public.processing_root) RETURNS public.custody_attempt
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
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
     JOIN public.context_verification v ON v.root_id=cat.root_id AND v.capture_id=cat.capture_id
     JOIN public.context_capture c ON c.root_id=cat.root_id AND c.id=cat.capture_id
     JOIN public.context_writer_completion w ON w.root_id=c.root_id AND w.capture_id=c.id AND w.attempt_id=c.attempt_id
     JOIN public.context_execution x ON x.root_id=w.root_id AND x.capture_id=w.capture_id AND x.attempt_id=w.attempt_id
     JOIN public.fleet_trust f ON f.installation_id=w.installation_id AND f.activated_postmaster_at=w.postmaster_at AND f.activated_database_oid=w.database_oid
     JOIN public.fleet_current_trust t ON t.installation_id=f.installation_id AND t.issuer_epoch=w.issuer_epoch
     WHERE cat.root_id=l.root_id AND cat.artifact_id=l.artifact_id AND cat.capture_id=l.capture_id AND c.attempt_id=a.id
      AND v.audit_acknowledged_at IS NOT NULL AND v.copies_digest=a.copies_digest AND v.expectation_digest=w.expectation_digest
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
END $$;


CREATE OR REPLACE FUNCTION public.guard_processing_decision() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE p public.processing_root; r public.processing_rule; n timestamptz; a_erasure public.custody_attempt;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'processing decision retirement requires independent completion' USING ERRCODE='23514'; END IF;
 -- Lock recovery before the permission/processing and storage locks for the erasure action.
 IF NEW.action='request_early_erasure' THEN
  PERFORM 1 FROM public.fleet_current_trust f WHERE f.installation_id=(SELECT installation_id FROM public.processing_root WHERE root_id=NEW.root_id) FOR SHARE;
 END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 IF NEW.rule_id IS NOT NULL THEN SELECT * INTO STRICT r FROM public.processing_rule WHERE root_id=NEW.root_id AND id=NEW.rule_id FOR UPDATE; END IF;
 n:=clock_timestamp();
 IF TG_OP='INSERT' THEN
  IF NEW.valid_until IS NOT NULL OR NEW.retire_by IS NOT NULL THEN RAISE EXCEPTION 'processing decision dates are source owned' USING ERRCODE='23514'; END IF;
  NEW.valid_until:=p.valid_until; NEW.retire_by:=p.retire_by;
  IF NEW.rule_id IS NOT NULL THEN NEW.valid_until:=r.valid_until; NEW.retire_by:=r.retire_by; END IF;
  IF n>=NEW.valid_until OR NEW.request_until>NEW.valid_until OR n<NEW.created_at OR n>=NEW.request_until OR n>=p.valid_until OR NEW.applied_at IS NOT NULL OR NEW.result_revision IS NOT NULL OR NEW.result_sequence IS NOT NULL THEN
   RAISE EXCEPTION 'invalid prepared processing decision' USING ERRCODE='23514'; END IF;
  IF NEW.action='initialize_processing' THEN
   IF p.initialized_at IS NOT NULL OR NEW.expected_revision<>0 OR p.root_transitions>=p.max_root_transitions OR EXISTS(SELECT 1 FROM public.context_catalog WHERE root_id=NEW.root_id) THEN
    RAISE EXCEPTION 'processing completeness needs empty reviewed history' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_root SET root_transitions=root_transitions+1 WHERE root_id=NEW.root_id;
  ELSIF NEW.action='request_early_erasure' THEN
   IF p.root_transitions+2>=p.max_root_transitions THEN RAISE EXCEPTION 'processing erasure capacity unavailable' USING ERRCODE='23514'; END IF;
   IF EXISTS(SELECT 1 FROM public.processing_decision d WHERE d.root_id=NEW.root_id AND d.action=NEW.action
       AND d.scope#>>'{Location,AttemptID}'=NEW.scope#>>'{Location,AttemptID}' AND (d.applied_at IS NOT NULL OR d.request_until>n)) THEN
    RAISE EXCEPTION 'processing erasure already requested' USING ERRCODE='23505'; END IF;
   PERFORM public.processing_erasure_attempt(NEW,p);
   SELECT LEAST(p.retire_by,l.retire_by) INTO STRICT NEW.retire_by FROM public.context_processing l
    WHERE l.root_id=NEW.root_id AND l.artifact_id=(NEW.scope#>>'{Location,ArtifactID}')::uuid;
   NEW.valid_until:=LEAST(p.valid_until,NEW.retire_by-interval '1 microsecond');
   IF NEW.request_until>NEW.valid_until THEN RAISE EXCEPTION 'processing erasure original retention ended' USING ERRCODE='23514'; END IF;
   -- Two backed root-transition units cover the decision and cutoff. Keep one existing unit for backed root renewal.
   UPDATE public.processing_root SET root_transitions=root_transitions+2 WHERE root_id=NEW.root_id;
   IF clock_timestamp()>=NEW.request_until THEN RAISE EXCEPTION 'processing erasure expired after reserve' USING ERRCODE='23514'; END IF;
  ELSE
   IF p.initialized_at IS NULL OR NOT public.processing_scope_valid(NEW.scope) OR NEW.scope IS DISTINCT FROM r.scope OR NEW.expected_revision<>r.revision OR r.decisions>=16 OR
      (NEW.action='restrict_processing' AND (r.revision%2<>0 OR r.decisions>=15)) OR
      (NEW.action='release_processing' AND (r.revision%2<>1 OR r.state<>'restricted')) OR
      (NEW.action='restrict_processing' AND EXISTS(SELECT 1 FROM public.context_processing c WHERE c.root_id=NEW.root_id AND c.delete_by>r.valid_until AND
       ((r.scope->>'Kind'='artifact' AND c.artifact_id=(r.scope#>>'{Location,ArtifactID}')::uuid AND c.attempt_id=(r.scope#>>'{Location,AttemptID}')::uuid AND c.cluster_id=(r.scope#>>'{Location,ClusterID}')::uuid) OR
        (r.scope->>'Kind'='workloadInterval' AND c.cluster_id=(r.scope->>'ClusterID')::uuid AND c.namespace_uid=r.scope->>'NamespaceUID' AND c.workload_uid=r.scope->>'WorkloadUID' AND c.anchor_at>=(r.scope->>'AcquiredFrom')::timestamptz AND c.anchor_at<(r.scope->>'AcquiredUntil')::timestamptz)))) OR
      EXISTS(SELECT 1 FROM public.processing_decision d WHERE d.root_id=NEW.root_id AND d.rule_id=NEW.rule_id AND d.applied_at IS NULL AND d.request_until>n) THEN
    RAISE EXCEPTION 'processing decision scope or capacity unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_rule SET decisions=decisions+1 WHERE root_id=NEW.root_id AND id=NEW.rule_id;
  END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['applied_at','result_revision','result_sequence']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['applied_at','result_revision','result_sequence']) OR OLD.applied_at IS NOT NULL OR NEW.applied_at IS NULL OR n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until THEN
   RAISE EXCEPTION 'immutable or expired processing decision' USING ERRCODE='23514'; END IF;
  IF NEW.action='request_early_erasure' THEN a_erasure:=public.processing_erasure_attempt(NEW,p); END IF;
  n:=clock_timestamp();
  IF NEW.action='initialize_processing' THEN
   IF p.initialized_at IS NOT NULL OR EXISTS(SELECT 1 FROM public.context_catalog WHERE root_id=NEW.root_id) THEN RAISE EXCEPTION 'processing history changed during review' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_root SET initialized_at=n,initialization_id=NEW.id,sequence=sequence+1 WHERE root_id=NEW.root_id;
   NEW.result_revision:=0;
  ELSIF NEW.action='request_early_erasure' THEN
   INSERT INTO public.retention_decision(id,root_id,attempt_id,sequence,previous_expires_at,previous_delete_by,expires_at,delete_by,decision_digest,decision_json)
    VALUES(NEW.id,NEW.root_id,a_erasure.id,a_erasure.retention_sequence+1,a_erasure.effective_expires_at,a_erasure.effective_delete_by,
           a_erasure.anchor_at,a_erasure.effective_delete_by,sha256(NEW.erasure_decision),NEW.erasure_decision);
   UPDATE public.custody_attempt SET effective_expires_at=a_erasure.anchor_at,retention_sequence=a_erasure.retention_sequence+1 WHERE id=a_erasure.id;
   NEW.result_revision:=0;
  ELSE
   IF p.initialized_at IS NULL OR r.revision<>NEW.expected_revision OR r.scope IS DISTINCT FROM NEW.scope OR
      (NEW.action='release_processing' AND r.state<>'restricted') OR (NEW.action='restrict_processing' AND r.state NOT IN ('reserved','released')) THEN
    RAISE EXCEPTION 'processing decision CAS changed' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_rule SET revision=revision+1,state=CASE WHEN NEW.action='release_processing' THEN 'released' ELSE 'restricted' END,current_decision=NEW.id WHERE root_id=NEW.root_id AND id=NEW.rule_id;
   UPDATE public.processing_root SET sequence=sequence+1 WHERE root_id=NEW.root_id;
   NEW.result_revision:=r.revision+1;
  END IF;
  -- Nested counter/rule triggers can wait. Recheck the original decision interval after those writes as well;
  -- an expiry rolls back every nested effect in this transaction.
  n:=clock_timestamp();
  IF n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until THEN RAISE EXCEPTION 'processing decision expired after nested locks' USING ERRCODE='23514'; END IF;
  IF NEW.action='request_early_erasure' AND NOT EXISTS(SELECT 1 FROM public.fleet_current_trust t
      WHERE t.installation_id=p.installation_id AND t.issuer_epoch=p.issuer_epoch AND NOT t.suspended
       AND t.observed_at<=n AND n<t.fresh_until) THEN
   RAISE EXCEPTION 'processing erasure recovery expired after apply' USING ERRCODE='23514'; END IF;
  NEW.applied_at:=n; NEW.result_sequence:=CASE WHEN NEW.action='request_early_erasure' THEN p.sequence ELSE p.sequence+1 END;
 END IF;
 RETURN NEW;
END $$;


CREATE OR REPLACE FUNCTION public.capacity_apply(r uuid, cluster uuid, namespace_uid text, av text, q jsonb, v jsonb) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE s public.capacity_settings;installation uuid:=(q->'RootBacking'->>'InstallationID')::uuid;i jsonb:=q->'RootBacking';b jsonb:=q->'Backends'->0;
 standing timestamptz:=public.capacity_standing();pool uuid;available bigint;prefix text;oids oid[]:='{}';o oid;k integer;stop jsonb;slots bigint:=100000;
 retire timestamptz;share bigint;
BEGIN
 IF r IS NULL OR installation IS NULL OR (i->>'RootID')::uuid IS DISTINCT FROM r OR jsonb_array_length(q->'Backends')<>1 OR
  (v->>'EvidenceBytes')::bigint IS NULL OR (v->>'LimitBytes')::bigint IS NULL THEN RAISE EXCEPTION 'capacity settings invalid' USING ERRCODE='23514';END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO s FROM public.capacity_settings WHERE root_id=r FOR UPDATE;
 IF NOT FOUND THEN
  pool:=(b->>'PoolID')::uuid;
  prefix:='as_'||replace(installation::text,'-','')||'_pub_';
  FOREACH k IN ARRAY ARRAY[71,40,41,42,43,44,45,16] LOOP
   SELECT oid INTO o FROM pg_catalog.pg_roles WHERE rolname=prefix||lpad(k::text,2,'0');
   IF o IS NULL THEN RAISE EXCEPTION 'capacity role missing' USING ERRCODE='55000';END IF;
   oids:=array_append(oids,o);
  END LOOP;
  INSERT INTO public.capture_audit_root(root_id,installation_id,source_role,admission_role,journal_role,acknowledge_role,cleanup_role,verifier_role,finalizer_role,reader_role,revision,paused,valid_until)
   VALUES(r,installation,oids[1],oids[2],oids[3],oids[4],oids[5],oids[6],oids[7],oids[8],1,false,standing) ON CONFLICT DO NOTHING;
  INSERT INTO public.custody_pool(id,store_id,revision,valid_until,paused,byte_limit,object_limit)
   VALUES(pool,(b->>'EvidenceStoreID')::uuid,1,standing,false,(v->>'EvidenceBytes')::bigint-(v->>'ReserveBytes')::bigint,1125899906842624);
  -- The capture audit allocation still reads the capture pool (capacity_enroll).
  INSERT INTO public.operation_audit_pool(root_id,lane,account_version,revision,paused,valid_until,account_limit,records_per_account,retained_seconds)
   VALUES(r,'capture',av,1,false,standing,(i->'Capture'->>'Accounts')::bigint,(i->'Capture'->>'RecordsPerAccount')::bigint,(i->'Capture'->>'RetainedSeconds')::bigint);
  retire:=standing+make_interval(secs=>(2*(i->'ProcessingState'->>'BackupHorizonSeconds')::bigint+(i->'ProcessingState'->>'CleanupSeconds')::bigint)::double precision);
  INSERT INTO public.processing_root(root_id,installation_id,issuer_epoch,epoch,source_uid,protection_digest,backing,backing_revision,valid_until,retire_by,max_captures,max_rules,max_root_transitions)
   SELECT r,installation,t.issuer_epoch,(i->>'ProcessingEpoch')::uuid,(i->>'ProcessingSourceUID')::uuid,public.connector_digest(i->'ProcessingProtectionDigest'),
    (i->'ProcessingState')||jsonb_build_object('ValidUntil',standing,'RetireBy',retire),
    1,standing,retire,
    (i->'ProcessingState'->>'MaxCaptures')::bigint,(i->'ProcessingState'->>'MaxRules')::bigint,(i->'ProcessingState'->>'MaxRootTransitions')::bigint
   FROM public.fleet_current_trust t WHERE t.installation_id=installation;
  stop:=i->'ContextHistory'->'Stop';
  INSERT INTO public.download_stop_pool(root_id,installation_id,store_id,policy_id,backup_profile_id,policy_digest,backup_profile_digest,slots,cipher_bytes,key_attempts,backup_bytes,wal_bytes,retained_seconds,backup_horizon_seconds,valid_until,lifecycle_policy)
   VALUES(r,installation,(stop->>'StoreID')::uuid,(stop->>'PolicyID')::uuid,(stop->>'BackupProfileID')::uuid,public.connector_digest(stop->'PolicyDigest'),public.connector_digest(stop->'BackupProfileDigest'),
    slots,slots*65536,slots*12,slots*2*(stop->>'MaximumRowFootprintBytes')::bigint*(stop->>'BackupCopies')::bigint,
    slots*2*(stop->>'MaximumTransitionWALBytes')::bigint*(stop->>'WALCopies')::bigint*(20+3*(stop->>'MaxPurgeLeases')::bigint),(i->>'StopRetainedSeconds')::bigint,(stop->>'BackupHorizonSeconds')::bigint,standing,stop);
  INSERT INTO public.capacity_settings(root_id,installation_id,account_version,qualification,pool_id,evidence_bytes,reserve_bytes,share_bytes,limit_bytes,namespace_limit_bytes,max_concurrent_expensive,on_full,revision)
   VALUES(r,installation,av,q,pool,(v->>'EvidenceBytes')::bigint,(v->>'ReserveBytes')::bigint,NULLIF((v->>'ShareBytes')::bigint,0),(v->>'LimitBytes')::bigint,NULLIF((v->>'NamespaceLimitBytes')::bigint,0),
    (v->>'MaxConcurrentExpensive')::integer,v->>'OnFull',1) RETURNING * INTO s;
  IF q ? 'ContextQuery' THEN PERFORM public.ensure_shared_context_query_capacity(r);END IF;
 ELSE
  available:=(v->>'EvidenceBytes')::bigint-(v->>'ReserveBytes')::bigint;
  PERFORM 1 FROM public.custody_pool WHERE id=s.pool_id FOR UPDATE;
  UPDATE public.capacity_settings SET evidence_bytes=(v->>'EvidenceBytes')::bigint,reserve_bytes=(v->>'ReserveBytes')::bigint,share_bytes=NULLIF((v->>'ShareBytes')::bigint,0),limit_bytes=(v->>'LimitBytes')::bigint,
   namespace_limit_bytes=NULLIF((v->>'NamespaceLimitBytes')::bigint,0),max_concurrent_expensive=(v->>'MaxConcurrentExpensive')::integer,on_full=v->>'OnFull',revision=revision+1
   WHERE root_id=r RETURNING * INTO s;
  -- ADR-335 D2/D3: a helm upgrade carries the new share to every enrolled
  -- account. A lower share never drops below the bytes already charged; those
  -- stay used and capacity_charge refuses new charges above the hard limit.
  SELECT count(*) INTO slots FROM public.capacity_account WHERE root_id=r;
  share:=COALESCE(s.share_bytes,available/GREATEST(8,slots));
  UPDATE public.capacity_account SET protected_bytes=share WHERE root_id=r;
  UPDATE public.custody_allocation a SET byte_limit=GREATEST(a.charged_bytes,share)
   FROM public.capacity_account c WHERE c.allocation_id=a.id AND c.root_id=r;
  UPDATE public.custody_pool SET allocated_bytes=(SELECT COALESCE(sum(a.byte_limit),0) FROM public.custody_allocation a WHERE a.pool_id=s.pool_id) WHERE id=s.pool_id;
  UPDATE public.custody_pool SET byte_limit=GREATEST(available,allocated_bytes) WHERE id=s.pool_id;
 END IF;
 RETURN jsonb_build_object('Qualification',s.qualification,'Revision',s.revision);
END $$;


