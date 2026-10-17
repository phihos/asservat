-- +goose Up
-- Fixed private extension of SQL49. Neither public input nor a registry can
-- choose these names, lanes, history layouts or prepaid costs.
ALTER TABLE operation_audit_pool DROP CONSTRAINT operation_audit_pool_lane_check;
ALTER TABLE operation_audit_pool ADD CHECK(lane IN ('normal','resolution','identity','processing'));
ALTER TABLE operation_audit_lifecycle DROP CONSTRAINT operation_audit_lifecycle_lane_check;
ALTER TABLE operation_audit_lifecycle ADD CHECK(lane IN ('normal','resolution','identity','processing'));
ALTER TABLE operation_audit_history DROP CONSTRAINT operation_audit_history_lane_check;
ALTER TABLE operation_audit_history ADD CHECK(lane IN ('normal','resolution','identity','processing'));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance') THEN 'identity'
 WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','initialize_processing','restrict_processing') THEN 'normal' ELSE NULL END
$$;
CREATE OR REPLACE FUNCTION operation_audit_history_layout_valid(lane text,layout text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE((lane IN ('normal','resolution') AND layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3')) OR (lane='identity' AND layout='connector-operation-history/v1') OR (lane='processing' AND layout='processing-release-history/v1'),false)
$$;
CREATE OR REPLACE FUNCTION operation_audit_history_fixed_transitions(layout text) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE layout WHEN 'operation-audit-history/v1' THEN 16 WHEN 'operation-audit-history/v2' THEN 19 WHEN 'operation-audit-history/v3' THEN 21 WHEN 'connector-operation-history/v1' THEN 32 WHEN 'processing-release-history/v1' THEN 32 ELSE NULL END::bigint
$$;
CREATE OR REPLACE FUNCTION operation_audit_history_verifier_backed(layout text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(layout IN ('operation-audit-history/v3','connector-operation-history/v1','processing-release-history/v1'),false)
$$;
CREATE OR REPLACE FUNCTION operation_audit_history_minimum_row(layout text) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN layout='connector-operation-history/v1' THEN 1048576 WHEN layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3','processing-release-history/v1') THEN 131072 ELSE NULL END::bigint
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION operation_audit_lane(text),operation_audit_history_layout_valid(text,text),operation_audit_history_fixed_transitions(text),operation_audit_history_verifier_backed(text),operation_audit_history_minimum_row(text) FROM PUBLIC;
-- No permitting rows or retrospective completeness backfill. Initialization is
-- a separately audited privacy decision under current installation authority.
CREATE TABLE processing_root (
 root_id uuid PRIMARY KEY REFERENCES permission_stream(id), installation_id uuid NOT NULL, issuer_epoch uuid NOT NULL,
 epoch uuid NOT NULL UNIQUE, source_uid uuid NOT NULL,
 protection_digest bytea NOT NULL CHECK(octet_length(protection_digest)=32),
 backing jsonb NOT NULL CHECK(jsonb_typeof(backing)='object' AND octet_length(backing::text)<=8192),
 release_policy jsonb NOT NULL CHECK(jsonb_typeof(release_policy)='object' AND octet_length(release_policy::text)<=8192),
 backing_revision bigint NOT NULL CHECK(backing_revision>0),
 valid_until timestamptz NOT NULL CHECK(isfinite(valid_until)), retire_by timestamptz NOT NULL CHECK(isfinite(retire_by) AND retire_by>valid_until),
 max_captures bigint NOT NULL CHECK(max_captures BETWEEN 1 AND 1000000),
 max_rules bigint NOT NULL CHECK(max_rules BETWEEN 1 AND 1024),
 max_root_transitions bigint NOT NULL CHECK(max_root_transitions BETWEEN 8 AND 65536),
 captures bigint NOT NULL DEFAULT 0 CHECK(captures BETWEEN 0 AND max_captures),
 rules bigint NOT NULL DEFAULT 0 CHECK(rules BETWEEN 0 AND max_rules),
 root_transitions bigint NOT NULL DEFAULT 0 CHECK(root_transitions BETWEEN 0 AND max_root_transitions),
 sequence bigint NOT NULL DEFAULT 1 CHECK(sequence BETWEEN 1 AND 1152921504606846976),
 initialized_at timestamptz, initialization_id uuid,
 CHECK((initialized_at IS NULL)=(initialization_id IS NULL))
);
-- This projection is published only by the exact verified catalog trigger. It
-- is not a caller-controlled declaration that an unknown artifact has no parents.
CREATE TABLE context_processing (
 artifact_id uuid PRIMARY KEY REFERENCES context_catalog(artifact_id) ON DELETE NO ACTION,
 root_id uuid NOT NULL REFERENCES processing_root(root_id), capture_id uuid NOT NULL UNIQUE,
 attempt_id uuid NOT NULL, cluster_id uuid NOT NULL,
 namespace_uid text NOT NULL CHECK(octet_length(namespace_uid) BETWEEN 1 AND 64),
 workload_uid text NOT NULL CHECK(octet_length(workload_uid) BETWEEN 1 AND 64),
 pod_uid text NOT NULL CHECK(octet_length(pod_uid) BETWEEN 1 AND 64),
 anchor_at timestamptz NOT NULL CHECK(isfinite(anchor_at)), delete_by timestamptz NOT NULL CHECK(isfinite(delete_by) AND delete_by>anchor_at),
 retire_by timestamptz NOT NULL CHECK(isfinite(retire_by) AND retire_by>delete_by),
 origin text NOT NULL CHECK(origin IN ('capture','derived')),
 parents jsonb NOT NULL CHECK(jsonb_typeof(parents)='array' AND jsonb_array_length(parents)<=16 AND octet_length(parents::text)<=4096),
 CHECK((origin='capture' AND parents='[]'::jsonb) OR (origin='derived' AND jsonb_array_length(parents)>0)),
 FOREIGN KEY(capture_id,root_id) REFERENCES context_capture(id,root_id) ON DELETE NO ACTION,
 UNIQUE(root_id,cluster_id,artifact_id,attempt_id)
);
CREATE INDEX context_processing_scope ON context_processing(root_id,cluster_id,namespace_uid,workload_uid,anchor_at);
CREATE TABLE processing_rule (
 root_id uuid NOT NULL REFERENCES processing_root(root_id), id uuid NOT NULL,
 release_account bytea NOT NULL CHECK(octet_length(release_account)=32),
 scope jsonb NOT NULL CHECK(jsonb_typeof(scope)='object' AND octet_length(scope::text)<=2048),
 revision bigint NOT NULL DEFAULT 0 CHECK(revision BETWEEN 0 AND 16),
 decisions bigint NOT NULL DEFAULT 0 CHECK(decisions BETWEEN 0 AND 16),
 valid_until timestamptz NOT NULL CHECK(isfinite(valid_until)),
 retire_by timestamptz NOT NULL CHECK(isfinite(retire_by) AND retire_by>valid_until),
 state text NOT NULL DEFAULT 'reserved' CHECK(state IN ('reserved','restricted','released')),
 current_decision uuid,
 PRIMARY KEY(root_id,id), UNIQUE(root_id,release_account),
 CHECK((revision=0 AND state='reserved' AND current_decision IS NULL) OR
       (revision>0 AND current_decision IS NOT NULL AND ((revision%2=1 AND state='restricted') OR (revision%2=0 AND state='released'))))
);
CREATE INDEX processing_rule_active ON processing_rule(root_id,id) WHERE state='restricted';
-- One immutable server request, including the original audit dates/identity.
-- intent_seed excludes Actor: current principal must reproduce actor_digest.
-- No names, free-text reasons, tokens, groups, filenames, content or native hash.
CREATE TABLE processing_decision (
 id uuid PRIMARY KEY, root_id uuid NOT NULL REFERENCES processing_root(root_id),
 rule_id uuid, expected_revision bigint NOT NULL CHECK(expected_revision BETWEEN 0 AND 15),
 release_account bytea CHECK(octet_length(release_account)=32),
 actor_digest bytea NOT NULL CHECK(octet_length(actor_digest)=32),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 scope jsonb NOT NULL CHECK(jsonb_typeof(scope)='object' AND octet_length(scope::text)<=2048),
 action text NOT NULL CHECK(action IN ('initialize_processing','restrict_processing','release_processing')),
 intent_seed jsonb NOT NULL CHECK(jsonb_typeof(intent_seed)='object' AND octet_length(intent_seed::text)<=8192 AND NOT intent_seed?'Actor' AND NOT intent_seed?'Peer' AND NOT intent_seed?'Process'),
 decision_digest bytea NOT NULL CHECK(octet_length(decision_digest)=32),
 created_at timestamptz NOT NULL, request_until timestamptz NOT NULL,
 valid_until timestamptz NOT NULL CHECK(isfinite(valid_until)),
 retire_by timestamptz NOT NULL CHECK(isfinite(retire_by) AND retire_by>valid_until),
 outcome_json jsonb NOT NULL CHECK(jsonb_typeof(outcome_json)='object' AND octet_length(outcome_json::text)<=2048),
 applied_at timestamptz, audit_digest bytea CHECK(octet_length(audit_digest)=32),
 result_revision bigint, result_sequence bigint,
 CHECK(isfinite(created_at) AND isfinite(request_until) AND request_until>created_at AND request_until<=created_at+interval '5 seconds' AND request_until<=valid_until),
 CHECK((rule_id IS NULL)=(action='initialize_processing') AND (rule_id IS NULL)=(release_account IS NULL)),
 CHECK((applied_at IS NULL)=(audit_digest IS NULL) AND (applied_at IS NULL)=(result_revision IS NULL) AND (applied_at IS NULL)=(result_sequence IS NULL)),
 FOREIGN KEY(root_id,rule_id) REFERENCES processing_rule(root_id,id) ON DELETE NO ACTION
);
CREATE UNIQUE INDEX processing_decision_revision ON processing_decision(root_id,rule_id,expected_revision) WHERE applied_at IS NOT NULL;
-- No cascade/refund or disappearing restriction through cleanup. A future
-- bounded retirement must prove descendants, evidence deletion and retained
-- backup/WAL obligations together; this migration does not invent that proof.
-- The configuration transaction reserves the complete release lifecycle before
-- any rule exists. This validates backing, not the truth of accepted backend
-- measurements; the protected producer remains the source of that acceptance.
-- +goose StatementBegin
CREATE FUNCTION processing_release_policy_valid(p jsonb,r uuid,i uuid,slots bigint) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(jsonb_typeof(p)='object' AND
 p ?& ARRAY['RootID','Lane','InstallationID','StoreID','PolicyID','BackupProfileID','PolicyDigest','BackupProfileDigest','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','BackupHorizonSeconds','CleanupBudgetSeconds','ProofWindowSeconds','ValidUntil','MaxPurgeLeases','History'] AND
 p->>'RootID'=r::text AND p->>'InstallationID'=i::text AND p->>'Lane'='processing' AND
 (p->>'StoreID')::uuid IS NOT NULL AND (p->>'PolicyID')::uuid IS NOT NULL AND (p->>'BackupProfileID')::uuid IS NOT NULL AND
 jsonb_array_length(p->'PolicyDigest')=32 AND jsonb_array_length(p->'BackupProfileDigest')=32 AND
 (p->>'BackingRevision')::bigint BETWEEN 1 AND 1152921504606846976 AND
 (p->>'MetadataSlots')::bigint BETWEEN slots AND 1000000000000 AND
 (p->>'BackupHorizonSeconds')::bigint BETWEEN 0 AND 316224000 AND
 (p->>'CleanupBudgetSeconds')::bigint BETWEEN 1 AND 86400 AND (p->>'ProofWindowSeconds')::bigint BETWEEN 1 AND 316224000 AND
 (p->>'MaxPurgeLeases')::bigint BETWEEN 2 AND 32 AND isfinite((p->>'ValidUntil')::timestamptz) AND
 (NOT p?'OverdueTerminal' OR p->>'OverdueTerminal'='overdue-original/v1') AND
 p->'History' ?& ARRAY['ID','Digest','Layout','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies'] AND
 (p->'History'->>'ID')::uuid IS NOT NULL AND jsonb_array_length(p->'History'->'Digest')=32 AND
 p->'History'->>'Layout'='processing-release-history/v1' AND
 (p->'History'->>'MaximumRowFootprintBytes')::bigint BETWEEN 131072 AND 16777216 AND
 (p->'History'->>'MaximumTransitionWALBytes')::bigint BETWEEN 131072 AND 67108864 AND
 (p->'History'->>'BackupCopies')::bigint BETWEEN 1 AND 64 AND (p->'History'->>'WALCopies')::bigint BETWEEN 1 AND 64 AND
 (p->>'BackupReservedBytes')::numeric >= (p->>'MetadataSlots')::numeric*2*(p->'History'->>'MaximumRowFootprintBytes')::numeric*(p->'History'->>'BackupCopies')::numeric AND
 (p->>'WALReservedBytes')::numeric >= (p->>'MetadataSlots')::numeric*2*(p->'History'->>'MaximumTransitionWALBytes')::numeric*(p->'History'->>'WALCopies')::numeric*(32+3*(p->>'MaxPurgeLeases')::bigint),false)
$$;
REVOKE ALL ON FUNCTION processing_release_policy_valid(jsonb,uuid,uuid,bigint) FROM PUBLIC;
CREATE FUNCTION guard_processing_root() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE n timestamptz; q jsonb; rows numeric; transitions numeric; h bigint; b bigint; pool public.operation_audit_pool;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'processing retirement requires independent completion' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='processing' FOR SHARE;
 n:=clock_timestamp();
 IF n>=NEW.valid_until OR NOT public.processing_release_policy_valid(NEW.release_policy,NEW.root_id,NEW.installation_id,NEW.max_rules*16) OR
    NEW.release_policy->>'RootID' IS DISTINCT FROM NEW.root_id::text OR NEW.release_policy->>'InstallationID' IS DISTINCT FROM NEW.installation_id::text OR
    NEW.release_policy->>'Lane' IS DISTINCT FROM 'processing' OR NEW.release_policy->'History'->>'Layout' IS DISTINCT FROM 'processing-release-history/v1' OR
    (NEW.release_policy->>'BackingRevision')::bigint IS DISTINCT FROM pool.revision OR (NEW.release_policy->>'MetadataSlots')::bigint<NEW.max_rules*16 OR (NEW.release_policy->>'MetadataSlots')::numeric<pool.account_limit::numeric*pool.records_per_account OR
    pool.account_limit<NEW.max_rules OR pool.records_per_account<16 OR
    pool.retained_seconds<=30+2*(NEW.release_policy->>'BackupHorizonSeconds')::bigint+3*(NEW.release_policy->>'CleanupBudgetSeconds')::bigint+(NEW.release_policy->>'ProofWindowSeconds')::bigint OR pool.paused OR n>=pool.valid_until OR NEW.valid_until>pool.valid_until OR
    NEW.valid_until>(NEW.release_policy->>'ValidUntil')::timestamptz THEN
  RAISE EXCEPTION 'processing release reserve unavailable' USING ERRCODE='23514'; END IF;
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
  IF NEW.backing IS DISTINCT FROM OLD.backing OR NEW.release_policy IS DISTINCT FROM OLD.release_policy THEN
   IF NEW.backing_revision<>OLD.backing_revision+1 OR NEW.root_transitions<>OLD.root_transitions+1 OR NEW.sequence<>OLD.sequence+1 OR
      ROW(NEW.captures,NEW.rules,NEW.initialized_at,NEW.initialization_id) IS DISTINCT FROM ROW(OLD.captures,OLD.rules,OLD.initialized_at,OLD.initialization_id) OR
      NEW.max_captures<OLD.max_captures OR NEW.max_rules<OLD.max_rules OR NEW.max_root_transitions<OLD.max_root_transitions OR NEW.valid_until<OLD.valid_until OR
      NEW.backing->'History' IS DISTINCT FROM OLD.backing->'History' OR NEW.backing->'PolicyID' IS DISTINCT FROM OLD.backing->'PolicyID' OR
      NEW.backing->'PolicyDigest' IS DISTINCT FROM OLD.backing->'PolicyDigest' OR NEW.backing->'BackupIdentity' IS DISTINCT FROM OLD.backing->'BackupIdentity' OR
      NEW.backing->'BackupDigest' IS DISTINCT FROM OLD.backing->'BackupDigest' OR NEW.backing->'BackupHorizonSeconds' IS DISTINCT FROM OLD.backing->'BackupHorizonSeconds' OR
      NEW.backing->'CleanupSeconds' IS DISTINCT FROM OLD.backing->'CleanupSeconds' OR
      (NEW.release_policy-ARRAY['BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','ValidUntil']) IS DISTINCT FROM (OLD.release_policy-ARRAY['BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','ValidUntil']) OR
      (NEW.release_policy->>'MetadataSlots')::bigint<(OLD.release_policy->>'MetadataSlots')::bigint OR
      (NEW.release_policy->>'BackupReservedBytes')::bigint<(OLD.release_policy->>'BackupReservedBytes')::bigint OR
      (NEW.release_policy->>'WALReservedBytes')::bigint<(OLD.release_policy->>'WALReservedBytes')::bigint OR
      (NEW.release_policy->>'ValidUntil')::timestamptz<(OLD.release_policy->>'ValidUntil')::timestamptz OR n>=NEW.valid_until THEN
    RAISE EXCEPTION 'processing backing update does not cover history' USING ERRCODE='23514'; END IF;
  ELSE
   IF NEW.backing_revision<>OLD.backing_revision OR ROW(NEW.valid_until,NEW.retire_by,NEW.max_captures,NEW.max_rules,NEW.max_root_transitions) IS DISTINCT FROM ROW(OLD.valid_until,OLD.retire_by,OLD.max_captures,OLD.max_rules,OLD.max_root_transitions) OR pg_trigger_depth()<2 THEN
    RAISE EXCEPTION 'processing counters are source managed' USING ERRCODE='23514'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION guard_context_processing() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'processing lineage is publication owned' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION project_context_processing() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.processing_root; e jsonb; n timestamptz;
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_catalog'::regclass THEN
  RAISE EXCEPTION 'invalid processing publication source' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 IF p.initialized_at IS NULL OR n>=p.valid_until OR p.captures>=p.max_captures THEN RAISE EXCEPTION 'processing completeness unavailable' USING ERRCODE='23514'; END IF;
 SELECT convert_from(c.expectation_json,'UTF8')::jsonb INTO STRICT e FROM public.context_capture c WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF e->>'ActionID' IS DISTINCT FROM 'pod-status' OR e->>'DataClass' IS DISTINCT FROM 'metadata' OR
    (e->>'CaptureUID')::uuid IS DISTINCT FROM NEW.capture_id OR (e#>>'{Registration,Location,ArtifactID}')::uuid IS DISTINCT FROM NEW.artifact_id OR
    (e#>>'{Registration,DeleteBy}')::timestamptz>p.valid_until THEN
  RAISE EXCEPTION 'unqualified processing lineage' USING ERRCODE='23514'; END IF;
 -- Renewing installation capacity does not expand an older restrictive rule's
 -- managed-history coverage. The restriction stays effective after its own
 -- administrative deadline; future matching evidence cannot outlive backing.
 IF EXISTS(SELECT 1 FROM public.processing_rule r WHERE r.root_id=NEW.root_id AND r.state='restricted' AND
    (e#>>'{Registration,DeleteBy}')::timestamptz>r.valid_until AND
    ((r.scope->>'Kind'='artifact' AND r.scope#>>'{Location,ArtifactID}'=NEW.artifact_id::text AND r.scope#>>'{Location,AttemptID}'=e#>>'{Registration,Location,AttemptID}' AND r.scope#>>'{Location,ClusterID}'=e#>>'{Registration,Location,ClusterID}') OR
     (r.scope->>'Kind'='workloadInterval' AND r.scope->>'ClusterID'=e#>>'{Registration,Location,ClusterID}' AND r.scope->>'NamespaceUID'=e->>'NamespaceUID' AND r.scope->>'WorkloadUID'=e->>'WorkloadUID' AND
      (e#>>'{Registration,AnchorAt}')::timestamptz>=(r.scope->>'AcquiredFrom')::timestamptz AND (e#>>'{Registration,AnchorAt}')::timestamptz<(r.scope->>'AcquiredUntil')::timestamptz))) THEN
  RAISE EXCEPTION 'retained processing restriction requires coverage reconciliation' USING ERRCODE='23514'; END IF;
 INSERT INTO public.context_processing(artifact_id,root_id,capture_id,attempt_id,cluster_id,namespace_uid,workload_uid,pod_uid,anchor_at,delete_by,retire_by,origin,parents)
 VALUES(NEW.artifact_id,NEW.root_id,NEW.capture_id,(e#>>'{Registration,Location,AttemptID}')::uuid,(e#>>'{Registration,Location,ClusterID}')::uuid,e->>'NamespaceUID',e->>'WorkloadUID',e->>'PodUID',(e#>>'{Registration,AnchorAt}')::timestamptz,(e#>>'{Registration,DeleteBy}')::timestamptz,p.retire_by,'capture','[]');
 UPDATE public.processing_root SET captures=captures+1 WHERE root_id=NEW.root_id;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_processing_root(),guard_context_processing(),project_context_processing() FROM PUBLIC;
CREATE TRIGGER processing_root_guard BEFORE INSERT OR UPDATE OR DELETE ON processing_root FOR EACH ROW EXECUTE FUNCTION guard_processing_root();
CREATE TRIGGER context_processing_guard BEFORE INSERT OR UPDATE OR DELETE ON context_processing FOR EACH ROW EXECUTE FUNCTION guard_context_processing();
CREATE TRIGGER context_processing_from_catalog AFTER INSERT ON context_catalog FOR EACH ROW EXECUTE FUNCTION project_context_processing();

-- +goose StatementBegin
CREATE FUNCTION processing_scope_valid(s jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT coalesce(jsonb_typeof(s)='object' AND octet_length(s::text)<=2048 AND
 s ?& ARRAY['Kind','Location','ClusterID','NamespaceUID','WorkloadUID','AcquiredFrom','AcquiredUntil'] AND
 s-ARRAY['Kind','Location','ClusterID','NamespaceUID','WorkloadUID','AcquiredFrom','AcquiredUntil']='{}'::jsonb AND
 jsonb_typeof(s->'Location')='object' AND (s->'Location')-ARRAY['ClusterID','ArtifactID','AttemptID']='{}'::jsonb AND
 CASE s->>'Kind'
 WHEN 'artifact' THEN (s#>>'{Location,ClusterID}')::uuid IS NOT NULL AND (s#>>'{Location,ArtifactID}')::uuid IS NOT NULL AND (s#>>'{Location,AttemptID}')::uuid IS NOT NULL
  AND s->>'ClusterID'='' AND s->>'NamespaceUID'='' AND s->>'WorkloadUID'='' AND s->>'AcquiredFrom'='0001-01-01T00:00:00Z' AND s->>'AcquiredUntil'='0001-01-01T00:00:00Z'
 WHEN 'workloadInterval' THEN s->'Location'='{"ClusterID":"","ArtifactID":"","AttemptID":""}'::jsonb AND (s->>'ClusterID')::uuid IS NOT NULL
  AND octet_length(s->>'NamespaceUID') BETWEEN 1 AND 64 AND octet_length(s->>'WorkloadUID') BETWEEN 1 AND 64
  AND isfinite((s->>'AcquiredFrom')::timestamptz) AND isfinite((s->>'AcquiredUntil')::timestamptz)
  AND (s->>'AcquiredUntil')::timestamptz>(s->>'AcquiredFrom')::timestamptz AND (s->>'AcquiredUntil')::timestamptz<=(s->>'AcquiredFrom')::timestamptz+interval '3660 days'
 ELSE false END,false)
$$;
CREATE FUNCTION guard_processing_rule() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
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
  IF ROW(NEW.root_id,NEW.id,NEW.scope,NEW.release_account,NEW.valid_until,NEW.retire_by) IS DISTINCT FROM ROW(OLD.root_id,OLD.id,OLD.scope,OLD.release_account,OLD.valid_until,OLD.retire_by) OR pg_trigger_depth()<2 THEN
   RAISE EXCEPTION 'processing rule is decision owned' USING ERRCODE='23514'; END IF;
  IF NOT (NEW.decisions=OLD.decisions+1 AND ROW(NEW.revision,NEW.state,NEW.current_decision) IS NOT DISTINCT FROM ROW(OLD.revision,OLD.state,OLD.current_decision)) AND
     NOT (NEW.decisions=OLD.decisions AND NEW.revision=OLD.revision+1 AND NEW.current_decision IS DISTINCT FROM OLD.current_decision AND NEW.state=(CASE WHEN NEW.revision%2=1 THEN 'restricted' ELSE 'released' END)) THEN
   RAISE EXCEPTION 'invalid processing transition' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION guard_processing_decision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.processing_root; r public.processing_rule; a public.operation_audit; n timestamptz; output jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'processing decision retirement requires independent completion' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 IF NEW.rule_id IS NOT NULL THEN SELECT * INTO STRICT r FROM public.processing_rule WHERE root_id=NEW.root_id AND id=NEW.rule_id FOR UPDATE; END IF;
 n:=clock_timestamp();
 IF TG_OP='INSERT' THEN
  IF NEW.valid_until IS NOT NULL OR NEW.retire_by IS NOT NULL THEN RAISE EXCEPTION 'processing decision dates are source owned' USING ERRCODE='23514'; END IF;
  NEW.valid_until:=p.valid_until; NEW.retire_by:=p.retire_by;
  IF NEW.rule_id IS NOT NULL THEN NEW.valid_until:=r.valid_until; NEW.retire_by:=r.retire_by; END IF;
  IF n>=NEW.valid_until OR NEW.request_until>NEW.valid_until OR n<NEW.created_at OR n>=NEW.request_until OR n>=p.valid_until OR NEW.applied_at IS NOT NULL OR NEW.audit_digest IS NOT NULL OR NEW.result_revision IS NOT NULL OR NEW.result_sequence IS NOT NULL OR
     NEW.intent_seed->>'ID' IS DISTINCT FROM NEW.id::text OR NEW.intent_seed->>'RootID' IS DISTINCT FROM NEW.root_id::text OR NEW.intent_seed->>'Name' IS DISTINCT FROM NEW.action OR NEW.intent_seed->>'InputFormat' IS DISTINCT FROM 'processing-input/v1' OR
     (NEW.intent_seed->>'CreatedAt')::timestamptz IS DISTINCT FROM NEW.created_at OR (NEW.intent_seed->>'RequestUntil')::timestamptz IS DISTINCT FROM NEW.request_until OR
     NEW.outcome_json->>'Status' IS DISTINCT FROM 'success' OR NEW.outcome_json->>'Reason' IS DISTINCT FROM 'prepared' OR NEW.outcome_json->>'Effect' IS DISTINCT FROM 'unknown' OR NEW.outcome_json->>'ClientReceipt' IS DISTINCT FROM 'unknown' OR NEW.outcome_json?'Intent' THEN
   RAISE EXCEPTION 'invalid prepared processing decision' USING ERRCODE='23514'; END IF;
  IF NEW.action='initialize_processing' THEN
   IF p.initialized_at IS NOT NULL OR NEW.expected_revision<>0 OR p.root_transitions>=p.max_root_transitions OR EXISTS(SELECT 1 FROM public.context_catalog WHERE root_id=NEW.root_id) THEN
    RAISE EXCEPTION 'processing completeness needs empty reviewed history' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_root SET root_transitions=root_transitions+1 WHERE root_id=NEW.root_id;
  ELSE
   IF p.initialized_at IS NULL OR NEW.release_account IS DISTINCT FROM r.release_account OR NOT public.processing_scope_valid(NEW.scope) OR NEW.scope IS DISTINCT FROM r.scope OR NEW.expected_revision<>r.revision OR r.decisions>=16 OR
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
  IF (to_jsonb(NEW)-ARRAY['applied_at','audit_digest','result_revision','result_sequence']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['applied_at','audit_digest','result_revision','result_sequence']) OR OLD.applied_at IS NOT NULL OR NEW.applied_at IS NULL OR n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until THEN
   RAISE EXCEPTION 'immutable or expired processing decision' USING ERRCODE='23514'; END IF;
  -- Every nested root write checks the prepaid release pool. Take it before
  -- the audit row, matching journal replay's pool -> audit ordering. Otherwise
  -- apply could hold the audit row while replay holds the pool.
  PERFORM 1 FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='processing' FOR SHARE;
  SELECT * INTO STRICT a FROM public.operation_audit WHERE root_id=NEW.root_id AND id=NEW.id FOR SHARE;
  n:=clock_timestamp();
  IF n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until OR a.lane<>(CASE WHEN NEW.action='release_processing' THEN 'processing' ELSE 'normal' END) OR a.intent_receipt IS NULL OR a.outcome_receipt IS NULL OR
     (a.intent-ARRAY['Actor','Peer','Process']) IS DISTINCT FROM NEW.intent_seed OR sha256(convert_to((a.intent->'Actor')::text,'UTF8')) IS DISTINCT FROM NEW.actor_digest OR
     a.outcome->'Intent' IS DISTINCT FROM a.intent OR (a.outcome-'Intent') IS DISTINCT FROM NEW.outcome_json OR
     NEW.audit_digest IS DISTINCT FROM sha256(convert_to(a.outcome_receipt::text,'UTF8')) THEN
   RAISE EXCEPTION 'processing decision needs exact independent audit' USING ERRCODE='23514'; END IF;
  IF NEW.action='initialize_processing' THEN
   IF p.initialized_at IS NOT NULL OR EXISTS(SELECT 1 FROM public.context_catalog WHERE root_id=NEW.root_id) THEN RAISE EXCEPTION 'processing history changed during review' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_root SET initialized_at=n,initialization_id=NEW.id,sequence=sequence+1 WHERE root_id=NEW.root_id;
   NEW.result_revision:=0;
  ELSE
   IF p.initialized_at IS NULL OR r.revision<>NEW.expected_revision OR r.scope IS DISTINCT FROM NEW.scope OR
      (NEW.action='release_processing' AND r.state<>'restricted') OR (NEW.action='restrict_processing' AND r.state NOT IN ('reserved','released')) THEN
    RAISE EXCEPTION 'processing decision CAS changed' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_rule SET revision=revision+1,state=CASE WHEN NEW.action='release_processing' THEN 'released' ELSE 'restricted' END,current_decision=NEW.id WHERE root_id=NEW.root_id AND id=NEW.rule_id;
   UPDATE public.processing_root SET sequence=sequence+1 WHERE root_id=NEW.root_id;
   NEW.result_revision:=r.revision+1;
  END IF;
  -- Nested counter/rule triggers can wait for the separately protected audit
  -- pool. Recheck the original decision interval after those writes as well;
  -- an expiry rolls back every nested effect in this transaction.
  n:=clock_timestamp();
  IF n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until THEN RAISE EXCEPTION 'processing decision expired after nested locks' USING ERRCODE='23514'; END IF;
  NEW.applied_at:=n; NEW.result_sequence:=p.sequence+1;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION processing_scope_valid(jsonb),guard_processing_rule(),guard_processing_decision() FROM PUBLIC;
CREATE TRIGGER processing_rule_guard BEFORE INSERT OR UPDATE OR DELETE ON processing_rule FOR EACH ROW EXECUTE FUNCTION guard_processing_rule();
CREATE TRIGGER processing_decision_guard BEFORE INSERT OR UPDATE OR DELETE ON processing_decision FOR EACH ROW EXECUTE FUNCTION guard_processing_decision();

-- SQL49 owns the peer-versus-human branch. Add only the closed private human
-- decision format; no peer input or public tool allowlist is changed here.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT coalesce(CASE
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','resolve_capture_request','invalid_operation') THEN input_format IN ('context-input/v1','invalid-input/v1')
 ELSE false END,false)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION operation_audit_human_input_valid(text,text) FROM PUBLIC;

-- The whole finite release account is reserved before a restriction can be
-- admitted. A later lane admission spends only an exact retained private
-- decision. Its actor is still the real currently authorized human; the stable
-- account digest is capacity identity, not a synthetic human principal.
-- +goose StatementBegin
CREATE FUNCTION guard_processing_release_audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE d public.processing_decision; r public.processing_rule; p public.processing_root; n timestamptz;
BEGIN
 IF NEW.lane<>'processing' THEN RETURN NEW; END IF;
 IF TG_OP<>'INSERT' THEN RETURN NEW; END IF;
 -- The generic journal already locks this pool. Take the same lock for direct
 -- SQL callers; business rows below are intentionally nonlocking MVCC reads.
 -- No audit path obtains the permission/processing root in reverse order.
 PERFORM 1 FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='processing' FOR UPDATE;
 SELECT * INTO STRICT d FROM public.processing_decision WHERE root_id=NEW.root_id AND id=NEW.id;
 SELECT * INTO STRICT r FROM public.processing_rule WHERE root_id=d.root_id AND id=d.rule_id;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=d.root_id;
 n:=clock_timestamp();
 IF d.action<>'release_processing' OR d.applied_at IS NOT NULL OR n>=d.request_until OR n>=d.valid_until OR n>=r.valid_until OR n>=p.valid_until OR
    p.initialized_at IS NULL OR r.state<>'restricted' OR r.revision<>d.expected_revision OR r.scope IS DISTINCT FROM d.scope OR
    d.release_account IS DISTINCT FROM r.release_account OR NEW.principal_digest IS DISTINCT FROM r.release_account OR
    NEW.intent->'PrincipalDigest' IS DISTINCT FROM to_jsonb(ARRAY(SELECT get_byte(r.release_account,i) FROM generate_series(0,31) i)) OR
    (NEW.intent-ARRAY['Actor','Peer','Process']) IS DISTINCT FROM d.intent_seed OR NEW.intent?'Peer' OR NEW.intent?'Process' OR
    sha256(convert_to((NEW.intent->'Actor')::text,'UTF8')) IS DISTINCT FROM d.actor_digest OR
    NEW.intent->'Lifecycle'->'Policy' IS DISTINCT FROM p.release_policy THEN
  RAISE EXCEPTION 'exact prepaid processing release unavailable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION preserve_processing_release_backing() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.processing_root;
BEGIN
 IF NEW.lane<>'processing' OR ROW(NEW.account_limit,NEW.records_per_account,NEW.valid_until,NEW.retained_seconds) IS NOT DISTINCT FROM ROW(OLD.account_limit,OLD.records_per_account,OLD.valid_until,OLD.retained_seconds) THEN RETURN NEW; END IF;
 -- This UPDATE owns the audit pool row. Configuration acceptance also locks
 -- that row before committing; this nonlocking read therefore cannot make a
 -- reverse root lock cycle. Root acceptance rechecks backing after its wait.
 SELECT * INTO p FROM public.processing_root WHERE root_id=NEW.root_id;
 IF FOUND AND (NEW.account_limit<p.max_rules OR NEW.records_per_account<16 OR NEW.valid_until<p.valid_until OR NEW.retained_seconds<OLD.retained_seconds) THEN
  RAISE EXCEPTION 'processing release backing below retained reservations' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_processing_release_audit(),preserve_processing_release_backing() FROM PUBLIC;
CREATE TRIGGER operation_audit_00_processing_release BEFORE INSERT ON operation_audit FOR EACH ROW EXECUTE FUNCTION guard_processing_release_audit();
CREATE TRIGGER operation_audit_pool_00_processing_reserve BEFORE UPDATE ON operation_audit_pool FOR EACH ROW EXECUTE FUNCTION preserve_processing_release_backing();
