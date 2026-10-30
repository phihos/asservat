-- +goose Up
-- Separate bounded completion projection; accepted scope/expectation stay immutable.
ALTER TABLE context_capture ADD COLUMN snapshot_coverage bytea;
ALTER TABLE context_capture ADD COLUMN snapshot_coverage_digest bytea;
ALTER TABLE context_capture ADD COLUMN snapshot_expectation_digest bytea;
ALTER TABLE context_capture ADD CONSTRAINT context_snapshot_completion_shape CHECK (
 (snapshot_coverage IS NULL AND snapshot_coverage_digest IS NULL AND snapshot_expectation_digest IS NULL) OR
 (snapshot_coverage IS NOT NULL AND octet_length(snapshot_coverage) BETWEEN 1 AND 8192 AND
 snapshot_coverage_digest IS NOT NULL AND octet_length(snapshot_coverage_digest)=32 AND
 snapshot_expectation_digest IS NOT NULL AND octet_length(snapshot_expectation_digest)=32));
-- +goose StatementBegin
CREATE FUNCTION guard_context_snapshot_completion() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE e public.context_execution; w public.context_writer_completion;
BEGIN
 IF TG_WHEN='BEFORE' THEN
  IF TG_OP='INSERT' THEN
   IF NEW.snapshot_coverage IS NOT NULL THEN RAISE EXCEPTION 'snapshot completion cannot precede admission' USING ERRCODE='23514'; END IF;
  ELSIF ROW(NEW.snapshot_coverage,NEW.snapshot_coverage_digest,NEW.snapshot_expectation_digest) IS DISTINCT FROM ROW(OLD.snapshot_coverage,OLD.snapshot_coverage_digest,OLD.snapshot_expectation_digest) THEN
   IF OLD.snapshot_coverage IS NOT NULL OR NEW.snapshot_coverage IS NULL OR
    (convert_from(NEW.expectation_json,'UTF8')::jsonb)->'Snapshot' IS NULL OR
    (convert_from(NEW.expectation_json,'UTF8')::jsonb)->'Snapshot'='null'::jsonb THEN
    RAISE EXCEPTION 'immutable snapshot completion' USING ERRCODE='23514';
   END IF;
   SELECT * INTO STRICT e FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id;
   IF e.phase<>'stored' OR e.attempt_id<>NEW.attempt_id OR e.writer_protocol<>'closed-small-context/v1' THEN
    RAISE EXCEPTION 'snapshot completion requires stored execution' USING ERRCODE='23514';
   END IF;
  END IF;
 ELSE
  IF NEW.snapshot_coverage IS NOT NULL THEN
   SELECT * INTO STRICT w FROM public.context_writer_completion WHERE root_id=NEW.root_id AND capture_id=NEW.id AND attempt_id=NEW.attempt_id;
   IF w.expectation_digest<>NEW.snapshot_expectation_digest THEN RAISE EXCEPTION 'snapshot completion requires joined writer' USING ERRCODE='23514'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_snapshot_completion() FROM PUBLIC;
CREATE TRIGGER context_snapshot_completion_guard BEFORE INSERT OR UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION guard_context_snapshot_completion();
CREATE CONSTRAINT TRIGGER context_snapshot_completion_required AFTER UPDATE ON context_capture DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION guard_context_snapshot_completion();
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_writer_completion() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE e public.context_execution; a public.custody_attempt; c public.context_capture;
BEGIN
 IF TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_RELID<>'public.context_writer_completion'::regclass OR TG_OP<>'INSERT' THEN RAISE EXCEPTION 'immutable writer completion' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT e FROM public.context_execution WHERE capture_id=NEW.capture_id AND root_id=NEW.root_id;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;
 SELECT * INTO STRICT c FROM public.context_capture WHERE id=NEW.capture_id AND root_id=NEW.root_id;
 IF (convert_from(c.expectation_json,'UTF8')::jsonb)->'Snapshot' IS NOT NULL AND (convert_from(c.expectation_json,'UTF8')::jsonb)->'Snapshot'<>'null'::jsonb AND c.snapshot_coverage IS NULL THEN RAISE EXCEPTION 'snapshot writer lacks coverage' USING ERRCODE='23514'; END IF;
 IF e.writer_protocol IS DISTINCT FROM 'closed-small-context/v1' OR e.phase<>'stored' OR a.state IN ('deleting','deleted') OR e.attempt_id<>a.id OR COALESCE(c.snapshot_expectation_digest,e.expectation_digest)<>NEW.expectation_digest OR e.copies_digest<>NEW.copies_digest OR a.request_digest<>NEW.registration_digest OR (convert_from(e.process_json,'UTF8')::jsonb)->>'InstallationID' IS DISTINCT FROM NEW.installation_id::text OR (convert_from(e.process_json,'UTF8')::jsonb)->>'IssuerEpoch' IS DISTINCT FROM NEW.issuer_epoch::text OR e.completed_at<>NEW.stored_at OR NEW.closed_at>clock_timestamp() OR NEW.recorded_at>clock_timestamp() OR NEW.stored_at>=a.write_until OR NOT public.incarnation_current(NEW.postmaster_at) OR NEW.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id AND issuer_epoch=NEW.issuer_epoch AND NOT recovery_blocked AND NOT suspended AND fresh_until>clock_timestamp()) THEN
  RAISE EXCEPTION 'writer completion lacks exact positive execution' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- The unchanged processing ledger also records saved source windows. Native
-- type/action identity remain exact; no source lease or recorder is created.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_context_processing() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.processing_root; e jsonb; n timestamptz;
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_catalog'::regclass THEN
  RAISE EXCEPTION 'invalid processing publication source' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 IF p.initialized_at IS NULL OR n>=p.valid_until OR p.captures>=p.max_captures THEN RAISE EXCEPTION 'processing completeness unavailable' USING ERRCODE='23514'; END IF;
 SELECT convert_from(c.expectation_json,'UTF8')::jsonb INTO STRICT e FROM public.context_capture c WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF NOT COALESCE(e->>'ActionID'='pod-status' AND NOT e ? 'NativeType' AND NOT e ? 'Recording' OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType'='pcapng' AND jsonb_typeof(e->'Recording')='object' OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType'='pcapng' AND jsonb_typeof(e->'Snapshot')='object' AND (NOT e ? 'Recording' OR e->'Recording'='null'::jsonb),false) OR e->>'DataClass' IS DISTINCT FROM 'metadata' OR
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

-- +goose Down
-- Existing completed snapshots cannot be represented by the previous schema.
-- +goose StatementBegin
DO $$ BEGIN IF EXISTS(SELECT 1 FROM context_capture WHERE snapshot_coverage IS NOT NULL) THEN RAISE EXCEPTION 'snapshot completion must be retired before downgrade'; END IF; END $$;
-- +goose StatementEnd
DROP TRIGGER context_snapshot_completion_required ON context_capture;
DROP TRIGGER context_snapshot_completion_guard ON context_capture;
DROP FUNCTION guard_context_snapshot_completion();
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_writer_completion() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE e public.context_execution; a public.custody_attempt;
BEGIN
 IF TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_RELID<>'public.context_writer_completion'::regclass OR TG_OP<>'INSERT' THEN RAISE EXCEPTION 'immutable writer completion' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT e FROM public.context_execution WHERE capture_id=NEW.capture_id AND root_id=NEW.root_id;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;
 IF e.writer_protocol IS DISTINCT FROM 'closed-small-context/v1' OR e.phase<>'stored' OR a.state IN ('deleting','deleted') OR e.attempt_id<>a.id OR e.expectation_digest<>NEW.expectation_digest OR e.copies_digest<>NEW.copies_digest OR a.request_digest<>NEW.registration_digest OR (convert_from(e.process_json,'UTF8')::jsonb)->>'InstallationID' IS DISTINCT FROM NEW.installation_id::text OR (convert_from(e.process_json,'UTF8')::jsonb)->>'IssuerEpoch' IS DISTINCT FROM NEW.issuer_epoch::text OR e.completed_at<>NEW.stored_at OR NEW.closed_at>clock_timestamp() OR NEW.recorded_at>clock_timestamp() OR NEW.stored_at>=a.write_until OR NOT public.incarnation_current(NEW.postmaster_at) OR NEW.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id AND issuer_epoch=NEW.issuer_epoch AND NOT recovery_blocked AND NOT suspended AND fresh_until>clock_timestamp()) THEN
  RAISE EXCEPTION 'writer completion lacks exact positive execution' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
ALTER TABLE context_capture DROP CONSTRAINT context_snapshot_completion_shape;
ALTER TABLE context_capture DROP COLUMN snapshot_expectation_digest;
ALTER TABLE context_capture DROP COLUMN snapshot_coverage_digest;
ALTER TABLE context_capture DROP COLUMN snapshot_coverage;

-- Restore the original finite publication predicate on downgrade.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_context_processing() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.processing_root; e jsonb; n timestamptz;
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_catalog'::regclass THEN
  RAISE EXCEPTION 'invalid processing publication source' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 IF p.initialized_at IS NULL OR n>=p.valid_until OR p.captures>=p.max_captures THEN RAISE EXCEPTION 'processing completeness unavailable' USING ERRCODE='23514'; END IF;
 SELECT convert_from(c.expectation_json,'UTF8')::jsonb INTO STRICT e FROM public.context_capture c WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF NOT COALESCE(e->>'ActionID'='pod-status' AND NOT e ? 'NativeType' AND NOT e ? 'Recording' OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType'='pcapng' AND jsonb_typeof(e->'Recording')='object',false) OR e->>'DataClass' IS DISTINCT FROM 'metadata' OR
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
