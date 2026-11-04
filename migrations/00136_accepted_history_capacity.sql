-- +goose Up
-- ADR-301: these are separately charged parameters of an already accepted
-- capture, not another workload acquisition. Purpose comes from the actual
-- immutable history association, never a caller flag, role or native size.
-- +goose StatementBegin
CREATE FUNCTION capacity_accepted_history_until(r uuid,attempt uuid,n timestamptz) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE h public.capture_history_parameter;a public.custody_attempt;c public.context_capture;g public.recording_save_group;
 source public.capacity_source;managed_pool public.capacity_pool;compiled jsonb;
 e jsonb;owner_root uuid;owner_id uuid;owner_scope bytea;owner_created timestamptz;owner_deadline timestamptz;owner_allocation uuid;owner_cluster uuid;
 root_until timestamptz;until_at timestamptz;
BEGIN
 IF r IS NULL OR attempt IS NULL OR n IS NULL OR NOT isfinite(n) THEN RETURN NULL;END IF;
 SELECT * INTO STRICT h FROM public.capture_history_parameter WHERE attempt_id=attempt;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=attempt;
 SELECT * INTO c FROM public.context_capture WHERE id=h.capture_id;
 IF FOUND THEN
  owner_root:=c.root_id;owner_id:=c.id;owner_scope:=c.scope_digest;owner_created:=c.created_at;owner_deadline:=c.deadline;
  owner_allocation:=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,AllocationID}')::uuid;
  owner_cluster:=c.history_cluster_id;
 ELSE
  SELECT * INTO STRICT g FROM public.recording_save_group WHERE id=h.capture_id;
  owner_root:=g.root_id;owner_id:=g.id;owner_scope:=g.scope_digest;owner_created:=g.accepted_at;owner_deadline:=g.deadline;
  owner_allocation:=g.allocation_id;
  -- Both recording-save and manual-composition parents use their actual
  -- original children; composition scope has no policy.clusterID branch.
  SELECT child.history_cluster_id INTO STRICT owner_cluster FROM public.context_capture child
   WHERE child.root_id=g.root_id AND child.group_id=g.id AND child.group_ordinal=0 AND child.id=g.child_ids[1];
  IF cardinality(g.child_ids) NOT BETWEEN 2 AND 16 OR
   (SELECT count(*) FROM public.context_capture child WHERE child.group_id=g.id)<>cardinality(g.child_ids) OR
   EXISTS(SELECT 1 FROM public.context_capture child JOIN public.custody_attempt original ON original.id=child.attempt_id
    WHERE child.group_id=g.id AND (child.root_id IS DISTINCT FROM g.root_id OR child.history_cluster_id IS DISTINCT FROM owner_cluster OR original.allocation_id IS DISTINCT FROM owner_allocation)) THEN RETURN NULL;END IF;
 END IF;
 e:=convert_from(h.expectation_json,'UTF8')::jsonb;
 -- Existing immediate history checks remain, but a row's mere presence is
 -- insufficient: SQL NULL/missing properties must never establish purpose.
 IF NOT COALESCE(h.root_id=r AND h.root_id=owner_root AND h.capture_id=owner_id AND h.attempt_id=a.id AND
  h.created_at=owner_created AND a.anchor_at=owner_created AND a.allocation_id=owner_allocation AND a.cluster_id=owner_cluster AND
  a.native_limit=131072 AND a.state='reserved' AND h.state='reserved' AND h.visible AND
  h.summary_expires_at>n AND a.expires_at<=h.summary_expires_at AND h.summary_expires_at<=owner_created+interval '3650 days' AND
  a.write_until<=owner_deadline AND n<a.write_until AND n<a.expires_at AND n<a.delete_by AND
  (e->>'RootID')::uuid=owner_root AND (e->>'CaptureID')::uuid=owner_id AND
  (e#>>'{Registration,Location,AttemptID}')::uuid=a.id AND (e#>>'{Registration,Location,ArtifactID}')::uuid=a.artifact_id AND
  (e#>>'{Registration,Location,ClusterID}')::uuid=a.cluster_id AND (e#>>'{Registration,AllocationID}')::uuid=a.allocation_id AND
  (e#>>'{Registration,NativeLimit}')::bigint=a.native_limit AND
  public.connector_digest(e->'OriginalExecutionDigest')=owner_scope AND
  public.connector_digest(e->'SelectorKey')=h.selector_key AND public.connector_digest(e->'SettingsKey')=h.settings_key AND
  e->>'MACVersion'=h.mac_version AND
  (e#>>'{Registration,StoreID}')::uuid=(SELECT p.store_id FROM public.custody_pool p JOIN public.custody_allocation x ON x.pool_id=p.id WHERE x.id=a.allocation_id) AND
  (e#>>'{Registration,PoolRevision}')::bigint=a.pool_revision AND (e#>>'{Registration,AllocationRevision}')::bigint=a.allocation_revision AND
  (e#>>'{Registration,AnchorAt}')::timestamptz=a.anchor_at AND (e#>>'{Registration,WriteUntil}')::timestamptz=a.write_until AND
  (e#>>'{Registration,ExpiresAt}')::timestamptz=a.expires_at AND (e#>>'{Registration,DeleteBy}')::timestamptz=a.delete_by,false) THEN RETURN NULL;END IF;
 root_until:=public.capacity_managed_root_until(r,n);
 IF root_until IS NULL OR n>=root_until THEN RETURN NULL;END IF;
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=r;
 SELECT managed.* INTO STRICT managed_pool FROM public.capacity_pool managed JOIN public.custody_allocation x ON x.pool_id=managed.id WHERE x.id=a.allocation_id AND managed.root_id=r;
 compiled:=public.capacity_compile_pool(source.accepted_snapshot,managed_pool.source_name);
 IF compiled IS NULL OR NOT COALESCE(compiled IS NOT DISTINCT FROM managed_pool.plan OR public.capacity_pool_extends(managed_pool.plan,compiled),false) THEN RETURN NULL;END IF;
 -- Keep the same original pool/allocation/control backing and current root.
 -- Only the live workload observation is absent from this metadata path.
 SELECT LEAST(root_until,p.valid_until,x.valid_until,ca.valid_until,control.valid_until,a.write_until,a.expires_at) INTO until_at
 FROM public.custody_allocation x JOIN public.custody_pool p ON p.id=x.pool_id
 JOIN public.capacity_pool managed ON managed.id=p.id AND managed.root_id=r
 JOIN public.context_control_account ca ON ca.root_id=r AND ca.allocation_id=x.id
 JOIN public.context_control_pool control ON control.root_id=ca.root_id
 WHERE x.id=a.allocation_id AND p.revision=a.pool_revision AND x.revision=a.allocation_revision AND
  NOT p.paused AND NOT x.paused AND n<p.valid_until AND n<x.valid_until AND
  ca.configured AND NOT ca.paused AND n<ca.valid_until AND control.configured AND NOT control.paused AND n<control.valid_until;
 IF until_at IS NULL OR clock_timestamp()>=until_at THEN RETURN NULL;END IF;
 RETURN until_at;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION capacity_accepted_history_until(uuid,uuid,timestamptz) FROM PUBLIC;

CREATE OR REPLACE FUNCTION require_capacity_new_admission() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r uuid;a uuid;until_at timestamptz;history boolean:=false;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' THEN RAISE EXCEPTION 'invalid capacity admission source' USING ERRCODE='23514';END IF;
 IF TG_RELID='public.custody_attempt'::regclass THEN
  SELECT p.root_id INTO r FROM public.custody_allocation allocation JOIN public.capacity_pool p ON p.id=allocation.pool_id WHERE allocation.id=NEW.allocation_id;
  IF NOT FOUND THEN RETURN NEW;END IF;
  a:=NEW.allocation_id;
  SELECT EXISTS(SELECT 1 FROM public.capture_history_parameter WHERE attempt_id=NEW.id) INTO history;
  IF history THEN until_at:=public.capacity_accepted_history_until(r,NEW.id,clock_timestamp());END IF;
 ELSIF TG_RELID='public.context_capture'::regclass THEN
  r:=NEW.root_id;SELECT allocation_id INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;
 ELSIF TG_RELID='public.operation_audit'::regclass THEN
  IF NEW.lane<>'capture' THEN RETURN NEW;END IF;
  r:=NEW.root_id;SELECT allocation_id INTO STRICT a FROM public.custody_attempt WHERE id=(NEW.intent#>>'{Capture,AttemptID}')::uuid;
 ELSE RAISE EXCEPTION 'invalid capacity admission table' USING ERRCODE='23514';END IF;
 IF NOT history THEN until_at:=public.capacity_managed_admission_until(r,a,'context',clock_timestamp());END IF;
 IF until_at IS NULL OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'managed capacity admission incomplete or expired' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
DROP TRIGGER zzz_capacity_new_admission ON custody_attempt;
CREATE CONSTRAINT TRIGGER zzz_capacity_new_admission AFTER INSERT ON custody_attempt
 DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW EXECUTE FUNCTION require_capacity_new_admission();
-- +goose StatementEnd

-- +goose Down
-- No persisted columns or obligations change. Only future registration returns
-- to the previous requirement for live workload capacity.
-- +goose StatementBegin
DROP TRIGGER zzz_capacity_new_admission ON custody_attempt;
CREATE TRIGGER zzz_capacity_new_admission AFTER INSERT ON custody_attempt FOR EACH ROW EXECUTE FUNCTION require_capacity_new_admission();
CREATE OR REPLACE FUNCTION require_capacity_new_admission() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r uuid;a uuid;until_at timestamptz;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' THEN RAISE EXCEPTION 'invalid capacity admission source' USING ERRCODE='23514';END IF;
 IF TG_RELID='public.custody_attempt'::regclass THEN
  SELECT p.root_id INTO r FROM public.custody_allocation allocation JOIN public.capacity_pool p ON p.id=allocation.pool_id WHERE allocation.id=NEW.allocation_id;
  IF NOT FOUND THEN RETURN NEW;END IF;
  a:=NEW.allocation_id;
 ELSIF TG_RELID='public.context_capture'::regclass THEN
  r:=NEW.root_id;SELECT allocation_id INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;
 ELSIF TG_RELID='public.operation_audit'::regclass THEN
  -- Only collection audit is workload-capacity gated; read and other lanes
  -- are bounded by their own per-principal audit allowance.
  IF NEW.lane<>'capture' THEN RETURN NEW;END IF;
  r:=NEW.root_id;SELECT allocation_id INTO STRICT a FROM public.custody_attempt WHERE id=(NEW.intent#>>'{Capture,AttemptID}')::uuid;
 ELSE RAISE EXCEPTION 'invalid capacity admission table' USING ERRCODE='23514';END IF;
 until_at:=public.capacity_managed_admission_until(r,a,'context',clock_timestamp());
 IF until_at IS NULL OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'managed capacity admission incomplete or expired' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
DROP FUNCTION capacity_accepted_history_until(uuid,uuid,timestamptz);
-- +goose StatementEnd
