-- +goose Up
-- ADR-335 D2: the capacity pool comes from the Helm `capacity` values.
-- storageAssurance defaults to bestEffort (specs/capacity.md); it reports
-- whether the isolation claim holds and no longer blocks enrollment.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_compile_pool(snapshot jsonb,pool_name text) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE pool jsonb;budget jsonb;slot jsonb;policy jsonb;shape jsonb;cluster jsonb;clusters jsonb:='{}';policies jsonb:='[]';cluster_list jsonb;
 pool_count bigint;policy_count bigint;slots bigint:=0;names text[]:='{}';cluster_id text;
 protected_bytes numeric:=0;protected_objects numeric:=0;bytes numeric;objects numeric;
BEGIN
 IF NOT public.capacity_source_observation_valid(snapshot) OR octet_length(pool_name) NOT BETWEEN 1 AND 63 THEN RETURN NULL;END IF;
 SELECT count(*) INTO pool_count FROM jsonb_array_elements(snapshot->'Snapshot'->'Pools') p WHERE p->'Resource'->>'Name'=pool_name;
 IF pool_count<>1 THEN RETURN NULL;END IF;
 SELECT value INTO STRICT pool FROM jsonb_array_elements(snapshot->'Snapshot'->'Pools') WHERE value->'Resource'->>'Name'=pool_name;
 budget:=pool->'Budget';
 IF pool->'Resource'->>'Deleting' IS DISTINCT FROM 'false' OR
  budget='null'::jsonb OR NOT public.capacity_decoded_pool_valid(budget,pool_name) THEN RETURN NULL;END IF;
 FOR slot IN SELECT value FROM jsonb_array_elements(budget->'Slots') ORDER BY (value->>'Policy') COLLATE "C" LOOP
  SELECT count(*) INTO policy_count FROM jsonb_array_elements(snapshot->'Snapshot'->'Policies') p WHERE p->'Resource'->>'Name'=slot->>'Policy';
  IF policy_count<>1 THEN RETURN NULL;END IF;
  SELECT value INTO STRICT policy FROM jsonb_array_elements(snapshot->'Snapshot'->'Policies') WHERE value->'Resource'->>'Name'=slot->>'Policy';
  shape:=policy->'Budget';
  IF policy->'Resource'->>'Deleting' IS DISTINCT FROM 'false' OR policy->>'Pool' IS DISTINCT FROM pool_name OR shape='null'::jsonb OR
   NOT public.capacity_decoded_policy_valid(shape,slot->>'Policy',pool_name,policy->'Scope') OR
   shape->'Protected' IS DISTINCT FROM slot->'Protected' OR
   (shape->'Hard'->>'Bytes')::bigint<(shape->'Protected'->>'Bytes')::bigint OR (shape->'Hard'->>'Objects')::bigint<(shape->'Protected'->>'Objects')::bigint OR
   (shape->'Protected'->>'Bytes')::bigint<(shape->'Context'->>'Bytes')::bigint OR (shape->'Protected'->>'Objects')::bigint<(shape->'Context'->>'Objects')::bigint OR
   (shape->'NamespaceMaximum'->>'Bytes')::bigint<(shape->'Protected'->>'Bytes')::bigint OR (shape->'NamespaceMaximum'->>'Objects')::bigint<(shape->'Protected'->>'Objects')::bigint THEN RETURN NULL;END IF;
  names:=array_append(names,slot->>'Policy');slots:=slots+(slot->>'Workloads')::bigint;
  -- Numeric intermediates avoid bigint wrap before the pool comparison. Only
  -- quantities proven below the original finite pool are converted to bigint.
  bytes:=(slot->'Protected'->>'Bytes')::numeric*(slot->>'Workloads')::numeric;
  objects:=(slot->'Protected'->>'Objects')::numeric*(slot->>'Workloads')::numeric;
  protected_bytes:=protected_bytes+bytes;protected_objects:=protected_objects+objects;
  IF protected_bytes>(budget->'Capacity'->>'Bytes')::numeric OR protected_objects>(budget->'Capacity'->>'Objects')::numeric THEN RETURN NULL;END IF;
  cluster_id:=shape->>'Cluster';cluster:=clusters->cluster_id;
  cluster:=jsonb_build_object('ProtectedBytes',COALESCE((cluster->>'ProtectedBytes')::numeric,0)+bytes,
   'ProtectedObjects',COALESCE((cluster->>'ProtectedObjects')::numeric,0)+objects,'Slots',COALESCE((cluster->>'Slots')::bigint,0)+(slot->>'Workloads')::bigint);
  clusters:=jsonb_set(clusters,ARRAY[cluster_id],cluster,true);
  policies:=policies||jsonb_build_array(jsonb_build_object('Name',slot->>'Policy','UID',policy->'Resource'->>'UID','Generation',policy->'Resource'->'Generation',
   'Digest',policy->'Resource'->'SpecDigest','Scope',policy->'Scope','Budget',shape,'Slots',(slot->>'Workloads')::bigint));
 END LOOP;
 -- An assigned declaration omitted from the slot inventory cannot borrow
 -- someone else's protected commitment, even if it does not match this target.
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(snapshot->'Snapshot'->'Policies') p WHERE p->>'Pool'=pool_name AND NOT (p->'Resource'->>'Name'=ANY(names))) OR slots NOT BETWEEN 1 AND 640000 THEN RETURN NULL;END IF;
 bytes:=protected_bytes+(budget->'Safety'->>'Bytes')::numeric+(budget->'System'->>'Bytes')::numeric+(budget->'Burst'->>'Bytes')::numeric;
 objects:=protected_objects+(budget->'Safety'->>'Objects')::numeric+(budget->'System'->>'Objects')::numeric+(budget->'Burst'->>'Objects')::numeric;
 IF bytes>(budget->'Capacity'->>'Bytes')::numeric OR objects>(budget->'Capacity'->>'Objects')::numeric THEN RETURN NULL;END IF;
 SELECT jsonb_agg(jsonb_build_object('ClusterID',key,'ProtectedBytes',(value->>'ProtectedBytes')::bigint,'ProtectedObjects',(value->>'ProtectedObjects')::bigint,
  'ByteLimit',(value->>'ProtectedBytes')::bigint+(budget->'Burst'->>'Bytes')::bigint,'ObjectLimit',(value->>'ProtectedObjects')::bigint+(budget->'Burst'->>'Objects')::bigint,
  'AccountLimit',(value->>'Slots')::bigint) ORDER BY key COLLATE "C") INTO cluster_list FROM jsonb_each(clusters);
 RETURN jsonb_build_object('Format','capacity-pool/v1','Name',pool_name,'UID',pool->'Resource'->>'UID','Generation',pool->'Resource'->'Generation','Digest',pool->'Resource'->'SpecDigest',
  'StorageProfile',pool->>'StorageProfile','Capacity',budget->'Capacity','Safety',budget->'Safety','System',budget->'System','Burst',budget->'Burst',
  'Protected',jsonb_build_object('Bytes',protected_bytes::bigint,'Objects',protected_objects::bigint),'AccountLimit',slots,'NamespaceLimit',slots,'Policies',policies,'Clusters',cluster_list);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN NULL;
END $$;
-- +goose StatementEnd

