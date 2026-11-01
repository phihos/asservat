-- +goose Up
-- ADR-262: optional lowering-only policy resource observation; storage budgets unchanged.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_source_observation_valid(v jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE snap jsonb;refs jsonb;ref jsonb;versions jsonb;ver jsonb;uid text;ids text[]:='{}';names text[]:='{}';d bytea;sd bytea;resources jsonb;limits jsonb;
BEGIN
 IF NOT public.capacity_json_fields(v,ARRAY['Snapshot','Versions','Digest']) OR octet_length(v::text)>262144 THEN RETURN false;END IF;
 snap:=v->'Snapshot';versions:=v->'Versions';
 IF NOT public.capacity_json_fields(snap,ARRAY['ClusterID','ControlNamespace','PoolResourceVersion','PolicyResourceVersion','ObservedAt','FreshUntil','Pools','Policies']) OR
  NOT public.capacity_json_fields(snap->'ControlNamespace',ARRAY['Name','UID']) OR
  NOT public.capacity_json_text(snap->'ClusterID',36,36) OR
  NOT public.capacity_json_text(snap->'ControlNamespace'->'Name',1,63) OR NOT public.capacity_json_text(snap->'ControlNamespace'->'UID',1,64) OR
  NOT public.capacity_json_text(snap->'PoolResourceVersion',1,128) OR NOT public.capacity_json_text(snap->'PolicyResourceVersion',1,128) OR
  NOT public.capacity_json_text(snap->'ObservedAt',1,64) OR NOT public.capacity_json_text(snap->'FreshUntil',1,64) OR
  jsonb_typeof(snap->'Pools')<>'array' OR jsonb_typeof(snap->'Policies')<>'array' OR jsonb_typeof(versions)<>'array' OR
  jsonb_array_length(snap->'Pools')>16 OR jsonb_array_length(snap->'Policies')>64 OR
  jsonb_array_length(versions)<>jsonb_array_length(snap->'Pools')+jsonb_array_length(snap->'Policies') OR
  octet_length(snap->'ControlNamespace'->>'Name') NOT BETWEEN 1 AND 63 OR octet_length(snap->'ControlNamespace'->>'UID') NOT BETWEEN 1 AND 64 OR
  octet_length(snap->>'PoolResourceVersion') NOT BETWEEN 1 AND 128 OR octet_length(snap->>'PolicyResourceVersion') NOT BETWEEN 1 AND 128 OR
  (snap->>'FreshUntil')::timestamptz<=(snap->>'ObservedAt')::timestamptz OR (snap->>'FreshUntil')::timestamptz>(snap->>'ObservedAt')::timestamptz+interval '5 seconds' OR
  NOT isfinite((snap->>'ObservedAt')::timestamptz) OR NOT isfinite((snap->>'FreshUntil')::timestamptz) THEN RETURN false;END IF;
 PERFORM (snap->>'ClusterID')::uuid;
 d:=public.connector_digest(v->'Digest');IF d IS NULL OR d=decode(repeat('00',32),'hex') THEN RETURN false;END IF;
 -- Decoding failures are explicit null scope/budget facts. They are preserved
 -- in a complete source, then excluded only by independently understood scope.
 FOR ref IN SELECT value FROM jsonb_array_elements(snap->'Pools') LOOP
  IF NOT public.capacity_json_fields(ref,ARRAY['Resource','StorageProfile','Assurance','Budget']) OR ref->'Resource'->>'Kind' IS DISTINCT FROM 'EvidenceStoragePool' OR
   NOT public.capacity_json_text(ref->'StorageProfile',0,63) OR NOT public.capacity_json_text(ref->'Assurance',0,32) THEN RETURN false;END IF;
  IF ref->'Budget'<>'null'::jsonb AND (NOT public.capacity_decoded_pool_valid(ref->'Budget',ref->'Resource'->>'Name') OR
   NOT public.capacity_json_text(ref->'StorageProfile',1,63) OR ref->>'Assurance' NOT IN('qualifiedReservedBackend','bestEffort') OR
   public.connector_digest(ref->'Resource'->'SpecDigest')=decode(repeat('00',32),'hex')) THEN RETURN false;END IF;
 END LOOP;
 FOR ref IN SELECT value FROM jsonb_array_elements(snap->'Policies') LOOP
  IF NOT public.capacity_json_fields(ref-'SourceResources',ARRAY['Resource','Scope','Pool','Budget']) OR ref->'Resource'->>'Kind' IS DISTINCT FROM 'EvidenceBudgetPolicy' OR
   NOT public.capacity_json_text(ref->'Pool',0,63) THEN RETURN false;END IF;
  IF ref->'Scope'<>'null'::jsonb AND NOT public.capacity_decoded_scope_valid(ref->'Scope') THEN RETURN false;END IF;
  IF ref->'Budget'<>'null'::jsonb AND (NOT public.capacity_decoded_policy_valid(ref->'Budget',ref->'Resource'->>'Name',ref->>'Pool',ref->'Scope') OR
   public.connector_digest(ref->'Resource'->'SpecDigest')=decode(repeat('00',32),'hex')) THEN RETURN false;END IF;

  IF ref ? 'SourceResources' THEN
   resources:=ref->'SourceResources';
   IF NOT public.capacity_json_fields(resources,ARRAY['Node','Workload']) OR
    NOT public.capacity_json_fields((resources->'Node')-ARRAY['maxActiveSources','inputBytesPerSecond','inputBurstBytes'],ARRAY['RingBytes','FrozenBytes','UploadBytesPerSecond','UploadBurstBytes']) OR
    NOT public.capacity_json_fields((resources->'Workload')-ARRAY['maxActiveSources','inputBytesPerSecond','inputBurstBytes'],ARRAY[]::text[]) OR
    NOT public.capacity_json_integer(resources->'Node'->'RingBytes',0,4294967296) OR
    NOT public.capacity_json_integer(resources->'Node'->'FrozenBytes',0,4294967296) OR
    NOT public.capacity_json_integer(resources->'Node'->'UploadBytesPerSecond',0,10737418240) OR
    NOT public.capacity_json_integer(resources->'Node'->'UploadBurstBytes',0,10737418240) THEN RETURN false;END IF;
   FOR limits IN SELECT value FROM jsonb_each(resources) LOOP
    IF NOT public.capacity_json_integer(COALESCE(limits->'maxActiveSources','0'::jsonb),0,1024) OR
     NOT public.capacity_json_integer(COALESCE(limits->'inputBytesPerSecond','0'::jsonb),0,10737418240) OR
     NOT public.capacity_json_integer(COALESCE(limits->'inputBurstBytes','0'::jsonb),0,10737418240) THEN RETURN false;END IF;
   END LOOP;
  END IF;
 END LOOP;
 refs:=(snap->'Pools')||(snap->'Policies');
 FOR ref IN SELECT value->'Resource' FROM jsonb_array_elements(refs) LOOP
  IF NOT public.capacity_json_fields(ref,ARRAY['ClusterID','Namespace','NamespaceUID','Kind','Name','UID','ResourceVersion','Generation','SpecDigest','Deleting']) OR
   NOT public.capacity_json_text(ref->'Name',1,63) OR NOT public.capacity_json_text(ref->'UID',1,64) OR NOT public.capacity_json_text(ref->'ResourceVersion',1,128) OR
   NOT public.capacity_json_integer(ref->'Generation',1,2147483647) OR
   ref->>'ClusterID' IS DISTINCT FROM snap->>'ClusterID' OR ref->>'Namespace' IS DISTINCT FROM snap->'ControlNamespace'->>'Name' OR ref->>'NamespaceUID' IS DISTINCT FROM snap->'ControlNamespace'->>'UID' OR
   octet_length(ref->>'Name') NOT BETWEEN 1 AND 63 OR octet_length(ref->>'UID') NOT BETWEEN 1 AND 64 OR octet_length(ref->>'ResourceVersion') NOT BETWEEN 1 AND 128 OR
   (ref->>'Generation')::bigint NOT BETWEEN 1 AND 2147483647 OR jsonb_typeof(ref->'Deleting')<>'boolean' THEN RETURN false;END IF;
  uid:=ref->>'UID';
  IF uid=ANY(ids) OR ((ref->>'Kind')||'/'||(ref->>'Name'))=ANY(names) THEN RETURN false;END IF;
  ids:=array_append(ids,uid);names:=array_append(names,(ref->>'Kind')||'/'||(ref->>'Name'));
  IF (SELECT count(*) FROM jsonb_array_elements(versions) p WHERE p->>'UID'=uid)<>1 THEN RETURN false;END IF;
  SELECT value INTO STRICT ver FROM jsonb_array_elements(versions) WHERE value->>'UID'=uid;
  IF NOT public.capacity_json_fields(ver,ARRAY['Kind','Name','UID','Generation','Deleting','Spec']) OR
   ROW(ver->>'Kind',ver->>'Name',ver->>'UID',ver->'Generation',ver->'Deleting') IS DISTINCT FROM ROW(ref->>'Kind',ref->>'Name',ref->>'UID',ref->'Generation',ref->'Deleting') THEN RETURN false;END IF;
  d:=public.connector_digest(ver->'Spec');sd:=public.connector_digest(ref->'SpecDigest');
  IF d IS NULL OR sd IS NULL OR d=decode(repeat('00',32),'hex') OR (sd<>decode(repeat('00',32),'hex') AND sd<>d) THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

CREATE OR REPLACE FUNCTION capacity_source_monotonic(old_value jsonb,new_value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE old_item jsonb;new_item jsonb;old_decoded jsonb;new_decoded jsonb;new_valid boolean;
BEGIN
 IF old_value IS NULL THEN RETURN true;END IF;
 FOR old_item IN SELECT value FROM jsonb_array_elements(old_value->'Versions') LOOP
  SELECT value INTO new_item FROM jsonb_array_elements(new_value->'Versions') WHERE value->>'UID'=old_item->>'UID';
  IF FOUND AND (ROW(new_item->>'Kind',new_item->>'Name') IS DISTINCT FROM ROW(old_item->>'Kind',old_item->>'Name') OR
   (new_item->>'Generation')::bigint<(old_item->>'Generation')::bigint OR
   ((new_item->>'Generation')::bigint=(old_item->>'Generation')::bigint AND new_item->'Spec' IS DISTINCT FROM old_item->'Spec') OR
   ((old_item->>'Deleting')::boolean AND NOT (new_item->>'Deleting')::boolean)) THEN RETURN false;END IF;
  IF new_item IS NOT NULL AND new_item->'Generation'=old_item->'Generation' THEN
   -- An unchanged canonical spec cannot silently acquire different decoded
   -- quantities/scope. Only an absent-to-valid lowering resource projection may enrich the
   -- same original spec once; existing decoded values may never change.
   SELECT value-'Resource' INTO STRICT old_decoded FROM jsonb_array_elements((old_value->'Snapshot'->'Pools')||(old_value->'Snapshot'->'Policies')) WHERE value->'Resource'->>'UID'=old_item->>'UID';
   SELECT value-'Resource' INTO STRICT new_decoded FROM jsonb_array_elements((new_value->'Snapshot'->'Pools')||(new_value->'Snapshot'->'Policies')) WHERE value->'Resource'->>'UID'=old_item->>'UID';
   IF new_decoded IS DISTINCT FROM old_decoded THEN
    IF NOT COALESCE(old_item->>'Kind'='EvidenceBudgetPolicy' AND
     public.capacity_json_fields(old_decoded,ARRAY['Scope','Pool','Budget']) AND
     public.capacity_decoded_policy_valid(old_decoded->'Budget',old_item->>'Name',old_decoded->>'Pool',old_decoded->'Scope') AND
     NOT (old_decoded ? 'SourceResources') AND new_decoded ? 'SourceResources' AND
     (new_decoded-'SourceResources')=old_decoded,false) THEN RETURN false;END IF;
    -- One full validation only, even for a maximum-size projection cohort.
    -- Ordinary unchanged observations never enter this branch.
    IF new_valid IS NULL THEN new_valid:=public.capacity_source_observation_valid(new_value);END IF;
    IF NOT COALESCE(new_valid,false) THEN RETURN false;END IF;
   END IF;
  END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Restore exact prior functions; do not rewrite accepted snapshots or spend.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_source_observation_valid(v jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE snap jsonb;refs jsonb;ref jsonb;versions jsonb;ver jsonb;uid text;ids text[]:='{}';names text[]:='{}';d bytea;sd bytea;
BEGIN
 IF NOT public.capacity_json_fields(v,ARRAY['Snapshot','Versions','Digest']) OR octet_length(v::text)>262144 THEN RETURN false;END IF;
 snap:=v->'Snapshot';versions:=v->'Versions';
 IF NOT public.capacity_json_fields(snap,ARRAY['ClusterID','ControlNamespace','PoolResourceVersion','PolicyResourceVersion','ObservedAt','FreshUntil','Pools','Policies']) OR
  NOT public.capacity_json_fields(snap->'ControlNamespace',ARRAY['Name','UID']) OR
  NOT public.capacity_json_text(snap->'ClusterID',36,36) OR
  NOT public.capacity_json_text(snap->'ControlNamespace'->'Name',1,63) OR NOT public.capacity_json_text(snap->'ControlNamespace'->'UID',1,64) OR
  NOT public.capacity_json_text(snap->'PoolResourceVersion',1,128) OR NOT public.capacity_json_text(snap->'PolicyResourceVersion',1,128) OR
  NOT public.capacity_json_text(snap->'ObservedAt',1,64) OR NOT public.capacity_json_text(snap->'FreshUntil',1,64) OR
  jsonb_typeof(snap->'Pools')<>'array' OR jsonb_typeof(snap->'Policies')<>'array' OR jsonb_typeof(versions)<>'array' OR
  jsonb_array_length(snap->'Pools')>16 OR jsonb_array_length(snap->'Policies')>64 OR
  jsonb_array_length(versions)<>jsonb_array_length(snap->'Pools')+jsonb_array_length(snap->'Policies') OR
  octet_length(snap->'ControlNamespace'->>'Name') NOT BETWEEN 1 AND 63 OR octet_length(snap->'ControlNamespace'->>'UID') NOT BETWEEN 1 AND 64 OR
  octet_length(snap->>'PoolResourceVersion') NOT BETWEEN 1 AND 128 OR octet_length(snap->>'PolicyResourceVersion') NOT BETWEEN 1 AND 128 OR
  (snap->>'FreshUntil')::timestamptz<=(snap->>'ObservedAt')::timestamptz OR (snap->>'FreshUntil')::timestamptz>(snap->>'ObservedAt')::timestamptz+interval '5 seconds' OR
  NOT isfinite((snap->>'ObservedAt')::timestamptz) OR NOT isfinite((snap->>'FreshUntil')::timestamptz) THEN RETURN false;END IF;
 PERFORM (snap->>'ClusterID')::uuid;
 d:=public.connector_digest(v->'Digest');IF d IS NULL OR d=decode(repeat('00',32),'hex') THEN RETURN false;END IF;
 -- Decoding failures are explicit null scope/budget facts. They are preserved
 -- in a complete source, then excluded only by independently understood scope.
 FOR ref IN SELECT value FROM jsonb_array_elements(snap->'Pools') LOOP
  IF NOT public.capacity_json_fields(ref,ARRAY['Resource','StorageProfile','Assurance','Budget']) OR ref->'Resource'->>'Kind' IS DISTINCT FROM 'EvidenceStoragePool' OR
   NOT public.capacity_json_text(ref->'StorageProfile',0,63) OR NOT public.capacity_json_text(ref->'Assurance',0,32) THEN RETURN false;END IF;
  IF ref->'Budget'<>'null'::jsonb AND (NOT public.capacity_decoded_pool_valid(ref->'Budget',ref->'Resource'->>'Name') OR
   NOT public.capacity_json_text(ref->'StorageProfile',1,63) OR ref->>'Assurance' NOT IN('qualifiedReservedBackend','bestEffort') OR
   public.connector_digest(ref->'Resource'->'SpecDigest')=decode(repeat('00',32),'hex')) THEN RETURN false;END IF;
 END LOOP;
 FOR ref IN SELECT value FROM jsonb_array_elements(snap->'Policies') LOOP
  IF NOT public.capacity_json_fields(ref,ARRAY['Resource','Scope','Pool','Budget']) OR ref->'Resource'->>'Kind' IS DISTINCT FROM 'EvidenceBudgetPolicy' OR
   NOT public.capacity_json_text(ref->'Pool',0,63) THEN RETURN false;END IF;
  IF ref->'Scope'<>'null'::jsonb AND NOT public.capacity_decoded_scope_valid(ref->'Scope') THEN RETURN false;END IF;
  IF ref->'Budget'<>'null'::jsonb AND (NOT public.capacity_decoded_policy_valid(ref->'Budget',ref->'Resource'->>'Name',ref->>'Pool',ref->'Scope') OR
   public.connector_digest(ref->'Resource'->'SpecDigest')=decode(repeat('00',32),'hex')) THEN RETURN false;END IF;
 END LOOP;
 refs:=(snap->'Pools')||(snap->'Policies');
 FOR ref IN SELECT value->'Resource' FROM jsonb_array_elements(refs) LOOP
  IF NOT public.capacity_json_fields(ref,ARRAY['ClusterID','Namespace','NamespaceUID','Kind','Name','UID','ResourceVersion','Generation','SpecDigest','Deleting']) OR
   NOT public.capacity_json_text(ref->'Name',1,63) OR NOT public.capacity_json_text(ref->'UID',1,64) OR NOT public.capacity_json_text(ref->'ResourceVersion',1,128) OR
   NOT public.capacity_json_integer(ref->'Generation',1,2147483647) OR
   ref->>'ClusterID' IS DISTINCT FROM snap->>'ClusterID' OR ref->>'Namespace' IS DISTINCT FROM snap->'ControlNamespace'->>'Name' OR ref->>'NamespaceUID' IS DISTINCT FROM snap->'ControlNamespace'->>'UID' OR
   octet_length(ref->>'Name') NOT BETWEEN 1 AND 63 OR octet_length(ref->>'UID') NOT BETWEEN 1 AND 64 OR octet_length(ref->>'ResourceVersion') NOT BETWEEN 1 AND 128 OR
   (ref->>'Generation')::bigint NOT BETWEEN 1 AND 2147483647 OR jsonb_typeof(ref->'Deleting')<>'boolean' THEN RETURN false;END IF;
  uid:=ref->>'UID';
  IF uid=ANY(ids) OR ((ref->>'Kind')||'/'||(ref->>'Name'))=ANY(names) THEN RETURN false;END IF;
  ids:=array_append(ids,uid);names:=array_append(names,(ref->>'Kind')||'/'||(ref->>'Name'));
  IF (SELECT count(*) FROM jsonb_array_elements(versions) p WHERE p->>'UID'=uid)<>1 THEN RETURN false;END IF;
  SELECT value INTO STRICT ver FROM jsonb_array_elements(versions) WHERE value->>'UID'=uid;
  IF NOT public.capacity_json_fields(ver,ARRAY['Kind','Name','UID','Generation','Deleting','Spec']) OR
   ROW(ver->>'Kind',ver->>'Name',ver->>'UID',ver->'Generation',ver->'Deleting') IS DISTINCT FROM ROW(ref->>'Kind',ref->>'Name',ref->>'UID',ref->'Generation',ref->'Deleting') THEN RETURN false;END IF;
  d:=public.connector_digest(ver->'Spec');sd:=public.connector_digest(ref->'SpecDigest');
  IF d IS NULL OR sd IS NULL OR d=decode(repeat('00',32),'hex') OR (sd<>decode(repeat('00',32),'hex') AND sd<>d) THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

CREATE OR REPLACE FUNCTION capacity_source_monotonic(old_value jsonb,new_value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE old_item jsonb;new_item jsonb;old_decoded jsonb;new_decoded jsonb;
BEGIN
 IF old_value IS NULL THEN RETURN true;END IF;
 FOR old_item IN SELECT value FROM jsonb_array_elements(old_value->'Versions') LOOP
  SELECT value INTO new_item FROM jsonb_array_elements(new_value->'Versions') WHERE value->>'UID'=old_item->>'UID';
  IF FOUND AND (ROW(new_item->>'Kind',new_item->>'Name') IS DISTINCT FROM ROW(old_item->>'Kind',old_item->>'Name') OR
   (new_item->>'Generation')::bigint<(old_item->>'Generation')::bigint OR
   ((new_item->>'Generation')::bigint=(old_item->>'Generation')::bigint AND new_item->'Spec' IS DISTINCT FROM old_item->'Spec') OR
   ((old_item->>'Deleting')::boolean AND NOT (new_item->>'Deleting')::boolean)) THEN RETURN false;END IF;
  IF new_item IS NOT NULL AND new_item->'Generation'=old_item->'Generation' THEN
   -- An unchanged canonical spec cannot silently acquire different decoded
   -- quantities/scope. Parser/profile changes need an explicit qualified source
   -- change; neither status progress nor a refreshed root observation is one.
   SELECT value-'Resource' INTO STRICT old_decoded FROM jsonb_array_elements((old_value->'Snapshot'->'Pools')||(old_value->'Snapshot'->'Policies')) WHERE value->'Resource'->>'UID'=old_item->>'UID';
   SELECT value-'Resource' INTO STRICT new_decoded FROM jsonb_array_elements((new_value->'Snapshot'->'Pools')||(new_value->'Snapshot'->'Policies')) WHERE value->'Resource'->>'UID'=old_item->>'UID';
   IF new_decoded IS DISTINCT FROM old_decoded THEN RETURN false;END IF;
  END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd
