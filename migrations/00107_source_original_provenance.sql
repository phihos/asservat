-- +goose Up
-- Original acquisition provenance, never a refreshed audience or Pod selection.
-- Existing rows remain NULL and cannot authorize Save.
ALTER TABLE policy_recording_source ADD COLUMN source_audience_json jsonb;
ALTER TABLE policy_recording_source ADD COLUMN source_audience_digest bytea;
ALTER TABLE policy_recording_source ADD COLUMN source_target_json jsonb;
ALTER TABLE policy_recording_source ADD CONSTRAINT policy_source_original_provenance_shape CHECK (
 (source_audience_json IS NULL AND source_audience_digest IS NULL AND source_target_json IS NULL) OR
 (source_audience_json IS NOT NULL AND jsonb_typeof(source_audience_json)='array' AND jsonb_array_length(source_audience_json) BETWEEN 1 AND 32 AND octet_length(source_audience_json::text)<=98304 AND
 source_audience_digest IS NOT NULL AND octet_length(source_audience_digest)=32 AND source_audience_digest<>decode(repeat('00',32),'hex') AND
 source_target_json IS NOT NULL AND jsonb_typeof(source_target_json)='object' AND octet_length(source_target_json::text) BETWEEN 2 AND 8192));
-- +goose StatementBegin
CREATE FUNCTION guard_policy_source_original_provenance() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.policy_recording_source'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION 'invalid original source provenance operation' USING ERRCODE='23514';
 END IF;
 -- RootMetadataQualification and SQL54 require at least 128KiB per record.
 -- Keep 16KiB for page/index overhead; this reuses the existing source charge.
 IF NEW.source_audience_json IS NULL OR NEW.source_audience_digest IS NULL OR NEW.source_target_json IS NULL OR
  public.connector_digest(NEW.binding_json->'AudienceDigest') IS DISTINCT FROM NEW.source_audience_digest OR
  NEW.source_target_json->>'SourceID' IS DISTINCT FROM NEW.id::text OR NEW.source_target_json->>'Fence' IS DISTINCT FROM NEW.fence::text OR
  NEW.source_target_json#>>'{Request,ClusterID}' IS DISTINCT FROM NEW.cluster_id::text OR
  NEW.source_target_json#>>'{Request,Namespace,UID}' IS DISTINCT FROM NEW.namespace_uid OR
  NEW.source_target_json#>>'{Request,Workload,UID}' IS DISTINCT FROM NEW.workload_uid OR
  NEW.source_target_json#>>'{Request,PodUID}' IS DISTINCT FROM NEW.pod_uid OR pg_column_size(NEW)>114688 THEN
  RAISE EXCEPTION 'original source provenance or backed record size unavailable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_policy_source_original_provenance() FROM PUBLIC;
CREATE TRIGGER policy_source_original_provenance BEFORE INSERT ON policy_recording_source FOR EACH ROW EXECUTE FUNCTION guard_policy_source_original_provenance();
-- The existing source UPDATE guard compares every field except the three
-- mutable credit/terminal fields; it also prevents NULL->current backfills.

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM policy_recording_source WHERE source_audience_json IS NOT NULL OR source_audience_digest IS NOT NULL OR source_target_json IS NOT NULL) THEN
  RAISE EXCEPTION 'retained original source provenance prevents downgrade' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER policy_source_original_provenance ON policy_recording_source;
DROP FUNCTION guard_policy_source_original_provenance();
ALTER TABLE policy_recording_source DROP CONSTRAINT policy_source_original_provenance_shape;
ALTER TABLE policy_recording_source DROP COLUMN source_audience_json;
ALTER TABLE policy_recording_source DROP COLUMN source_audience_digest;
ALTER TABLE policy_recording_source DROP COLUMN source_target_json;
