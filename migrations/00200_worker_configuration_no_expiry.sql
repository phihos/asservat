-- +goose Up
-- An accepted worker configuration revision stays current until a later
-- observation replaces it (AGENTS.md: cached state remains valid until
-- replaced). The five-second head expiry forced a once-a-second refresh loop
-- and failed downloads whenever that loop stalled. Drop it.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_shared_profile_current(r uuid,p jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.context_query_backing;t public.fleet_current_trust;h public.download_worker_configuration;v public.download_worker_configuration_revision;path jsonb:=p->'Path';profile jsonb;snapshot jsonb;n timestamptz;
BEGIN
 SELECT * INTO STRICT s FROM public.context_query_backing WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 SELECT * INTO STRICT h FROM public.download_worker_configuration WHERE installation_id=s.installation_id AND cluster_id=(path->>'AcquisitionClusterID')::uuid AND source_uid=(path->'WorkerConfiguration'->>'UID')::uuid FOR SHARE;
 SELECT * INTO STRICT v FROM public.download_worker_configuration_revision WHERE installation_id=h.installation_id AND cluster_id=h.cluster_id AND source_uid=h.source_uid AND generation=h.generation;
 snapshot:=convert_from(v.snapshot_json,'UTF8')::jsonb;profile:=snapshot->'Profile';n:=clock_timestamp();
 RETURN COALESCE(NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=n AND n<t.fresh_until AND
 NOT (snapshot->>'Suspended')::boolean AND snapshot->>'RecoveryEpoch'=t.issuer_epoch::text AND
 v.audit_receipt_json IS NOT NULL AND profile->'Configuration'=path->'WorkerConfiguration' AND profile->>'InstallationID'=s.installation_id::text AND profile->>'ClusterID'=path->>'AcquisitionClusterID' AND
 profile->>'StoreCredentialSecret'<>'' AND (profile->>'CPUMillis')::numeric=(p->'Worker'->>'CPUMilli')::numeric AND (profile->>'MemoryBytes')::numeric=(p->'Worker'->>'MemoryBytes')::numeric AND
 (p->'Worker'->>'EphemeralStorageBytes')::numeric=4194304 AND (p->'Worker'->>'Runtime')::numeric<=(profile->>'MaxRuntime')::numeric AND
 path->>'Purpose'='context-projection/v1' AND path->>'ConnectorClusterID'=path->>'AcquisitionClusterID' AND clock_timestamp()<t.fresh_until,false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd
ALTER TABLE download_worker_configuration DROP COLUMN fresh_until;
