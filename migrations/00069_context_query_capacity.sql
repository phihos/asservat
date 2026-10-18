-- +goose Up
-- Original-install-only ADR-206 capacity extension. Existing roots without the
-- exact optional installer qualification remain unavailable. No role grant,
-- bootstrap update, refill, refund or runtime enablement is performed here.
-- The original base graph remains exact; the additive residual reservation is
-- a separate immutable charge. Every query consumer must lock/check this anchor.

CREATE TABLE context_query_capacity (
 root_id uuid PRIMARY KEY REFERENCES capacity_source(root_id),
 acceptance_id uuid UNIQUE NOT NULL,
 capacity_id uuid UNIQUE NOT NULL,
 plan jsonb NOT NULL CHECK(jsonb_typeof(plan)='object' AND octet_length(plan::text)<=131072),
 source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 issuer_epoch uuid NOT NULL,
 postmaster_at timestamptz NOT NULL,
 database_oid oid NOT NULL,
 accepted_at timestamptz NOT NULL CHECK(isfinite(accepted_at)),
 observations bigint NOT NULL DEFAULT 0 CHECK(observations BETWEEN 0 AND 1000001),
 observation_id uuid, observation_ordinal bigint, observation_started_at timestamptz, observation_until timestamptz,
 observation_accepted boolean NOT NULL DEFAULT false, observation_completed boolean NOT NULL DEFAULT false,
 negative_observed_at timestamptz CHECK (negative_observed_at IS NULL OR isfinite(negative_observed_at)),
 CHECK ((observation_id IS NULL AND observation_ordinal IS NULL AND observation_started_at IS NULL AND observation_until IS NULL AND NOT observation_accepted AND NOT observation_completed) OR
  (observation_id IS NOT NULL AND observation_ordinal IS NOT NULL AND observation_started_at IS NOT NULL AND observation_until IS NOT NULL AND observation_ordinal BETWEEN 1 AND observations AND isfinite(observation_started_at) AND isfinite(observation_until) AND
   observation_started_at<observation_until AND observation_until<=observation_started_at+interval '5 seconds'))
);
REVOKE ALL ON context_query_capacity FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_qualification_valid(q jsonb,base jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE k text;j text;p jsonb:=q->'Profile';h jsonb:=q->'History';n jsonb:=q->'Native';v jsonb;client jsonb;item jsonb;seen text[]:='{}';role_name text;need numeric;calls numeric;controls numeric;extra numeric;total numeric;
BEGIN
 IF NOT public.capacity_json_fields(q,ARRAY['Format','CapacityID','Profile','Native','History','Envelope','RootQueries','PrincipalQueries','PrincipalAccounts','WorkloadAccounts','WorkloadQueries','SourceTransitionLimit','Admission','PolicyRevision','PermittedRegions','Clients']) OR
  q->>'Format' IS DISTINCT FROM 'protected-context-query-qualification/v1' OR NOT public.capacity_json_uuid(q->'CapacityID') OR
  NOT public.context_query_cost_valid(p) OR NOT public.capacity_json_integer(q->'Admission',1000000000,86400000000000) OR (q->>'Admission')::numeric>(base->>'AdmissionSeconds')::numeric*1000000000 OR
  NOT public.capacity_json_fields(n,ARRAY['Revision','Format','RunID','ReportDigest','SourceTree','ProfileDigest','Worker','Hub','KeyService','Provider','Combined']) OR
  n->>'Format' IS DISTINCT FROM 'context-query-native-qualification/v1' OR n->'Revision' IS DISTINCT FROM p->'Qualification' OR NOT public.capacity_json_text(n->'RunID',1,128) OR
  NOT public.capacity_json_fields(h,ARRAY['Layout','Revision','FixedBytes','PrincipalBytes','AllocationBytes','RowBytes','FixedQueryRows','InvocationRows','ControlRows','TransitionWALBytes','BackupCopies','WALCopies','AuditCipherBytes','AuthenticationPerCall','ProviderPerCall','AuthenticationPerControl','ProviderPerControl','AuthenticationPerSource','ProviderPerSource','BackupHorizon','RetirementCleanup']) OR
  h->>'Layout' IS DISTINCT FROM 'context-query-worker-history/v1' THEN RETURN false;END IF;
 IF NOT public.capacity_json_fields(p,ARRAY['ID','Source','Qualification','Path','Lifetime','Worker','Cost','PollLimit','ControlTransitionLimit']) OR
  NOT public.capacity_json_uuid(p->'ID') OR NOT public.capacity_revision_valid(p->'Source') OR NOT public.capacity_revision_valid(p->'Qualification') OR
  NOT public.capacity_revision_valid(q->'PolicyRevision') OR NOT public.capacity_revision_valid(h->'Revision') OR
  NOT public.capacity_json_fields(p->'Path',ARRAY['Purpose','ID','TargetClusterID','StoreID','StorageRegion','AcquisitionClusterID','AcquisitionRegion','ConnectorClusterID','ConnectorRegion','HubClusterID','HubRegion','WorkerConfiguration','HubConfiguration']) OR
  NOT public.capacity_revision_valid(p->'Path'->'WorkerConfiguration') OR NOT public.capacity_revision_valid(p->'Path'->'HubConfiguration') OR
  NOT public.capacity_json_uuid(p->'Path'->'WorkerConfiguration'->'UID') OR NOT public.capacity_json_uuid(p->'Path'->'HubConfiguration'->'UID') OR
  p->'Path'->'ConnectorClusterID' IS DISTINCT FROM p->'Path'->'AcquisitionClusterID' OR
  NOT public.capacity_json_fields(p->'Worker',ARRAY['CPUMilli','MemoryBytes','EphemeralStorageBytes','WorkerTransientBytes','HubTransientBytes','ProviderConcurrency','AuthenticationConcurrency','Runtime','CredentialLifetime','ProviderEffectLifetime','Cleanup']) OR
  NOT public.capacity_json_fields(p->'Cost',ARRAY['Workers','ReadBatches','ReadBytes','StructuredBytes','WireBytes','UnwrapAttempts','ProviderRequests','AuthenticationRequests','SigningAttempts','AuditObjects','SQLRows','SQLBytes','WALBytes','BackupBytes']) OR
  NOT public.capacity_json_fields(q->'Envelope',ARRAY['Workers','ReadBatches','ReadBytes','StructuredBytes','WireBytes','UnwrapAttempts','ProviderRequests','AuthenticationRequests','SigningAttempts','AuditObjects','SQLRows','SQLBytes','WALBytes','BackupBytes','CPUMilli','MemoryBytes','EphemeralStorageBytes','WorkerTransientBytes','HubTransientBytes','ProviderConcurrency','AuthenticationConcurrency']) OR
  NOT public.capacity_json_fields(n->'Combined',ARRAY['CPUMilli','MemoryBytes','EphemeralStorageBytes','WorkerTransientBytes','HubTransientBytes','ProviderConcurrency','AuthenticationConcurrency']) THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['ID','TargetClusterID','StoreID','AcquisitionClusterID','HubClusterID'] LOOP
  IF NOT public.capacity_json_uuid(p->'Path'->k) THEN RETURN false;END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['StorageRegion','AcquisitionRegion','ConnectorRegion','HubRegion'] LOOP
  IF NOT public.capacity_json_text(p->'Path'->k,1,63) OR p->'Path'->>k ~ '[[:cntrl:]]' THEN RETURN false;END IF;
 END LOOP;
 IF jsonb_typeof(q->'PermittedRegions') IS DISTINCT FROM 'array' OR jsonb_array_length(q->'PermittedRegions')>64 OR jsonb_typeof(q->'Clients') IS DISTINCT FROM 'array' OR jsonb_array_length(q->'Clients')>64 THEN RETURN false;END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(q->'PermittedRegions') LOOP
  IF NOT public.capacity_json_text(item,1,63) OR item#>>'{}' ~ '[[:cntrl:]]' OR item#>>'{}'=ANY(seen) THEN RETURN false;END IF;
  seen:=array_append(seen,item#>>'{}');
 END LOOP;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(q->'Clients') c GROUP BY c->>'Issuer',c->>'ID' HAVING count(*)>1) THEN RETURN false;END IF;
 FOR client IN SELECT value FROM jsonb_array_elements(q->'Clients') LOOP
  IF NOT public.capacity_json_fields(client,ARRAY['Issuer','ID','Kind','Purposes']) OR NOT public.capacity_json_text(client->'Issuer',1,2048) OR NOT public.capacity_json_text(client->'ID',1,256) OR client->>'Issuer' ~ '[[:cntrl:]]' OR client->>'ID' ~ '[[:cntrl:]]' OR
   NOT COALESCE(client->>'Kind' IN ('human','workload'),false) OR jsonb_typeof(client->'Purposes') IS DISTINCT FROM 'array' OR jsonb_array_length(client->'Purposes')>32 THEN RETURN false;END IF;
  seen:='{}';
  FOR item IN SELECT value FROM jsonb_array_elements(client->'Purposes') LOOP
   IF NOT public.capacity_json_text(item,1,128) OR item#>>'{}' ~ '[[:cntrl:]]' OR item#>>'{}'=ANY(seen) THEN RETURN false;END IF;
   seen:=array_append(seen,item#>>'{}');
  END LOOP;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['Runtime','CredentialLifetime','ProviderEffectLifetime','Cleanup'] LOOP
  IF NOT public.capacity_json_integer(p->'Worker'->k,1000,31536000000000000) OR mod((p->'Worker'->>k)::numeric,1000)<>0 THEN RETURN false;END IF;
 END LOOP;
 IF (p->'Worker'->>'Runtime')::numeric<(p->>'Lifetime')::numeric OR (p->'Worker'->>'WorkerTransientBytes')::numeric>(p->'Worker'->>'MemoryBytes')::numeric THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['ReportDigest','SourceTree','ProfileDigest'] LOOP IF NOT public.capacity_json_digest(n->k) THEN RETURN false;END IF;END LOOP;
 FOREACH k IN ARRAY ARRAY['RootQueries','PrincipalQueries','PrincipalAccounts','WorkloadAccounts','WorkloadQueries','SourceTransitionLimit'] LOOP IF NOT public.capacity_json_integer(q->k,1,1000000) THEN RETURN false;END IF;END LOOP;
 IF (q->>'PrincipalQueries')::bigint>(q->>'RootQueries')::bigint OR (q->>'PrincipalAccounts')::bigint>(q->>'RootQueries')::bigint OR
  (q->>'WorkloadAccounts')::bigint>(base->>'Accounts')::bigint OR (q->>'WorkloadAccounts')::numeric*(q->>'WorkloadQueries')::numeric>(q->>'RootQueries')::numeric THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['Worker','Hub','KeyService','Provider'] LOOP
  v:=n->k;role_name:=CASE k WHEN 'Worker' THEN 'query-worker' WHEN 'Hub' THEN 'hub' WHEN 'KeyService' THEN 'query-key-service' ELSE 'query-provider' END;
  IF NOT public.capacity_json_fields(v,ARRAY['Role','ClusterID','NamespaceUID','WorkloadUID','Image','Configuration','ProtectionDigest','EnforcedLimitsDigest','Limits']) OR v->>'Role' IS DISTINCT FROM role_name OR
   NOT public.capacity_json_uuid(v->'ClusterID') OR NOT public.capacity_json_text(v->'NamespaceUID',1,64) OR NOT public.capacity_json_text(v->'WorkloadUID',1,64) OR
   NOT public.capacity_json_text(v->'Image',73,512) OR v->>'Image' !~ '@sha256:[0-9a-f]{64}$' OR
   NOT public.capacity_json_digest(v->'ProtectionDigest') OR NOT public.capacity_json_digest(v->'EnforcedLimitsDigest') OR
   NOT public.capacity_json_fields(v->'Configuration',ARRAY['UID','Generation','Digest']) OR NOT public.capacity_json_text(v->'Configuration'->'UID',1,64) OR
   NOT public.capacity_json_integer(v->'Configuration'->'Generation',1,2147483647) OR NOT public.capacity_json_digest(v->'Configuration'->'Digest') OR NOT public.capacity_json_fields(v->'Limits',ARRAY['CPUMilli','MemoryBytes','EphemeralStorageBytes','WorkerTransientBytes','HubTransientBytes','ProviderConcurrency','AuthenticationConcurrency']) THEN RETURN false;END IF;
  FOREACH j IN ARRAY ARRAY['CPUMilli','MemoryBytes','EphemeralStorageBytes','WorkerTransientBytes','HubTransientBytes','ProviderConcurrency','AuthenticationConcurrency'] LOOP
   IF NOT public.capacity_json_integer(v->'Limits'->j,1,1152921504606846976) THEN RETURN false;END IF;
  END LOOP;
  IF (v->'Limits'->>'WorkerTransientBytes')::numeric+(v->'Limits'->>'HubTransientBytes')::numeric>(v->'Limits'->>'MemoryBytes')::numeric OR (v->'Limits'->>'AuthenticationConcurrency')::numeric<(p->'Worker'->>'AuthenticationConcurrency')::numeric*(q->>'RootQueries')::numeric THEN RETURN false;END IF;
 END LOOP;
 -- This layout reserves distinct complete deployments. Sharing a physical
 -- deployment requires an independently accepted partition contract; it cannot
 -- multiply one enforced limit by assigning it four role names.
 IF EXISTS(SELECT 1 FROM jsonb_each(n) e WHERE e.key IN ('Worker','Hub','KeyService','Provider')
  GROUP BY e.value->>'ClusterID',e.value->>'NamespaceUID',e.value->>'WorkloadUID' HAVING count(*)>1) THEN RETURN false;END IF;
 IF n->'Worker'->'Configuration' IS DISTINCT FROM p->'Path'->'WorkerConfiguration' OR n->'Hub'->'Configuration' IS DISTINCT FROM p->'Path'->'HubConfiguration' OR
  n->'Worker'->'ClusterID' IS DISTINCT FROM p->'Path'->'AcquisitionClusterID' OR n->'Hub'->'ClusterID' IS DISTINCT FROM p->'Path'->'HubClusterID' THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['FixedBytes','PrincipalBytes','AllocationBytes','RowBytes','FixedQueryRows','InvocationRows','ControlRows','TransitionWALBytes','AuditCipherBytes','AuthenticationPerCall','ProviderPerCall','AuthenticationPerControl','ProviderPerControl','AuthenticationPerSource','ProviderPerSource'] LOOP
  IF NOT public.capacity_json_integer(h->k,1,1152921504606846976) THEN RETURN false;END IF;
 END LOOP;
 IF (h->>'BackupCopies')::numeric<(base->'Metadata'->>'BackupCopies')::numeric OR (h->>'WALCopies')::numeric<(base->'Metadata'->>'WALCopies')::numeric OR (h->>'BackupHorizon')::numeric<(base->'Normal'->'Policy'->>'BackupHorizonSeconds')::numeric*1000000000 OR (h->>'RetirementCleanup')::numeric<(base->'Normal'->'Policy'->>'CleanupBudgetSeconds')::numeric*1000000000 OR NOT public.capacity_json_integer(h->'BackupCopies',1,64) OR NOT public.capacity_json_integer(h->'WALCopies',1,64) OR
  NOT public.capacity_json_integer(h->'BackupHorizon',1,31536000000000000) OR NOT public.capacity_json_integer(h->'RetirementCleanup',1,86400000000000) THEN RETURN false;END IF;
 calls:=1+(p->>'PollLimit')::numeric;controls:=(p->>'ControlTransitionLimit')::numeric;
 IF (p->'Cost'->>'AuditObjects')::numeric<2*calls+1+(p->'Cost'->>'SigningAttempts')::numeric OR (h->>'FixedQueryRows')::numeric<8+(p->'Cost'->>'SigningAttempts')::numeric OR (p->'Cost'->>'SQLRows')::numeric<(h->>'FixedQueryRows')::numeric+calls*(h->>'InvocationRows')::numeric+controls*(h->>'ControlRows')::numeric OR (p->'Cost'->>'SQLBytes')::numeric<(p->'Cost'->>'SQLRows')::numeric*(h->>'RowBytes')::numeric OR
  (p->'Cost'->>'BackupBytes')::numeric<(p->'Cost'->>'SQLBytes')::numeric*(h->>'BackupCopies')::numeric OR
  (p->'Cost'->>'WALBytes')::numeric<controls*(h->>'TransitionWALBytes')::numeric*(h->>'WALCopies')::numeric OR
  (p->'Cost'->>'AuthenticationRequests')::numeric<calls*(h->>'AuthenticationPerCall')::numeric+controls*(h->>'AuthenticationPerControl')::numeric OR
  (p->'Cost'->>'ProviderRequests')::numeric<calls*(h->>'ProviderPerCall')::numeric+controls*(h->>'ProviderPerControl')::numeric+(p->'Cost'->>'UnwrapAttempts')::numeric+(p->'Cost'->>'SigningAttempts')::numeric THEN RETURN false;END IF;
 extra:=(h->>'FixedBytes')::numeric+(h->>'PrincipalBytes')::numeric*(q->>'PrincipalAccounts')::numeric+(h->>'AllocationBytes')::numeric*(q->>'WorkloadAccounts')::numeric;
 FOREACH k IN ARRAY ARRAY['Workers','ReadBatches','ReadBytes','StructuredBytes','WireBytes','UnwrapAttempts','ProviderRequests','AuthenticationRequests','SigningAttempts','AuditObjects','SQLRows','SQLBytes','WALBytes','BackupBytes'] LOOP
  need:=(p->'Cost'->>k)::numeric*(q->>'RootQueries')::numeric;
  IF k='AuthenticationRequests' THEN need:=need+(1+(q->>'SourceTransitionLimit')::numeric)*(h->>'AuthenticationPerSource')::numeric;ELSIF k='ProviderRequests' THEN need:=need+(1+(q->>'SourceTransitionLimit')::numeric)*(h->>'ProviderPerSource')::numeric;ELSIF k='SQLBytes' THEN need:=need+extra;ELSIF k='BackupBytes' THEN need:=need+extra*(h->>'BackupCopies')::numeric;ELSIF k='WALBytes' THEN need:=need+(2+(q->>'PrincipalAccounts')::numeric+(q->>'WorkloadAccounts')::numeric+3*(q->>'SourceTransitionLimit')::numeric)*(h->>'TransitionWALBytes')::numeric*(h->>'WALCopies')::numeric;END IF;
  IF NOT public.capacity_json_integer(q->'Envelope'->k,1,1152921504606846976) OR (q->'Envelope'->>k)::numeric<need THEN RETURN false;END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['CPUMilli','MemoryBytes','EphemeralStorageBytes','WorkerTransientBytes','HubTransientBytes','ProviderConcurrency','AuthenticationConcurrency'] LOOP
  need:=(p->'Worker'->>k)::numeric*(q->>'RootQueries')::numeric;
  total:=(n->'Worker'->'Limits'->>k)::numeric+(n->'Hub'->'Limits'->>k)::numeric+(n->'KeyService'->'Limits'->>k)::numeric+(n->'Provider'->'Limits'->>k)::numeric;
  IF NOT public.capacity_json_integer(p->'Worker'->k,1,1152921504606846976) OR NOT public.capacity_json_integer(q->'Envelope'->k,1,1152921504606846976) OR NOT public.capacity_json_integer(n->'Combined'->k,1,1152921504606846976) OR
   (q->'Envelope'->>k)::numeric<need OR (q->'Envelope'->>k)::numeric<>(n->'Combined'->>k)::numeric OR (n->'Combined'->>k)::numeric<>total OR
   k IN ('CPUMilli','MemoryBytes','EphemeralStorageBytes','WorkerTransientBytes') AND (n->'Worker'->'Limits'->>k)::numeric<need OR
   k='HubTransientBytes' AND (n->'Hub'->'Limits'->>k)::numeric<need OR k='ProviderConcurrency' AND (n->'Provider'->'Limits'->>k)::numeric<need THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;
-- +goose StatementEnd

-- Preserve the original accepted closed shape when the extension is omitted.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_qualification_valid(v jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE g jsonb;b jsonb;k text;key_value jsonb;previous_key text;clusters text[]:='{}';pools text[]:='{}';capacities text[]:='{}';ids text[]:='{}';stores text[]:='{}';system_found boolean:=false;
BEGIN
 IF v ? 'ContextQuery' THEN
  IF NOT public.context_query_qualification_valid(v->'ContextQuery',v->'RootBacking') THEN RETURN false;END IF;
  v:=v-'ContextQuery';
 END IF;
 IF NOT public.capacity_json_fields(v,ARRAY['ID','Digest','RootBacking','NamespaceGuards','Backends']) OR NOT public.capacity_json_uuid(v->'ID') OR
  NOT public.capacity_json_digest(v->'Digest') OR v->'RootBacking'->'QualificationID' IS DISTINCT FROM v->'ID' OR v->'RootBacking'->'QualificationDigest' IS DISTINCT FROM v->'Digest' OR
  jsonb_typeof(v->'NamespaceGuards') IS DISTINCT FROM 'array' OR jsonb_array_length(v->'NamespaceGuards') NOT BETWEEN 1 AND 16 OR
  jsonb_typeof(v->'Backends') IS DISTINCT FROM 'array' OR jsonb_array_length(v->'Backends') NOT BETWEEN 1 AND 16 THEN RETURN false;END IF;
 FOR g IN SELECT value FROM jsonb_array_elements(v->'NamespaceGuards') LOOP
  IF NOT public.capacity_json_fields(g,ARRAY['ClusterID','Digest','Keys']) OR NOT public.capacity_json_uuid(g->'ClusterID') OR NOT public.capacity_json_digest(g->'Digest') OR
   g->>'ClusterID'=ANY(clusters) OR jsonb_typeof(g->'Keys') IS DISTINCT FROM 'array' OR jsonb_array_length(g->'Keys') NOT BETWEEN 1 AND 256 THEN RETURN false;END IF;
  clusters:=array_append(clusters,g->>'ClusterID');previous_key:=NULL;
  FOR key_value IN SELECT value FROM jsonb_array_elements(g->'Keys') LOOP
   IF NOT public.capacity_json_text(key_value,1,253) OR previous_key IS NOT NULL AND (key_value#>>'{}') COLLATE "C"<=previous_key COLLATE "C" THEN RETURN false;END IF;
   previous_key:=key_value#>>'{}';
  END LOOP;
 END LOOP;
 FOR b IN SELECT value FROM jsonb_array_elements(v->'Backends') LOOP
  IF NOT public.capacity_json_fields(b,ARRAY['Layout','ID','Digest','PoolUID','StorageProfile','CapacityID','PoolID','EvidenceStoreID','AuditStoreID','Usable']) OR
   b->>'Layout' IS DISTINCT FROM 'dedicated-capacity-envelope/v1' OR NOT public.capacity_json_digest(b->'Digest') OR
   NOT public.capacity_json_text(b->'PoolUID',1,64) OR NOT public.capacity_json_text(b->'StorageProfile',1,63) OR NOT public.capacity_amount_valid(b->'Usable') OR
   b->>'PoolUID'=ANY(pools) OR b->>'CapacityID'=ANY(capacities) OR b->>'PoolID'=ANY(ids) OR b->>'EvidenceStoreID'=ANY(stores) THEN RETURN false;END IF;
  FOREACH k IN ARRAY ARRAY['ID','CapacityID','PoolID','EvidenceStoreID','AuditStoreID'] LOOP IF NOT public.capacity_json_uuid(b->k) THEN RETURN false;END IF;END LOOP;
  pools:=array_append(pools,b->>'PoolUID');capacities:=array_append(capacities,b->>'CapacityID');ids:=array_append(ids,b->>'PoolID');stores:=array_append(stores,b->>'EvidenceStoreID');
  IF b->>'PoolUID'=v->'RootBacking'->>'SystemPoolUID' THEN
   IF b->>'AuditStoreID' IS DISTINCT FROM v->'RootBacking'->'Capture'->'Policy'->>'StoreID' THEN RETURN false;END IF;system_found:=true;
  END IF;
 END LOOP;
 RETURN system_found;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;

-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION context_query_capacity_plan(s public.capacity_source,acceptance uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE q jsonb:=s.qualification->'ContextQuery';c jsonb:=s.root_configuration;t jsonb:=s.root_plan->'Totals';e jsonb:=q->'Envelope';reservation jsonb;pool public.capacity_pool;k text;
 object_bytes numeric;object_count numeric;keys numeric;hard timestamptz;effects timestamptz;cleanup timestamptz;retire timestamptz;
BEGIN
 IF acceptance IS NULL OR NOT public.context_query_qualification_valid(q,s.qualification->'RootBacking') OR NOT public.capacity_root_configuration_valid(c) OR s.root_plan IS NULL THEN RETURN NULL;END IF;
 SELECT * INTO STRICT pool FROM public.capacity_pool WHERE root_id=s.root_id AND source_uid=s.root_plan->'Input'->>'SystemPoolUID';
 object_count:=(e->>'AuditObjects')::numeric;object_bytes:=object_count*(q->'History'->>'AuditCipherBytes')::numeric;
 keys:=(e->>'UnwrapAttempts')::numeric+(e->>'SigningAttempts')::numeric+(e->>'ProviderRequests')::numeric;
 IF object_bytes>1152921504606846976 OR keys>1152921504606846976 OR
  object_bytes+(t->'SystemObjects'->>'Bytes')::numeric>(s.root_plan#>>'{Input,Envelope,SystemObjects,Bytes}')::numeric OR
  object_count+(t->'SystemObjects'->>'Objects')::numeric>(s.root_plan#>>'{Input,Envelope,SystemObjects,Objects}')::numeric OR
  object_bytes+pool.backed_system_bytes>pool.system_bytes OR object_count+pool.backed_system_objects>pool.system_objects OR
  keys+(t->>'KeyAttempts')::numeric>(s.root_plan#>>'{Input,Envelope,KeyAttempts}')::numeric THEN RETURN NULL;END IF;
 FOREACH k IN ARRAY ARRAY['SQLBytes','BackupBytes','WALBytes'] LOOP
  IF (e->>k)::numeric+(t->>k)::numeric>(s.root_plan->'Input'->'Envelope'->>k)::numeric THEN RETURN NULL;END IF;
 END LOOP;
 reservation:=jsonb_build_object('SystemObjects',jsonb_build_object('Bytes',object_bytes::bigint,'Objects',object_count::bigint),'SQLBytes',e->'SQLBytes','BackupBytes',e->'BackupBytes','WALBytes',e->'WALBytes','KeyAttempts',keys::bigint);
 -- Dates derive once from the ORIGINAL root attempt, not a renewal, source
 -- heartbeat, poll or caller's requested interval. Only microsecond-aligned
 -- durations are eligible, avoiding PostgreSQL upward rounding.
 FOREACH k IN ARRAY ARRAY['Runtime','CredentialLifetime','ProviderEffectLifetime','Cleanup'] LOOP
  IF NOT public.capacity_json_integer(q->'Profile'->'Worker'->k,1000,31536000000000000) OR mod((q->'Profile'->'Worker'->>k)::numeric,1000)<>0 THEN RETURN NULL;END IF;
 END LOOP;
 IF mod((q->>'Admission')::numeric,1000)<>0 OR mod((q->'History'->>'BackupHorizon')::numeric,1000)<>0 OR mod((q->'History'->>'RetirementCleanup')::numeric,1000)<>0 THEN RETURN NULL;END IF;
 hard:=(c->>'InitialObservedAt')::timestamptz+((q->>'Admission')::numeric/1000)*interval '1 microsecond';
 effects:=hard+(GREATEST((q->'Profile'->'Worker'->>'Runtime')::numeric,(q->'Profile'->'Worker'->>'CredentialLifetime')::numeric,(q->'Profile'->'Worker'->>'ProviderEffectLifetime')::numeric)/1000)*interval '1 microsecond';
 cleanup:=effects+((q->'Profile'->'Worker'->>'Cleanup')::numeric/1000)*interval '1 microsecond';
 retire:=cleanup+((2*(q->'History'->>'BackupHorizon')::numeric+(q->'History'->>'RetirementCleanup')::numeric)/1000)*interval '1 microsecond';
 IF hard>(c->>'PlannedUntil')::timestamptz THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('RootID',s.root_id,'InstallationID',s.installation_id,'AcceptanceID',acceptance,'RootAttemptID',c->'AttemptID','RootPlanDigest',c->'PlanDigest',
  'SetupInputDigest',to_jsonb(ARRAY(SELECT get_byte(decode(s.setup_receipt->>'inputDigest','hex'),byte_index.value) FROM generate_series(0,31) AS byte_index(value))),
  'Qualification',q,'Reservation',reservation,'HardUntil',public.capacity_json_timestamp(hard),'EffectsUntil',public.capacity_json_timestamp(effects),'CleanupUntil',public.capacity_json_timestamp(cleanup),'RetireBy',public.capacity_json_timestamp(retire));
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN NULL;
END $$;

CREATE FUNCTION guard_context_query_capacity() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query capacity remains reserved' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.observations<>0 OR NEW.observation_id IS NOT NULL OR NEW.observation_accepted OR NEW.observation_completed THEN RAISE EXCEPTION 'query observation starts spent' USING ERRCODE='23514';END IF;
 ELSIF NOT public.capacity_role_ok(OLD.root_id,'capacity') OR
  (to_jsonb(NEW)-ARRAY['observations','observation_id','observation_ordinal','observation_started_at','observation_until','observation_accepted','observation_completed','negative_observed_at']) IS DISTINCT FROM
  (to_jsonb(OLD)-ARRAY['observations','observation_id','observation_ordinal','observation_started_at','observation_until','observation_accepted','observation_completed','negative_observed_at']) THEN
  RAISE EXCEPTION 'query capacity immutable charge changed' USING ERRCODE='23514';
 ELSIF NEW.observations=OLD.observations THEN
  IF NEW.observation_ordinal<>NEW.observations OR
   (to_jsonb(NEW)-ARRAY['observation_accepted','observation_completed']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['observation_accepted','observation_completed']) OR
   NOT ((NOT OLD.observation_accepted AND NEW.observation_accepted AND NOT OLD.observation_completed AND NOT NEW.observation_completed) OR
    (OLD.observation_accepted=NEW.observation_accepted AND NOT OLD.observation_completed AND NEW.observation_completed)) THEN
   RAISE EXCEPTION 'query observation finalization changed' USING ERRCODE='23514';END IF;
 ELSIF NEW.observations<>OLD.observations+1 OR NEW.observations>(OLD.plan->'Qualification'->>'SourceTransitionLimit')::bigint+1 THEN
  RAISE EXCEPTION 'query source allowance exhausted' USING ERRCODE='23514';
 ELSIF (to_jsonb(NEW)-ARRAY['observations','negative_observed_at']) IS NOT DISTINCT FROM (to_jsonb(OLD)-ARRAY['observations','negative_observed_at']) THEN
  IF NEW.negative_observed_at IS NULL OR NEW.negative_observed_at<COALESCE(OLD.negative_observed_at,OLD.observation_started_at) OR
   NEW.negative_observed_at>clock_timestamp() THEN RAISE EXCEPTION 'query negative watermark regressed' USING ERRCODE='23514';END IF;
 ELSE
  -- A new paid interval requires a joined predecessor. Expiry never proves
  -- quiescence. Negative transitions preserve the unresolved claim above.
  IF NEW.observations>(OLD.plan->'Qualification'->>'SourceTransitionLimit')::bigint OR NEW.observation_id IS NULL OR NEW.observation_id IS NOT DISTINCT FROM OLD.observation_id OR
   NEW.observation_ordinal<>NEW.observations OR NEW.observation_accepted OR NEW.observation_completed OR NEW.observation_started_at>clock_timestamp() OR NEW.observation_until<=clock_timestamp() OR
   NEW.negative_observed_at IS DISTINCT FROM OLD.negative_observed_at OR NEW.observation_started_at<=OLD.negative_observed_at OR
   (OLD.observation_id IS NOT NULL AND NOT OLD.observation_completed) THEN
   RAISE EXCEPTION 'query source claim unavailable' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER context_query_capacity_immutable BEFORE UPDATE OR DELETE ON context_query_capacity FOR EACH ROW EXECUTE FUNCTION guard_context_query_capacity();

-- +goose StatementBegin
-- Caller transactions lock recovery, permission, source, anchor, query backing,
-- allocation, principal/query/batch/key in this order. Never perform provider
-- work in this function or while those locks are held.
CREATE FUNCTION lock_context_query_capacity(r uuid,acceptance uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;a public.context_query_capacity;t public.fleet_current_trust;n timestamptz;until_at timestamptz;expected jsonb;
BEGIN
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR SHARE;
 SELECT * INTO STRICT a FROM public.context_query_capacity WHERE root_id=r AND acceptance_id=acceptance FOR SHARE;
 n:=clock_timestamp();until_at:=public.capacity_managed_root_until(r,n);expected:=public.context_query_capacity_plan(s,acceptance);
 RETURN COALESCE(until_at IS NOT NULL AND n<until_at AND NOT s.suspended AND s.negative_snapshot IS NULL AND
  public.capacity_setup_original_valid(s) AND expected IS NOT NULL AND a.plan=expected AND a.source_digest=s.accepted_digest AND
  EXISTS(SELECT 1 FROM public.context_query_backing b WHERE b.root_id=r AND b.acceptance_id=acceptance) AND
  a.capacity_id=(expected->'Qualification'->>'CapacityID')::uuid AND a.observations<=(expected->'Qualification'->>'SourceTransitionLimit')::bigint AND a.issuer_epoch=t.issuer_epoch AND
  a.postmaster_at=pg_postmaster_start_time() AND a.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND
  n<(a.plan->>'HardUntil')::timestamptz AND clock_timestamp()<until_at,false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

-- This reader returns only original protected configuration/current source
-- facts. It cannot accept, observe, issue credentials or create an allocation.
CREATE FUNCTION read_context_query_capacity_source(r uuid,recovery jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;n timestamptz;until_at timestamptz;pool public.capacity_pool;acceptance uuid;
BEGIN
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR SHARE;
 n:=clock_timestamp();until_at:=LEAST(public.capacity_managed_root_until(r,n),(recovery->>'FreshUntil')::timestamptz);
 IF NOT (public.capacity_role_ok(r,'capacity') OR public.capacity_audit_reader_pin_valid(s) AND EXISTS(SELECT 1 FROM pg_roles WHERE oid=s.audit_reader_role AND rolname=session_user)) OR
  NOT public.capacity_setup_original_valid(s) OR NOT public.context_query_qualification_valid(s.qualification->'ContextQuery',s.qualification->'RootBacking') OR
  NOT public.capacity_recovery_current(s,t,recovery,n) OR s.negative_snapshot IS NOT NULL OR public.capacity_managed_root_until(r,n) IS NULL OR until_at IS NULL OR n>=until_at THEN
  RAISE EXCEPTION 'query capacity source unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT pool FROM public.capacity_pool WHERE root_id=r AND source_uid=s.root_plan->'Input'->>'SystemPoolUID' FOR SHARE;
 SELECT acceptance_id INTO acceptance FROM public.context_query_capacity WHERE root_id=r FOR SHARE;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'query capacity source expired' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Qualification',s.qualification,'Root',s.root_configuration,'System',pool.plan,'AcceptanceID',COALESCE(acceptance::text,''),'Ready',COALESCE(acceptance IS NOT NULL AND public.lock_context_query_capacity(r,acceptance) AND EXISTS(SELECT 1 FROM public.context_query_backing b WHERE b.root_id=r AND NOT b.suspended AND b.observed_at<=n AND n<b.fresh_until),false),
  'ObservationCount',COALESCE((SELECT a.observations FROM public.context_query_capacity a WHERE a.root_id=r),0),
  'BackingUntil',public.capacity_json_timestamp(COALESCE((SELECT b.fresh_until FROM public.context_query_backing b WHERE b.root_id=r),n)),
  'SetupInputDigest',to_jsonb(ARRAY(SELECT get_byte(decode(s.setup_receipt->>'inputDigest','hex'),byte_index.value) FROM generate_series(0,31) AS byte_index(value))),
  'SourceRevision',s.accepted_revision,'SourceDigest',to_jsonb(ARRAY(SELECT get_byte(s.accepted_digest,byte_index.value) FROM generate_series(0,31) AS byte_index(value))),
  'Recovery',recovery,'ObservedAt',public.capacity_json_timestamp(n),'FreshUntil',public.capacity_json_timestamp(until_at));
END $$;

CREATE FUNCTION begin_context_query_capacity_observation(r uuid,proposal jsonb,o jsonb,claim uuid,prior bigint) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;a public.context_query_capacity;n timestamptz;until_at timestamptz;expected jsonb;q jsonb;acceptance uuid;observed timestamptz;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') OR claim IS NULL OR prior IS NULL OR prior<0 OR
  NOT public.capacity_json_fields(o,ARRAY['SourceRevision','SourceDigest','Recovery','ObservedAt','FreshUntil']) OR octet_length(proposal::text)>131072 THEN
  RAISE EXCEPTION 'query capacity claim unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 acceptance:=(proposal->>'AcceptanceID')::uuid;expected:=public.context_query_capacity_plan(s,acceptance);q:=expected->'Qualification';n:=clock_timestamp();observed:=(o->>'ObservedAt')::timestamptz;
 until_at:=LEAST((o->>'FreshUntil')::timestamptz,public.capacity_managed_root_until(r,n),(o->'Recovery'->>'FreshUntil')::timestamptz);
 IF NOT public.capacity_setup_original_valid(s) OR NOT public.capacity_recovery_current(s,t,o->'Recovery',n) OR s.suspended OR s.negative_snapshot IS NOT NULL OR
  expected IS NULL OR proposal IS DISTINCT FROM expected OR (o->>'SourceRevision')::bigint<>s.accepted_revision OR public.connector_digest(o->'SourceDigest') IS DISTINCT FROM s.accepted_digest OR
  public.capacity_managed_root_until(r,n) IS NULL OR NOT COALESCE(observed<=n AND until_at>observed AND until_at<=observed+interval '5 seconds' AND n<until_at AND n<(expected->>'HardUntil')::timestamptz,false) THEN
  RAISE EXCEPTION 'query capacity current original proof unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO a FROM public.context_query_capacity WHERE root_id=r FOR UPDATE;
 IF FOUND THEN
  IF a.plan IS DISTINCT FROM expected OR a.source_digest IS DISTINCT FROM s.accepted_digest OR a.issuer_epoch<>t.issuer_epoch OR a.postmaster_at<>pg_postmaster_start_time() OR a.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) THEN
   RAISE EXCEPTION 'query capacity immutable replay mismatch' USING ERRCODE='23514';END IF;
 ELSE
  IF prior<>0 OR EXISTS(SELECT 1 FROM public.context_query_backing WHERE root_id=r) THEN RAISE EXCEPTION 'query capacity cannot adopt backing' USING ERRCODE='23514';END IF;
  -- Reserve the original residual before external work; this row alone cannot
  -- make a readable backing or satisfy the accepted consumer anchor.
  INSERT INTO public.context_query_capacity(root_id,acceptance_id,capacity_id,plan,source_digest,issuer_epoch,postmaster_at,database_oid,accepted_at)
   VALUES(r,acceptance,(q->>'CapacityID')::uuid,expected,s.accepted_digest,t.issuer_epoch,pg_postmaster_start_time(),(SELECT oid FROM pg_database WHERE datname=current_database()),n);
  SELECT * INTO STRICT a FROM public.context_query_capacity WHERE root_id=r FOR UPDATE;
 END IF;
 IF a.observations<>prior OR observed<=a.negative_observed_at OR a.observations>=(q->>'SourceTransitionLimit')::bigint OR a.observation_id=claim OR
  (a.observation_id IS NOT NULL AND NOT a.observation_completed) THEN RAISE EXCEPTION 'query source claim exhausted or already owned' USING ERRCODE='23514';END IF;
 UPDATE public.context_query_capacity SET observations=observations+1,observation_id=claim,observation_ordinal=observations+1,
  observation_started_at=observed,observation_until=until_at,observation_accepted=false,observation_completed=false WHERE root_id=r;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'query source claim expired' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('ID',claim,'AcceptanceID',acceptance,'Ordinal',prior+1,'ObservedAt',public.capacity_json_timestamp(observed),'ValidUntil',public.capacity_json_timestamp(until_at));
END $$;

CREATE FUNCTION accept_context_query_capacity(r uuid,proposal jsonb,o jsonb,claim jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;a public.context_query_capacity;b public.context_query_backing;n timestamptz;until_at timestamptz;expected jsonb;q jsonb;acceptance uuid;observed timestamptz;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') OR NOT public.capacity_json_fields(o,ARRAY['SourceRevision','SourceDigest','Recovery','ObservedAt','FreshUntil']) OR octet_length(proposal::text)>131072 OR
  NOT public.capacity_json_fields(claim,ARRAY['ID','AcceptanceID','Ordinal','ObservedAt','ValidUntil']) THEN RAISE EXCEPTION 'query capacity producer unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 acceptance:=(proposal->>'AcceptanceID')::uuid;expected:=public.context_query_capacity_plan(s,acceptance);q:=expected->'Qualification';n:=clock_timestamp();observed:=(o->>'ObservedAt')::timestamptz;
 until_at:=LEAST((o->>'FreshUntil')::timestamptz,public.capacity_managed_root_until(r,n),(o->'Recovery'->>'FreshUntil')::timestamptz);
 IF NOT public.capacity_setup_original_valid(s) OR NOT public.capacity_recovery_current(s,t,o->'Recovery',n) OR s.suspended OR s.negative_snapshot IS NOT NULL OR
  expected IS NULL OR proposal IS DISTINCT FROM expected OR (o->>'SourceRevision')::bigint<>s.accepted_revision OR public.connector_digest(o->'SourceDigest') IS DISTINCT FROM s.accepted_digest OR
  public.capacity_managed_root_until(r,n) IS NULL OR NOT COALESCE(observed<=n AND until_at>observed AND until_at<=observed+interval '5 seconds' AND n<until_at AND n<(expected->>'HardUntil')::timestamptz,false) THEN
  RAISE EXCEPTION 'query capacity current original proof unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT a FROM public.context_query_capacity WHERE root_id=r FOR UPDATE;
 IF a.plan IS DISTINCT FROM expected OR a.source_digest IS DISTINCT FROM s.accepted_digest OR a.issuer_epoch<>t.issuer_epoch OR a.postmaster_at<>pg_postmaster_start_time() OR a.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR
  a.observation_id IS DISTINCT FROM (claim->>'ID')::uuid OR a.acceptance_id IS DISTINCT FROM (claim->>'AcceptanceID')::uuid OR
  a.observations IS DISTINCT FROM (claim->>'Ordinal')::bigint OR a.observation_ordinal IS DISTINCT FROM a.observations OR a.observation_accepted OR a.observation_completed OR
  a.observation_started_at IS DISTINCT FROM (claim->>'ObservedAt')::timestamptz OR a.observation_until IS DISTINCT FROM (claim->>'ValidUntil')::timestamptz OR
  observed<>a.observation_started_at OR until_at>a.observation_until OR clock_timestamp()>=a.observation_until THEN
  RAISE EXCEPTION 'query source claim mismatch or already finalized' USING ERRCODE='23514';END IF;
 SELECT * INTO b FROM public.context_query_backing WHERE root_id=r FOR UPDATE;
 IF NOT FOUND THEN
  INSERT INTO public.context_query_backing(root_id,installation_id,acceptance_id,profile,qualification,envelope,query_limit,principal_query_limit,principal_account_limit,allocation_limit,
   observed_at,fresh_until,hard_until,effects_until,cleanup_until,retire_by,suspended)
   VALUES(r,s.installation_id,acceptance,q->'Profile',q->'Profile'->'Qualification',q->'Envelope',(q->>'RootQueries')::bigint,(q->>'PrincipalQueries')::bigint,(q->>'PrincipalAccounts')::bigint,(q->>'WorkloadAccounts')::bigint,
   observed,until_at,(expected->>'HardUntil')::timestamptz,(expected->>'EffectsUntil')::timestamptz,(expected->>'CleanupUntil')::timestamptz,(expected->>'RetireBy')::timestamptz,false);
  SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r FOR UPDATE;
 END IF;
 IF b.acceptance_id<>acceptance OR b.profile IS DISTINCT FROM q->'Profile' OR b.envelope IS DISTINCT FROM q->'Envelope' OR b.hard_until<>(expected->>'HardUntil')::timestamptz OR b.effects_until<>(expected->>'EffectsUntil')::timestamptz OR b.cleanup_until<>(expected->>'CleanupUntil')::timestamptz OR b.retire_by<>(expected->>'RetireBy')::timestamptz THEN RAISE EXCEPTION 'query backing differs' USING ERRCODE='23514';END IF;
 IF observed<b.observed_at OR observed=b.observed_at AND (until_at>b.fresh_until OR b.suspended) THEN RAISE EXCEPTION 'query source observation regressed' USING ERRCODE='23514';END IF;
 UPDATE public.context_query_backing SET observed_at=observed,fresh_until=until_at,suspended=false WHERE root_id=r;
 UPDATE public.context_query_capacity SET observation_accepted=true WHERE root_id=r;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'query capacity source expired' USING ERRCODE='23514';END IF;
 RETURN expected;
END $$;

-- Positive acceptance does not release the in-flight owner before the outer
-- native guard callbacks and final source checks have actually returned.
CREATE FUNCTION complete_context_query_capacity_observation(r uuid,claim jsonb,until_at timestamptz) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;a public.context_query_capacity;t public.fleet_current_trust;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') OR until_at IS NULL OR NOT isfinite(until_at) OR clock_timestamp()>=until_at OR
  NOT public.capacity_json_fields(claim,ARRAY['ID','AcceptanceID','Ordinal','ObservedAt','ValidUntil']) THEN RAISE EXCEPTION 'query source completion unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 PERFORM 1 FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT a FROM public.context_query_capacity WHERE root_id=r FOR UPDATE;
 IF a.observation_completed OR a.observations IS DISTINCT FROM (claim->>'Ordinal')::bigint OR a.observation_ordinal IS DISTINCT FROM a.observations OR
  a.observation_id IS DISTINCT FROM (claim->>'ID')::uuid OR a.acceptance_id IS DISTINCT FROM (claim->>'AcceptanceID')::uuid OR
  a.observation_started_at IS DISTINCT FROM (claim->>'ObservedAt')::timestamptz OR a.observation_until IS DISTINCT FROM (claim->>'ValidUntil')::timestamptz OR
  a.issuer_epoch<>t.issuer_epoch OR a.postmaster_at<>pg_postmaster_start_time() OR a.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR
  until_at>a.observation_until OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'query source completion mismatched or expired' USING ERRCODE='23514';END IF;
 UPDATE public.context_query_capacity SET observation_completed=true WHERE root_id=r;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'query source completion expired' USING ERRCODE='23514';END IF;
END $$;

CREATE FUNCTION suspend_context_query_capacity(r uuid,observed timestamptz) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;b public.context_query_backing;a public.context_query_capacity;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') OR observed IS NULL OR NOT isfinite(observed) OR observed>clock_timestamp() THEN RAISE EXCEPTION 'query negative source unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 PERFORM 1 FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 PERFORM 1 FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 SELECT * INTO a FROM public.context_query_capacity WHERE root_id=r FOR UPDATE;
 SELECT * INTO b FROM public.context_query_backing WHERE root_id=r FOR UPDATE;
 IF a.root_id IS NOT NULL AND observed>=GREATEST(b.observed_at,a.observation_started_at,a.negative_observed_at) AND a.observations<(a.plan->'Qualification'->>'SourceTransitionLimit')::bigint+1 THEN
  UPDATE public.context_query_capacity SET observations=observations+1,negative_observed_at=observed WHERE root_id=r;
  UPDATE public.context_query_backing SET suspended=true,observed_at=observed,fresh_until=observed+interval '1 microsecond' WHERE root_id=r;
 END IF;
END $$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION context_query_qualification_valid(jsonb,jsonb),context_query_capacity_plan(capacity_source,uuid),guard_context_query_capacity(),lock_context_query_capacity(uuid,uuid),read_context_query_capacity_source(uuid,jsonb),begin_context_query_capacity_observation(uuid,jsonb,jsonb,uuid,bigint),accept_context_query_capacity(uuid,jsonb,jsonb,jsonb),complete_context_query_capacity_observation(uuid,jsonb,timestamptz),suspend_context_query_capacity(uuid,timestamptz) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_capacity_allocation_current(r uuid,allocation uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.context_query_allocation;w public.capacity_workload;p public.capacity_pool;b public.context_query_backing;c public.context_query_capacity;n timestamptz;until_at timestamptz;
BEGIN
 SELECT * INTO STRICT c FROM public.context_query_capacity WHERE root_id=r;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r;
 SELECT * INTO STRICT a FROM public.context_query_allocation WHERE root_id=r AND id=allocation;
 SELECT * INTO STRICT w FROM public.capacity_workload WHERE root_id=r AND cluster_id=a.cluster_id AND namespace_uid=a.namespace_uid AND workload_uid=a.workload_uid;
 SELECT * INTO STRICT p FROM public.capacity_pool WHERE root_id=r AND id=w.pool_id;
 n:=clock_timestamp();until_at:=public.capacity_managed_admission_until(r,w.allocation_id,'context',n);
 RETURN COALESCE(until_at IS NOT NULL AND n<until_at AND NOT b.suspended AND b.observed_at<=n AND n<b.fresh_until AND
  a.cluster_id=(b.profile->'Path'->>'TargetClusterID')::uuid AND a.revision=w.revision AND a.query_limit=(c.plan->'Qualification'->>'WorkloadQueries')::bigint AND
  a.pool_source=jsonb_build_object('UID',w.plan->'PoolUID','Generation',w.plan->'PoolGeneration','Digest',p.plan->'Digest') AND
  a.policy_source=jsonb_build_object('UID',w.plan->'PolicyUID','Generation',w.plan->'PolicyGeneration','Digest',w.plan->'PolicyDigest') AND
  clock_timestamp()<LEAST(until_at,b.fresh_until),false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

CREATE FUNCTION allocate_context_query_capacity(r uuid,acceptance uuid,cluster uuid,namespace_id text,workload text,new_id uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b public.context_query_backing;c public.context_query_capacity;w public.capacity_workload;p public.capacity_pool;a public.context_query_allocation;limit_value bigint;until_at timestamptz;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') OR NOT public.lock_context_query_capacity(r,acceptance) THEN RAISE EXCEPTION 'query allocation source unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT c FROM public.context_query_capacity WHERE root_id=r;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r FOR UPDATE;
 IF b.suspended OR clock_timestamp()>=b.fresh_until OR cluster<>(b.profile->'Path'->>'TargetClusterID')::uuid THEN RAISE EXCEPTION 'query backing unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT w FROM public.capacity_workload WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload FOR SHARE;
 SELECT * INTO STRICT p FROM public.capacity_pool WHERE root_id=r AND id=w.pool_id FOR SHARE;
 until_at:=LEAST(b.fresh_until,public.capacity_managed_admission_until(r,w.allocation_id,'context',clock_timestamp()));
 IF public.capacity_managed_admission_until(r,w.allocation_id,'context',clock_timestamp()) IS NULL OR until_at IS NULL OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'query workload capacity unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO a FROM public.context_query_allocation WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload FOR UPDATE;
 IF NOT FOUND THEN
  limit_value:=(c.plan->'Qualification'->>'WorkloadQueries')::bigint;
  IF new_id IS NULL OR (b.allocations+1)::numeric*limit_value>b.query_limit OR b.allocations>=b.allocation_limit THEN RAISE EXCEPTION 'query reserved workload slots exhausted' USING ERRCODE='23514';END IF;
  INSERT INTO public.context_query_allocation(id,root_id,cluster_id,namespace_uid,workload_uid,revision,pool_source,policy_source,query_limit)
   VALUES(new_id,r,cluster,namespace_id,workload,w.revision,jsonb_build_object('UID',w.plan->'PoolUID','Generation',w.plan->'PoolGeneration','Digest',p.plan->'Digest'),
    jsonb_build_object('UID',w.plan->'PolicyUID','Generation',w.plan->'PolicyGeneration','Digest',w.plan->'PolicyDigest'),limit_value) RETURNING * INTO a;
 END IF;
 IF NOT public.context_query_capacity_allocation_current(r,a.id) OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'query allocation changed' USING ERRCODE='23514';END IF;
 RETURN a.id;
END $$;

CREATE FUNCTION read_context_query_capacity_plan(r uuid,acceptance uuid,cluster uuid,namespace_id text,workload text,actor jsonb,principal_key_value bytea,proposed_account uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;b public.context_query_backing;a public.context_query_allocation;account uuid;n timestamptz;until_at timestamptz;
BEGIN
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 IF NOT (public.capacity_role_ok(r,'capacity') OR public.capacity_audit_reader_pin_valid(s) AND EXISTS(SELECT 1 FROM pg_roles WHERE oid=s.audit_reader_role AND rolname=session_user)) OR
  NOT public.lock_context_query_capacity(r,acceptance) OR principal_key_value IS NULL OR octet_length(principal_key_value)<>32 OR octet_length(actor::text)>4096 OR proposed_account IS NULL THEN
  RAISE EXCEPTION 'query capacity reader unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r FOR SHARE;
 SELECT * INTO STRICT a FROM public.context_query_allocation WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload FOR SHARE;
 IF NOT public.context_query_capacity_allocation_current(r,a.id) THEN RAISE EXCEPTION 'query workload capacity unavailable' USING ERRCODE='23514';END IF;
 SELECT id INTO account FROM public.context_query_principal WHERE root_id=r AND principal_key=principal_key_value FOR SHARE;
 n:=clock_timestamp();until_at:=LEAST(b.fresh_until,public.capacity_managed_root_until(r,n),b.hard_until);
 IF until_at IS NULL OR n>=until_at THEN RAISE EXCEPTION 'query capacity read expired' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('AcceptanceID',acceptance,'AccountID',COALESCE(account,proposed_account),'AllocationID',a.id,'RootID',r,'InstallationID',b.installation_id,
  'ClusterID',a.cluster_id,'NamespaceUID',a.namespace_uid,'WorkloadUID',a.workload_uid,'AllocationRevision',a.revision,'PoolSource',a.pool_source,'PolicySource',a.policy_source,'Principal',actor,'Profile',b.profile,
  'ObservedAt',public.capacity_json_timestamp(n),'ValidUntil',public.capacity_json_timestamp(until_at),'HardUntil',public.capacity_json_timestamp(b.hard_until),'EffectsUntil',public.capacity_json_timestamp(b.effects_until),'CleanupUntil',public.capacity_json_timestamp(b.cleanup_until),'RetireBy',public.capacity_json_timestamp(b.retire_by));
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_query_capacity_allocation_current(uuid,uuid),allocate_context_query_capacity(uuid,uuid,uuid,text,text,uuid),read_context_query_capacity_plan(uuid,uuid,uuid,text,text,jsonb,bytea,uuid) FROM PUBLIC;

-- Ephemeral storage is a separate finite enforced Job dimension, never inferred
-- from the native read or transient-memory limits. Frozen SQL68 is unchanged.
ALTER TABLE context_query_backing ADD CONSTRAINT context_query_ephemeral_storage_backed CHECK(
 COALESCE(public.capacity_json_integer(profile->'Worker'->'EphemeralStorageBytes',1,1152921504606846976) AND
 public.capacity_json_integer(envelope->'EphemeralStorageBytes',1,1152921504606846976) AND
 (envelope->>'EphemeralStorageBytes')::numeric >= query_limit::numeric*(profile->'Worker'->>'EphemeralStorageBytes')::numeric,false));
