-- +goose Up
-- This is a contract migration: the prior binary's strict profile decoder
-- rejects the additional processing lane. Never advertise an old image as
-- compatible with this development baseline (ADR-227/318).
-- +goose StatementBegin
DO $$ BEGIN
 EXECUTE 'COMMENT ON TABLE public.goose_db_version IS ''asservat:oldest-binary-schema=149''';
END $$;
-- +goose StatementEnd
-- Expose only the already accepted, independently reserved processing release
-- profile. No lane, account, pool, grant or initialization is created here.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION read_capacity_audit_profiles(r uuid,i uuid,q uuid,qd bytea,av text,observed timestamptz,original_until timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;p public.permission_stream;a public.operation_audit_pool;backing public.capacity_pool;processing public.processing_root;
 c jsonb;v jsonb;policy jsonb;result jsonb;n timestamptz;until_at timestamptz;lane_name text;field_name text;normalized jsonb;pool_name text;pool_plan jsonb;
BEGIN
 n:=clock_timestamp();
 IF r IS NULL OR i IS NULL OR q IS NULL OR qd IS NULL OR octet_length(qd)<>32 OR av IS NULL OR octet_length(av) NOT BETWEEN 1 AND 64 OR
  observed IS NULL OR original_until IS NULL OR NOT isfinite(observed) OR NOT isfinite(original_until) OR observed>n OR n>=original_until OR original_until>observed+interval '5 seconds' THEN
  RAISE EXCEPTION 'capacity audit profile input unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=i FOR SHARE;
 SELECT * INTO STRICT p FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR SHARE;
 n:=clock_timestamp();c:=s.root_configuration;
 until_at:=LEAST(original_until,t.fresh_until,p.fresh_until,p.lease_until,s.fresh_until,(c->>'PlannedUntil')::timestamptz);
 IF NOT public.capacity_audit_reader_pin_valid(s) OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE oid=s.audit_reader_role AND rolname=session_user) OR
  s.installation_id<>i OR s.qualification_digest<>qd OR s.qualification->>'ID'<>q::text OR s.account_version<>av OR
  t.suspended OR t.recovery_blocked OR t.observed_at IS NULL OR t.observed_at>n OR t.fresh_until IS NULL OR
  p.suspended OR p.observed_at IS NULL OR p.observed_at>n OR p.fresh_until IS NULL OR p.lease_until IS NULL OR p.fresh_until>p.observed_at+interval '30 seconds' OR
  s.suspended OR s.observed_at IS NULL OR s.observed_at>n OR s.fresh_until IS NULL OR s.accepted_revision<1 OR s.accepted_snapshot IS NULL OR
  s.root_plan IS NULL OR s.root_mutation_xid IS NOT NULL OR NOT COALESCE(public.capacity_root_configuration_valid(c),false) OR c->'ReadyAt'='null'::jsonb OR c->'ReconciledAt'<>'null'::jsonb OR
  (c->>'ReadyAt')::timestamptz>n OR public.connector_digest(c->'PlanDigest') IS DISTINCT FROM s.root_plan_digest OR
  s.root_plan->'Input' IS DISTINCT FROM s.qualification->'RootBacking' OR n>=until_at OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit proof WHERE proof.id=p.initial_audit_id AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit proof WHERE proof.id=p.epoch AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL) THEN
  RAISE EXCEPTION 'current capacity audit profile unavailable' USING ERRCODE='23514',
   -- Operator-only diagnostics use already-held rows. Do not repeat role/pin or
   -- audit lookups here; other current-guard failures remain unclassified.
   DETAIL=left(jsonb_build_object(
    'stage','capacity-audit-current',
    'cut',CASE WHEN n>=original_until THEN 'caller' WHEN n>=t.fresh_until THEN 'trust'
      WHEN n>=p.fresh_until OR n>=p.lease_until THEN 'permission' WHEN n>=s.fresh_until THEN 'source'
      WHEN n>=(c->>'PlannedUntil')::timestamptz THEN 'configuration' ELSE 'other-current' END,
    'now',n,'inputObserved',observed,'callerUntil',original_until,'effectiveUntil',until_at,
    'trustObserved',t.observed_at,'trustUntil',t.fresh_until,'trustSuspended',t.suspended,'recoveryBlocked',t.recovery_blocked,
    'permissionObserved',p.observed_at,'permissionUntil',p.fresh_until,'permissionLeaseUntil',p.lease_until,'permissionSuspended',p.suspended,
    'sourceObserved',s.observed_at,'sourceUntil',s.fresh_until,'sourceSuspended',s.suspended,
    'plannedUntil',(c->>'PlannedUntil')::timestamptz,'reconciled',c->'ReconciledAt'<>'null'::jsonb)::text,2048);END IF;
 SELECT x->'Resource'->>'Name' INTO STRICT pool_name FROM jsonb_array_elements(s.accepted_snapshot->'Snapshot'->'Pools') x
  WHERE x->'Resource'->>'UID'=s.root_plan->'Input'->>'SystemPoolUID';
 pool_plan:=public.capacity_compile_pool(s.accepted_snapshot,pool_name);
 SELECT * INTO STRICT backing FROM public.capacity_pool WHERE root_id=r AND source_uid=s.root_plan->'Input'->>'SystemPoolUID' FOR SHARE;
 IF pool_plan IS NULL OR NOT (backing.plan IS NOT DISTINCT FROM pool_plan OR public.capacity_pool_extends(backing.plan,pool_plan)) OR public.capacity_backend_for(s,pool_plan) IS NULL OR
  public.capacity_compile_root(s.qualification->'RootBacking',pool_plan) IS DISTINCT FROM s.root_plan THEN
  RAISE EXCEPTION 'capacity audit source backing mismatch' USING ERRCODE='23514';END IF;
 result:=jsonb_build_object('Format','accepted-capacity-audit-profiles/v1','RootID',r,'InstallationID',i,'QualificationID',q,'AccountVersion',av,
  'QualificationDigest',to_jsonb(ARRAY(SELECT get_byte(qd,k) FROM generate_series(0,31) k)),
  'PlanDigest',to_jsonb(ARRAY(SELECT get_byte(s.root_plan_digest,k) FROM generate_series(0,31) k)),
  'ConfigurationRevision',(c->>'Revision')::bigint,'SourceRevision',s.accepted_revision,'ObservedAt',observed);
 -- Stable sorted lock order, also used by the root producer.
 FOREACH lane_name IN ARRAY ARRAY['normal','processing','resolution'] LOOP
  field_name:=CASE lane_name WHEN 'normal' THEN 'Normal' WHEN 'processing' THEN 'Processing' ELSE 'Resolution' END;
  v:=s.root_plan->'Input'->field_name;
  IF NOT public.capacity_root_audit_valid(v,r,i,lane_name,CASE lane_name WHEN 'processing' THEN 'processing-release-history/v1' ELSE 'operation-audit-history/v3' END) THEN
   RAISE EXCEPTION 'capacity audit layout unavailable' USING ERRCODE='23514';END IF;
  SELECT * INTO STRICT a FROM public.operation_audit_pool WHERE root_id=r AND lane=lane_name FOR SHARE;
  n:=clock_timestamp();until_at:=LEAST(until_at,a.valid_until);
  IF n>=until_at OR a.paused OR a.account_version<>av OR a.revision<>(c->>'Revision')::bigint OR
   a.valid_until<>(c->>'PlannedUntil')::timestamptz OR a.account_limit<>(v->>'Accounts')::bigint OR
   a.records_per_account<>(v->>'RecordsPerAccount')::bigint OR a.retained_seconds<>(v->>'RetainedSeconds')::bigint THEN
   RAISE EXCEPTION 'capacity audit pool mismatch' USING ERRCODE='23514';END IF;
  -- Only admission revision/date vary. Every other original accepted field,
  -- including H=0 backup/store/layout identity, is retained byte-for-byte.
  policy:=(v->'Policy')||jsonb_build_object('BackingRevision',a.revision,'ValidUntil',public.capacity_json_timestamp(a.valid_until));
  IF lane_name='processing' THEN
   -- The shared permission lock above serializes processing configuration and
   -- decision writers. Read without a late reverse-order business-row lock.
   -- Initialization may still be absent: this profile also precedes that first
   -- independently audited decision and never declares the root initialized.
   SELECT * INTO STRICT processing FROM public.processing_root WHERE root_id=r;
   IF processing.installation_id<>i OR processing.issuer_epoch<>t.issuer_epoch OR
    processing.epoch<>(s.root_plan->'Input'->>'ProcessingEpoch')::uuid OR
    processing.source_uid<>(s.root_plan->'Input'->>'ProcessingSourceUID')::uuid OR
    processing.protection_digest IS DISTINCT FROM public.connector_digest(s.root_plan->'Input'->'ProcessingProtectionDigest') OR
    processing.backing_revision<>(c->>'Revision')::bigint OR processing.valid_until<>a.valid_until OR
    processing.release_policy IS DISTINCT FROM policy THEN
    RAISE EXCEPTION 'processing release profile mismatch' USING ERRCODE='23514';END IF;
  END IF;
  normalized:=policy-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds'];
  IF a.history_profile IS NOT NULL AND a.history_profile IS DISTINCT FROM normalized THEN
   RAISE EXCEPTION 'capacity audit history mismatch' USING ERRCODE='23514';END IF;
  result:=result||jsonb_build_object(field_name,jsonb_build_object('Policy',policy,'RetainedSeconds',a.retained_seconds));
 END LOOP;
 n:=clock_timestamp();
 IF n>=until_at OR NOT public.capacity_audit_reader_pin_valid(s) THEN RAISE EXCEPTION 'capacity audit profile expired after read' USING ERRCODE='23514';END IF;
 RETURN result||jsonb_build_object('FreshUntil',until_at);
END $$;
-- +goose StatementEnd


-- +goose Down

-- +goose StatementBegin
DO $$ BEGIN
 EXECUTE 'COMMENT ON TABLE public.goose_db_version IS ''asservat:oldest-binary-schema=102''';
END $$;
-- +goose StatementEnd

-- Restore the exact prior projection; retained processing decisions and audit
-- reservations remain untouched.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION read_capacity_audit_profiles(r uuid,i uuid,q uuid,qd bytea,av text,observed timestamptz,original_until timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;p public.permission_stream;a public.operation_audit_pool;backing public.capacity_pool;
 c jsonb;v jsonb;policy jsonb;result jsonb;n timestamptz;until_at timestamptz;lane_name text;field_name text;normalized jsonb;pool_name text;pool_plan jsonb;
BEGIN
 n:=clock_timestamp();
 IF r IS NULL OR i IS NULL OR q IS NULL OR qd IS NULL OR octet_length(qd)<>32 OR av IS NULL OR octet_length(av) NOT BETWEEN 1 AND 64 OR
  observed IS NULL OR original_until IS NULL OR NOT isfinite(observed) OR NOT isfinite(original_until) OR observed>n OR n>=original_until OR original_until>observed+interval '5 seconds' THEN
  RAISE EXCEPTION 'capacity audit profile input unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=i FOR SHARE;
 SELECT * INTO STRICT p FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR SHARE;
 n:=clock_timestamp();c:=s.root_configuration;
 until_at:=LEAST(original_until,t.fresh_until,p.fresh_until,p.lease_until,s.fresh_until,(c->>'PlannedUntil')::timestamptz);
 IF NOT public.capacity_audit_reader_pin_valid(s) OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE oid=s.audit_reader_role AND rolname=session_user) OR
  s.installation_id<>i OR s.qualification_digest<>qd OR s.qualification->>'ID'<>q::text OR s.account_version<>av OR
  t.suspended OR t.recovery_blocked OR t.observed_at IS NULL OR t.observed_at>n OR t.fresh_until IS NULL OR
  p.suspended OR p.observed_at IS NULL OR p.observed_at>n OR p.fresh_until IS NULL OR p.lease_until IS NULL OR p.fresh_until>p.observed_at+interval '30 seconds' OR
  s.suspended OR s.observed_at IS NULL OR s.observed_at>n OR s.fresh_until IS NULL OR s.accepted_revision<1 OR s.accepted_snapshot IS NULL OR
  s.root_plan IS NULL OR s.root_mutation_xid IS NOT NULL OR NOT COALESCE(public.capacity_root_configuration_valid(c),false) OR c->'ReadyAt'='null'::jsonb OR c->'ReconciledAt'<>'null'::jsonb OR
  (c->>'ReadyAt')::timestamptz>n OR public.connector_digest(c->'PlanDigest') IS DISTINCT FROM s.root_plan_digest OR
  s.root_plan->'Input' IS DISTINCT FROM s.qualification->'RootBacking' OR n>=until_at OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit proof WHERE proof.id=p.initial_audit_id AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit proof WHERE proof.id=p.epoch AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL) THEN
  RAISE EXCEPTION 'current capacity audit profile unavailable' USING ERRCODE='23514',
   -- Operator-only diagnostics use already-held rows. Do not repeat role/pin or
   -- audit lookups here; other current-guard failures remain unclassified.
   DETAIL=left(jsonb_build_object(
    'stage','capacity-audit-current',
    'cut',CASE WHEN n>=original_until THEN 'caller' WHEN n>=t.fresh_until THEN 'trust'
      WHEN n>=p.fresh_until OR n>=p.lease_until THEN 'permission' WHEN n>=s.fresh_until THEN 'source'
      WHEN n>=(c->>'PlannedUntil')::timestamptz THEN 'configuration' ELSE 'other-current' END,
    'now',n,'inputObserved',observed,'callerUntil',original_until,'effectiveUntil',until_at,
    'trustObserved',t.observed_at,'trustUntil',t.fresh_until,'trustSuspended',t.suspended,'recoveryBlocked',t.recovery_blocked,
    'permissionObserved',p.observed_at,'permissionUntil',p.fresh_until,'permissionLeaseUntil',p.lease_until,'permissionSuspended',p.suspended,
    'sourceObserved',s.observed_at,'sourceUntil',s.fresh_until,'sourceSuspended',s.suspended,
    'plannedUntil',(c->>'PlannedUntil')::timestamptz,'reconciled',c->'ReconciledAt'<>'null'::jsonb)::text,2048);END IF;
 SELECT x->'Resource'->>'Name' INTO STRICT pool_name FROM jsonb_array_elements(s.accepted_snapshot->'Snapshot'->'Pools') x
  WHERE x->'Resource'->>'UID'=s.root_plan->'Input'->>'SystemPoolUID';
 pool_plan:=public.capacity_compile_pool(s.accepted_snapshot,pool_name);
 SELECT * INTO STRICT backing FROM public.capacity_pool WHERE root_id=r AND source_uid=s.root_plan->'Input'->>'SystemPoolUID' FOR SHARE;
 IF pool_plan IS NULL OR NOT (backing.plan IS NOT DISTINCT FROM pool_plan OR public.capacity_pool_extends(backing.plan,pool_plan)) OR public.capacity_backend_for(s,pool_plan) IS NULL OR
  public.capacity_compile_root(s.qualification->'RootBacking',pool_plan) IS DISTINCT FROM s.root_plan THEN
  RAISE EXCEPTION 'capacity audit source backing mismatch' USING ERRCODE='23514';END IF;
 result:=jsonb_build_object('Format','accepted-capacity-audit-profiles/v1','RootID',r,'InstallationID',i,'QualificationID',q,'AccountVersion',av,
  'QualificationDigest',to_jsonb(ARRAY(SELECT get_byte(qd,k) FROM generate_series(0,31) k)),
  'PlanDigest',to_jsonb(ARRAY(SELECT get_byte(s.root_plan_digest,k) FROM generate_series(0,31) k)),
  'ConfigurationRevision',(c->>'Revision')::bigint,'SourceRevision',s.accepted_revision,'ObservedAt',observed);
 -- Stable sorted lock order, also used by the root producer.
 FOREACH lane_name IN ARRAY ARRAY['normal','resolution'] LOOP
  field_name:=CASE lane_name WHEN 'normal' THEN 'Normal' ELSE 'Resolution' END;
  v:=s.root_plan->'Input'->field_name;
  IF NOT public.capacity_root_audit_valid(v,r,i,lane_name,'operation-audit-history/v3') THEN
   RAISE EXCEPTION 'capacity audit layout unavailable' USING ERRCODE='23514';END IF;
  SELECT * INTO STRICT a FROM public.operation_audit_pool WHERE root_id=r AND lane=lane_name FOR SHARE;
  n:=clock_timestamp();until_at:=LEAST(until_at,a.valid_until);
  IF n>=until_at OR a.paused OR a.account_version<>av OR a.revision<>(c->>'Revision')::bigint OR
   a.valid_until<>(c->>'PlannedUntil')::timestamptz OR a.account_limit<>(v->>'Accounts')::bigint OR
   a.records_per_account<>(v->>'RecordsPerAccount')::bigint OR a.retained_seconds<>(v->>'RetainedSeconds')::bigint THEN
   RAISE EXCEPTION 'capacity audit pool mismatch' USING ERRCODE='23514';END IF;
  -- Only admission revision/date vary. Every other original accepted field,
  -- including H=0 backup/store/layout identity, is retained byte-for-byte.
  policy:=(v->'Policy')||jsonb_build_object('BackingRevision',a.revision,'ValidUntil',public.capacity_json_timestamp(a.valid_until));
  normalized:=policy-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds'];
  IF a.history_profile IS NOT NULL AND a.history_profile IS DISTINCT FROM normalized THEN
   RAISE EXCEPTION 'capacity audit history mismatch' USING ERRCODE='23514';END IF;
  result:=result||jsonb_build_object(field_name,jsonb_build_object('Policy',policy,'RetainedSeconds',a.retained_seconds));
 END LOOP;
 n:=clock_timestamp();
 IF n>=until_at OR NOT public.capacity_audit_reader_pin_valid(s) THEN RAISE EXCEPTION 'capacity audit profile expired after read' USING ERRCODE='23514';END IF;
 RETURN result||jsonb_build_object('FreshUntil',until_at);
END $$;
-- +goose StatementEnd
