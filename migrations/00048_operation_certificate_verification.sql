-- +goose Up
-- Existing records have no remaining verifiable pre-I/O allowance. The constant
-- default backfills logically without UPDATEs, replacing neither binding nor
-- original receipt, completion, deadlines or already acknowledged cleanup.
ALTER TABLE operation_audit_lifecycle ADD COLUMN certificate_verify_attempts bigint NOT NULL DEFAULT 2 CHECK(certificate_verify_attempts BETWEEN 0 AND 2);
-- New rows can begin at zero ONLY through the source-managed v3 INSERT below.
-- +goose StatementBegin
CREATE FUNCTION operation_audit_profile_covers(candidate jsonb, prior jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE q jsonb:=candidate->'History'; oldq jsonb:=prior->'History'; k text;
BEGIN
 -- This is only a structural resource-coverage predicate. The candidate still
 -- needs independently accepted protected policy and current backing at INSERT.
 IF candidate IS NULL OR prior IS NULL OR q->>'Layout' IS DISTINCT FROM 'operation-audit-history/v3' OR
  (candidate-'History') IS DISTINCT FROM (prior-'History') THEN RETURN false; END IF;
 IF oldq IS NULL THEN RETURN COALESCE((prior->>'BackupHorizonSeconds')::bigint=0,false); END IF;
 IF oldq->>'Layout' IS NULL OR oldq->>'Layout' NOT IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3') THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies'] LOOP
  IF q->>k IS NULL OR oldq->>k IS NULL OR (q->>k)::bigint<(oldq->>k)::bigint THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END $$;

CREATE OR REPLACE FUNCTION create_operation_audit_lifecycle() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b jsonb; p jsonb; t public.fleet_current_trust; a public.operation_audit_pool; n timestamptz:=clock_timestamp(); budget interval; horizon interval; proof interval;
BEGIN
 IF TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'AFTER' OR TG_OP<>'INSERT' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid audit lifecycle source' USING ERRCODE='23514'; END IF;
 b:=NEW.intent->'Lifecycle';
 IF b IS NULL THEN RETURN NEW; END IF;
 p:=b->'Policy';
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=(p->>'InstallationID')::uuid FOR SHARE;
 SELECT * INTO STRICT a FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane=NEW.lane FOR UPDATE;
 n:=clock_timestamp();
 budget:=make_interval(secs=>(p->>'CleanupBudgetSeconds')::double precision);
 horizon:=make_interval(secs=>(p->>'BackupHorizonSeconds')::double precision);
 proof:=make_interval(secs=>(p->>'ProofWindowSeconds')::double precision);
 IF (p ? 'OverdueTerminal' AND p->>'OverdueTerminal' IS DISTINCT FROM 'overdue-original/v1') OR b->>'Protocol' IS DISTINCT FROM 'closed-operation-audit/v1' OR jsonb_typeof(p)<>'object' OR
  NOT(p ?& ARRAY['MaxPurgeLeases','RootID','Lane','InstallationID','StoreID','PolicyID','BackupProfileID','PolicyDigest','BackupProfileDigest','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','BackupHorizonSeconds','CleanupBudgetSeconds','ProofWindowSeconds','ValidUntil']) OR
  (p->>'RootID')::uuid<>NEW.root_id OR p->>'Lane'<>NEW.lane OR (p->>'StoreID')::uuid IS NULL OR (p->>'PolicyID')::uuid IS NULL OR (p->>'BackupProfileID')::uuid IS NULL OR
  jsonb_array_length(p->'PolicyDigest')<>32 OR jsonb_array_length(p->'BackupProfileDigest')<>32 OR
  (p->>'BackingRevision')::bigint<>a.revision OR (p->>'MetadataSlots')::bigint<a.account_limit*a.records_per_account OR (p->>'MetadataSlots')::bigint>1000000000000 OR
  budget<interval '1 second' OR budget>interval '1 day' OR horizon<interval '0 seconds' OR horizon>interval '3660 days' OR proof<interval '1 second' OR proof>interval '3660 days' OR
  (p->>'BackupReservedBytes')::bigint<0 OR (p->>'WALReservedBytes')::bigint<0 OR horizon>interval '0 seconds' AND ((p->>'BackupReservedBytes')::bigint<=0 OR (p->>'WALReservedBytes')::bigint<=0) OR
  n>=(p->>'ValidUntil')::timestamptz OR n>=NEW.request_until OR n>=a.valid_until OR t.recovery_blocked OR t.suspended OR n>=t.fresh_until OR t.observed_at>n OR t.issuer_epoch<>NEW.issuer_epoch OR
  (p->>'MaxPurgeLeases')::bigint NOT BETWEEN 2 AND 32 OR
  (b->>'HistoryReleaseAt')::timestamptz<>NEW.retain_until-horizon-budget OR (b->>'HistoryDeleteBy')::timestamptz<>NEW.retain_until-horizon OR
  (b->>'LiveRetireBy')::timestamptz<>NEW.retain_until-2*horizon-budget OR (b->>'CertificatePurgeAt')::timestamptz<>(b->>'LiveRetireBy')::timestamptz-budget OR
  (b->>'OriginalPurgeAt')::timestamptz<>(b->>'CertificatePurgeAt')::timestamptz-proof-budget OR (b->>'OriginalPurgeAt')::timestamptz<=NEW.write_until THEN
  RAISE EXCEPTION 'audit lifecycle backing unavailable' USING ERRCODE='23514'; END IF;
 -- A qualification is an exact accepted layout/profile, with conservative
 -- measured full-transaction bounds. Positive arbitrary byte counts are not a
 -- qualification; source acceptance is deliberately outside this adapter.
 IF p->'History' IS NULL OR p->'History'->>'Layout' IS DISTINCT FROM 'operation-audit-history/v3' OR
   NOT(p->'History' ?& ARRAY['ID','Digest','Layout','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies']) OR
   (p->'History'->>'ID')::uuid IS NULL OR jsonb_array_length(p->'History'->'Digest')<>32 OR
   (p->'History'->>'MaximumRowFootprintBytes')::bigint NOT BETWEEN 131072 AND 16777216 OR
   (p->'History'->>'MaximumTransitionWALBytes')::bigint NOT BETWEEN 131072 AND 67108864 OR
   (p->'History'->>'BackupCopies')::bigint NOT BETWEEN 1 AND 64 OR (p->'History'->>'WALCopies')::bigint NOT BETWEEN 1 AND 64 OR
   (p->>'BackupReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'MaximumRowFootprintBytes')::bigint*(p->'History'->>'BackupCopies')::bigint OR
   (p->>'WALReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'MaximumTransitionWALBytes')::bigint*(p->'History'->>'WALCopies')::bigint*(21+3*(p->>'MaxPurgeLeases')::bigint) THEN
   RAISE EXCEPTION 'audit history qualification unavailable' USING ERRCODE='23514'; END IF;

 IF a.history_backing_until IS NOT NULL AND n<a.history_backing_until AND NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),a.history_profile) THEN
  RAISE EXCEPTION 'residual audit history backing protected' USING ERRCODE='23514'; END IF;
 -- Renewal may refresh a source/revision or increase backing. Outstanding
 -- obligations cannot be moved to a smaller/different backup or account profile.
 IF EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.root_id=NEW.root_id AND d.lane=NEW.lane AND
   NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),((d.binding->'Policy') - ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']))) OR
  EXISTS(SELECT 1 FROM public.operation_audit_history h WHERE h.root_id=NEW.root_id AND h.lane=NEW.lane AND NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),h.history_policy)) THEN
  RAISE EXCEPTION 'outstanding audit history profile mismatch' USING ERRCODE='23514'; END IF;
 IF horizon>interval '0 seconds' THEN
  UPDATE public.operation_audit_pool SET
   history_profile=p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds'],
   history_backing_until=GREATEST(history_backing_until,NEW.retain_until)
  WHERE root_id=NEW.root_id AND lane=NEW.lane;
 END IF;
 INSERT INTO public.operation_audit_lifecycle(operation_id,root_id,lane,principal_digest,installation_id,issuer_epoch,postmaster_at,database_oid,binding,original_purge_at,certificate_purge_at,live_retire_by,certificate_verify_attempts)
 VALUES(NEW.id,NEW.root_id,NEW.lane,NEW.principal_digest,t.installation_id,t.issuer_epoch,(SELECT activated_postmaster_at FROM public.fleet_trust WHERE installation_id=t.installation_id),(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()),b,(b->>'OriginalPurgeAt')::timestamptz,(b->>'CertificatePurgeAt')::timestamptz,(b->>'LiveRetireBy')::timestamptz,0);
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION guard_operation_audit_lifecycle() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit; t public.fleet_current_trust; n timestamptz; c jsonb; phase text; original jsonb;
BEGIN
 IF TG_RELID<>'public.operation_audit_lifecycle'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid audit lifecycle source' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN
  IF OLD.finalization_xid IS DISTINCT FROM pg_current_xact_id() OR EXISTS(SELECT 1 FROM public.operation_audit WHERE id=OLD.operation_id) THEN RAISE EXCEPTION 'audit lifecycle retirement unavailable' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 SELECT * INTO STRICT a FROM public.operation_audit WHERE id=NEW.operation_id;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id FOR SHARE;
 n:=clock_timestamp();
 IF t.recovery_blocked OR t.suspended OR n>=t.fresh_until OR t.observed_at>n OR t.issuer_epoch<>NEW.issuer_epoch OR NOT public.incarnation_current(NEW.postmaster_at) OR (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())<>NEW.database_oid OR NEW.root_id<>a.root_id OR NEW.lane<>a.lane OR NEW.principal_digest<>a.principal_digest OR NEW.issuer_epoch<>a.issuer_epoch OR NEW.binding IS DISTINCT FROM a.intent->'Lifecycle' THEN RAISE EXCEPTION 'audit lifecycle recovery unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF pg_trigger_depth()<2 OR NEW.certificate_verify_attempts<>0 OR NEW.binding->'Policy'->'History'->>'Layout' IS DISTINCT FROM 'operation-audit-history/v3' OR NEW.overdue_selected_at IS NOT NULL OR NEW.overdue_purge IS NOT NULL OR NEW.intent_completion IS NOT NULL OR NEW.outcome_completion IS NOT NULL OR NEW.lease IS NOT NULL OR NEW.retirement IS NOT NULL OR NEW.certificate_started OR NEW.certificate_completion IS NOT NULL OR NEW.certificate_receipt IS NOT NULL OR NEW.terminal_purge IS NOT NULL OR NEW.terminal_acknowledged_at IS NOT NULL OR NEW.finalization_xid IS NOT NULL THEN RAISE EXCEPTION 'audit lifecycle is source managed' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.operation_id,NEW.root_id,NEW.lane,NEW.principal_digest,NEW.installation_id,NEW.issuer_epoch,NEW.postmaster_at,NEW.database_oid,NEW.binding,NEW.original_purge_at,NEW.certificate_purge_at,NEW.live_retire_by) IS DISTINCT FROM ROW(OLD.operation_id,OLD.root_id,OLD.lane,OLD.principal_digest,OLD.installation_id,OLD.issuer_epoch,OLD.postmaster_at,OLD.database_oid,OLD.binding,OLD.original_purge_at,OLD.certificate_purge_at,OLD.live_retire_by) OR
  OLD.intent_completion IS NOT NULL AND NEW.intent_completion IS DISTINCT FROM OLD.intent_completion OR OLD.outcome_completion IS NOT NULL AND NEW.outcome_completion IS DISTINCT FROM OLD.outcome_completion OR
  OLD.overdue_selected_at IS NOT NULL AND NEW.overdue_selected_at IS DISTINCT FROM OLD.overdue_selected_at OR
  OLD.retirement IS NOT NULL AND NEW.retirement IS DISTINCT FROM OLD.retirement OR OLD.certificate_started AND NOT NEW.certificate_started OR
  OLD.certificate_completion IS NOT NULL AND NEW.certificate_completion IS DISTINCT FROM OLD.certificate_completion OR OLD.certificate_receipt IS NOT NULL AND NEW.certificate_receipt IS DISTINCT FROM OLD.certificate_receipt OR
  OLD.certificate_acknowledged_at IS NOT NULL AND NEW.certificate_acknowledged_at IS DISTINCT FROM OLD.certificate_acknowledged_at OR
  OLD.finalization_xid IS NOT NULL AND NEW.finalization_xid IS DISTINCT FROM OLD.finalization_xid THEN RAISE EXCEPTION 'immutable audit lifecycle' USING ERRCODE='23514'; END IF;
 IF NEW.overdue_selected_at IS NOT NULL THEN
  IF NEW.binding->'Policy'->>'OverdueTerminal' IS DISTINCT FROM 'overdue-original/v1' OR NEW.certificate_started OR NEW.certificate_completion IS NOT NULL OR NEW.certificate_receipt IS NOT NULL OR NEW.certificate_acknowledged_at IS NOT NULL OR NEW.terminal_purge IS NOT NULL THEN
   RAISE EXCEPTION 'overdue certificate fence unavailable' USING ERRCODE='23514'; END IF;
  IF OLD.overdue_selected_at IS NULL AND
   (NEW.overdue_selected_at>n OR NEW.overdue_selected_at<NEW.certificate_purge_at-make_interval(secs=>(NEW.binding->'Policy'->>'ProofWindowSeconds')::double precision) OR
    NEW.lease->>'Phase' IS DISTINCT FROM 'overdueOriginal' OR NEW.overdue_selected_at<>(NEW.lease->>'StartedAt')::timestamptz OR NEW.lease IS NOT DISTINCT FROM OLD.lease) THEN
   RAISE EXCEPTION 'overdue mode must be atomically leased' USING ERRCODE='23514'; END IF;
 ELSIF NEW.overdue_purge IS NOT NULL THEN RAISE EXCEPTION 'overdue proof without fence' USING ERRCODE='23514'; END IF;
 FOREACH phase IN ARRAY ARRAY['intent','outcome','deletion-certificate'] LOOP
  IF phase='intent' THEN c:=NEW.intent_completion;original:=OLD.intent_completion;
  ELSIF phase='outcome' THEN c:=NEW.outcome_completion;original:=OLD.outcome_completion;
  ELSE c:=NEW.certificate_completion;original:=OLD.certificate_completion;END IF;
  IF c IS NOT NULL AND original IS NULL THEN
   IF c->>'Protocol' IS DISTINCT FROM 'closed-operation-audit/v1' OR (c->>'RootID')::uuid<>NEW.root_id OR (c->>'OperationID')::uuid<>NEW.operation_id OR c->>'StoreID'<>NEW.binding->'Policy'->>'StoreID' OR c->>'Phase'<>phase OR
    NOT(c ?& ARRAY['Protocol','RootID','OperationID','StoreID','Phase','RecordDigest','Receipt','StoredAt','ClosedAt']) OR
    jsonb_array_length(c->'RecordDigest')<>32 OR c->'Receipt'->>'Key'<>'operation-audit/v1/'||NEW.root_id::text||'/'||NEW.operation_id::text||'/'||phase OR
    (c->'Receipt'->>'Bytes')::bigint NOT BETWEEN 1 AND 65536 OR jsonb_array_length(c->'Receipt'->'SHA256')<>32 OR
    (c->>'StoredAt')::timestamptz>(c->>'ClosedAt')::timestamptz OR (c->>'ClosedAt')::timestamptz>n OR
    phase<>'deletion-certificate' AND (n>=a.write_until OR (c->>'StoredAt')::timestamptz<(a.intent->>'CreatedAt')::timestamptz OR (phase='intent' AND NOT a.intent_started) OR (phase='outcome' AND NOT a.outcome_started)) OR
    phase='deletion-certificate' AND (NOT NEW.certificate_started OR n>=(NEW.retirement->>'CertificateWriteUntil')::timestamptz OR (c->>'StoredAt')::timestamptz<(NEW.retirement->>'PurgedAt')::timestamptz) THEN RAISE EXCEPTION 'positive audit writer completion unavailable' USING ERRCODE='23514'; END IF;
  END IF;
 END LOOP;
 IF NEW.lease IS DISTINCT FROM OLD.lease THEN
  -- Source-managed reset: cleanup has no UPDATE privilege on acknowledgements.
  NEW.terminal_purge:=NULL; NEW.overdue_purge:=NULL; NEW.terminal_acknowledged_at:=NULL;
  IF NEW.lease_fence>(NEW.binding->'Policy'->>'MaxPurgeLeases')::bigint OR NEW.lease_fence<>OLD.lease_fence+1 OR OLD.lease IS NOT NULL AND n<(OLD.lease->>'Until')::timestamptz OR NEW.finalization_xid IS NOT NULL OR
   NOT(NEW.lease ?& ARRAY['RootID','OperationID','StoreID','InstallationID','IssuerEpoch','Phase','PostmasterAt','DatabaseOID','ObjectsDigest','WritersDigest','Fence','StartedAt','Until']) OR
   (NEW.lease->>'RootID')::uuid<>NEW.root_id OR (NEW.lease->>'OperationID')::uuid<>NEW.operation_id OR NEW.lease->>'StoreID'<>NEW.binding->'Policy'->>'StoreID' OR (NEW.lease->>'InstallationID')::uuid<>NEW.installation_id OR (NEW.lease->>'IssuerEpoch')::uuid<>NEW.issuer_epoch OR
   (NEW.lease->>'PostmasterAt')::timestamptz<>NEW.postmaster_at OR (NEW.lease->>'DatabaseOID')::oid<>NEW.database_oid OR (NEW.lease->>'Fence')::bigint<>NEW.lease_fence OR (NEW.lease->>'StartedAt')::timestamptz>n OR n>=(NEW.lease->>'Until')::timestamptz OR (NEW.lease->>'Until')::timestamptz>(NEW.lease->>'StartedAt')::timestamptz+interval '5 seconds' OR
   a.intent_receipt IS NULL OR a.outcome_receipt IS NULL OR NEW.intent_completion->'Receipt' IS DISTINCT FROM a.intent_receipt OR NEW.outcome_completion->'Receipt' IS DISTINCT FROM a.outcome_receipt OR n<a.write_until OR
   NEW.lease->>'Phase' NOT IN ('original','terminal','overdueOriginal') OR
   NEW.lease->>'Phase'='original' AND (NEW.overdue_selected_at IS NOT NULL OR NEW.retirement IS NOT NULL OR n<NEW.original_purge_at OR n>=NEW.certificate_purge_at-make_interval(secs=>(NEW.binding->'Policy'->>'ProofWindowSeconds')::double precision)) OR
   NEW.lease->>'Phase'='overdueOriginal' AND (NEW.overdue_selected_at IS NULL OR NEW.certificate_started OR n<NEW.certificate_purge_at-make_interval(secs=>(NEW.binding->'Policy'->>'ProofWindowSeconds')::double precision)) OR
   NEW.lease->>'Phase'='terminal' AND (NEW.overdue_selected_at IS NOT NULL OR NEW.certificate_receipt IS NULL OR NEW.certificate_completion IS NULL OR n<NEW.certificate_purge_at) OR
   NEW.terminal_purge IS NOT NULL OR NEW.terminal_acknowledged_at IS NOT NULL THEN RAISE EXCEPTION 'audit purge lease unavailable' USING ERRCODE='23514'; END IF;
 ELSIF NEW.lease_fence<>OLD.lease_fence THEN RAISE EXCEPTION 'immutable audit purge fence' USING ERRCODE='23514'; END IF;
 IF NEW.retirement IS NOT NULL AND OLD.retirement IS NULL THEN
  IF NOT(NEW.retirement ?& ARRAY['RootID','OperationID','StoreID','InstallationID','IssuerEpoch','PostmasterAt','DatabaseOID','ObjectsDigest','WritersDigest','PurgeFence','PurgedAt','CertificateWriteUntil','CertificatePurgeAt','LiveRetireBy']) OR NEW.lease->>'Phase'<>'original' OR n>=(NEW.lease->>'Until')::timestamptz OR
   (NEW.retirement->>'RootID')::uuid<>NEW.root_id OR (NEW.retirement->>'OperationID')::uuid<>NEW.operation_id OR NEW.retirement->>'StoreID'<>NEW.binding->'Policy'->>'StoreID' OR
   (NEW.retirement->>'InstallationID')::uuid<>NEW.installation_id OR (NEW.retirement->>'IssuerEpoch')::uuid<>NEW.issuer_epoch OR (NEW.retirement->>'PostmasterAt')::timestamptz<>NEW.postmaster_at OR (NEW.retirement->>'DatabaseOID')::oid<>NEW.database_oid OR
   (NEW.retirement->>'PurgeFence')::bigint<>NEW.lease_fence OR NEW.retirement->'ObjectsDigest' IS DISTINCT FROM NEW.lease->'ObjectsDigest' OR NEW.retirement->'WritersDigest' IS DISTINCT FROM NEW.lease->'WritersDigest' OR
   (NEW.retirement->>'PurgedAt')::timestamptz<(NEW.lease->>'StartedAt')::timestamptz OR (NEW.retirement->>'PurgedAt')::timestamptz>n OR
   (NEW.retirement->>'CertificateWriteUntil')::timestamptz>LEAST((NEW.retirement->>'PurgedAt')::timestamptz+interval '30 seconds',NEW.certificate_purge_at-make_interval(secs=>(NEW.binding->'Policy'->>'ProofWindowSeconds')::double precision)) OR n>=(NEW.retirement->>'CertificateWriteUntil')::timestamptz OR
   (NEW.retirement->>'CertificatePurgeAt')::timestamptz<>NEW.certificate_purge_at OR (NEW.retirement->>'LiveRetireBy')::timestamptz<>NEW.live_retire_by THEN RAISE EXCEPTION 'audit purge result mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.certificate_started AND NOT OLD.certificate_started AND (NEW.retirement IS NULL OR n>=(NEW.retirement->>'CertificateWriteUntil')::timestamptz) THEN RAISE EXCEPTION 'audit certificate interval expired' USING ERRCODE='23514'; END IF;
 -- Only the independent acknowledgement credential can UPDATE this column.
 -- One exact stand-alone transition spends one attempt before provider I/O.
 IF NEW.certificate_verify_attempts IS DISTINCT FROM OLD.certificate_verify_attempts THEN
  IF NEW.certificate_verify_attempts<>OLD.certificate_verify_attempts+1 OR OLD.certificate_verify_attempts>=2 OR
   (to_jsonb(NEW)-'certificate_verify_attempts') IS DISTINCT FROM (to_jsonb(OLD)-'certificate_verify_attempts') OR
   NEW.binding->'Policy'->'History'->>'Layout' IS DISTINCT FROM 'operation-audit-history/v3' OR
   NEW.overdue_selected_at IS NOT NULL OR NEW.retirement IS NULL OR NOT NEW.certificate_started OR NEW.certificate_completion IS NULL OR
   NEW.certificate_receipt IS NOT NULL OR NEW.certificate_acknowledged_at IS NOT NULL OR
   n>=(NEW.retirement->>'CertificateWriteUntil')::timestamptz THEN
   RAISE EXCEPTION 'audit certificate verification attempt unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.certificate_receipt IS DISTINCT FROM OLD.certificate_receipt OR NEW.certificate_acknowledged_at IS DISTINCT FROM OLD.certificate_acknowledged_at THEN
  IF NEW.binding->'Policy'->'History'->>'Layout' IS DISTINCT FROM 'operation-audit-history/v3' OR NEW.certificate_verify_attempts<1 OR NEW.certificate_receipt IS DISTINCT FROM NEW.certificate_completion->'Receipt' OR NEW.certificate_acknowledged_at IS NULL OR NEW.certificate_acknowledged_at>n OR NEW.certificate_acknowledged_at<(NEW.certificate_completion->>'ClosedAt')::timestamptz OR n>=(NEW.retirement->>'CertificateWriteUntil')::timestamptz THEN RAISE EXCEPTION 'audit certificate acknowledgement unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.lease IS NOT DISTINCT FROM OLD.lease AND NEW.terminal_purge IS DISTINCT FROM OLD.terminal_purge THEN
  IF NOT(NEW.terminal_purge ?& ARRAY['RootID','OperationID','RetirementDigest','CertificateDigest','Fence','PurgedAt','LeaseUntil']) OR OLD.terminal_acknowledged_at IS NOT NULL OR NEW.terminal_purge IS NULL OR NEW.lease->>'Phase'<>'terminal' OR n>=(NEW.lease->>'Until')::timestamptz OR
   (NEW.terminal_purge->>'RootID')::uuid<>NEW.root_id OR (NEW.terminal_purge->>'OperationID')::uuid<>NEW.operation_id OR (NEW.terminal_purge->>'Fence')::bigint<>NEW.lease_fence OR
   (NEW.terminal_purge->>'PurgedAt')::timestamptz<(NEW.lease->>'StartedAt')::timestamptz OR (NEW.terminal_purge->>'PurgedAt')::timestamptz>n OR (NEW.terminal_purge->>'LeaseUntil')::timestamptz<>(NEW.lease->>'Until')::timestamptz THEN RAISE EXCEPTION 'terminal audit purge unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.lease IS NOT DISTINCT FROM OLD.lease AND NEW.overdue_purge IS DISTINCT FROM OLD.overdue_purge THEN
  IF NEW.overdue_selected_at IS NULL OR NEW.overdue_purge IS NULL OR OLD.overdue_purge IS NOT NULL OR OLD.terminal_acknowledged_at IS NOT NULL OR NEW.lease->>'Phase' IS DISTINCT FROM 'overdueOriginal' OR
   NOT(NEW.overdue_purge ?& ARRAY['RootID','OperationID','Mode','BindingDigest','ObjectsDigest','WritersDigest','Fence','SelectedAt','PurgedAt','LeaseUntil']) OR
   (NEW.overdue_purge->>'RootID')::uuid<>NEW.root_id OR (NEW.overdue_purge->>'OperationID')::uuid<>NEW.operation_id OR NEW.overdue_purge->>'Mode' IS DISTINCT FROM 'overdue-original/v1' OR
   jsonb_array_length(NEW.overdue_purge->'BindingDigest')<>32 OR NEW.overdue_purge->'ObjectsDigest' IS DISTINCT FROM NEW.lease->'ObjectsDigest' OR NEW.overdue_purge->'WritersDigest' IS DISTINCT FROM NEW.lease->'WritersDigest' OR
   (NEW.overdue_purge->>'Fence')::bigint<>NEW.lease_fence OR (NEW.overdue_purge->>'SelectedAt')::timestamptz<>NEW.overdue_selected_at OR
   (NEW.overdue_purge->>'PurgedAt')::timestamptz<(NEW.lease->>'StartedAt')::timestamptz OR (NEW.overdue_purge->>'PurgedAt')::timestamptz>n OR
   (NEW.overdue_purge->>'LeaseUntil')::timestamptz<>(NEW.lease->>'Until')::timestamptz OR n>=(NEW.lease->>'Until')::timestamptz THEN
   RAISE EXCEPTION 'overdue purge result mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.lease IS NOT DISTINCT FROM OLD.lease AND NEW.terminal_acknowledged_at IS DISTINCT FROM OLD.terminal_acknowledged_at THEN
  IF NEW.overdue_selected_at IS NULL THEN original:=NEW.terminal_purge; ELSE original:=NEW.overdue_purge; END IF;
  IF original IS NULL OR OLD.terminal_acknowledged_at IS NOT NULL OR NEW.terminal_acknowledged_at IS NULL OR NEW.terminal_acknowledged_at>n OR NEW.terminal_acknowledged_at<(original->>'PurgedAt')::timestamptz OR n>=(NEW.lease->>'Until')::timestamptz THEN RAISE EXCEPTION 'terminal audit acknowledgement unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.finalization_xid IS DISTINCT FROM OLD.finalization_xid AND (NEW.finalization_xid IS DISTINCT FROM pg_current_xact_id() OR NEW.terminal_acknowledged_at IS NULL OR n>=(NEW.lease->>'Until')::timestamptz) THEN RAISE EXCEPTION 'audit finalization unavailable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION guard_operation_audit_pool() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'audit backing retirement unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.proof_window_missed<>0 OR NEW.revision<>1 OR NEW.accounts<>0 OR NEW.history_profile IS NOT NULL OR NEW.history_backing_until IS NOT NULL THEN RAISE EXCEPTION 'invalid initial audit backing' USING ERRCODE='23514'; END IF;
 ELSE
  IF NEW.proof_window_missed<>OLD.proof_window_missed AND (pg_trigger_depth()<2 OR NEW.proof_window_missed<>LEAST(OLD.proof_window_missed+1,1152921504606846976)) THEN RAISE EXCEPTION 'proof window aggregate is source managed' USING ERRCODE='23514'; END IF;
  IF ROW(NEW.root_id,NEW.lane,NEW.account_version) IS DISTINCT FROM ROW(OLD.root_id,OLD.lane,OLD.account_version) THEN
   RAISE EXCEPTION 'immutable audit backing identity' USING ERRCODE='23514'; END IF;
  IF ROW(NEW.history_profile,NEW.history_backing_until) IS DISTINCT FROM ROW(OLD.history_profile,OLD.history_backing_until) THEN
   IF pg_trigger_depth()<2 OR NEW.history_profile IS NULL OR NEW.history_backing_until IS NULL OR
    OLD.history_backing_until IS NOT NULL AND NEW.history_backing_until<OLD.history_backing_until OR
    OLD.history_profile IS NOT NULL AND NEW.history_profile IS DISTINCT FROM OLD.history_profile AND
     NOT public.operation_audit_profile_covers(NEW.history_profile,OLD.history_profile) AND
     (clock_timestamp()<OLD.history_backing_until OR EXISTS(SELECT 1 FROM public.operation_audit_lifecycle WHERE root_id=OLD.root_id AND lane=OLD.lane) OR EXISTS(SELECT 1 FROM public.operation_audit_history WHERE root_id=OLD.root_id AND lane=OLD.lane)) THEN
    RAISE EXCEPTION 'audit residual backing is source managed' USING ERRCODE='23514'; END IF;
  END IF;
  IF (NEW.account_limit<OLD.account_limit OR NEW.records_per_account<OLD.records_per_account) AND
   ((OLD.history_backing_until IS NOT NULL AND clock_timestamp()<OLD.history_backing_until) OR
    EXISTS(SELECT 1 FROM public.operation_audit_lifecycle WHERE root_id=OLD.root_id AND lane=OLD.lane AND (binding->'Policy'->>'BackupHorizonSeconds')::bigint>0) OR
    EXISTS(SELECT 1 FROM public.operation_audit_history WHERE root_id=OLD.root_id AND lane=OLD.lane)) THEN
   RAISE EXCEPTION 'audit residual backing cannot shrink' USING ERRCODE='23514'; END IF;
  IF NEW.accounts<>OLD.accounts AND (pg_trigger_depth()<2 OR
   (NEW.accounts<>OLD.accounts+1 AND NOT (NEW.accounts=OLD.accounts-1 AND
    (EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.root_id=OLD.root_id AND d.lane=OLD.lane AND d.finalization_xid=pg_current_xact_id() AND d.terminal_acknowledged_at IS NOT NULL) OR
     EXISTS(SELECT 1 FROM public.operation_audit_history h WHERE h.root_id=OLD.root_id AND h.lane=OLD.lane AND h.drain_xid=pg_current_xact_id()))))) THEN
   RAISE EXCEPTION 'audit accounts source managed' USING ERRCODE='23514'; END IF;
  IF ROW(NEW.revision,NEW.paused,NEW.valid_until,NEW.account_limit,NEW.records_per_account,NEW.retained_seconds) IS DISTINCT FROM ROW(OLD.revision,OLD.paused,OLD.valid_until,OLD.account_limit,OLD.records_per_account,OLD.retained_seconds) AND
   (NEW.revision<>OLD.revision+1 OR NEW.accounts<>OLD.accounts) THEN RAISE EXCEPTION 'audit backing revision mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 IF EXISTS(SELECT 1 FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND charged>NEW.records_per_account) THEN
  RAISE EXCEPTION 'audit backing below retained spend' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION operation_audit_profile_covers(jsonb,jsonb) FROM PUBLIC;
