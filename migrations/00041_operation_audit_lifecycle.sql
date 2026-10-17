-- +goose Up
-- Protocol opt-in only. Each original charged record backs one fixed child plus
-- its indexes. No historical receipt is upgraded to writer completion.
-- Root-only accounting protects the last residual backup generation after its
-- principal row disappears. These are not identity, recovery or retention leases.
ALTER TABLE operation_audit_pool ADD COLUMN history_profile jsonb
 CHECK(history_profile IS NULL OR (jsonb_typeof(history_profile)='object' AND octet_length(history_profile::text)<=4096));
ALTER TABLE operation_audit_pool ADD COLUMN history_backing_until timestamptz
 CHECK(history_backing_until IS NULL OR isfinite(history_backing_until));
ALTER TABLE operation_audit_pool ADD CONSTRAINT operation_audit_history_backing_pair CHECK((history_profile IS NULL)=(history_backing_until IS NULL));

CREATE TABLE operation_audit_lifecycle (
 operation_id uuid PRIMARY KEY REFERENCES operation_audit(id) DEFERRABLE INITIALLY DEFERRED,
 root_id uuid NOT NULL, lane text NOT NULL CHECK(lane IN ('normal','resolution')),
 principal_digest bytea NOT NULL CHECK(octet_length(principal_digest)=32),
 installation_id uuid NOT NULL, issuer_epoch uuid NOT NULL,
 postmaster_at timestamptz NOT NULL CHECK(isfinite(postmaster_at)), database_oid oid NOT NULL,
 binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object' AND octet_length(binding::text)<=4096),
 original_purge_at timestamptz NOT NULL CHECK(isfinite(original_purge_at)),
 certificate_purge_at timestamptz NOT NULL CHECK(isfinite(certificate_purge_at)),
 live_retire_by timestamptz NOT NULL CHECK(isfinite(live_retire_by)),
 intent_completion jsonb CHECK(intent_completion IS NULL OR (jsonb_typeof(intent_completion)='object' AND octet_length(intent_completion::text)<=8192)),
 outcome_completion jsonb CHECK(outcome_completion IS NULL OR (jsonb_typeof(outcome_completion)='object' AND octet_length(outcome_completion::text)<=8192)),
 lease_fence bigint NOT NULL DEFAULT 0 CHECK(lease_fence BETWEEN 0 AND 1152921504606846976),
 lease jsonb CHECK(lease IS NULL OR (jsonb_typeof(lease)='object' AND octet_length(lease::text)<=4096)),
 retirement jsonb CHECK(retirement IS NULL OR (jsonb_typeof(retirement)='object' AND octet_length(retirement::text)<=4096)),
 certificate_started boolean NOT NULL DEFAULT false,
 certificate_completion jsonb CHECK(certificate_completion IS NULL OR (jsonb_typeof(certificate_completion)='object' AND octet_length(certificate_completion::text)<=8192)),
 certificate_receipt jsonb CHECK(certificate_receipt IS NULL OR (jsonb_typeof(certificate_receipt)='object' AND octet_length(certificate_receipt::text)<=4096)),
 certificate_acknowledged_at timestamptz CHECK(certificate_acknowledged_at IS NULL OR isfinite(certificate_acknowledged_at)),
 terminal_purge jsonb CHECK(terminal_purge IS NULL OR (jsonb_typeof(terminal_purge)='object' AND octet_length(terminal_purge::text)<=4096)),
 terminal_acknowledged_at timestamptz CHECK(terminal_acknowledged_at IS NULL OR isfinite(terminal_acknowledged_at)),
 finalization_xid xid8,
 CHECK(original_purge_at<certificate_purge_at AND certificate_purge_at<live_retire_by),
 CHECK((lease IS NULL)=(lease_fence=0)),
 CHECK(NOT certificate_started OR retirement IS NOT NULL),
 CHECK(certificate_completion IS NULL OR certificate_started),
 CHECK((certificate_receipt IS NULL)=(certificate_acknowledged_at IS NULL)),
 CHECK(certificate_receipt IS NULL OR certificate_completion IS NOT NULL),
 CHECK(terminal_purge IS NULL OR certificate_receipt IS NOT NULL),
 CHECK(terminal_acknowledged_at IS NULL OR terminal_purge IS NOT NULL),
 CHECK(finalization_xid IS NULL OR terminal_acknowledged_at IS NOT NULL)
);
CREATE INDEX operation_audit_lifecycle_due ON operation_audit_lifecycle(root_id,lane,original_purge_at,operation_id);

-- Aggregate cooling retains no operation, trace, full actor or case identifier.
-- The principal HMAC remains a stable pseudonymous human identifier.
-- Each count keeps its ORIGINAL account/record charge; the number of rows is
-- therefore bounded by the original admitted record slots, not a second queue.
CREATE TABLE operation_audit_history (
 root_id uuid NOT NULL, lane text NOT NULL CHECK(lane IN ('normal','resolution')),
 principal_digest bytea NOT NULL CHECK(octet_length(principal_digest)=32),
 release_at timestamptz NOT NULL CHECK(isfinite(release_at)),
 delete_by timestamptz NOT NULL CHECK(isfinite(delete_by)),
 hard_delete_by timestamptz NOT NULL CHECK(isfinite(hard_delete_by)),
 eligible_at timestamptz NOT NULL CHECK(isfinite(eligible_at)),
 installation_id uuid NOT NULL, issuer_epoch uuid NOT NULL,
 postmaster_at timestamptz NOT NULL CHECK(isfinite(postmaster_at)), database_oid oid NOT NULL,
 horizon_seconds bigint NOT NULL CHECK(horizon_seconds BETWEEN 1 AND 316224000),
 history_policy jsonb NOT NULL CHECK(jsonb_typeof(history_policy)='object' AND octet_length(history_policy::text)<=4096),
 records bigint NOT NULL CHECK(records BETWEEN 1 AND 1000000000),
 overdue boolean NOT NULL, drain_xid xid8,
 PRIMARY KEY(root_id,lane,principal_digest,release_at,delete_by),
 FOREIGN KEY(root_id,lane,principal_digest) REFERENCES operation_audit_account(root_id,lane,principal_digest) DEFERRABLE INITIALLY DEFERRED,
 CHECK(release_at<delete_by AND delete_by<hard_delete_by AND eligible_at>=release_at)
);
CREATE INDEX operation_audit_history_due ON operation_audit_history(root_id,lane,eligible_at,release_at,delete_by,principal_digest);

-- +goose StatementBegin
CREATE FUNCTION operation_lifecycle_retiring(r uuid,l text,p bytea) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.root_id=r AND d.lane=l AND d.principal_digest=p AND d.finalization_xid=pg_current_xact_id() AND d.terminal_acknowledged_at IS NOT NULL)
$$;
CREATE FUNCTION operation_history_releasing(r uuid,l text,p bytea) RETURNS bigint
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(sum(records),0)::bigint FROM public.operation_audit_history WHERE root_id=r AND lane=l AND principal_digest=p AND drain_xid=pg_current_xact_id()
$$;
CREATE FUNCTION create_operation_audit_lifecycle() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
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
 IF b->>'Protocol' IS DISTINCT FROM 'closed-operation-audit/v1' OR jsonb_typeof(p)<>'object' OR
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
 IF horizon>interval '0 seconds' THEN
  IF p->'History' IS NULL OR p->'History'->>'Layout' IS DISTINCT FROM 'operation-audit-history/v1' OR
   NOT(p->'History' ?& ARRAY['ID','Digest','Layout','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies']) OR
   (p->'History'->>'ID')::uuid IS NULL OR jsonb_array_length(p->'History'->'Digest')<>32 OR
   (p->'History'->>'MaximumRowFootprintBytes')::bigint NOT BETWEEN 131072 AND 16777216 OR
   (p->'History'->>'MaximumTransitionWALBytes')::bigint NOT BETWEEN 131072 AND 67108864 OR
   (p->'History'->>'BackupCopies')::bigint NOT BETWEEN 1 AND 64 OR (p->'History'->>'WALCopies')::bigint NOT BETWEEN 1 AND 64 OR
   (p->>'BackupReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'MaximumRowFootprintBytes')::bigint*(p->'History'->>'BackupCopies')::bigint OR
   (p->>'WALReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'MaximumTransitionWALBytes')::bigint*(p->'History'->>'WALCopies')::bigint*(16+3*(p->>'MaxPurgeLeases')::bigint) THEN
   RAISE EXCEPTION 'audit history qualification unavailable' USING ERRCODE='23514'; END IF;
 ELSIF p ? 'History' THEN RAISE EXCEPTION 'unexpected zero-history qualification' USING ERRCODE='23514'; END IF;
 IF a.history_backing_until IS NOT NULL AND n<a.history_backing_until AND a.history_profile IS DISTINCT FROM
  (p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']) THEN
  RAISE EXCEPTION 'residual audit history backing protected' USING ERRCODE='23514'; END IF;
 -- Renewal may refresh a source/revision or increase backing. Outstanding
 -- obligations cannot be moved to a smaller/different backup or account profile.
 IF EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.root_id=NEW.root_id AND d.lane=NEW.lane AND
   ((d.binding->'Policy') - ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']) IS DISTINCT FROM
   (p - ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds'])) OR
  EXISTS(SELECT 1 FROM public.operation_audit_history h WHERE h.root_id=NEW.root_id AND h.lane=NEW.lane AND h.history_policy IS DISTINCT FROM
   (p - ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds'])) THEN
  RAISE EXCEPTION 'outstanding audit history profile mismatch' USING ERRCODE='23514'; END IF;
 IF horizon>interval '0 seconds' THEN
  UPDATE public.operation_audit_pool SET
   history_profile=p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds'],
   history_backing_until=GREATEST(history_backing_until,NEW.retain_until)
  WHERE root_id=NEW.root_id AND lane=NEW.lane;
 END IF;
 INSERT INTO public.operation_audit_lifecycle(operation_id,root_id,lane,principal_digest,installation_id,issuer_epoch,postmaster_at,database_oid,binding,original_purge_at,certificate_purge_at,live_retire_by)
 VALUES(NEW.id,NEW.root_id,NEW.lane,NEW.principal_digest,t.installation_id,t.issuer_epoch,pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()),b,(b->>'OriginalPurgeAt')::timestamptz,(b->>'CertificatePurgeAt')::timestamptz,(b->>'LiveRetireBy')::timestamptz);
 RETURN NEW;
END $$;

CREATE FUNCTION guard_operation_audit_lifecycle() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
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
 IF t.recovery_blocked OR t.suspended OR n>=t.fresh_until OR t.observed_at>n OR t.issuer_epoch<>NEW.issuer_epoch OR pg_postmaster_start_time()<>NEW.postmaster_at OR (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())<>NEW.database_oid OR NEW.root_id<>a.root_id OR NEW.lane<>a.lane OR NEW.principal_digest<>a.principal_digest OR NEW.issuer_epoch<>a.issuer_epoch OR NEW.binding IS DISTINCT FROM a.intent->'Lifecycle' THEN RAISE EXCEPTION 'audit lifecycle recovery unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF pg_trigger_depth()<2 OR NEW.intent_completion IS NOT NULL OR NEW.outcome_completion IS NOT NULL OR NEW.lease IS NOT NULL OR NEW.retirement IS NOT NULL OR NEW.certificate_started OR NEW.certificate_completion IS NOT NULL OR NEW.certificate_receipt IS NOT NULL OR NEW.terminal_purge IS NOT NULL OR NEW.terminal_acknowledged_at IS NOT NULL OR NEW.finalization_xid IS NOT NULL THEN RAISE EXCEPTION 'audit lifecycle is source managed' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.operation_id,NEW.root_id,NEW.lane,NEW.principal_digest,NEW.installation_id,NEW.issuer_epoch,NEW.postmaster_at,NEW.database_oid,NEW.binding,NEW.original_purge_at,NEW.certificate_purge_at,NEW.live_retire_by) IS DISTINCT FROM ROW(OLD.operation_id,OLD.root_id,OLD.lane,OLD.principal_digest,OLD.installation_id,OLD.issuer_epoch,OLD.postmaster_at,OLD.database_oid,OLD.binding,OLD.original_purge_at,OLD.certificate_purge_at,OLD.live_retire_by) OR
  OLD.intent_completion IS NOT NULL AND NEW.intent_completion IS DISTINCT FROM OLD.intent_completion OR OLD.outcome_completion IS NOT NULL AND NEW.outcome_completion IS DISTINCT FROM OLD.outcome_completion OR
  OLD.retirement IS NOT NULL AND NEW.retirement IS DISTINCT FROM OLD.retirement OR OLD.certificate_started AND NOT NEW.certificate_started OR
  OLD.certificate_completion IS NOT NULL AND NEW.certificate_completion IS DISTINCT FROM OLD.certificate_completion OR OLD.certificate_receipt IS NOT NULL AND NEW.certificate_receipt IS DISTINCT FROM OLD.certificate_receipt OR
  OLD.certificate_acknowledged_at IS NOT NULL AND NEW.certificate_acknowledged_at IS DISTINCT FROM OLD.certificate_acknowledged_at OR
  OLD.finalization_xid IS NOT NULL AND NEW.finalization_xid IS DISTINCT FROM OLD.finalization_xid THEN RAISE EXCEPTION 'immutable audit lifecycle' USING ERRCODE='23514'; END IF;
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
  NEW.terminal_purge:=NULL; NEW.terminal_acknowledged_at:=NULL;
  IF NEW.lease_fence>(NEW.binding->'Policy'->>'MaxPurgeLeases')::bigint OR NEW.lease_fence<>OLD.lease_fence+1 OR OLD.lease IS NOT NULL AND n<(OLD.lease->>'Until')::timestamptz OR NEW.finalization_xid IS NOT NULL OR
   NOT(NEW.lease ?& ARRAY['RootID','OperationID','StoreID','InstallationID','IssuerEpoch','Phase','PostmasterAt','DatabaseOID','ObjectsDigest','WritersDigest','Fence','StartedAt','Until']) OR
   (NEW.lease->>'RootID')::uuid<>NEW.root_id OR (NEW.lease->>'OperationID')::uuid<>NEW.operation_id OR NEW.lease->>'StoreID'<>NEW.binding->'Policy'->>'StoreID' OR (NEW.lease->>'InstallationID')::uuid<>NEW.installation_id OR (NEW.lease->>'IssuerEpoch')::uuid<>NEW.issuer_epoch OR
   (NEW.lease->>'PostmasterAt')::timestamptz<>NEW.postmaster_at OR (NEW.lease->>'DatabaseOID')::oid<>NEW.database_oid OR (NEW.lease->>'Fence')::bigint<>NEW.lease_fence OR (NEW.lease->>'StartedAt')::timestamptz>n OR n>=(NEW.lease->>'Until')::timestamptz OR (NEW.lease->>'Until')::timestamptz>(NEW.lease->>'StartedAt')::timestamptz+interval '5 seconds' OR
   a.intent_receipt IS NULL OR a.outcome_receipt IS NULL OR NEW.intent_completion->'Receipt' IS DISTINCT FROM a.intent_receipt OR NEW.outcome_completion->'Receipt' IS DISTINCT FROM a.outcome_receipt OR n<a.write_until OR
   NEW.lease->>'Phase' NOT IN ('original','terminal') OR
   NEW.lease->>'Phase'='original' AND (NEW.retirement IS NOT NULL OR n<NEW.original_purge_at OR n>=NEW.certificate_purge_at-make_interval(secs=>(NEW.binding->'Policy'->>'ProofWindowSeconds')::double precision)) OR
   NEW.lease->>'Phase'='terminal' AND (NEW.certificate_receipt IS NULL OR NEW.certificate_completion IS NULL OR n<NEW.certificate_purge_at) OR
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
 IF NEW.certificate_receipt IS DISTINCT FROM OLD.certificate_receipt OR NEW.certificate_acknowledged_at IS DISTINCT FROM OLD.certificate_acknowledged_at THEN
  IF NEW.certificate_receipt IS DISTINCT FROM NEW.certificate_completion->'Receipt' OR NEW.certificate_acknowledged_at IS NULL OR NEW.certificate_acknowledged_at>n OR NEW.certificate_acknowledged_at<(NEW.certificate_completion->>'ClosedAt')::timestamptz OR n>=(NEW.retirement->>'CertificateWriteUntil')::timestamptz THEN RAISE EXCEPTION 'audit certificate acknowledgement unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.lease IS NOT DISTINCT FROM OLD.lease AND NEW.terminal_purge IS DISTINCT FROM OLD.terminal_purge THEN
  IF NOT(NEW.terminal_purge ?& ARRAY['RootID','OperationID','RetirementDigest','CertificateDigest','Fence','PurgedAt','LeaseUntil']) OR OLD.terminal_acknowledged_at IS NOT NULL OR NEW.terminal_purge IS NULL OR NEW.lease->>'Phase'<>'terminal' OR n>=(NEW.lease->>'Until')::timestamptz OR
   (NEW.terminal_purge->>'RootID')::uuid<>NEW.root_id OR (NEW.terminal_purge->>'OperationID')::uuid<>NEW.operation_id OR (NEW.terminal_purge->>'Fence')::bigint<>NEW.lease_fence OR
   (NEW.terminal_purge->>'PurgedAt')::timestamptz<(NEW.lease->>'StartedAt')::timestamptz OR (NEW.terminal_purge->>'PurgedAt')::timestamptz>n OR (NEW.terminal_purge->>'LeaseUntil')::timestamptz<>(NEW.lease->>'Until')::timestamptz THEN RAISE EXCEPTION 'terminal audit purge unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.lease IS NOT DISTINCT FROM OLD.lease AND NEW.terminal_acknowledged_at IS DISTINCT FROM OLD.terminal_acknowledged_at THEN
  IF NOT(NEW.terminal_purge ?& ARRAY['RootID','OperationID','RetirementDigest','CertificateDigest','Fence','PurgedAt','LeaseUntil']) OR OLD.terminal_acknowledged_at IS NOT NULL OR NEW.terminal_purge IS NULL OR NEW.terminal_acknowledged_at IS NULL OR NEW.terminal_acknowledged_at>n OR NEW.terminal_acknowledged_at<(NEW.terminal_purge->>'PurgedAt')::timestamptz OR n>=(NEW.lease->>'Until')::timestamptz THEN RAISE EXCEPTION 'terminal audit acknowledgement unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.finalization_xid IS DISTINCT FROM OLD.finalization_xid AND (NEW.finalization_xid IS DISTINCT FROM pg_current_xact_id() OR NEW.terminal_acknowledged_at IS NULL OR n>=(NEW.lease->>'Until')::timestamptz) THEN RAISE EXCEPTION 'audit finalization unavailable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_operation_audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.operation_audit_pool; a public.operation_audit_account; n timestamptz;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN
  RAISE EXCEPTION 'invalid operation audit source' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN
  IF NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d JOIN public.fleet_current_trust t ON t.installation_id=d.installation_id
   WHERE d.operation_id=OLD.id AND d.root_id=OLD.root_id AND d.finalization_xid=pg_current_xact_id() AND d.terminal_acknowledged_at IS NOT NULL AND
    NOT t.recovery_blocked AND NOT t.suspended AND clock_timestamp()<t.fresh_until AND t.issuer_epoch=d.issuer_epoch AND pg_postmaster_start_time()=d.postmaster_at AND (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())=d.database_oid AND clock_timestamp()<(d.lease->>'Until')::timestamptz)
   THEN RAISE EXCEPTION 'audit retirement unavailable' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT p FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane=NEW.lane FOR UPDATE;
  n:=clock_timestamp();
  IF p.paused OR n>=p.valid_until OR n>=NEW.request_until OR n<(NEW.intent->>'CreatedAt')::timestamptz OR NEW.intent_started OR NEW.intent_receipt IS NOT NULL OR NEW.outcome IS NOT NULL OR NEW.outcome_started OR NEW.outcome_receipt IS NOT NULL OR
   NOT (NEW.intent ?& ARRAY['ID','RootID','MACVersion','AccountVersion','Name','CreatedAt','RequestUntil','WriteUntil','RetainUntil']) OR NEW.intent->>'Name' NOT IN ('list_diagnostics','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','invalid_operation') OR
   (NEW.intent->>'ID')::uuid<>NEW.id OR (NEW.intent->>'RootID')::uuid<>NEW.root_id OR NEW.intent->>'AccountVersion'<>p.account_version OR
   NEW.request_until<>(NEW.intent->>'RequestUntil')::timestamptz OR NEW.write_until<>(NEW.intent->>'WriteUntil')::timestamptz OR NEW.retain_until<>(NEW.intent->>'RetainUntil')::timestamptz OR
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '5 seconds' OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
   NEW.retain_until>(NEW.intent->>'CreatedAt')::timestamptz+make_interval(secs=>p.retained_seconds::double precision) OR
   NEW.lane<>(CASE WHEN NEW.intent->>'Name'='resolve_capture_request' THEN 'resolution' ELSE 'normal' END) THEN
   RAISE EXCEPTION 'operation audit unavailable' USING ERRCODE='23514'; END IF;
  SELECT * INTO a FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest FOR UPDATE;
  IF NOT FOUND THEN
   IF p.accounts>=p.account_limit THEN RAISE EXCEPTION 'audit accounts exhausted' USING ERRCODE='23514'; END IF;
   UPDATE public.operation_audit_pool SET accounts=accounts+1 WHERE root_id=NEW.root_id AND lane=NEW.lane;
   INSERT INTO public.operation_audit_account(root_id,lane,principal_digest) VALUES(NEW.root_id,NEW.lane,NEW.principal_digest) RETURNING * INTO a;
  END IF;
  IF a.charged>=p.records_per_account THEN RAISE EXCEPTION 'audit records exhausted' USING ERRCODE='23514'; END IF;
  UPDATE public.operation_audit_account SET charged=charged+1 WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest;
 ELSE
  IF ROW(NEW.id,NEW.root_id,NEW.lane,NEW.issuer_epoch,NEW.principal_digest,NEW.intent,NEW.request_until,NEW.write_until,NEW.retain_until) IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.lane,OLD.issuer_epoch,OLD.principal_digest,OLD.intent,OLD.request_until,OLD.write_until,OLD.retain_until) OR
   (OLD.intent_started AND NOT NEW.intent_started) OR (OLD.outcome_started AND NOT NEW.outcome_started) OR
   (OLD.intent_receipt IS NOT NULL AND NEW.intent_receipt IS DISTINCT FROM OLD.intent_receipt) OR
   (OLD.outcome IS NOT NULL AND NEW.outcome IS DISTINCT FROM OLD.outcome) OR
   (OLD.outcome_receipt IS NOT NULL AND NEW.outcome_receipt IS DISTINCT FROM OLD.outcome_receipt) THEN
   RAISE EXCEPTION 'immutable operation audit' USING ERRCODE='23514'; END IF;
  IF NEW.intent ? 'Lifecycle' AND NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.operation_id=NEW.id AND
    (NEW.intent_receipt IS NULL OR d.intent_completion->'Receipt'=NEW.intent_receipt) AND (NEW.outcome_receipt IS NULL OR d.outcome_completion->'Receipt'=NEW.outcome_receipt)) THEN
   RAISE EXCEPTION 'receipt lacks positive writer completion' USING ERRCODE='23514'; END IF;
  n:=clock_timestamp();
  IF n>=NEW.write_until OR (NOT OLD.intent_started AND NEW.intent_started AND n>=NEW.request_until) THEN
   RAISE EXCEPTION 'operation audit interval expired' USING ERRCODE='23514'; END IF;
  IF NEW.outcome IS NOT NULL AND NEW.outcome->'Intent' IS DISTINCT FROM NEW.intent THEN
   RAISE EXCEPTION 'outcome intent mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION guard_operation_audit_pool() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'audit backing retirement unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 OR NEW.accounts<>0 OR NEW.history_profile IS NOT NULL OR NEW.history_backing_until IS NOT NULL THEN RAISE EXCEPTION 'invalid initial audit backing' USING ERRCODE='23514'; END IF;
 ELSE
  IF ROW(NEW.root_id,NEW.lane,NEW.account_version) IS DISTINCT FROM ROW(OLD.root_id,OLD.lane,OLD.account_version) THEN
   RAISE EXCEPTION 'immutable audit backing identity' USING ERRCODE='23514'; END IF;
  IF ROW(NEW.history_profile,NEW.history_backing_until) IS DISTINCT FROM ROW(OLD.history_profile,OLD.history_backing_until) THEN
   IF pg_trigger_depth()<2 OR NEW.history_profile IS NULL OR NEW.history_backing_until IS NULL OR
    OLD.history_backing_until IS NOT NULL AND NEW.history_backing_until<OLD.history_backing_until OR
    OLD.history_profile IS NOT NULL AND NEW.history_profile IS DISTINCT FROM OLD.history_profile AND
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
CREATE OR REPLACE FUNCTION guard_operation_audit_account() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF pg_trigger_depth()<2 THEN RAISE EXCEPTION 'audit account source managed' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN
  IF OLD.charged<>0 OR NOT (public.operation_lifecycle_retiring(OLD.root_id,OLD.lane,OLD.principal_digest) OR public.operation_history_releasing(OLD.root_id,OLD.lane,OLD.principal_digest)>0) OR EXISTS(SELECT 1 FROM public.operation_audit WHERE root_id=OLD.root_id AND lane=OLD.lane AND principal_digest=OLD.principal_digest) OR EXISTS(SELECT 1 FROM public.operation_audit_history WHERE root_id=OLD.root_id AND lane=OLD.lane AND principal_digest=OLD.principal_digest AND drain_xid IS DISTINCT FROM pg_current_xact_id()) THEN RAISE EXCEPTION 'audit account still charged' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.charged<>0 THEN RAISE EXCEPTION 'invalid audit account charge' USING ERRCODE='23514'; END IF;
 ELSIF ROW(NEW.root_id,NEW.lane,NEW.principal_digest) IS DISTINCT FROM ROW(OLD.root_id,OLD.lane,OLD.principal_digest) OR (NEW.charged<>OLD.charged+1 AND NOT ((NEW.charged=OLD.charged-1 AND public.operation_lifecycle_retiring(OLD.root_id,OLD.lane,OLD.principal_digest)) OR (public.operation_history_releasing(OLD.root_id,OLD.lane,OLD.principal_digest)>0 AND NEW.charged=OLD.charged-public.operation_history_releasing(OLD.root_id,OLD.lane,OLD.principal_digest)))) THEN
  RAISE EXCEPTION 'immutable audit account' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION release_operation_audit_charge() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE remaining bigint; d public.operation_audit_lifecycle; p jsonb; h bigint; n timestamptz:=clock_timestamp();
BEGIN
 IF TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'DELETE' OR NOT public.operation_lifecycle_retiring(OLD.root_id,OLD.lane,OLD.principal_digest) THEN RAISE EXCEPTION 'invalid audit release source' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT d FROM public.operation_audit_lifecycle WHERE operation_id=OLD.id AND finalization_xid=pg_current_xact_id();
 p:=d.binding->'Policy'; h:=(p->>'BackupHorizonSeconds')::bigint;
 IF h>0 THEN
  -- SQL retirement removes operation identity now. Backup history remains
  -- charged, including overdue actual-H debt; original dates never slide.
  INSERT INTO public.operation_audit_history(root_id,lane,principal_digest,release_at,delete_by,hard_delete_by,eligible_at,installation_id,issuer_epoch,postmaster_at,database_oid,horizon_seconds,history_policy,records,overdue)
  VALUES(d.root_id,d.lane,d.principal_digest,(d.binding->>'HistoryReleaseAt')::timestamptz,(d.binding->>'HistoryDeleteBy')::timestamptz,OLD.retain_until,
   GREATEST((d.binding->>'HistoryReleaseAt')::timestamptz,n+make_interval(secs=>h::double precision)),d.installation_id,d.issuer_epoch,d.postmaster_at,d.database_oid,h,
   p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds'],1,n>=d.live_retire_by)
  ON CONFLICT(root_id,lane,principal_digest,release_at,delete_by) DO UPDATE SET
   records=operation_audit_history.records+1,eligible_at=GREATEST(operation_audit_history.eligible_at,EXCLUDED.eligible_at),overdue=operation_audit_history.overdue OR EXCLUDED.overdue;
  RETURN OLD;
 END IF;
 UPDATE public.operation_audit_account SET charged=charged-1 WHERE root_id=OLD.root_id AND lane=OLD.lane AND principal_digest=OLD.principal_digest AND charged>0 RETURNING charged INTO STRICT remaining;
 IF remaining=0 THEN
  DELETE FROM public.operation_audit_account WHERE root_id=OLD.root_id AND lane=OLD.lane AND principal_digest=OLD.principal_digest;
  UPDATE public.operation_audit_pool SET accounts=accounts-1 WHERE root_id=OLD.root_id AND lane=OLD.lane AND accounts>0;
  IF NOT FOUND THEN RAISE EXCEPTION 'audit account charge mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN OLD;
END $$;
CREATE FUNCTION guard_operation_audit_history() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE d public.operation_audit_lifecycle; t public.fleet_current_trust; n timestamptz;
BEGIN
 IF TG_RELID<>'public.operation_audit_history'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid audit history source' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN
  IF OLD.drain_xid IS DISTINCT FROM pg_current_xact_id() OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'audit history release unavailable' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id FOR SHARE;
 n:=clock_timestamp();
 IF t.recovery_blocked OR t.suspended OR n>=t.fresh_until OR t.observed_at>n OR t.issuer_epoch<>NEW.issuer_epoch OR pg_postmaster_start_time()<>NEW.postmaster_at OR (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())<>NEW.database_oid THEN RAISE EXCEPTION 'audit history recovery unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' AND NEW.drain_xid IS DISTINCT FROM OLD.drain_xid THEN
  IF OLD.drain_xid IS NOT NULL OR NEW.drain_xid IS DISTINCT FROM pg_current_xact_id() OR n<OLD.eligible_at OR (to_jsonb(NEW)-'drain_xid') IS DISTINCT FROM (to_jsonb(OLD)-'drain_xid') THEN RAISE EXCEPTION 'audit history drain unavailable' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF pg_trigger_depth()<2 OR NEW.drain_xid IS NOT NULL THEN RAISE EXCEPTION 'audit history is source managed' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT d FROM public.operation_audit_lifecycle WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest AND finalization_xid=pg_current_xact_id() AND terminal_acknowledged_at IS NOT NULL AND
  (binding->>'HistoryReleaseAt')::timestamptz=NEW.release_at AND (binding->>'HistoryDeleteBy')::timestamptz=NEW.delete_by;
 IF ROW(NEW.installation_id,NEW.issuer_epoch,NEW.postmaster_at,NEW.database_oid) IS DISTINCT FROM ROW(d.installation_id,d.issuer_epoch,d.postmaster_at,d.database_oid) OR NEW.horizon_seconds<>(d.binding->'Policy'->>'BackupHorizonSeconds')::bigint OR
  NEW.hard_delete_by<>NEW.delete_by+make_interval(secs=>NEW.horizon_seconds::double precision) OR NEW.history_policy IS DISTINCT FROM
   ((d.binding->'Policy')-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']) THEN RAISE EXCEPTION 'audit history binding mismatch' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.records<>1 THEN RAISE EXCEPTION 'invalid initial audit history charge' USING ERRCODE='23514'; END IF;
 ELSE
  IF OLD.drain_xid IS NOT NULL OR NEW.records<>OLD.records+1 OR (to_jsonb(NEW)-ARRAY['records','eligible_at','overdue']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['records','eligible_at','overdue']) OR NEW.eligible_at<OLD.eligible_at OR OLD.overdue AND NOT NEW.overdue THEN RAISE EXCEPTION 'immutable audit history' USING ERRCODE='23514'; END IF;
 END IF;
 -- This actual floor concerns safe capacity reuse, never authorized retention.
 NEW.eligible_at:=GREATEST(NEW.eligible_at,NEW.release_at,n+make_interval(secs=>NEW.horizon_seconds::double precision));
 NEW.overdue:=NEW.overdue OR n>=d.live_retire_by;
 IF NEW.records>(SELECT charged FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest) THEN RAISE EXCEPTION 'audit history exceeds original charge' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION drain_operation_audit_history() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE remaining bigint;
BEGIN
 IF TG_RELID<>'public.operation_audit_history'::regclass OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'invalid audit history drain source' USING ERRCODE='23514'; END IF;
 IF NEW.drain_xid IS NULL THEN RETURN NEW; END IF;
 IF OLD.drain_xid IS NOT NULL OR NEW.drain_xid IS DISTINCT FROM pg_current_xact_id() THEN RAISE EXCEPTION 'audit history drain unavailable' USING ERRCODE='23514'; END IF;
 -- The final backup generation still exists after this identifying aggregate
 -- disappears. Keep root backing through its actual H, including late drains.
 UPDATE public.operation_audit_pool SET history_backing_until=GREATEST(history_backing_until,clock_timestamp()+make_interval(secs=>NEW.horizon_seconds::double precision))
 WHERE root_id=NEW.root_id AND lane=NEW.lane AND history_profile=NEW.history_policy;
 IF NOT FOUND THEN RAISE EXCEPTION 'audit residual history profile mismatch' USING ERRCODE='23514'; END IF;

 UPDATE public.operation_audit_account SET charged=charged-NEW.records WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest AND charged>=NEW.records RETURNING charged INTO STRICT remaining;
 IF remaining=0 THEN
  DELETE FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest;
  UPDATE public.operation_audit_pool SET accounts=accounts-1 WHERE root_id=NEW.root_id AND lane=NEW.lane AND accounts>0;
  IF NOT FOUND THEN RAISE EXCEPTION 'audit history account charge mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 DELETE FROM public.operation_audit_history WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest AND release_at=NEW.release_at AND delete_by=NEW.delete_by;
 RETURN NEW;
END $$;
CREATE FUNCTION finish_operation_audit_history(r uuid,l text,p bytea,releases timestamptz,deletes timestamptz,installation uuid) RETURNS TABLE(records bigint,overdue boolean) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE h public.operation_audit_history; t public.fleet_current_trust; started timestamptz:=clock_timestamp(); n timestamptz;
BEGIN
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=installation FOR SHARE;
 PERFORM 1 FROM public.operation_audit_pool WHERE root_id=r AND lane=l FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_account WHERE root_id=r AND lane=l AND principal_digest=p FOR UPDATE;
 SELECT * INTO h FROM public.operation_audit_history WHERE root_id=r AND lane=l AND principal_digest=p AND release_at=releases AND delete_by=deletes FOR UPDATE;
 n:=clock_timestamp();
 IF n>=started+interval '5 seconds' OR n>=t.fresh_until OR t.observed_at>n OR t.suspended OR t.recovery_blocked THEN RAISE EXCEPTION 'audit history recovery unavailable' USING ERRCODE='23514'; END IF;
 IF NOT FOUND THEN RETURN QUERY SELECT 0::bigint,false; RETURN; END IF;
 IF h.installation_id<>installation OR t.issuer_epoch<>h.issuer_epoch OR pg_postmaster_start_time()<>h.postmaster_at OR (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())<>h.database_oid OR n<h.eligible_at OR h.drain_xid IS NOT NULL THEN RAISE EXCEPTION 'audit history release unavailable' USING ERRCODE='23514'; END IF;
 UPDATE public.operation_audit_history SET drain_xid=pg_current_xact_id() WHERE root_id=r AND lane=l AND principal_digest=p AND release_at=releases AND delete_by=deletes;
 RETURN QUERY SELECT h.records,h.overdue OR n>=h.delete_by;
END $$;
CREATE FUNCTION require_operation_audit_history_retirement() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.drain_xid IS NOT NULL AND EXISTS(SELECT 1 FROM public.operation_audit_history WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest AND release_at=NEW.release_at AND delete_by=NEW.delete_by) THEN RAISE EXCEPTION 'stranded audit history retirement' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE FUNCTION finish_operation_audit_retirement(r uuid,i uuid,installation uuid) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit; d public.operation_audit_lifecycle; t public.fleet_current_trust; started timestamptz:=clock_timestamp(); n timestamptz;
BEGIN
 -- Recovery first. The preliminary read supplies no effect authority.
 SELECT * INTO d FROM public.operation_audit_lifecycle WHERE root_id=r AND operation_id=i AND installation_id=installation;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=installation FOR SHARE;
 PERFORM 1 FROM public.operation_audit_pool WHERE root_id=r AND lane=d.lane FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_account WHERE root_id=r AND lane=d.lane AND principal_digest=d.principal_digest FOR UPDATE;
 SELECT * INTO STRICT a FROM public.operation_audit WHERE root_id=r AND id=i FOR UPDATE;
 SELECT * INTO STRICT d FROM public.operation_audit_lifecycle WHERE root_id=r AND operation_id=i AND installation_id=installation FOR UPDATE;
 n:=clock_timestamp();
 IF n>=started+interval '5 seconds' OR n>=t.fresh_until OR t.observed_at>n OR t.suspended OR t.recovery_blocked OR t.issuer_epoch<>d.issuer_epoch OR pg_postmaster_start_time()<>d.postmaster_at OR (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())<>d.database_oid OR
  d.terminal_acknowledged_at IS NULL OR d.lease->>'Phase'<>'terminal' OR n>=(d.lease->>'Until')::timestamptz OR d.certificate_receipt IS NULL OR d.finalization_xid IS NOT NULL THEN RAISE EXCEPTION 'audit retirement unavailable' USING ERRCODE='23514'; END IF;
 UPDATE public.operation_audit_lifecycle SET finalization_xid=pg_current_xact_id() WHERE operation_id=i;
 DELETE FROM public.operation_audit WHERE root_id=r AND id=i;
 DELETE FROM public.operation_audit_lifecycle WHERE root_id=r AND operation_id=i;
 RETURN true;
END $$;
CREATE FUNCTION require_operation_audit_retirement() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.finalization_xid IS NOT NULL AND EXISTS(SELECT 1 FROM public.operation_audit_lifecycle WHERE operation_id=NEW.operation_id) THEN RAISE EXCEPTION 'stranded audit retirement transaction' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION operation_lifecycle_retiring(uuid,text,bytea),create_operation_audit_lifecycle(),guard_operation_audit_lifecycle(),release_operation_audit_charge(),finish_operation_audit_retirement(uuid,uuid,uuid),require_operation_audit_retirement() FROM PUBLIC;
CREATE TRIGGER operation_audit_lifecycle_create AFTER INSERT ON operation_audit FOR EACH ROW EXECUTE FUNCTION create_operation_audit_lifecycle();
CREATE TRIGGER operation_audit_lifecycle_guard BEFORE INSERT OR UPDATE OR DELETE ON operation_audit_lifecycle FOR EACH ROW EXECUTE FUNCTION guard_operation_audit_lifecycle();
CREATE TRIGGER operation_audit_charge_release AFTER DELETE ON operation_audit FOR EACH ROW EXECUTE FUNCTION release_operation_audit_charge();
CREATE CONSTRAINT TRIGGER operation_audit_retirement_complete AFTER UPDATE ON operation_audit_lifecycle DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_operation_audit_retirement();

REVOKE ALL ON FUNCTION operation_history_releasing(uuid,text,bytea),guard_operation_audit_history(),drain_operation_audit_history(),finish_operation_audit_history(uuid,text,bytea,timestamptz,timestamptz,uuid),require_operation_audit_history_retirement() FROM PUBLIC;
CREATE TRIGGER operation_audit_history_guard BEFORE INSERT OR UPDATE OR DELETE ON operation_audit_history FOR EACH ROW EXECUTE FUNCTION guard_operation_audit_history();
CREATE TRIGGER operation_audit_history_drain AFTER UPDATE ON operation_audit_history FOR EACH ROW EXECUTE FUNCTION drain_operation_audit_history();
CREATE CONSTRAINT TRIGGER operation_audit_history_retirement_complete AFTER UPDATE ON operation_audit_history DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_operation_audit_history_retirement();
