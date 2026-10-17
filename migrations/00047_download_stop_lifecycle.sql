-- +goose Up
-- Only newly admitted Stop obligations can use the closed writer protocol.
ALTER TABLE download_stop_pool ADD COLUMN lifecycle_policy jsonb CHECK(lifecycle_policy IS NULL OR jsonb_typeof(lifecycle_policy)='object' AND octet_length(lifecycle_policy::text)<=4096);
ALTER TABLE download_stop_pool ADD COLUMN history_backing_until timestamptz NOT NULL DEFAULT '-infinity';
CREATE TABLE download_stop_lifecycle (
 download_id uuid PRIMARY KEY REFERENCES download_stop(download_id) DEFERRABLE INITIALLY DEFERRED,
 root_id uuid NOT NULL REFERENCES download_stop_pool(root_id), allocation_id uuid NOT NULL REFERENCES download_stop_backing(allocation_id),
 installation_id uuid NOT NULL, issuer_epoch uuid NOT NULL,
 binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object' AND octet_length(binding::text)<=8192),
 original_purge_at timestamptz NOT NULL, certificate_purge_at timestamptz NOT NULL, live_retire_by timestamptz NOT NULL,
 original_completion jsonb CHECK(original_completion IS NULL OR jsonb_typeof(original_completion)='object' AND octet_length(original_completion::text)<=8192),
 closed_at timestamptz, mode text CHECK(mode IS NULL OR mode IN ('written','unused','unwritten')), overdue_selected_at timestamptz,
 lease jsonb CHECK(lease IS NULL OR jsonb_typeof(lease)='object' AND octet_length(lease::text)<=4096), lease_fence bigint NOT NULL DEFAULT 0 CHECK(lease_fence BETWEEN 0 AND 32),
 retirement jsonb CHECK(retirement IS NULL OR jsonb_typeof(retirement)='object' AND octet_length(retirement::text)<=8192),
 certificate_started boolean NOT NULL DEFAULT false,
 certificate_verify_attempts bigint NOT NULL DEFAULT 0 CHECK(certificate_verify_attempts BETWEEN 0 AND 2),
 certificate_completion jsonb CHECK(certificate_completion IS NULL OR jsonb_typeof(certificate_completion)='object' AND octet_length(certificate_completion::text)<=8192),
 certificate_receipt jsonb CHECK(certificate_receipt IS NULL OR jsonb_typeof(certificate_receipt)='object' AND octet_length(certificate_receipt::text)<=4096),
 certificate_acknowledged_at timestamptz,
 terminal_purge jsonb CHECK(terminal_purge IS NULL OR jsonb_typeof(terminal_purge)='object' AND octet_length(terminal_purge::text)<=4096),
 terminal_acknowledged_at timestamptz, finalization_xid xid8,
 CHECK(original_purge_at<certificate_purge_at AND certificate_purge_at<live_retire_by),
 CHECK((closed_at IS NULL)=(mode IS NULL)), CHECK(certificate_completion IS NULL OR certificate_started),
 CHECK((certificate_receipt IS NULL)=(certificate_acknowledged_at IS NULL)),
 CHECK(certificate_receipt IS NULL OR certificate_completion IS NOT NULL),
 CHECK(terminal_acknowledged_at IS NULL OR terminal_purge IS NOT NULL)
);
CREATE INDEX download_stop_lifecycle_due ON download_stop_lifecycle(root_id,original_purge_at,download_id);
CREATE TABLE download_stop_history (
 root_id uuid NOT NULL REFERENCES download_stop_pool(root_id), allocation_id uuid NOT NULL REFERENCES download_stop_backing(allocation_id),
 installation_id uuid NOT NULL, issuer_epoch uuid NOT NULL,
 policy_digest bytea NOT NULL CHECK(octet_length(policy_digest)=32),
 release_at timestamptz NOT NULL, delete_by timestamptz NOT NULL, hard_delete_by timestamptz NOT NULL,
 eligible_at timestamptz NOT NULL, horizon_seconds bigint NOT NULL CHECK(horizon_seconds>0),
 records bigint NOT NULL CHECK(records BETWEEN 1 AND 100000), overdue boolean NOT NULL, drain_xid xid8,
 PRIMARY KEY(root_id,allocation_id,policy_digest,release_at,delete_by),
 CHECK(release_at<delete_by AND delete_by<hard_delete_by AND eligible_at>=release_at)
);
CREATE INDEX download_stop_history_due ON download_stop_history(root_id,eligible_at,allocation_id);

-- +goose StatementBegin
CREATE FUNCTION download_stop_retiring(i uuid) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM public.download_stop_lifecycle l WHERE l.download_id=i AND l.finalization_xid=pg_current_xact_id() AND l.terminal_acknowledged_at IS NOT NULL)
$$;
CREATE FUNCTION download_stop_releasing(a uuid) RETURNS bigint LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(sum(records),0)::bigint FROM public.download_stop_history h WHERE h.allocation_id=a AND h.drain_xid=pg_current_xact_id()
$$;
CREATE FUNCTION validate_download_stop_lifecycle_policy(p public.download_stop_pool, v jsonb) RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE h bigint; b bigint; proof bigint; row_bytes bigint; wal_bytes bigint; copies bigint; wal_copies bigint; leases bigint;
BEGIN
 IF v IS NULL OR jsonb_typeof(v)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(v))<>18 OR EXISTS(SELECT 1 FROM jsonb_each(v) AS entry WHERE entry.value='null'::jsonb) OR octet_length(v::text)>4096 OR
  NOT(v ?& ARRAY['RootID','InstallationID','StoreID','PolicyID','BackupProfileID','QualificationID','PolicyDigest','BackupProfileDigest','QualificationDigest','Layout','BackupHorizonSeconds','CleanupBudgetSeconds','ProofWindowSeconds','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies','MaxPurgeLeases']) OR v->>'Layout'<>'download-stop-history/v1' OR (v->>'RootID')::uuid<>p.root_id OR (v->>'InstallationID')::uuid<>p.installation_id OR (v->>'StoreID')::uuid<>p.store_id OR (v->>'PolicyID')::uuid<>p.policy_id OR (v->>'BackupProfileID')::uuid<>p.backup_profile_id OR
  v->'PolicyDigest' IS DISTINCT FROM to_jsonb(ARRAY(SELECT get_byte(p.policy_digest,i) FROM generate_series(0,31)i)) OR v->'BackupProfileDigest' IS DISTINCT FROM to_jsonb(ARRAY(SELECT get_byte(p.backup_profile_digest,i) FROM generate_series(0,31)i)) OR
  (v->>'QualificationID')::uuid IS NULL OR jsonb_array_length(v->'QualificationDigest')<>32 THEN RETURN false;END IF;
 h:=(v->>'BackupHorizonSeconds')::bigint;b:=(v->>'CleanupBudgetSeconds')::bigint;proof:=(v->>'ProofWindowSeconds')::bigint;
 row_bytes:=(v->>'MaximumRowFootprintBytes')::bigint;wal_bytes:=(v->>'MaximumTransitionWALBytes')::bigint;copies:=(v->>'BackupCopies')::bigint;wal_copies:=(v->>'WALCopies')::bigint;leases:=(v->>'MaxPurgeLeases')::bigint;
 RETURN COALESCE(h=p.backup_horizon_seconds AND h BETWEEN 0 AND 316224000 AND b BETWEEN 1 AND 86400 AND proof BETWEEN 1 AND 316224000 AND p.retained_seconds>2*h+3*b+proof+30 AND row_bytes BETWEEN 131072 AND 16777216 AND wal_bytes BETWEEN 131072 AND 67108864 AND copies BETWEEN 1 AND 64 AND wal_copies BETWEEN 1 AND 64 AND leases BETWEEN 2 AND 32 AND p.key_attempts/p.slots>=12 AND p.cipher_bytes/p.slots>=65536 AND p.backup_bytes/p.slots>=2*row_bytes*copies AND p.wal_bytes/p.slots>=2*wal_bytes*wal_copies*(20+3*leases),false);
END $$;
CREATE OR REPLACE FUNCTION guard_download_stop_pool() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'stop backing retirement requires positive proof' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 OR NEW.allocated<>0 OR NEW.valid_until<=clock_timestamp() OR NEW.history_backing_until<>'-infinity' OR NEW.lifecycle_policy IS NOT NULL AND NOT public.validate_download_stop_lifecycle_policy(NEW,NEW.lifecycle_policy) THEN RAISE EXCEPTION 'invalid initial stop backing' USING ERRCODE='23514';END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['allocated','revision','valid_until','lifecycle_policy','history_backing_until']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['allocated','revision','valid_until','lifecycle_policy','history_backing_until']) OR NEW.allocated<OLD.allocated OR NEW.allocated<>OLD.allocated AND (pg_trigger_depth()<2 OR NEW.revision<>OLD.revision OR NEW.valid_until<>OLD.valid_until) OR NEW.valid_until<>OLD.valid_until AND (NEW.revision<>OLD.revision+1 OR NEW.allocated<>OLD.allocated OR NEW.valid_until<=clock_timestamp()) OR NEW.valid_until=OLD.valid_until AND NEW.revision<>OLD.revision THEN RAISE EXCEPTION 'immutable stop pool and retained charge' USING ERRCODE='23514';END IF;
  IF NEW.lifecycle_policy IS DISTINCT FROM OLD.lifecycle_policy AND (OLD.lifecycle_policy IS NOT NULL OR NEW.lifecycle_policy IS NULL OR NOT public.validate_download_stop_lifecycle_policy(NEW,NEW.lifecycle_policy) OR EXISTS(SELECT 1 FROM public.download_stop WHERE root_id=NEW.root_id)) THEN RAISE EXCEPTION 'stop lifecycle must precede use' USING ERRCODE='23514';END IF;
  IF NEW.history_backing_until IS DISTINCT FROM OLD.history_backing_until AND (pg_trigger_depth()<2 OR NEW.history_backing_until<OLD.history_backing_until) THEN RAISE EXCEPTION 'stop history backing is source managed' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE FUNCTION create_download_stop_lifecycle() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.download_stop_pool; d public.artifact_download; v jsonb; h interval; b interval; proof interval; original timestamptz; certificate timestamptz; retire timestamptz;
BEGIN
 SELECT * INTO STRICT p FROM public.download_stop_pool WHERE root_id=NEW.root_id FOR UPDATE;
 IF p.lifecycle_policy IS NULL THEN RETURN NEW;END IF;
 IF NOT public.validate_download_stop_lifecycle_policy(p,p.lifecycle_policy) THEN RAISE EXCEPTION 'stop lifecycle backing unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT d FROM public.artifact_download WHERE id=NEW.download_id;
 h:=make_interval(secs=>(p.lifecycle_policy->>'BackupHorizonSeconds')::double precision);b:=make_interval(secs=>(p.lifecycle_policy->>'CleanupBudgetSeconds')::double precision);proof:=make_interval(secs=>(p.lifecycle_policy->>'ProofWindowSeconds')::double precision);
 original:=NEW.retain_until-2*h-3*b-proof;certificate:=NEW.retain_until-2*h-2*b;retire:=NEW.retain_until-2*h-b;
 IF NEW.reserved_at>=d.deadline OR original<=d.deadline+interval '30 seconds' THEN RAISE EXCEPTION 'stop lifecycle has no usable interval' USING ERRCODE='23514';END IF;
 v:=jsonb_build_object('Protocol','closed-download-stop/v1','RootID',NEW.root_id,'DownloadID',NEW.download_id,'AllocationID',NEW.allocation_id,'IssuerEpoch',NEW.issuer_epoch,'Policy',p.lifecycle_policy,'ReservedAt',NEW.reserved_at,'TransferUntil',d.deadline,'HardDeleteBy',NEW.retain_until,'OriginalPurgeAt',original,'CertificatePurgeAt',certificate,'LiveRetireBy',retire,'HistoryReleaseAt',NEW.retain_until-h-b,'HistoryDeleteBy',NEW.retain_until-h);
 INSERT INTO public.download_stop_lifecycle(download_id,root_id,allocation_id,installation_id,issuer_epoch,binding,original_purge_at,certificate_purge_at,live_retire_by) VALUES(NEW.download_id,NEW.root_id,NEW.allocation_id,NEW.installation_id,NEW.issuer_epoch,v,original,certificate,retire);
 UPDATE public.download_stop_pool SET history_backing_until=GREATEST(history_backing_until,NEW.retain_until) WHERE root_id=NEW.root_id;
 RETURN NEW;
END $$;
CREATE FUNCTION guard_download_stop_lifecycle() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.download_stop; t public.fleet_current_trust; n timestamptz; c jsonb; phase text; since timestamptz; until_at timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN
  IF OLD.finalization_xid IS DISTINCT FROM pg_current_xact_id() OR OLD.terminal_acknowledged_at IS NULL OR EXISTS(SELECT 1 FROM public.download_stop WHERE download_id=OLD.download_id) THEN RAISE EXCEPTION 'stop retirement not joined' USING ERRCODE='23514';END IF;RETURN OLD;
 END IF;
 SELECT * INTO STRICT s FROM public.download_stop WHERE download_id=NEW.download_id;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id FOR SHARE;
 n:=clock_timestamp();
 IF t.recovery_blocked OR t.suspended OR n>=t.fresh_until OR t.observed_at>n OR t.issuer_epoch<>NEW.issuer_epoch OR NEW.installation_id<>s.installation_id OR NEW.issuer_epoch<>s.issuer_epoch OR NEW.root_id<>s.root_id OR NEW.allocation_id<>s.allocation_id THEN RAISE EXCEPTION 'stop lifecycle recovery unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF pg_trigger_depth()<2 OR NEW.original_completion IS NOT NULL OR NEW.closed_at IS NOT NULL OR NEW.overdue_selected_at IS NOT NULL OR NEW.lease IS NOT NULL OR NEW.lease_fence<>0 OR NEW.retirement IS NOT NULL OR NEW.certificate_started OR NEW.certificate_verify_attempts<>0 OR NEW.certificate_completion IS NOT NULL OR NEW.certificate_receipt IS NOT NULL OR NEW.terminal_purge IS NOT NULL OR NEW.finalization_xid IS NOT NULL THEN RAISE EXCEPTION 'invalid initial stop lifecycle' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 IF ROW(NEW.download_id,NEW.root_id,NEW.allocation_id,NEW.installation_id,NEW.issuer_epoch,NEW.binding,NEW.original_purge_at,NEW.certificate_purge_at,NEW.live_retire_by) IS DISTINCT FROM ROW(OLD.download_id,OLD.root_id,OLD.allocation_id,OLD.installation_id,OLD.issuer_epoch,OLD.binding,OLD.original_purge_at,OLD.certificate_purge_at,OLD.live_retire_by) OR
  OLD.original_completion IS NOT NULL AND NEW.original_completion IS DISTINCT FROM OLD.original_completion OR OLD.closed_at IS NOT NULL AND ROW(NEW.closed_at,NEW.mode) IS DISTINCT FROM ROW(OLD.closed_at,OLD.mode) OR OLD.overdue_selected_at IS NOT NULL AND NEW.overdue_selected_at IS DISTINCT FROM OLD.overdue_selected_at OR OLD.retirement IS NOT NULL AND NEW.retirement IS DISTINCT FROM OLD.retirement OR OLD.certificate_started AND NOT NEW.certificate_started OR OLD.certificate_completion IS NOT NULL AND NEW.certificate_completion IS DISTINCT FROM OLD.certificate_completion OR OLD.certificate_receipt IS NOT NULL AND ROW(NEW.certificate_receipt,NEW.certificate_acknowledged_at) IS DISTINCT FROM ROW(OLD.certificate_receipt,OLD.certificate_acknowledged_at) OR OLD.finalization_xid IS NOT NULL THEN RAISE EXCEPTION 'immutable stop lifecycle' USING ERRCODE='23514';END IF;
 FOREACH phase IN ARRAY ARRAY['decision','certificate'] LOOP
  c:=CASE WHEN phase='decision' THEN NEW.original_completion ELSE NEW.certificate_completion END;
  IF c IS NOT NULL AND (phase='decision' AND OLD.original_completion IS NULL OR phase='certificate' AND OLD.certificate_completion IS NULL) THEN
   since:=CASE WHEN phase='decision' THEN s.requested_at ELSE (NEW.retirement->>'PurgedAt')::timestamptz END;
   until_at:=CASE WHEN phase='decision' THEN s.write_until ELSE (NEW.retirement->>'CertificateWriteUntil')::timestamptz END;
   IF NOT(c ?& ARRAY['Protocol','RootID','DownloadID','StoreID','Phase','BindingDigest','RecordDigest','Receipt','StoredAt','ClosedAt']) OR (SELECT count(*) FROM jsonb_object_keys(c))<>10 OR EXISTS(SELECT 1 FROM jsonb_each(c) AS entry WHERE entry.value='null'::jsonb) OR phase='decision' AND (NOT s.write_started OR NEW.closed_at IS NOT NULL) OR phase='certificate' AND NOT NEW.certificate_started OR c->>'Protocol'<>'closed-download-stop/v1' OR (c->>'RootID')::uuid<>NEW.root_id OR (c->>'DownloadID')::uuid<>NEW.download_id OR (c->>'StoreID')::uuid<>s.store_id OR c->>'Phase'<>phase OR jsonb_array_length(c->'RecordDigest')<>32 OR jsonb_array_length(c->'BindingDigest')<>32 OR
    (SELECT count(*) FROM jsonb_object_keys(c->'Receipt'))<>5 OR NOT(c->'Receipt' ?& ARRAY['Key','Version','ETag','Bytes','SHA256']) OR EXISTS(SELECT 1 FROM jsonb_each(c->'Receipt') AS entry WHERE entry.value='null'::jsonb) OR jsonb_array_length(c->'Receipt'->'SHA256')<>32 OR c->'Receipt'->>'Key'<>'download-stop/v1/'||NEW.root_id::text||'/'||NEW.download_id::text||(CASE WHEN phase='certificate' THEN '/deletion-certificate' ELSE '' END) OR (c->'Receipt'->>'Bytes')::bigint NOT BETWEEN 1 AND 65536 OR
    (c->>'StoredAt')::timestamptz<since OR (c->>'ClosedAt')::timestamptz<(c->>'StoredAt')::timestamptz OR (c->>'ClosedAt')::timestamptz>=until_at OR (c->>'ClosedAt')::timestamptz>n OR n>=until_at THEN RAISE EXCEPTION 'stop completion lacks exact positive writer' USING ERRCODE='23514';END IF;
  END IF;
 END LOOP;
 IF OLD.closed_at IS NULL AND NEW.closed_at IS NOT NULL THEN
  IF NEW.closed_at<>n AND (NEW.closed_at>n OR NEW.closed_at<n-interval '5 seconds') OR n<NEW.original_purge_at OR NEW.mode='unused' AND (s.decision IS NOT NULL OR s.write_started OR s.receipt IS NOT NULL) OR NEW.mode='written' AND (NEW.original_completion IS NULL OR s.receipt IS NULL OR NEW.original_completion->'Receipt' IS DISTINCT FROM s.receipt) OR NEW.mode='unwritten' AND (s.decision IS NULL OR s.write_started OR NEW.original_completion IS NOT NULL OR s.receipt IS NOT NULL OR n<s.write_until) THEN RAISE EXCEPTION 'stop writer remains unresolved' USING ERRCODE='23514';END IF;
 END IF;
 IF OLD.overdue_selected_at IS NULL AND NEW.overdue_selected_at IS NOT NULL THEN
  IF NEW.closed_at IS NULL OR NEW.certificate_started OR NEW.certificate_completion IS NOT NULL OR NEW.certificate_receipt IS NOT NULL OR NEW.overdue_selected_at>n OR NEW.overdue_selected_at<n-interval '5 seconds' OR n<NEW.certificate_purge_at-make_interval(secs=>(NEW.binding->'Policy'->>'ProofWindowSeconds')::double precision) THEN RAISE EXCEPTION 'stop overdue fence unavailable' USING ERRCODE='23514';END IF;
 END IF;
 IF NEW.lease IS DISTINCT FROM OLD.lease THEN
  NEW.terminal_purge:=NULL;NEW.terminal_acknowledged_at:=NULL;
  IF (SELECT count(*) FROM jsonb_object_keys(NEW.lease))<>12 OR EXISTS(SELECT 1 FROM jsonb_each(NEW.lease) AS entry WHERE entry.value='null'::jsonb) OR NOT(NEW.lease ?& ARRAY['RootID','DownloadID','StoreID','InstallationID','IssuerEpoch','Phase','BindingDigest','ObjectsDigest','WritersDigest','Fence','StartedAt','Until']) OR NEW.lease IS NULL OR NEW.closed_at IS NULL OR NEW.lease_fence<>OLD.lease_fence+1 OR NEW.lease_fence>(NEW.binding->'Policy'->>'MaxPurgeLeases')::bigint OR (NEW.lease->>'Fence')::bigint<>NEW.lease_fence OR (NEW.lease->>'RootID')::uuid<>NEW.root_id OR (NEW.lease->>'DownloadID')::uuid<>NEW.download_id OR (NEW.lease->>'InstallationID')::uuid<>NEW.installation_id OR (NEW.lease->>'IssuerEpoch')::uuid<>NEW.issuer_epoch OR (NEW.lease->>'StartedAt')::timestamptz>n OR (NEW.lease->>'Until')::timestamptz<=n OR (NEW.lease->>'Until')::timestamptz>(NEW.lease->>'StartedAt')::timestamptz+interval '5 seconds' OR NEW.terminal_purge IS NOT NULL OR NEW.terminal_acknowledged_at IS NOT NULL OR OLD.lease IS NOT NULL AND n<(OLD.lease->>'Until')::timestamptz THEN RAISE EXCEPTION 'stop cleanup lease unavailable' USING ERRCODE='23514';END IF;
  phase:=NEW.lease->>'Phase';
  IF phase='original' AND (NEW.overdue_selected_at IS NOT NULL OR NEW.retirement IS NOT NULL OR n>=NEW.certificate_purge_at-make_interval(secs=>(NEW.binding->'Policy'->>'ProofWindowSeconds')::double precision)) OR phase='terminal' AND (NEW.certificate_receipt IS NULL OR NEW.certificate_completion IS NULL OR n<NEW.certificate_purge_at OR NEW.overdue_selected_at IS NOT NULL) OR phase='overdue' AND (NEW.overdue_selected_at IS NULL OR NEW.certificate_started) OR phase NOT IN ('original','terminal','overdue') THEN RAISE EXCEPTION 'stop cleanup phase unavailable' USING ERRCODE='23514';END IF;
 ELSIF NEW.lease_fence<>OLD.lease_fence THEN RAISE EXCEPTION 'stop cleanup fence changed' USING ERRCODE='23514';END IF;
 IF OLD.retirement IS NULL AND NEW.retirement IS NOT NULL THEN
  IF (SELECT count(*) FROM jsonb_object_keys(NEW.retirement))<>14 OR EXISTS(SELECT 1 FROM jsonb_each(NEW.retirement) AS entry WHERE entry.value='null'::jsonb) OR NOT(NEW.retirement ?& ARRAY['RootID','DownloadID','StoreID','InstallationID','IssuerEpoch','Mode','BindingDigest','ObjectsDigest','WritersDigest','PurgeFence','PurgedAt','CertificateWriteUntil','CertificatePurgeAt','LiveRetireBy']) OR (NEW.retirement->>'RootID')::uuid<>NEW.root_id OR (NEW.retirement->>'DownloadID')::uuid<>NEW.download_id OR (NEW.retirement->>'StoreID')::uuid<>s.store_id OR (NEW.retirement->>'InstallationID')::uuid<>NEW.installation_id OR (NEW.retirement->>'IssuerEpoch')::uuid<>NEW.issuer_epoch OR NEW.retirement->'BindingDigest' IS DISTINCT FROM NEW.lease->'BindingDigest' OR NEW.retirement->'ObjectsDigest' IS DISTINCT FROM NEW.lease->'ObjectsDigest' OR NEW.retirement->'WritersDigest' IS DISTINCT FROM NEW.lease->'WritersDigest' OR (NEW.retirement->>'CertificatePurgeAt')::timestamptz<>NEW.certificate_purge_at OR (NEW.retirement->>'LiveRetireBy')::timestamptz<>NEW.live_retire_by OR NEW.lease->>'Phase'<>'original' OR n>=(NEW.lease->>'Until')::timestamptz OR (NEW.retirement->>'PurgeFence')::bigint<>NEW.lease_fence OR NEW.retirement->>'Mode'<>NEW.mode OR (NEW.retirement->>'PurgedAt')::timestamptz<(NEW.lease->>'StartedAt')::timestamptz OR (NEW.retirement->>'PurgedAt')::timestamptz>n OR (NEW.retirement->>'CertificateWriteUntil')::timestamptz<=n OR (NEW.retirement->>'CertificateWriteUntil')::timestamptz>(NEW.retirement->>'PurgedAt')::timestamptz+interval '30 seconds' OR (NEW.retirement->>'CertificateWriteUntil')::timestamptz>NEW.certificate_purge_at-make_interval(secs=>(NEW.binding->'Policy'->>'ProofWindowSeconds')::double precision) THEN RAISE EXCEPTION 'stop original purge unavailable' USING ERRCODE='23514';END IF;
 END IF;
 IF NOT OLD.certificate_started AND NEW.certificate_started AND (NEW.retirement IS NULL OR NEW.overdue_selected_at IS NOT NULL OR n>=(NEW.retirement->>'CertificateWriteUntil')::timestamptz) THEN RAISE EXCEPTION 'stop certificate claim unavailable' USING ERRCODE='23514';END IF;
 IF NEW.certificate_verify_attempts<>OLD.certificate_verify_attempts AND (NEW.certificate_verify_attempts<>OLD.certificate_verify_attempts+1 OR NEW.certificate_completion IS NULL OR NEW.certificate_receipt IS NOT NULL OR n>=(NEW.retirement->>'CertificateWriteUntil')::timestamptz) THEN RAISE EXCEPTION 'stop certificate verification attempt unavailable' USING ERRCODE='23514';END IF;
 IF OLD.certificate_receipt IS NULL AND NEW.certificate_receipt IS NOT NULL AND (NEW.certificate_verify_attempts<1 OR NEW.certificate_completion IS NULL OR NEW.certificate_receipt IS DISTINCT FROM NEW.certificate_completion->'Receipt' OR NEW.certificate_acknowledged_at>n OR NEW.certificate_acknowledged_at<(NEW.certificate_completion->>'ClosedAt')::timestamptz OR n>=(NEW.retirement->>'CertificateWriteUntil')::timestamptz) THEN RAISE EXCEPTION 'stop certificate acknowledgement unavailable' USING ERRCODE='23514';END IF;
 IF NEW.terminal_purge IS DISTINCT FROM OLD.terminal_purge AND NEW.terminal_purge IS NOT NULL THEN
  IF (SELECT count(*) FROM jsonb_object_keys(NEW.terminal_purge))<>9 OR EXISTS(SELECT 1 FROM jsonb_each(NEW.terminal_purge) AS entry WHERE entry.value='null'::jsonb) OR NOT(NEW.terminal_purge ?& ARRAY['RootID','DownloadID','Phase','BindingDigest','ObjectsDigest','WritersDigest','Fence','PurgedAt','LeaseUntil']) OR OLD.terminal_purge IS NOT NULL AND NEW.lease IS NOT DISTINCT FROM OLD.lease OR (NEW.terminal_purge->>'RootID')::uuid<>NEW.root_id OR (NEW.terminal_purge->>'DownloadID')::uuid<>NEW.download_id OR NEW.terminal_purge->'BindingDigest' IS DISTINCT FROM NEW.lease->'BindingDigest' OR NEW.terminal_purge->'ObjectsDigest' IS DISTINCT FROM NEW.lease->'ObjectsDigest' OR NEW.terminal_purge->'WritersDigest' IS DISTINCT FROM NEW.lease->'WritersDigest' OR NEW.lease->>'Phase' NOT IN ('terminal','overdue') OR NEW.terminal_purge->>'Phase'<>NEW.lease->>'Phase' OR (NEW.terminal_purge->>'Fence')::bigint<>NEW.lease_fence OR (NEW.terminal_purge->>'PurgedAt')::timestamptz<(NEW.lease->>'StartedAt')::timestamptz OR (NEW.terminal_purge->>'PurgedAt')::timestamptz>n OR (NEW.terminal_purge->>'LeaseUntil')::timestamptz<>(NEW.lease->>'Until')::timestamptz OR n>=(NEW.lease->>'Until')::timestamptz THEN RAISE EXCEPTION 'stop terminal purge unavailable' USING ERRCODE='23514';END IF;
 END IF;
 IF NEW.lease IS NOT DISTINCT FROM OLD.lease AND NEW.terminal_acknowledged_at IS DISTINCT FROM OLD.terminal_acknowledged_at AND (OLD.terminal_acknowledged_at IS NOT NULL OR NEW.terminal_acknowledged_at IS NULL OR NEW.terminal_purge IS NULL OR NEW.terminal_acknowledged_at>n OR NEW.terminal_acknowledged_at<(NEW.terminal_purge->>'PurgedAt')::timestamptz OR n>=(NEW.lease->>'Until')::timestamptz) THEN RAISE EXCEPTION 'stop terminal acknowledgement unavailable' USING ERRCODE='23514';END IF;
 IF NEW.finalization_xid IS NOT NULL AND (NEW.finalization_xid IS DISTINCT FROM pg_current_xact_id() OR NEW.terminal_acknowledged_at IS NULL OR n>=(NEW.lease->>'Until')::timestamptz) THEN RAISE EXCEPTION 'stop finalization unavailable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION download_stop_retiring(uuid),download_stop_releasing(uuid),validate_download_stop_lifecycle_policy(download_stop_pool,jsonb),create_download_stop_lifecycle(),guard_download_stop_lifecycle() FROM PUBLIC;
CREATE TRIGGER download_stop_lifecycle_create AFTER INSERT ON download_stop FOR EACH ROW EXECUTE FUNCTION create_download_stop_lifecycle();
CREATE TRIGGER download_stop_lifecycle_guard BEFORE INSERT OR UPDATE OR DELETE ON download_stop_lifecycle FOR EACH ROW EXECUTE FUNCTION guard_download_stop_lifecycle();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_download_stop() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE d public.artifact_download; a public.download_stop_backing; p public.download_stop_pool; t public.fleet_current_trust; n timestamptz; l public.download_stop_lifecycle;
BEGIN
 IF TG_OP='DELETE' THEN IF NOT public.download_stop_retiring(OLD.download_id) THEN RAISE EXCEPTION 'stop retirement requires writer and backup proof' USING ERRCODE='23514';END IF;RETURN OLD;END IF;
 SELECT * INTO STRICT d FROM public.artifact_download WHERE id=NEW.download_id AND root_id=NEW.root_id;
 n:=clock_timestamp();
 IF TG_OP='INSERT' THEN
  -- Same pool -> backing order as cleanup; child creation later reuses it.
  SELECT * INTO STRICT p FROM public.download_stop_pool WHERE root_id=NEW.root_id FOR UPDATE;
  SELECT * INTO STRICT a FROM public.download_stop_backing WHERE allocation_id=NEW.allocation_id AND root_id=NEW.root_id FOR UPDATE;
  n:=clock_timestamp();
  IF pg_trigger_depth()<2 OR d.stop_protocol<>'prepaid-download-stop/v1' OR d.allocation_id<>NEW.allocation_id OR d.state<>'Preparing' OR a.charged>=a.slots OR n>=p.valid_until OR NEW.installation_id<>p.installation_id OR NEW.store_id<>p.store_id OR NEW.retain_until<>d.deadline+make_interval(secs=>p.retained_seconds::double precision) OR NEW.decision IS NOT NULL OR NEW.write_started OR NEW.receipt IS NOT NULL OR NEW.lookup_attempts<>0 THEN RAISE EXCEPTION 'stop obligation admission unavailable' USING ERRCODE='23514';END IF;
  UPDATE public.download_stop_backing SET charged=charged+1 WHERE allocation_id=NEW.allocation_id;
 ELSE
  SELECT * INTO l FROM public.download_stop_lifecycle WHERE download_id=NEW.download_id;
  IF FOUND AND (l.closed_at IS NOT NULL OR n>=l.original_purge_at OR NEW.receipt IS NOT NULL AND l.original_completion->'Receipt' IS DISTINCT FROM NEW.receipt) THEN RAISE EXCEPTION 'stop decision or writer is closed' USING ERRCODE='23514';END IF;
  IF ROW(NEW.download_id,NEW.root_id,NEW.allocation_id,NEW.installation_id,NEW.issuer_epoch,NEW.store_id,NEW.reserved_at,NEW.retain_until) IS DISTINCT FROM ROW(OLD.download_id,OLD.root_id,OLD.allocation_id,OLD.installation_id,OLD.issuer_epoch,OLD.store_id,OLD.reserved_at,OLD.retain_until) OR NEW.lookup_attempts<OLD.lookup_attempts OR NEW.lookup_attempts>OLD.lookup_attempts+1 OR NEW.lookup_attempts<>OLD.lookup_attempts AND NOT OLD.write_started OR OLD.write_started AND NOT NEW.write_started OR OLD.receipt IS NOT NULL AND NEW.receipt IS DISTINCT FROM OLD.receipt OR OLD.decision IS NOT NULL AND ROW(NEW.decision,NEW.key_digest,NEW.request_id,NEW.requested_at,NEW.write_until) IS DISTINCT FROM ROW(OLD.decision,OLD.key_digest,OLD.request_id,OLD.requested_at,OLD.write_until) THEN RAISE EXCEPTION 'immutable stop decision or spend' USING ERRCODE='23514';END IF;
  IF OLD.decision IS NULL AND NEW.decision IS NOT NULL THEN
   IF (SELECT count(*) FROM jsonb_object_keys(NEW.decision))<>11 OR NOT (NEW.decision ?& ARRAY['Protocol','RootID','DownloadID','RequestID','StoreID','Actor','KeyDigest','State','RequestedAt','WriteUntil','RetainUntil']) OR NEW.requested_at<NEW.reserved_at OR NEW.requested_at>n OR NEW.requested_at<n-interval '5 seconds' OR NEW.write_until<=n OR NEW.write_started OR NEW.receipt IS NOT NULL OR d.state NOT IN ('Completed','Cancelled','Expired','Denied','Failed') OR
    NEW.decision->>'Protocol'<>'prepaid-download-stop/v1' OR (NEW.decision->>'RootID')::uuid<>NEW.root_id OR (NEW.decision->>'DownloadID')::uuid<>NEW.download_id OR (NEW.decision->>'RequestID')::uuid<>NEW.request_id OR (NEW.decision->>'StoreID')::uuid<>NEW.store_id OR
    NEW.decision->'KeyDigest' IS DISTINCT FROM to_jsonb(ARRAY(SELECT get_byte(NEW.key_digest,i) FROM generate_series(0,31) AS i)) OR NEW.decision->>'State' NOT IN ('Cancelled','AlreadyTerminal') OR NEW.decision->>'State'='Cancelled' AND d.state<>'Cancelled' OR
    (NEW.decision->>'RequestedAt')::timestamptz<>NEW.requested_at OR (NEW.decision->>'WriteUntil')::timestamptz<>NEW.write_until OR (NEW.decision->>'RetainUntil')::timestamptz<>NEW.retain_until OR NEW.decision->'Actor' IS DISTINCT FROM d.scope_json->'Principal' THEN
    RAISE EXCEPTION 'invalid stop decision' USING ERRCODE='23514';END IF;
  END IF;
  IF (NOT OLD.write_started AND NEW.write_started) OR NEW.lookup_attempts<>OLD.lookup_attempts OR (OLD.receipt IS NULL AND NEW.receipt IS NOT NULL) THEN
   SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id FOR SHARE;
   n:=clock_timestamp();
   IF t.recovery_blocked OR t.suspended OR t.issuer_epoch<>NEW.issuer_epoch OR n>=t.fresh_until THEN RAISE EXCEPTION 'stop audit recovery unavailable' USING ERRCODE='23514';END IF;
  END IF;
  IF NOT OLD.write_started AND NEW.write_started AND n>=NEW.write_until THEN RAISE EXCEPTION 'stop write attempt ended' USING ERRCODE='23514';END IF;
  IF n>=NEW.retain_until THEN RAISE EXCEPTION 'stop audit retention ended' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE FUNCTION download_stop_charge_releasing(a uuid) RETURNS bigint LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.download_stop_releasing(a)+(SELECT count(*) FROM public.download_stop_lifecycle l WHERE l.allocation_id=a AND l.finalization_xid=pg_current_xact_id() AND l.terminal_acknowledged_at IS NOT NULL AND (l.binding->'Policy'->>'BackupHorizonSeconds')::bigint=0)
$$;
CREATE OR REPLACE FUNCTION guard_download_stop_backing() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.download_stop_pool; a public.download_allocation;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'stop allocation retirement requires positive proof' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT p FROM public.download_stop_pool WHERE root_id=NEW.root_id FOR UPDATE;
  SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id FOR SHARE;
  IF NEW.charged<>0 OR NEW.slots>a.session_limit OR NEW.slots>p.slots-p.allocated OR clock_timestamp()>=p.valid_until THEN RAISE EXCEPTION 'stop backing unavailable' USING ERRCODE='23514';END IF;
  UPDATE public.download_stop_pool SET allocated=allocated+NEW.slots WHERE root_id=NEW.root_id;
 ELSIF (to_jsonb(NEW)-'charged') IS DISTINCT FROM (to_jsonb(OLD)-'charged') OR pg_trigger_depth()<2 OR (NEW.charged<>OLD.charged+1 AND NEW.charged<>OLD.charged-public.download_stop_charge_releasing(OLD.allocation_id)) THEN
  RAISE EXCEPTION 'immutable stop backing and charge' USING ERRCODE='23514';
 END IF;RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION download_stop_charge_releasing(uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION release_download_stop_charge() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE l public.download_stop_lifecycle; p public.download_stop_pool; h bigint;
BEGIN
 IF NOT public.download_stop_retiring(OLD.download_id) THEN RAISE EXCEPTION 'stop charge remains unresolved' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT l FROM public.download_stop_lifecycle WHERE download_id=OLD.download_id;
 SELECT * INTO STRICT p FROM public.download_stop_pool WHERE root_id=OLD.root_id;
 h:=(l.binding->'Policy'->>'BackupHorizonSeconds')::bigint;
 IF h>0 THEN
  INSERT INTO public.download_stop_history(root_id,allocation_id,installation_id,issuer_epoch,policy_digest,release_at,delete_by,hard_delete_by,eligible_at,horizon_seconds,records,overdue)
  VALUES(OLD.root_id,OLD.allocation_id,OLD.installation_id,OLD.issuer_epoch,p.policy_digest,(l.binding->>'HistoryReleaseAt')::timestamptz,(l.binding->>'HistoryDeleteBy')::timestamptz,OLD.retain_until,(l.binding->>'HistoryReleaseAt')::timestamptz,h,1,clock_timestamp()>=l.live_retire_by OR l.overdue_selected_at IS NOT NULL OR l.mode='unwritten')
  ON CONFLICT(root_id,allocation_id,policy_digest,release_at,delete_by) DO UPDATE SET records=public.download_stop_history.records+1;
 ELSE
  UPDATE public.download_stop_backing SET charged=charged-1 WHERE allocation_id=OLD.allocation_id AND charged>0;
  IF NOT FOUND THEN RAISE EXCEPTION 'stop charge mismatch' USING ERRCODE='23514';END IF;
 END IF;RETURN OLD;
END $$;
CREATE FUNCTION guard_download_stop_history() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE l public.download_stop_lifecycle; t public.fleet_current_trust; n timestamptz; p public.download_stop_pool;
BEGIN
 IF TG_OP='DELETE' THEN
  IF OLD.drain_xid IS DISTINCT FROM pg_current_xact_id() OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'stop history remains backed' USING ERRCODE='23514';END IF;RETURN OLD;
 END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id FOR SHARE;
 n:=clock_timestamp();
 IF t.recovery_blocked OR t.suspended OR t.observed_at>n OR n>=t.fresh_until OR t.issuer_epoch<>NEW.issuer_epoch THEN RAISE EXCEPTION 'stop history recovery unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND NEW.drain_xid IS DISTINCT FROM OLD.drain_xid THEN
  IF OLD.drain_xid IS NOT NULL OR NEW.drain_xid IS DISTINCT FROM pg_current_xact_id() OR n<OLD.eligible_at OR (to_jsonb(NEW)-'drain_xid') IS DISTINCT FROM (to_jsonb(OLD)-'drain_xid') THEN RAISE EXCEPTION 'stop history drain unavailable' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 IF pg_trigger_depth()<2 OR NEW.drain_xid IS NOT NULL THEN RAISE EXCEPTION 'stop history source unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT l FROM public.download_stop_lifecycle WHERE root_id=NEW.root_id AND allocation_id=NEW.allocation_id AND finalization_xid=pg_current_xact_id() AND terminal_acknowledged_at IS NOT NULL AND (binding->>'HistoryReleaseAt')::timestamptz=NEW.release_at AND (binding->>'HistoryDeleteBy')::timestamptz=NEW.delete_by;
 SELECT * INTO STRICT p FROM public.download_stop_pool WHERE root_id=NEW.root_id;
 IF NEW.installation_id<>l.installation_id OR NEW.issuer_epoch<>l.issuer_epoch OR NEW.policy_digest<>p.policy_digest OR NEW.horizon_seconds<>(l.binding->'Policy'->>'BackupHorizonSeconds')::bigint OR NEW.hard_delete_by<>(l.binding->>'HardDeleteBy')::timestamptz THEN RAISE EXCEPTION 'stop history binding changed' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.records<>1 THEN RAISE EXCEPTION 'invalid first stop history charge' USING ERRCODE='23514';END IF;
 ELSE
  IF OLD.drain_xid IS NOT NULL OR NEW.records<>OLD.records+1 OR (to_jsonb(NEW)-ARRAY['records','eligible_at','overdue']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['records','eligible_at','overdue']) OR NEW.eligible_at<OLD.eligible_at OR OLD.overdue AND NOT NEW.overdue THEN RAISE EXCEPTION 'immutable stop history' USING ERRCODE='23514';END IF;
 END IF;
 NEW.eligible_at:=GREATEST(NEW.eligible_at,NEW.release_at,n+make_interval(secs=>NEW.horizon_seconds::double precision));
 NEW.overdue:=NEW.overdue OR n>=l.live_retire_by OR l.overdue_selected_at IS NOT NULL OR l.mode='unwritten';
 IF NEW.records>(SELECT charged FROM public.download_stop_backing WHERE allocation_id=NEW.allocation_id) THEN RAISE EXCEPTION 'stop history exceeds original charge' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE FUNCTION drain_download_stop_history() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.drain_xid IS NULL THEN RETURN NEW;END IF;
 IF OLD.drain_xid IS NOT NULL OR NEW.drain_xid IS DISTINCT FROM pg_current_xact_id() THEN RAISE EXCEPTION 'stop history drain unavailable' USING ERRCODE='23514';END IF;
 UPDATE public.download_stop_pool SET history_backing_until=GREATEST(history_backing_until,clock_timestamp()+make_interval(secs=>NEW.horizon_seconds::double precision)) WHERE root_id=NEW.root_id;
 UPDATE public.download_stop_backing SET charged=charged-NEW.records WHERE allocation_id=NEW.allocation_id AND root_id=NEW.root_id AND charged>=NEW.records;
 IF NOT FOUND THEN RAISE EXCEPTION 'stop history charge mismatch' USING ERRCODE='23514';END IF;
 DELETE FROM public.download_stop_history WHERE root_id=NEW.root_id AND allocation_id=NEW.allocation_id AND policy_digest=NEW.policy_digest AND release_at=NEW.release_at AND delete_by=NEW.delete_by;
 RETURN NEW;
END $$;
CREATE FUNCTION finish_download_stop_retirement(r uuid,i uuid,installation uuid) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE l public.download_stop_lifecycle; t public.fleet_current_trust; started timestamptz:=clock_timestamp(); n timestamptz;
BEGIN
 SELECT * INTO l FROM public.download_stop_lifecycle WHERE root_id=r AND download_id=i AND installation_id=installation;
 IF NOT FOUND THEN RETURN false;END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=installation FOR SHARE;
 PERFORM 1 FROM public.download_stop_pool WHERE root_id=r FOR UPDATE;
 PERFORM 1 FROM public.download_stop_backing WHERE allocation_id=l.allocation_id AND root_id=r FOR UPDATE;
 PERFORM 1 FROM public.download_stop WHERE download_id=i AND root_id=r FOR UPDATE;
 SELECT * INTO STRICT l FROM public.download_stop_lifecycle WHERE root_id=r AND download_id=i AND installation_id=installation FOR UPDATE;
 n:=clock_timestamp();
 IF n>=started+interval '5 seconds' OR n>=t.fresh_until OR t.observed_at>n OR t.recovery_blocked OR t.suspended OR t.issuer_epoch<>l.issuer_epoch OR l.terminal_acknowledged_at IS NULL OR l.terminal_purge IS NULL OR l.lease->>'Phase' NOT IN ('terminal','overdue') OR n>=(l.lease->>'Until')::timestamptz OR l.finalization_xid IS NOT NULL THEN RAISE EXCEPTION 'stop retirement unavailable' USING ERRCODE='23514';END IF;
 UPDATE public.download_stop_lifecycle SET finalization_xid=pg_current_xact_id() WHERE download_id=i;
 DELETE FROM public.download_stop WHERE root_id=r AND download_id=i;
 DELETE FROM public.download_stop_lifecycle WHERE root_id=r AND download_id=i;
 RETURN true;
END $$;
CREATE FUNCTION finish_download_stop_history(r uuid,a uuid,p bytea,releases timestamptz,deletes timestamptz,installation uuid) RETURNS TABLE(records bigint,overdue boolean) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE h public.download_stop_history; t public.fleet_current_trust; started timestamptz:=clock_timestamp(); n timestamptz; present boolean;
BEGIN
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=installation FOR SHARE;
 PERFORM 1 FROM public.download_stop_pool WHERE root_id=r FOR UPDATE;
 PERFORM 1 FROM public.download_stop_backing WHERE allocation_id=a AND root_id=r FOR UPDATE;
 SELECT * INTO h FROM public.download_stop_history WHERE root_id=r AND allocation_id=a AND policy_digest=p AND release_at=releases AND delete_by=deletes FOR UPDATE;
 present:=FOUND;n:=clock_timestamp();
 IF n>=started+interval '5 seconds' OR n>=t.fresh_until OR t.observed_at>n OR t.recovery_blocked OR t.suspended THEN RAISE EXCEPTION 'stop history recovery unavailable' USING ERRCODE='23514';END IF;
 IF NOT present THEN RETURN QUERY SELECT 0::bigint,false;RETURN;END IF;
 IF h.installation_id<>installation OR h.issuer_epoch<>t.issuer_epoch OR n<h.eligible_at OR h.drain_xid IS NOT NULL THEN RAISE EXCEPTION 'stop history release unavailable' USING ERRCODE='23514';END IF;
 UPDATE public.download_stop_history SET drain_xid=pg_current_xact_id() WHERE root_id=r AND allocation_id=a AND policy_digest=p AND release_at=releases AND delete_by=deletes;
 RETURN QUERY SELECT h.records,h.overdue OR n>=h.delete_by;
END $$;
CREATE FUNCTION require_download_stop_retirement() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.finalization_xid IS NOT NULL AND EXISTS(SELECT 1 FROM public.download_stop_lifecycle WHERE download_id=NEW.download_id) THEN RAISE EXCEPTION 'stranded stop retirement' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE FUNCTION require_download_stop_history_retirement() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.drain_xid IS NOT NULL AND EXISTS(SELECT 1 FROM public.download_stop_history WHERE root_id=NEW.root_id AND allocation_id=NEW.allocation_id AND policy_digest=NEW.policy_digest AND release_at=NEW.release_at AND delete_by=NEW.delete_by) THEN RAISE EXCEPTION 'stranded stop history drain' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION release_download_stop_charge(),guard_download_stop_history(),drain_download_stop_history(),finish_download_stop_retirement(uuid,uuid,uuid),finish_download_stop_history(uuid,uuid,bytea,timestamptz,timestamptz,uuid),require_download_stop_retirement(),require_download_stop_history_retirement() FROM PUBLIC;
CREATE TRIGGER download_stop_charge_release AFTER DELETE ON download_stop FOR EACH ROW EXECUTE FUNCTION release_download_stop_charge();
CREATE TRIGGER download_stop_history_guard BEFORE INSERT OR UPDATE OR DELETE ON download_stop_history FOR EACH ROW EXECUTE FUNCTION guard_download_stop_history();
CREATE TRIGGER download_stop_history_drain AFTER UPDATE ON download_stop_history FOR EACH ROW EXECUTE FUNCTION drain_download_stop_history();
CREATE CONSTRAINT TRIGGER download_stop_retirement_complete AFTER UPDATE ON download_stop_lifecycle DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_download_stop_retirement();
CREATE CONSTRAINT TRIGGER download_stop_history_retirement_complete AFTER UPDATE ON download_stop_history DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_download_stop_history_retirement();
