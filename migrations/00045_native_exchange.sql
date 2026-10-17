-- +goose Up
-- Native rendezvous is distinct from certificate enrollment/request ownership.
-- No credentials, native metadata, plaintext, keys or arbitrary routes persist.
CREATE TABLE download_native_backing (
 allocation_id uuid PRIMARY KEY, root_id uuid NOT NULL,
 FOREIGN KEY(allocation_id,root_id) REFERENCES download_allocation(id,root_id),
 policy_json jsonb NOT NULL CHECK(jsonb_typeof(policy_json)='object' AND octet_length(policy_json::text)<=4096),
 rows_limit bigint NOT NULL CHECK(rows_limit BETWEEN 1 AND 100000),
 keys_limit bigint NOT NULL CHECK(keys_limit BETWEEN 1 AND 263168),
 transitions_per_row bigint NOT NULL CHECK(transitions_per_row BETWEEN 8 AND 65536),
 charged_rows bigint NOT NULL DEFAULT 0 CHECK(charged_rows BETWEEN 0 AND rows_limit),
 charged_keys bigint NOT NULL DEFAULT 0 CHECK(charged_keys BETWEEN 0 AND keys_limit),
 backup_horizon_seconds bigint NOT NULL CHECK(backup_horizon_seconds BETWEEN 0 AND 316224000),
 cleanup_seconds bigint NOT NULL CHECK(cleanup_seconds BETWEEN 1 AND 86400),
 valid_until timestamptz NOT NULL CHECK(isfinite(valid_until)),
 retire_by timestamptz NOT NULL CHECK(isfinite(retire_by)),
 residual_until timestamptz NOT NULL CHECK(isfinite(residual_until) AND residual_until>=retire_by),
 overdue boolean NOT NULL DEFAULT false,
 CHECK(retire_by=valid_until+make_interval(secs=>(2*backup_horizon_seconds+cleanup_seconds)::double precision))
);
CREATE TABLE download_native_owner (
 worker_id uuid PRIMARY KEY REFERENCES download_worker(id),
 root_id uuid NOT NULL, allocation_id uuid NOT NULL REFERENCES download_native_backing(allocation_id),
 operation_id uuid NOT NULL UNIQUE,
 fence bigint NOT NULL CHECK(fence BETWEEN 1 AND 1152921504606846976),
 operation_json jsonb NOT NULL CHECK(jsonb_typeof(operation_json)='object' AND octet_length(operation_json::text)<=8192),
 authority_json jsonb NOT NULL CHECK(jsonb_typeof(authority_json)='object' AND octet_length(authority_json::text)<=16384),
 lease_sequence bigint NOT NULL CHECK(lease_sequence BETWEEN 1 AND 1152921504606846976),
 lease_started timestamptz NOT NULL, lease_until timestamptz NOT NULL,
 updates bigint NOT NULL DEFAULT 1 CHECK(updates BETWEEN 1 AND 65536),
 closed boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL,
 retired_at timestamptz,
 CHECK(isfinite(lease_started) AND lease_until>lease_started AND lease_until<=lease_started+interval '5 seconds'),
 CHECK(retired_at IS NULL OR closed)
);
CREATE TABLE download_native_key (
 window_id uuid PRIMARY KEY REFERENCES download_window(id),
 worker_id uuid NOT NULL REFERENCES download_native_owner(worker_id),
 root_id uuid NOT NULL, allocation_id uuid NOT NULL REFERENCES download_native_backing(allocation_id),
 operation_id uuid NOT NULL, operation_fence bigint NOT NULL CHECK(operation_fence>0),
 authority_json jsonb NOT NULL CHECK(jsonb_typeof(authority_json)='object' AND octet_length(authority_json::text)<=16384),
 proof_json jsonb NOT NULL CHECK(jsonb_typeof(proof_json)='object' AND octet_length(proof_json::text)<=16384),
 installation_id uuid NOT NULL,key_id text NOT NULL CHECK(length(key_id) BETWEEN 1 AND 128),
 peer_id uuid NOT NULL, certificate_sha256 bytea NOT NULL CHECK(octet_length(certificate_sha256)=32),
 valid_until timestamptz NOT NULL CHECK(isfinite(valid_until)),
 used_roles smallint NOT NULL DEFAULT 0 CHECK(used_roles BETWEEN 0 AND 7),
 created_at timestamptz NOT NULL,
 CHECK(valid_until>created_at AND valid_until<=created_at+interval '5 seconds')
);

-- +goose StatementBegin
CREATE FUNCTION guard_download_native_backing() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE p jsonb;q jsonb;need_backup numeric;need_wal numeric;a public.download_allocation;
BEGIN
 IF TG_OP='DELETE' THEN
  IF clock_timestamp()<OLD.residual_until OR EXISTS(SELECT 1 FROM public.download_native_owner WHERE allocation_id=OLD.allocation_id) OR EXISTS(SELECT 1 FROM public.download_native_key WHERE allocation_id=OLD.allocation_id) THEN RAISE EXCEPTION 'native residual history still backed' USING ERRCODE='23514';END IF;RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' THEN
  IF pg_trigger_depth()>=2 AND (to_jsonb(NEW)-ARRAY['residual_until','overdue']) IS NOT DISTINCT FROM (to_jsonb(OLD)-ARRAY['residual_until','overdue']) AND NEW.residual_until>=OLD.residual_until AND (NOT OLD.overdue OR NEW.overdue) THEN RETURN NEW;END IF;
  IF pg_trigger_depth()<2 OR (to_jsonb(NEW)-ARRAY['charged_rows','charged_keys']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['charged_rows','charged_keys']) OR NEW.charged_rows<OLD.charged_rows OR NEW.charged_keys<OLD.charged_keys OR (NEW.charged_rows-OLD.charged_rows)+(NEW.charged_keys-OLD.charged_keys)<>1 THEN RAISE EXCEPTION 'immutable native backing' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id;
 p:=NEW.policy_json;q:=p->'History';
 IF NOT(p ?& ARRAY['AllocationID','RootID','PolicyID','PolicyDigest','Rows','Keys','TransitionsPerRow','BackupBytes','WALBytes','BackupHorizonSeconds','CleanupSeconds','ValidUntil','RetireBy','History']) OR jsonb_typeof(q) IS DISTINCT FROM 'object' OR NEW.charged_rows<>0 OR NEW.charged_keys<>0 OR NEW.residual_until<>NEW.retire_by OR NEW.overdue OR NEW.valid_until>a.valid_until OR NEW.valid_until<=clock_timestamp() OR (p->>'AllocationID')::uuid IS DISTINCT FROM NEW.allocation_id OR (p->>'RootID')::uuid IS DISTINCT FROM NEW.root_id OR (p->>'Rows')::bigint IS DISTINCT FROM NEW.rows_limit OR (p->>'Keys')::bigint IS DISTINCT FROM NEW.keys_limit OR (p->>'TransitionsPerRow')::bigint IS DISTINCT FROM NEW.transitions_per_row OR (p->>'BackupHorizonSeconds')::bigint IS DISTINCT FROM NEW.backup_horizon_seconds OR (p->>'CleanupSeconds')::bigint IS DISTINCT FROM NEW.cleanup_seconds OR (p->>'ValidUntil')::timestamptz IS DISTINCT FROM NEW.valid_until OR (p->>'RetireBy')::timestamptz IS DISTINCT FROM NEW.retire_by THEN RAISE EXCEPTION 'invalid native backing' USING ERRCODE='23514';END IF;
 IF NOT(q ?& ARRAY['ID','Digest','RowBytes','TransitionWALBytes','BackupCopies','WALCopies']) OR jsonb_typeof(q->'ID') IS DISTINCT FROM 'string' OR jsonb_typeof(q->'Digest') IS DISTINCT FROM 'array' OR NOT COALESCE((q->>'RowBytes')::bigint BETWEEN 65536 AND 16777216 AND (q->>'TransitionWALBytes')::bigint BETWEEN 65536 AND 67108864 AND (q->>'BackupCopies')::bigint BETWEEN 1 AND 64 AND (q->>'WALCopies')::bigint BETWEEN 1 AND 64,FALSE) THEN RAISE EXCEPTION 'native history qualification missing' USING ERRCODE='23514';END IF;
 need_backup:=2*(q->>'RowBytes')::numeric*(q->>'BackupCopies')::numeric*(NEW.rows_limit+NEW.keys_limit);
 need_wal:=(q->>'TransitionWALBytes')::numeric*(q->>'WALCopies')::numeric*((NEW.transitions_per_row+4)*NEW.rows_limit+8*NEW.keys_limit);
 IF NOT COALESCE((p->>'BackupBytes')::numeric>=need_backup AND (p->>'BackupBytes')::numeric<=9223372036854775807 AND (p->>'WALBytes')::numeric>=need_wal AND (p->>'WALBytes')::numeric<=9223372036854775807,FALSE) THEN RAISE EXCEPTION 'native history backing insufficient' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER download_native_backing_guard BEFORE INSERT OR UPDATE OR DELETE ON download_native_backing FOR EACH ROW EXECUTE FUNCTION guard_download_native_backing();

CREATE FUNCTION guard_download_native_owner() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE w public.download_worker;s public.artifact_download;b public.download_native_backing;e public.download_worker_enrollment;n timestamptz;o jsonb;ref jsonb;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=OLD.allocation_id;
  SELECT * INTO STRICT w FROM public.download_worker WHERE id=OLD.worker_id;
  n:=clock_timestamp();
  IF OLD.retired_at IS NULL OR w.retired_proof_json IS NULL OR n<OLD.retired_at+make_interval(secs=>b.backup_horizon_seconds::double precision) OR EXISTS(SELECT 1 FROM public.download_native_key WHERE worker_id=OLD.worker_id) THEN RAISE EXCEPTION 'native owner history not quiescent' USING ERRCODE='23514';END IF;
  UPDATE public.download_native_backing SET residual_until=GREATEST(residual_until,n+make_interval(secs=>backup_horizon_seconds::double precision)),overdue=overdue OR n+make_interval(secs=>backup_horizon_seconds::double precision)>retire_by WHERE allocation_id=b.allocation_id;RETURN OLD;
 END IF;
 SELECT * INTO STRICT w FROM public.download_worker WHERE id=NEW.worker_id;
 SELECT * INTO STRICT s FROM public.artifact_download WHERE id=w.session_id;
 SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=NEW.allocation_id FOR UPDATE;
 n:=clock_timestamp();o:=NEW.operation_json;ref:=o->'Reference';
 IF TG_OP='UPDATE' AND NEW.retired_at IS NOT NULL THEN
  IF OLD.retired_at IS NOT NULL OR w.retired_proof_json IS NULL OR NOT NEW.closed OR NEW.retired_at<>NEW.updated_at OR NEW.updated_at>n OR NEW.updates<>OLD.updates+1 OR (to_jsonb(NEW)-ARRAY['closed','retired_at','updated_at','updates']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['closed','retired_at','updated_at','updates']) OR NEW.updates>b.transitions_per_row THEN RAISE EXCEPTION 'invalid native owner retirement' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 IF TG_OP='UPDATE' AND NEW.closed THEN
  IF OLD.retired_at IS NOT NULL OR OLD.closed OR NEW.updates<>OLD.updates+1 OR NEW.updated_at>n OR (to_jsonb(NEW)-ARRAY['closed','updated_at','updates']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['closed','updated_at','updates']) OR NEW.updates>b.transitions_per_row-1 THEN RAISE EXCEPTION 'invalid native owner close' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 SELECT * INTO STRICT e FROM public.download_worker_enrollment WHERE worker_id=NEW.worker_id;
 IF jsonb_typeof(o->'StartedAt') IS DISTINCT FROM 'string' OR jsonb_typeof(o->'Until') IS DISTINCT FROM 'string' OR jsonb_typeof(NEW.authority_json->'ValidUntil') IS DISTINCT FROM 'string' OR n>=b.valid_until OR n>=NEW.lease_until OR NEW.lease_started>n OR NEW.updated_at<>NEW.lease_started OR NEW.updates>b.transitions_per_row-2 OR NEW.closed OR NEW.retired_at IS NOT NULL OR w.termination_json IS NOT NULL OR w.retired_proof_json IS NOT NULL OR w.audit_receipt_json IS NULL OR NEW.root_id<>w.root_id OR NEW.allocation_id<>w.allocation_id OR NEW.lease_until>w.run_until OR NEW.lease_until>s.deadline OR (ref->>'WorkerID')::uuid IS DISTINCT FROM NEW.worker_id OR (ref->>'SessionID')::uuid IS DISTINCT FROM s.id OR (ref->>'InstallationID')::uuid IS DISTINCT FROM w.installation_id OR (ref->>'OperationID')::uuid IS DISTINCT FROM NEW.operation_id OR (ref->>'Fence')::bigint IS DISTINCT FROM NEW.fence OR o->'SourceVersion' IS DISTINCT FROM NEW.authority_json#>'{Scope,Version}' OR NEW.authority_json->'Scope' IS DISTINCT FROM s.scope_json OR (NEW.authority_json->>'ValidUntil')::timestamptz<NEW.lease_until OR (o->>'Until')::timestamptz<NEW.lease_until OR (o->>'Until')::timestamptz>w.run_until OR (o->>'WorkerPodUID') IS DISTINCT FROM (convert_from(w.binding_json,'UTF8')::jsonb)->>'PodUID' OR o->'WorkerPublicKey' IS DISTINCT FROM (convert_from(e.enrollment_json,'UTF8')::jsonb)->'PublicKeyDigest' OR e.audit_receipt_json IS NULL THEN RAISE EXCEPTION 'native operation binding mismatch' USING ERRCODE='23514';END IF;
 IF o->>'Kind' IN ('prepare-context','observe-prepared-context') THEN
  IF NEW.lease_sequence<>1 OR (o->>'Until')::timestamptz>(o->>'StartedAt')::timestamptz+interval '5 seconds' OR NOT EXISTS(SELECT 1 FROM public.download_batch p WHERE p.id=(o->>'ParentID')::uuid AND p.session_id=s.id AND p.generation=(o->>'Generation')::bigint AND p.intent_json#>>'{Batch,Purpose}'='prepare' AND p.audit_receipt_json IS NOT NULL) THEN RAISE EXCEPTION 'native preparation parent unavailable' USING ERRCODE='23514';END IF;
 ELSIF o->>'Kind'='read-context-response' THEN
  IF NOT EXISTS(SELECT 1 FROM public.download_response r WHERE r.id=(o->>'ParentID')::uuid AND r.session_id=s.id AND r.generation=(o->>'Generation')::bigint AND r.generation=s.generation AND NOT r.closed AND r.lease_sequence=NEW.lease_sequence AND r.lease_until>=NEW.lease_until AND r.until_at>n) THEN RAISE EXCEPTION 'native response parent unavailable' USING ERRCODE='23514';END IF;
 ELSE RAISE EXCEPTION 'unknown native operation' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.fence<>1 OR NEW.updates<>1 THEN RAISE EXCEPTION 'native initial fence' USING ERRCODE='23514';END IF;
  UPDATE public.download_native_backing SET charged_rows=charged_rows+1 WHERE allocation_id=b.allocation_id;
 ELSE
  IF OLD.retired_at IS NOT NULL OR NEW.updates<>OLD.updates+1 OR ROW(NEW.worker_id,NEW.root_id,NEW.allocation_id) IS DISTINCT FROM ROW(OLD.worker_id,OLD.root_id,OLD.allocation_id) THEN RAISE EXCEPTION 'native immutable owner' USING ERRCODE='23514';END IF;
  IF NEW.operation_id=OLD.operation_id THEN
   IF OLD.closed OR NEW.operation_json IS DISTINCT FROM OLD.operation_json OR NEW.fence<>OLD.fence OR o->>'Kind'<>'read-context-response' OR NEW.lease_sequence<=OLD.lease_sequence THEN RAISE EXCEPTION 'native operation replay cannot renew' USING ERRCODE='23514';END IF;
  ELSIF NOT OLD.closed OR NEW.fence<>OLD.fence+1 THEN RAISE EXCEPTION 'native previous owner not closed' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER download_native_owner_guard BEFORE INSERT OR UPDATE OR DELETE ON download_native_owner FOR EACH ROW EXECUTE FUNCTION guard_download_native_owner();

CREATE FUNCTION guard_download_native_key() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b public.download_native_backing;o public.download_native_owner;w public.download_worker;n timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=OLD.allocation_id;
  SELECT * INTO STRICT o FROM public.download_native_owner WHERE worker_id=OLD.worker_id;
  SELECT * INTO STRICT w FROM public.download_worker WHERE id=OLD.worker_id;
  n:=clock_timestamp();
  IF o.retired_at IS NULL OR w.retired_proof_json IS NULL OR n<o.retired_at+make_interval(secs=>b.backup_horizon_seconds::double precision) THEN RAISE EXCEPTION 'native key history not quiescent' USING ERRCODE='23514';END IF;
  UPDATE public.download_native_backing SET residual_until=GREATEST(residual_until,n+make_interval(secs=>backup_horizon_seconds::double precision)),overdue=overdue OR n+make_interval(secs=>backup_horizon_seconds::double precision)>retire_by WHERE allocation_id=b.allocation_id;RETURN OLD;
 END IF;
 SELECT * INTO STRICT o FROM public.download_native_owner WHERE worker_id=NEW.worker_id;
 SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=NEW.allocation_id FOR UPDATE;
 n:=clock_timestamp();
 IF o.closed OR o.retired_at IS NOT NULL OR o.root_id<>NEW.root_id OR o.allocation_id<>NEW.allocation_id OR o.operation_id<>NEW.operation_id OR o.fence<>NEW.operation_fence OR NEW.valid_until>o.lease_until OR n>=NEW.valid_until OR NOT EXISTS(SELECT 1 FROM public.download_window win JOIN public.download_response r ON r.id=win.response_id JOIN public.artifact_download s ON s.id=r.session_id WHERE win.id=NEW.window_id AND r.id=(o.operation_json->>'ParentID')::uuid AND r.generation=(o.operation_json->>'Generation')::bigint AND r.generation=s.generation AND r.active_window=win.id AND NOT r.closed AND r.lease_until>=NEW.valid_until AND win.intent_receipt IS NOT NULL AND win.intent_completion IS NOT NULL AND win.outcome_json IS NULL AND NEW.authority_json->'Scope'=s.scope_json) THEN RAISE EXCEPTION 'native key current window unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF jsonb_typeof(NEW.authority_json->'ValidUntil') IS DISTINCT FROM 'string' OR jsonb_typeof(NEW.proof_json->'FreshUntil') IS DISTINCT FROM 'string' OR NEW.used_roles<>0 OR NEW.created_at>n OR NEW.valid_until>(NEW.authority_json->>'ValidUntil')::timestamptz OR NEW.valid_until>(NEW.proof_json->>'FreshUntil')::timestamptz OR NEW.installation_id IS DISTINCT FROM (o.operation_json#>>'{Reference,InstallationID}')::uuid OR NEW.peer_id IS DISTINCT FROM (o.operation_json->>'WorkerPodUID')::uuid THEN RAISE EXCEPTION 'native key identity mismatch' USING ERRCODE='23514';END IF;
  UPDATE public.download_native_backing SET charged_keys=charged_keys+1 WHERE allocation_id=b.allocation_id;
 ELSIF (to_jsonb(NEW)-'used_roles') IS DISTINCT FROM (to_jsonb(OLD)-'used_roles') OR NEW.used_roles=OLD.used_roles OR NEW.used_roles|OLD.used_roles<>NEW.used_roles OR (NEW.used_roles#OLD.used_roles) NOT IN (1,2,4) THEN RAISE EXCEPTION 'native key slots immutable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER download_native_key_guard BEFORE INSERT OR UPDATE OR DELETE ON download_native_key FOR EACH ROW EXECUTE FUNCTION guard_download_native_key();
REVOKE ALL ON FUNCTION guard_download_native_backing(),guard_download_native_owner(),guard_download_native_key() FROM PUBLIC;
-- +goose StatementEnd
