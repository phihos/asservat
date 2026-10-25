-- +goose Up
-- ADR-206: purpose-specific bounded query state. No runtime role or protected
-- backing producer is installed here. Missing independently accepted backing,
-- live C-07 guard, audit completion or C-14 worker proof denies effects.
-- Every retained row stays charged after expiry; retirement is not inferred.

CREATE TABLE context_query_backing (
 root_id uuid PRIMARY KEY REFERENCES permission_stream(id),
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id),
 acceptance_id uuid UNIQUE NOT NULL,
 profile jsonb NOT NULL CHECK(jsonb_typeof(profile)='object' AND octet_length(profile::text) BETWEEN 2 AND 32768),
 qualification jsonb NOT NULL CHECK(jsonb_typeof(qualification)='object' AND octet_length(qualification::text) BETWEEN 2 AND 32768),
 envelope jsonb NOT NULL CHECK(jsonb_typeof(envelope)='object' AND octet_length(envelope::text) BETWEEN 2 AND 8192),
 query_limit bigint NOT NULL CHECK(query_limit BETWEEN 1 AND 1000000),
 principal_query_limit bigint NOT NULL CHECK(principal_query_limit BETWEEN 1 AND query_limit),
 principal_account_limit bigint NOT NULL CHECK(principal_account_limit BETWEEN 1 AND query_limit),
 allocation_limit bigint NOT NULL CHECK(allocation_limit BETWEEN 1 AND 1000000),
 allocated bigint NOT NULL DEFAULT 0 CHECK(allocated BETWEEN 0 AND query_limit),
 principals bigint NOT NULL DEFAULT 0 CHECK(principals BETWEEN 0 AND principal_account_limit),
 allocations bigint NOT NULL DEFAULT 0 CHECK(allocations BETWEEN 0 AND allocation_limit),
 observed_at timestamptz NOT NULL, fresh_until timestamptz NOT NULL,
 hard_until timestamptz NOT NULL, effects_until timestamptz NOT NULL, cleanup_until timestamptz NOT NULL, retire_by timestamptz NOT NULL,
 suspended boolean NOT NULL DEFAULT true,
 CHECK(isfinite(observed_at) AND isfinite(fresh_until) AND fresh_until>observed_at AND fresh_until<=observed_at+interval '5 seconds'),
 CHECK(isfinite(hard_until) AND isfinite(effects_until) AND isfinite(cleanup_until) AND isfinite(retire_by) AND effects_until>=hard_until AND cleanup_until>effects_until AND retire_by>=cleanup_until)
);
CREATE TABLE context_query_allocation (
 id uuid PRIMARY KEY, root_id uuid NOT NULL REFERENCES context_query_backing(root_id),
 cluster_id uuid NOT NULL, namespace_uid text NOT NULL CHECK(octet_length(namespace_uid) BETWEEN 1 AND 64),
 workload_uid text NOT NULL CHECK(octet_length(workload_uid) BETWEEN 1 AND 64),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1152921504606846976),
 pool_source jsonb NOT NULL CHECK(jsonb_typeof(pool_source)='object' AND octet_length(pool_source::text)<=4096),
 policy_source jsonb NOT NULL CHECK(jsonb_typeof(policy_source)='object' AND octet_length(policy_source::text)<=4096),
 query_limit bigint NOT NULL CHECK(query_limit BETWEEN 1 AND 1000000),
 allocated bigint NOT NULL DEFAULT 0 CHECK(allocated BETWEEN 0 AND query_limit),
 UNIQUE(root_id,cluster_id,namespace_uid,workload_uid), UNIQUE(id,root_id)
);
CREATE TABLE context_query_principal (
 id uuid PRIMARY KEY, root_id uuid NOT NULL REFERENCES context_query_backing(root_id),
 principal_key bytea NOT NULL CHECK(octet_length(principal_key)=32),
 allocated bigint NOT NULL CHECK(allocated BETWEEN 0 AND 1000000),
 UNIQUE(root_id,principal_key), UNIQUE(id,root_id)
);
CREATE TABLE context_query (
 id uuid PRIMARY KEY, root_id uuid NOT NULL REFERENCES context_query_backing(root_id),
 allocation_id uuid NOT NULL, account_id uuid NOT NULL,
 principal_key bytea NOT NULL CHECK(octet_length(principal_key)=32),
 actor jsonb NOT NULL CHECK(jsonb_typeof(actor)='object' AND octet_length(actor::text)<=4096),
 query jsonb NOT NULL CHECK(jsonb_typeof(query)='object' AND octet_length(query::text) BETWEEN 2 AND 65536),
 initial_request jsonb NOT NULL CHECK(jsonb_typeof(initial_request)='object' AND octet_length(initial_request::text) BETWEEN 2 AND 8192),
 operation_id uuid UNIQUE NOT NULL, worker_id uuid UNIQUE NOT NULL,
 created_at timestamptz NOT NULL, deadline timestamptz NOT NULL,
 cleanup_until timestamptz NOT NULL, retire_by timestamptz NOT NULL,
 issuer_epoch uuid NOT NULL, postmaster_at timestamptz NOT NULL, database_oid oid NOT NULL,
 generation smallint NOT NULL DEFAULT 0 CHECK(generation BETWEEN 0 AND 2),
 active_batch uuid, polls bigint NOT NULL DEFAULT 0 CHECK(polls BETWEEN 0 AND 1000000),
 controls bigint NOT NULL DEFAULT 0 CHECK(controls BETWEEN 0 AND 1000000),
 uncertain boolean NOT NULL DEFAULT false,
 FOREIGN KEY(allocation_id,root_id) REFERENCES context_query_allocation(id,root_id),
 FOREIGN KEY(account_id,root_id) REFERENCES context_query_principal(id,root_id),
 CHECK(isfinite(created_at) AND isfinite(deadline) AND deadline>created_at AND deadline<=created_at+interval '60 seconds'),
 CHECK(isfinite(cleanup_until) AND isfinite(retire_by) AND cleanup_until>=deadline AND retire_by>=cleanup_until),
 CHECK(isfinite(postmaster_at)), UNIQUE(id,root_id)
);
-- Every invocation is bounded by the original poll/control allowance. This
-- association makes retries idempotent without creating another execution.
CREATE TABLE context_query_call (
 operation_id uuid PRIMARY KEY, query_id uuid NOT NULL REFERENCES context_query(id),
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object' AND octet_length(request::text) BETWEEN 2 AND 8192),
 is_poll boolean NOT NULL
);
CREATE TABLE context_query_worker (
 query_id uuid PRIMARY KEY REFERENCES context_query(id),
 worker_id uuid UNIQUE NOT NULL,
 binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object' AND octet_length(binding::text) BETWEEN 2 AND 16384),
 proof jsonb NOT NULL CHECK(jsonb_typeof(proof)='object' AND octet_length(proof::text) BETWEEN 2 AND 16384)
);
CREATE TABLE context_query_batch (
 id uuid PRIMARY KEY, query_id uuid NOT NULL REFERENCES context_query(id),
 operation_id uuid UNIQUE NOT NULL REFERENCES context_query_call(operation_id),
 generation smallint NOT NULL CHECK(generation BETWEEN 1 AND 2),
 batch jsonb NOT NULL CHECK(jsonb_typeof(batch)='object' AND octet_length(batch::text) BETWEEN 2 AND 16384),
 claim_id uuid, closed boolean NOT NULL DEFAULT false,
 UNIQUE(query_id,generation), UNIQUE(id,query_id)
);
CREATE TABLE context_query_key_binding (
 batch_id uuid PRIMARY KEY, query_id uuid NOT NULL,
 binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object' AND octet_length(binding::text) BETWEEN 2 AND 16384),
 used_roles smallint NOT NULL DEFAULT 0 CHECK(used_roles BETWEEN 0 AND 7),
 FOREIGN KEY(batch_id,query_id) REFERENCES context_query_batch(id,query_id)
);
-- A qualified worker/key producer must exist before any insert is granted.
-- This separate purpose table is not filled by a download proof or UUID cast.
REVOKE ALL ON context_query_backing,context_query_allocation,context_query_principal,context_query,context_query_call,context_query_worker,context_query_batch,context_query_key_binding FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_complete_object(j jsonb,required text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(jsonb_typeof(j)='object' AND NOT EXISTS(SELECT 1 FROM unnest(required) k WHERE j->k IS NULL OR j->k='null'::jsonb),false)
$$;

CREATE FUNCTION context_query_cost_valid(p jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE c jsonb:=p->'Cost'; k text; n numeric;
BEGIN
 IF NOT COALESCE(jsonb_typeof(c)='object' AND
  c->>'Workers'='1' AND c->>'ReadBatches'='2' AND c->>'ReadBytes'='8388608' AND
  c->>'StructuredBytes'='49152' AND c->>'WireBytes'='131072' AND c->>'UnwrapAttempts'='6',false) THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['ProviderRequests','AuthenticationRequests','SigningAttempts','AuditObjects','SQLRows','SQLBytes','WALBytes','BackupBytes'] LOOP
  n:=(c->>k)::numeric;
  IF n IS NULL OR n<1 OR n>1152921504606846976 OR trunc(n)<>n THEN RETURN false; END IF;
 END LOOP;
 RETURN COALESCE((c->>'ProviderRequests')::bigint>=6 AND
  (p->>'PollLimit')::bigint BETWEEN 1 AND 1000000 AND (p->>'ControlTransitionLimit')::bigint BETWEEN 1 AND 1000000 AND
  (c->>'SQLRows')::numeric>=8+(p->>'PollLimit')::numeric AND
  (c->>'AuditObjects')::numeric>=2*(1+(p->>'PollLimit')::numeric) AND
  (p->>'Lifetime')::numeric BETWEEN 1 AND 60000000000 AND p->'Path'->>'Purpose'='context-projection/v1',false);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;

-- Existing C-08 acknowledgement owns the writer receipt and immutable record
-- digest. Go checks its canonical typed digest; JSONB text is never rehashed.
CREATE FUNCTION context_query_intent_current(r uuid,op uuid,actor jsonb,epoch uuid,call jsonb) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(EXISTS(SELECT 1 FROM public.operation_audit a
 JOIN public.operation_audit_lifecycle l ON l.operation_id=a.id AND l.root_id=a.root_id
 JOIN public.fleet_current_trust t ON t.installation_id=l.installation_id
 WHERE a.id=op AND a.root_id=r AND a.lane='normal' AND l.lane='normal' AND a.issuer_epoch=epoch AND l.issuer_epoch=epoch AND t.issuer_epoch=epoch
 AND NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=clock_timestamp() AND clock_timestamp()<t.fresh_until
 AND public.incarnation_current(l.postmaster_at) AND l.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND a.intent_started AND a.intent_receipt IS NOT NULL AND l.intent_completion IS NOT NULL AND l.intent_completion->'Receipt'=a.intent_receipt
 AND l.binding=a.intent->'Lifecycle' AND l.retirement IS NULL AND NOT l.certificate_started AND l.finalization_xid IS NULL
 AND a.intent->'Actor'=actor AND call->'Principal'=actor AND call->>'ID'=op::text AND call->>'RootID'=r::text
 AND a.intent->>'Name'=call->>'Tool' AND a.intent->>'Name' IN ('get_file_excerpt','get_query_result')
 AND a.intent->>'InputFormat'='context-query-input/v1' AND call->>'InputFormat'='context-query-input/v1'
 AND a.intent->>'MACVersion'=call->>'MACVersion' AND a.intent->'InputDigest'=call->'InputDigest' AND a.intent->'PrincipalDigest'=call->'PrincipalDigest'
 AND (a.intent->>'CreatedAt')::timestamptz=(call->>'StartedAt')::timestamptz AND a.request_until=(call->>'Until')::timestamptz AND a.write_until=(call->>'WriteUntil')::timestamptz
 AND (a.intent->>'CreatedAt')::timestamptz<=clock_timestamp() AND clock_timestamp()<a.request_until
 AND l.intent_completion->>'Protocol'='closed-operation-audit/v1' AND l.intent_completion->>'RootID'=r::text AND l.intent_completion->>'OperationID'=op::text
 AND l.intent_completion->>'StoreID'=l.binding->'Policy'->>'StoreID' AND l.intent_completion->>'Phase'='intent'
 AND (l.intent_completion->>'StoredAt')::timestamptz>=(a.intent->>'CreatedAt')::timestamptz
 AND (l.intent_completion->>'ClosedAt')::timestamptz>=(l.intent_completion->>'StoredAt')::timestamptz
 AND (l.intent_completion->>'ClosedAt')::timestamptz<a.write_until AND (l.intent_completion->>'ClosedAt')::timestamptz<=clock_timestamp()),false)
$$;

-- Restrictive joined closure may finish after the request expires, but only
-- within the original cleanup interval and with the SAME positively closed
-- outcome. Current public access is neither required nor granted by closure.
CREATE FUNCTION context_query_outcome_closed(r uuid,op uuid,actor jsonb,epoch uuid) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(EXISTS(SELECT 1 FROM public.operation_audit a
 JOIN public.operation_audit_lifecycle l ON l.operation_id=a.id AND l.root_id=a.root_id
 JOIN public.fleet_current_trust t ON t.installation_id=l.installation_id
 WHERE a.id=op AND a.root_id=r AND a.lane='normal' AND l.lane='normal' AND a.issuer_epoch=epoch AND l.issuer_epoch=epoch AND t.issuer_epoch=epoch AND NOT t.recovery_blocked
 AND public.incarnation_current(l.postmaster_at) AND l.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND a.intent->'Actor'=actor AND a.intent->>'Name' IN ('get_file_excerpt','get_query_result') AND a.intent->>'InputFormat'='context-query-input/v1'
 AND a.intent_started AND a.intent_receipt IS NOT NULL AND l.intent_completion->'Receipt'=a.intent_receipt
 AND a.outcome_started AND a.outcome_receipt IS NOT NULL AND l.outcome_completion->'Receipt'=a.outcome_receipt
 AND a.outcome->>'Effect' IN ('none','accepted','unknown') AND a.outcome->'Intent'=a.intent
 AND l.binding=a.intent->'Lifecycle' AND l.retirement IS NULL AND NOT l.certificate_started AND l.finalization_xid IS NULL
 AND l.outcome_completion->>'Protocol'='closed-operation-audit/v1' AND l.outcome_completion->>'RootID'=r::text AND l.outcome_completion->>'OperationID'=op::text
 AND l.outcome_completion->>'StoreID'=l.binding->'Policy'->>'StoreID' AND l.outcome_completion->>'Phase'='outcome'
 AND (l.outcome_completion->>'StoredAt')::timestamptz>=(a.intent->>'CreatedAt')::timestamptz
 AND (l.outcome_completion->>'ClosedAt')::timestamptz>=(l.outcome_completion->>'StoredAt')::timestamptz
 AND (l.outcome_completion->>'ClosedAt')::timestamptz<a.write_until AND (l.outcome_completion->>'ClosedAt')::timestamptz<=clock_timestamp()),false)
$$;

CREATE FUNCTION guard_context_query_backing() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE k text; need numeric;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query obligations remain backed' USING ERRCODE='23514'; END IF;
 IF NOT public.context_query_cost_valid(NEW.profile) OR NEW.qualification IS DISTINCT FROM NEW.profile->'Qualification' THEN RAISE EXCEPTION 'query profile incomplete' USING ERRCODE='23514'; END IF;
 FOREACH k IN ARRAY ARRAY['Workers','ReadBatches','ReadBytes','StructuredBytes','WireBytes','UnwrapAttempts','ProviderRequests','AuthenticationRequests','SigningAttempts','AuditObjects','SQLRows','SQLBytes','WALBytes','BackupBytes'] LOOP
  need:=(NEW.profile->'Cost'->>k)::numeric*NEW.query_limit;
  IF (NEW.envelope->>k)::numeric IS NULL OR (NEW.envelope->>k)::numeric<need OR (NEW.envelope->>k)::numeric>1152921504606846976 THEN RAISE EXCEPTION 'query envelope insufficient' USING ERRCODE='23514'; END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['CPUMilli','MemoryBytes','WorkerTransientBytes','HubTransientBytes','ProviderConcurrency','AuthenticationConcurrency'] LOOP
  need:=(NEW.profile->'Worker'->>k)::numeric*NEW.query_limit;
  IF need IS NULL OR need<1 OR need>1152921504606846976 OR trunc(need)<>need OR
   (NEW.envelope->>k)::numeric IS NULL OR (NEW.envelope->>k)::numeric<need OR (NEW.envelope->>k)::numeric>1152921504606846976 THEN RAISE EXCEPTION 'query process or copy envelope incomplete' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF TG_OP='INSERT' THEN
  IF NEW.allocated<>0 OR NEW.principals<>0 OR NEW.allocations<>0 THEN RAISE EXCEPTION 'query initial spend invalid' USING ERRCODE='23514'; END IF;
 ELSIF (to_jsonb(NEW)-ARRAY['allocated','principals','allocations','observed_at','fresh_until','suspended']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['allocated','principals','allocations','observed_at','fresh_until','suspended']) OR
  NEW.allocated<OLD.allocated OR NEW.principals<OLD.principals OR NEW.allocations<OLD.allocations OR
  (ROW(NEW.allocated,NEW.principals,NEW.allocations) IS DISTINCT FROM ROW(OLD.allocated,OLD.principals,OLD.allocations) AND pg_trigger_depth()<2) OR
  NEW.observed_at<OLD.observed_at OR NEW.observed_at=OLD.observed_at AND NEW.fresh_until>OLD.fresh_until THEN
  RAISE EXCEPTION 'immutable query backing and spend' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER context_query_backing_guard BEFORE INSERT OR UPDATE OR DELETE ON context_query_backing FOR EACH ROW EXECUTE FUNCTION guard_context_query_backing();

CREATE FUNCTION guard_context_query_account() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b public.context_query_backing;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query account remains charged' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=NEW.root_id FOR UPDATE;
 IF TG_OP='UPDATE' THEN
  IF pg_trigger_depth()<2 OR (to_jsonb(NEW)-'allocated') IS DISTINCT FROM (to_jsonb(OLD)-'allocated') OR NEW.allocated<>OLD.allocated+1 THEN RAISE EXCEPTION 'query account mutation denied' USING ERRCODE='23514'; END IF;
 ELSIF NEW.allocated<>0 THEN RAISE EXCEPTION 'query initial account spend invalid' USING ERRCODE='23514';
 ELSIF TG_TABLE_NAME='context_query_principal' THEN
  UPDATE public.context_query_backing SET principals=principals+1 WHERE root_id=NEW.root_id;
 ELSE
  IF NEW.query_limit>b.query_limit THEN RAISE EXCEPTION 'query allocation exceeds root' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query_backing SET allocations=allocations+1 WHERE root_id=NEW.root_id;
 END IF;
 IF TG_TABLE_NAME='context_query_principal' AND NEW.allocated>b.principal_query_limit THEN RAISE EXCEPTION 'query principal capacity exhausted' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER context_query_allocation_guard BEFORE INSERT OR UPDATE OR DELETE ON context_query_allocation FOR EACH ROW EXECUTE FUNCTION guard_context_query_account();
CREATE TRIGGER context_query_principal_guard BEFORE INSERT OR UPDATE OR DELETE ON context_query_principal FOR EACH ROW EXECUTE FUNCTION guard_context_query_account();

CREATE FUNCTION guard_context_query() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b public.context_query_backing; a public.context_query_allocation; p public.context_query_principal; n timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query history retirement unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN
  IF pg_trigger_depth()<2 OR (to_jsonb(NEW)-ARRAY['generation','active_batch','polls','controls','uncertain']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['generation','active_batch','polls','controls','uncertain']) OR
   NEW.generation<OLD.generation OR NEW.generation>OLD.generation+1 OR NEW.polls<OLD.polls OR NEW.controls<>OLD.controls+1 OR OLD.uncertain AND NOT NEW.uncertain OR
   NEW.polls>(NEW.query->'Plan'->'Profile'->>'PollLimit')::bigint OR NEW.controls>(NEW.query->'Plan'->'Profile'->>'ControlTransitionLimit')::bigint THEN RAISE EXCEPTION 'query counters immutable' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT a FROM public.context_query_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.context_query_principal WHERE id=NEW.account_id AND root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 IF NOT public.context_query_intent_current(NEW.root_id,NEW.operation_id,NEW.actor,NEW.issuer_epoch,NEW.initial_request->'Call') OR
  NOT public.context_query_complete_object(NEW.query,ARRAY['ID','OperationID','WorkerID','Scope','Plan','RecoveryIssuerEpoch','RecoveryRevision','CreatedAt','Deadline','WorkerUntil','CredentialUntil','ProviderUntil','CleanupUntil']) OR
  NOT public.context_query_complete_object(NEW.query->'Plan',ARRAY['AcceptanceID','AccountID','AllocationID','RootID','InstallationID','ClusterID','NamespaceUID','WorkloadUID','AllocationRevision','PoolSource','PolicySource','Principal','Profile','ObservedAt','ValidUntil','HardUntil','EffectsUntil','CleanupUntil','RetireBy']) OR
  NOT public.context_query_complete_object(NEW.query->'Scope',ARRAY['RootID','CaseID','ArtifactID','CaptureID','ClusterID','NamespaceUID','WorkloadUID','PodUID','Version','SourceProjectionDigest','SourceFormat','DisplayVersion','Selection','Principal']) OR
  b.suspended OR n<b.observed_at OR n>=b.fresh_until OR p.principal_key<>NEW.principal_key OR NEW.generation<>0 OR NEW.active_batch IS NOT NULL OR NEW.polls<>0 OR NEW.controls<>0 OR NEW.uncertain OR
  NEW.query->'Plan'->'Profile' IS DISTINCT FROM b.profile OR NEW.query->'Plan'->>'AcceptanceID'<>b.acceptance_id::text OR NEW.query->'Plan'->>'AllocationID'<>a.id::text OR
  NEW.query->'Plan'->>'AccountID'<>p.id::text OR NEW.query->'Plan'->>'ClusterID'<>a.cluster_id::text OR NEW.query->'Plan'->>'NamespaceUID'<>a.namespace_uid OR NEW.query->'Plan'->>'WorkloadUID'<>a.workload_uid OR
  NEW.query->'Plan'->'Principal' IS DISTINCT FROM NEW.actor OR NEW.query->'Scope'->>'RootID' IS DISTINCT FROM NEW.root_id::text OR NEW.query->'Scope'->>'ClusterID' IS DISTINCT FROM a.cluster_id::text OR NEW.query->'Scope'->>'NamespaceUID' IS DISTINCT FROM a.namespace_uid OR NEW.query->'Scope'->>'WorkloadUID' IS DISTINCT FROM a.workload_uid OR
  NEW.query->'Plan'->'PoolSource' IS DISTINCT FROM a.pool_source OR NEW.query->'Plan'->'PolicySource' IS DISTINCT FROM a.policy_source OR
  (NEW.query->'Plan'->>'AllocationRevision')::bigint<>a.revision OR NEW.query->'Scope'->'Principal' IS DISTINCT FROM NEW.actor OR
  NEW.query->>'ID'<>NEW.id::text OR NEW.query->>'WorkerID'<>NEW.worker_id::text OR NEW.query->>'OperationID'<>NEW.operation_id::text OR
  (NEW.query->>'CreatedAt')::timestamptz<>NEW.created_at OR (NEW.query->>'Deadline')::timestamptz<>NEW.deadline OR (NEW.query->>'CleanupUntil')::timestamptz<>NEW.cleanup_until OR
  NEW.deadline>NEW.created_at+make_interval(secs=>(b.profile->>'Lifetime')::double precision/1000000000) OR
  (NEW.query->'Plan'->>'RootID')::uuid<>NEW.root_id OR (NEW.query->'Plan'->>'InstallationID')::uuid<>b.installation_id OR
  (NEW.query->'Plan'->>'RetireBy')::timestamptz<>NEW.retire_by OR NEW.retire_by<>b.retire_by OR
  (NEW.query->'Plan'->>'HardUntil')::timestamptz<>b.hard_until OR (NEW.query->'Plan'->>'EffectsUntil')::timestamptz<>b.effects_until OR (NEW.query->'Plan'->>'CleanupUntil')::timestamptz<>b.cleanup_until OR
  NEW.deadline>b.hard_until OR NEW.cleanup_until>b.cleanup_until OR n>=(NEW.query->'Plan'->>'ValidUntil')::timestamptz OR n<(NEW.query->'Plan'->>'ObservedAt')::timestamptz OR
  (NEW.query->>'WorkerUntil')::timestamptz>b.effects_until OR (NEW.query->>'CredentialUntil')::timestamptz>b.effects_until OR (NEW.query->>'ProviderUntil')::timestamptz>b.effects_until OR
  NEW.query->>'RecoveryIssuerEpoch' IS DISTINCT FROM NEW.issuer_epoch::text OR NEW.created_at>n OR NEW.created_at<(NEW.initial_request->'Call'->>'StartedAt')::timestamptz OR
  NOT public.incarnation_current(NEW.postmaster_at) OR NEW.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR n>=NEW.deadline THEN
  RAISE EXCEPTION 'query accepted backing unavailable' USING ERRCODE='23514'; END IF;
 UPDATE public.context_query_backing SET allocated=allocated+1 WHERE root_id=NEW.root_id;
 UPDATE public.context_query_allocation SET allocated=allocated+1 WHERE id=NEW.allocation_id;
 UPDATE public.context_query_principal SET allocated=allocated+1 WHERE id=NEW.account_id;
 RETURN NEW;
END $$;
CREATE TRIGGER context_query_guard BEFORE INSERT OR UPDATE OR DELETE ON context_query FOR EACH ROW EXECUTE FUNCTION guard_context_query();

CREATE FUNCTION guard_context_query_child() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE q public.context_query; n timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query child history remains charged' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT q FROM public.context_query WHERE id=NEW.query_id FOR UPDATE;
 n:=clock_timestamp();
 IF TG_TABLE_NAME='context_query_call' THEN
  IF TG_OP<>'INSERT' OR n>=q.deadline OR NOT public.context_query_complete_object(NEW.request,ARRAY['Call','OwnerID','HubProcessEpoch']) OR NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.request->'Call') OR NEW.request->'Call'->>'ID'<>NEW.operation_id::text OR NEW.request->'Call'->'Principal' IS DISTINCT FROM q.actor OR
   NEW.request->'Call'->>'RootID'<>q.root_id::text OR NEW.is_poll<>(NEW.operation_id<>q.operation_id) OR NEW.request->'Call'->>'Tool' IS DISTINCT FROM (CASE WHEN NEW.is_poll THEN 'get_query_result' ELSE 'get_file_excerpt' END) THEN RAISE EXCEPTION 'query invocation mismatch' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET polls=polls+CASE WHEN NEW.is_poll THEN 1 ELSE 0 END,controls=controls+1 WHERE id=q.id;
 ELSIF TG_TABLE_NAME='context_query_batch' THEN
  IF TG_OP='INSERT' THEN
   IF NOT public.context_query_complete_object(NEW.batch,ARRAY['ID','QueryID','OperationID','Generation','Worker','Request','StartedAt','Until','CleanupUntil']) OR
    n>=q.deadline OR (NEW.batch->>'StartedAt')::timestamptz>n OR n>=(NEW.batch->>'Until')::timestamptz OR
    (NEW.batch->>'Until')::timestamptz>q.deadline OR (NEW.batch->>'Until')::timestamptz>(NEW.batch->'Request'->'Call'->>'Until')::timestamptz OR (NEW.batch->>'CleanupUntil')::timestamptz<>q.cleanup_until OR
    NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call') OR
    q.active_batch IS NOT NULL OR q.uncertain OR NEW.generation<>q.generation+1 OR NEW.claim_id IS NOT NULL OR NEW.closed OR
    NEW.batch->>'OperationID' IS DISTINCT FROM NEW.operation_id::text OR NEW.batch->>'ID'<>NEW.id::text OR NEW.batch->>'QueryID'<>q.id::text OR (NEW.batch->>'Generation')::smallint<>NEW.generation OR
    NOT EXISTS(SELECT 1 FROM public.context_query_call c WHERE c.operation_id=NEW.operation_id AND c.query_id=q.id AND c.request=NEW.batch->'Request') OR
    NOT EXISTS(SELECT 1 FROM public.context_query_worker w WHERE w.query_id=q.id AND w.binding=NEW.batch->'Worker') THEN RAISE EXCEPTION 'query batch unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.context_query SET generation=NEW.generation,active_batch=NEW.id,controls=controls+1 WHERE id=q.id;
  ELSE
   IF (to_jsonb(NEW)-ARRAY['claim_id','closed']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['claim_id','closed']) OR OLD.closed OR q.active_batch IS DISTINCT FROM NEW.id OR
    OLD.claim_id IS NOT NULL AND NEW.claim_id IS DISTINCT FROM OLD.claim_id OR OLD.claim_id IS NULL AND NEW.claim_id IS NULL OR
    OLD.claim_id IS NULL AND NEW.closed OR NEW.claim_id IS DISTINCT FROM NEW.id OR
    NOT NEW.closed AND (OLD.claim_id IS NOT NULL OR n>=(NEW.batch->>'Until')::timestamptz OR n>=q.deadline OR NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call')) OR
    NEW.closed AND (n>=q.cleanup_until OR n>=(NEW.batch->'Request'->'Call'->>'WriteUntil')::timestamptz OR NOT public.context_query_outcome_closed(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch)) THEN RAISE EXCEPTION 'query batch claim or close unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.context_query SET active_batch=CASE WHEN NEW.closed THEN NULL ELSE active_batch END,controls=controls+1 WHERE id=q.id;
  END IF;
 ELSIF TG_TABLE_NAME='context_query_worker' THEN
  IF TG_OP<>'INSERT' OR NEW.worker_id<>q.worker_id OR NEW.binding->>'QueryID' IS DISTINCT FROM q.id::text OR NEW.binding->>'WorkerID' IS DISTINCT FROM q.worker_id::text THEN RAISE EXCEPTION 'query worker immutable' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
 ELSE
  IF TG_OP='INSERT' THEN
   IF NEW.used_roles<>0 OR q.active_batch IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'query key binding unavailable' USING ERRCODE='23514'; END IF;
  ELSIF (to_jsonb(NEW)-'used_roles') IS DISTINCT FROM (to_jsonb(OLD)-'used_roles') OR (NEW.used_roles|OLD.used_roles)<>NEW.used_roles OR
   (NEW.used_roles#OLD.used_roles) NOT IN (1,2,4) OR q.active_batch IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'query key role already spent' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER context_query_call_guard BEFORE INSERT OR UPDATE OR DELETE ON context_query_call FOR EACH ROW EXECUTE FUNCTION guard_context_query_child();
CREATE TRIGGER context_query_worker_guard BEFORE INSERT OR UPDATE OR DELETE ON context_query_worker FOR EACH ROW EXECUTE FUNCTION guard_context_query_child();
CREATE TRIGGER context_query_batch_guard BEFORE INSERT OR UPDATE OR DELETE ON context_query_batch FOR EACH ROW EXECUTE FUNCTION guard_context_query_child();
CREATE TRIGGER context_query_key_guard BEFORE INSERT OR UPDATE OR DELETE ON context_query_key_binding FOR EACH ROW EXECUTE FUNCTION guard_context_query_child();

CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result') THEN 'normal' ELSE NULL END
$$;
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format='capture-intent/v2'
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_query_complete_object(jsonb,text[]),context_query_outcome_closed(uuid,uuid,jsonb,uuid),context_query_intent_current(uuid,uuid,jsonb,uuid,jsonb),context_query_cost_valid(jsonb),guard_context_query_backing(),guard_context_query_account(),guard_context_query(),guard_context_query_child(),operation_audit_lane(text),operation_audit_human_input_valid(text,text) FROM PUBLIC;
-- No destructive Down: uncertainty and prepaid residual history survive expiry.
