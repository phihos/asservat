-- +goose Up
-- Private connector identity uses the existing closed encrypted audit pair.
-- Public operation names/roles and historical human encodings stay distinct.
-- Source rows are inserted only by the protected post-activation producer; this
-- migration grants no runtime role and seeds no installation authority.
CREATE TABLE connector_identity_root (
 root_id uuid PRIMARY KEY REFERENCES permission_stream(id),
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id),
 issuer_epoch uuid NOT NULL, postmaster_at timestamptz NOT NULL, database_oid oid NOT NULL,
 source_name name NOT NULL, source_oid oid NOT NULL,
 journal_name name NOT NULL, journal_oid oid NOT NULL,
 acknowledgement_name name NOT NULL, acknowledgement_oid oid NOT NULL,
 cleanup_name name NOT NULL, cleanup_oid oid NOT NULL,
 verifier_name name NOT NULL, verifier_oid oid NOT NULL, finalizer_name name NOT NULL, finalizer_oid oid NOT NULL,
 profile_limit bigint NOT NULL CHECK(profile_limit BETWEEN 1 AND 4096),
 profiles bigint NOT NULL DEFAULT 0 CHECK(profiles>=0 AND profiles<=profile_limit),
 source_transition_limit bigint NOT NULL CHECK(source_transition_limit BETWEEN 1 AND 1000000),
 source_transitions bigint NOT NULL DEFAULT 0 CHECK(source_transitions>=0 AND source_transitions<=source_transition_limit),
 -- Separately accepted actual backend/SQL/history qualification. A JSON value
 -- or a matching digest alone never establishes that qualification.
 qualification jsonb NOT NULL CHECK(jsonb_typeof(qualification)='object' AND octet_length(qualification::text)<=4096),
 policy jsonb NOT NULL CHECK(jsonb_typeof(policy)='object' AND octet_length(policy::text)<=16384),
 backing jsonb NOT NULL CHECK(jsonb_typeof(backing)='object' AND octet_length(backing::text)<=24576),
 backing_digest bytea NOT NULL CHECK(octet_length(backing_digest)=32),
 source_backup_bytes bigint NOT NULL CHECK(source_backup_bytes>0),
 source_wal_bytes bigint NOT NULL CHECK(source_wal_bytes>0),
 valid_until timestamptz NOT NULL CHECK(isfinite(valid_until)),
 pending_id uuid, pending_backing jsonb, pending_digest bytea, pending_at timestamptz, active_backing_id uuid,
 closed_candidate_id uuid, closed_candidate_digest bytea, closed_candidate_revision bigint, closed_candidate_at timestamptz,
 CHECK((closed_candidate_id IS NULL)=(closed_candidate_digest IS NULL) AND (closed_candidate_id IS NULL)=(closed_candidate_revision IS NULL) AND (closed_candidate_id IS NULL)=(closed_candidate_at IS NULL)),
 CHECK(closed_candidate_digest IS NULL OR octet_length(closed_candidate_digest)=32),
 CHECK((pending_id IS NULL)=(pending_backing IS NULL) AND (pending_id IS NULL)=(pending_digest IS NULL) AND (pending_id IS NULL)=(pending_at IS NULL)),
 CHECK(pending_backing IS NULL OR jsonb_typeof(pending_backing)='object' AND octet_length(pending_backing::text)<=24576),
 CHECK(pending_digest IS NULL OR octet_length(pending_digest)=32),
 CHECK(source_oid<>journal_oid AND source_oid<>acknowledgement_oid AND source_oid<>cleanup_oid AND source_oid<>verifier_oid AND source_oid<>finalizer_oid AND journal_oid<>acknowledgement_oid AND journal_oid<>cleanup_oid AND journal_oid<>verifier_oid AND journal_oid<>finalizer_oid AND acknowledgement_oid<>cleanup_oid AND acknowledgement_oid<>verifier_oid AND acknowledgement_oid<>finalizer_oid AND cleanup_oid<>verifier_oid AND cleanup_oid<>finalizer_oid AND verifier_oid<>finalizer_oid)
);
CREATE TABLE connector_identity_profile (
 root_id uuid NOT NULL REFERENCES connector_identity_root(root_id), peer_id uuid NOT NULL,
 installation_id uuid NOT NULL, cluster_id uuid NOT NULL, issuer_epoch uuid NOT NULL,
 source_uid uuid NOT NULL, source_generation bigint NOT NULL CHECK(source_generation BETWEEN 1 AND 2147483647),
 source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 complete_digest bytea NOT NULL CHECK(octet_length(complete_digest)=32),
 backing_revision bigint NOT NULL CHECK(backing_revision BETWEEN 1 AND 1152921504606846976),
 backing_digest bytea NOT NULL CHECK(octet_length(backing_digest)=32),
 protection_digest bytea NOT NULL CHECK(octet_length(protection_digest)=32),
 configuration jsonb NOT NULL CHECK(jsonb_typeof(configuration)='object' AND octet_length(configuration::text)<=131072),
 suspended boolean NOT NULL, fenced boolean NOT NULL DEFAULT true, blocked boolean NOT NULL DEFAULT false,
 candidate_id uuid, accepted_id uuid, account_digest bytea CHECK(account_digest IS NULL OR octet_length(account_digest)=32),
 PRIMARY KEY(root_id,peer_id), UNIQUE(root_id,account_digest), UNIQUE(root_id,peer_id,installation_id,cluster_id,issuer_epoch),
 CHECK(accepted_id IS NULL OR candidate_id=accepted_id)
);
CREATE TABLE connector_identity_process (
 id uuid PRIMARY KEY REFERENCES operation_audit(id) DEFERRABLE INITIALLY DEFERRED,
 root_id uuid NOT NULL, peer_id uuid NOT NULL,
 pod_uid uuid NOT NULL, process_epoch uuid NOT NULL,
 client_key bytea NOT NULL CHECK(octet_length(client_key)=32), server_key bytea NOT NULL CHECK(octet_length(server_key)=32),
 process jsonb NOT NULL CHECK(jsonb_typeof(process)='object' AND octet_length(process::text)<=4096),
 source_uid uuid NOT NULL, source_generation bigint NOT NULL, source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 claimed_at timestamptz NOT NULL, initial_not_after timestamptz NOT NULL, run_until timestamptz NOT NULL,
 accepted_at timestamptz, serving boolean NOT NULL DEFAULT false, retired_at timestamptz,
 client_epoch bigint NOT NULL DEFAULT -1 CHECK(client_epoch>=-1), client_attempts bigint NOT NULL DEFAULT 0 CHECK(client_attempts BETWEEN 0 AND 2),
 server_epoch bigint NOT NULL DEFAULT -1 CHECK(server_epoch>=-1), server_attempts bigint NOT NULL DEFAULT 0 CHECK(server_attempts BETWEEN 0 AND 2),
 client_current_id uuid, client_previous_id uuid, server_current_id uuid, server_previous_id uuid,
 UNIQUE(root_id,peer_id,pod_uid,process_epoch), UNIQUE(root_id,id), FOREIGN KEY(root_id,peer_id) REFERENCES connector_identity_profile(root_id,peer_id),
 CHECK(client_key<>server_key), CHECK(initial_not_after=date_trunc('second',claimed_at+interval '30 minutes')),
 CHECK(run_until>=initial_not_after AND isfinite(run_until)),
 CHECK(NOT serving OR accepted_at IS NOT NULL AND client_current_id IS NOT NULL AND server_current_id IS NOT NULL AND retired_at IS NULL)
);
CREATE UNIQUE INDEX connector_one_pending_pod ON connector_identity_process(root_id,peer_id,pod_uid) WHERE NOT serving AND retired_at IS NULL;
CREATE UNIQUE INDEX connector_one_serving_pod ON connector_identity_process(root_id,peer_id,pod_uid) WHERE serving;
CREATE TABLE connector_credential_attempt (
 id uuid PRIMARY KEY REFERENCES operation_audit(id) DEFERRABLE INITIALLY DEFERRED,
 root_id uuid NOT NULL, peer_id uuid NOT NULL, process_id uuid NOT NULL REFERENCES connector_identity_process(id),
 usage text NOT NULL CHECK(usage IN ('client','server')),
 epoch bigint NOT NULL CHECK(epoch>=0), ordinal bigint NOT NULL CHECK(ordinal BETWEEN 1 AND 2),
 public_key bytea NOT NULL CHECK(octet_length(public_key)=32),
 source_uid uuid NOT NULL, source_generation bigint NOT NULL CHECK(source_generation BETWEEN 1 AND 2147483647), source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 permit jsonb NOT NULL CHECK(jsonb_typeof(permit)='object' AND octet_length(permit::text)<=262144),
 checked_at timestamptz NOT NULL, sign_before timestamptz NOT NULL, certificate_not_after timestamptz NOT NULL,
 provider_started boolean NOT NULL DEFAULT false,
 issued jsonb CHECK(issued IS NULL OR jsonb_typeof(issued)='object' AND octet_length(issued::text)<=65536),
 certificate_digest bytea CHECK(certificate_digest IS NULL OR octet_length(certificate_digest)=32), certificate_not_before timestamptz,
 activated_at timestamptz, detached_at timestamptz,
 UNIQUE(root_id,peer_id,process_id,usage,epoch,ordinal), UNIQUE(root_id,id),
 FOREIGN KEY(root_id,peer_id) REFERENCES connector_identity_profile(root_id,peer_id),
 CHECK(sign_before>checked_at AND sign_before<=checked_at+interval '5 seconds' AND sign_before<certificate_not_after),
 CHECK((issued IS NULL)=(certificate_digest IS NULL) AND (issued IS NULL)=(certificate_not_before IS NULL)),
 CHECK(issued IS NULL OR provider_started), CHECK(activated_at IS NULL OR issued IS NOT NULL)
);
CREATE TABLE connector_backing_transition (
 id uuid PRIMARY KEY REFERENCES operation_audit(id) DEFERRABLE INITIALLY DEFERRED,
 root_id uuid NOT NULL REFERENCES connector_identity_root(root_id), peer_id uuid NOT NULL,
 previous_backing jsonb NOT NULL CHECK(jsonb_typeof(previous_backing)='object' AND octet_length(previous_backing::text)<=24576),
 proposed jsonb NOT NULL CHECK(jsonb_typeof(proposed)='object' AND octet_length(proposed::text)<=196608),
 authority_until timestamptz NOT NULL CHECK(isfinite(authority_until)),
 detach_after timestamptz NOT NULL CHECK(isfinite(detach_after) AND detach_after=authority_until+interval '1 minute'),
 activated_at timestamptz, closed_at timestamptz,
 FOREIGN KEY(root_id,peer_id) REFERENCES connector_identity_profile(root_id,peer_id),
 CHECK(activated_at IS NULL OR closed_at IS NULL)
);
ALTER TABLE connector_identity_root ADD FOREIGN KEY(active_backing_id) REFERENCES connector_backing_transition(id) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX connector_backing_retirement ON connector_backing_transition(root_id,detach_after,id);

ALTER TABLE connector_identity_profile ADD FOREIGN KEY(candidate_id) REFERENCES operation_audit(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE connector_identity_profile ADD FOREIGN KEY(accepted_id) REFERENCES operation_audit(id) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX connector_credential_retirement ON connector_credential_attempt(root_id,certificate_not_after,id);
CREATE INDEX connector_process_retirement ON connector_identity_process(root_id,run_until,id);

-- +goose StatementBegin
CREATE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(operation_name IN ('list_diagnostics','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation') AND input_format IN ('context-input/v1','invalid-input/v1'),false)
$$;
-- Fixed classifications only. Later purpose-specific migrations can extend
-- these closed functions without copying unrelated guard/retention logic.
CREATE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance') THEN 'identity'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation') THEN 'normal' ELSE NULL END
$$;
CREATE FUNCTION operation_audit_history_layout_valid(lane text,layout text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE((lane IN ('normal','resolution') AND layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3')) OR (lane='identity' AND layout='connector-operation-history/v1'),false)
$$;
CREATE FUNCTION operation_audit_history_fixed_transitions(layout text) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE layout WHEN 'operation-audit-history/v1' THEN 16 WHEN 'operation-audit-history/v2' THEN 19 WHEN 'operation-audit-history/v3' THEN 21 WHEN 'connector-operation-history/v1' THEN 32 ELSE NULL END::bigint
$$;
CREATE FUNCTION operation_audit_history_verifier_backed(layout text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(layout IN ('operation-audit-history/v3','connector-operation-history/v1'),false)
$$;
CREATE FUNCTION operation_audit_history_minimum_row(layout text) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN layout='connector-operation-history/v1' THEN 1048576 WHEN layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3') THEN 131072 ELSE NULL END::bigint
$$;
CREATE FUNCTION connector_identity_role_ok(r uuid,purpose text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.connector_identity_root; expected_oid oid; expected_name name; login record;
BEGIN
 SELECT * INTO p FROM public.connector_identity_root WHERE root_id=r;
 IF NOT FOUND OR p.postmaster_at<>pg_postmaster_start_time() OR p.database_oid<>(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) THEN RETURN false;END IF;
 CASE purpose WHEN 'source' THEN expected_oid:=p.source_oid;expected_name:=p.source_name;
 WHEN 'journal' THEN expected_oid:=p.journal_oid;expected_name:=p.journal_name;
 WHEN 'acknowledgement' THEN expected_oid:=p.acknowledgement_oid;expected_name:=p.acknowledgement_name;
 WHEN 'cleanup' THEN expected_oid:=p.cleanup_oid;expected_name:=p.cleanup_name;
 WHEN 'verifier' THEN expected_oid:=p.verifier_oid;expected_name:=p.verifier_name;
 WHEN 'finalizer' THEN expected_oid:=p.finalizer_oid;expected_name:=p.finalizer_name;
 ELSE RETURN false;END CASE;
 SELECT oid,rolname,rolcanlogin,rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls INTO login FROM pg_catalog.pg_roles WHERE rolname=session_user;
 RETURN FOUND AND login.oid=expected_oid AND login.rolname=expected_name AND login.rolcanlogin AND NOT login.rolsuper AND NOT login.rolcreaterole AND NOT login.rolcreatedb AND NOT login.rolreplication AND NOT login.rolbypassrls
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=login.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relowner=login.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspowner=login.oid);
END $$;
CREATE FUNCTION connector_identity_login_is_private() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM public.connector_identity_root p JOIN pg_catalog.pg_roles r ON r.rolname=session_user AND r.oid IN (p.source_oid,p.journal_oid,p.acknowledgement_oid,p.cleanup_oid,p.verifier_oid,p.finalizer_oid))
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION operation_audit_lane(text),operation_audit_history_layout_valid(text,text),operation_audit_history_fixed_transitions(text),operation_audit_history_verifier_backed(text),operation_audit_history_minimum_row(text),operation_audit_human_input_valid(text,text),connector_identity_role_ok(uuid,text),connector_identity_login_is_private() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION connector_backing_can_renew(previous jsonb,next_value jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE((next_value->'Policy'->>'BackingRevision')::bigint=(previous->'Policy'->>'BackingRevision')::bigint+1
 AND (next_value->'Policy'->>'ValidUntil')::timestamptz>(previous->'Policy'->>'ValidUntil')::timestamptz
 AND (next_value-'Policy')=(previous-'Policy')
 AND ((next_value->'Policy')-ARRAY['PolicyID','PolicyDigest','BackingRevision','ValidUntil'])=((previous->'Policy')-ARRAY['PolicyID','PolicyDigest','BackingRevision','ValidUntil']),false)
$$;
REVOKE ALL ON FUNCTION connector_backing_can_renew(jsonb,jsonb) FROM PUBLIC;
CREATE FUNCTION guard_connector_identity_root() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE t public.fleet_current_trust; login record; role_name name; role_oid oid; n timestamptz; q jsonb;
BEGIN
 IF TG_RELID<>'public.connector_identity_root'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP='DELETE' THEN RAISE EXCEPTION 'connector backing retirement unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id FOR SHARE;
 n:=clock_timestamp();
 IF t.recovery_blocked OR t.suspended OR n>=t.fresh_until OR t.observed_at>n OR NEW.issuer_epoch<>t.issuer_epoch OR NEW.postmaster_at<>pg_postmaster_start_time() OR NEW.database_oid<>(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) THEN RAISE EXCEPTION 'connector backing recovery unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.profiles<>0 OR NEW.source_transitions<>0 OR NEW.source_name<>session_user OR NEW.valid_until<=n OR NEW.pending_id IS NOT NULL OR NEW.active_backing_id IS NOT NULL OR NEW.closed_candidate_id IS NOT NULL THEN RAISE EXCEPTION 'connector source role unavailable' USING ERRCODE='23514';END IF;
  FOR role_name,role_oid IN SELECT * FROM (VALUES(NEW.source_name,NEW.source_oid),(NEW.journal_name,NEW.journal_oid),(NEW.acknowledgement_name,NEW.acknowledgement_oid),(NEW.cleanup_name,NEW.cleanup_oid),(NEW.verifier_name,NEW.verifier_oid),(NEW.finalizer_name,NEW.finalizer_oid)) AS pin(role_name,role_oid) LOOP
   SELECT oid,rolname,rolcanlogin,rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls INTO login FROM pg_catalog.pg_roles WHERE oid=role_oid AND rolname=role_name;
   IF NOT FOUND OR NOT login.rolcanlogin OR login.rolsuper OR login.rolcreaterole OR login.rolcreatedb OR login.rolreplication OR login.rolbypassrls OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=role_oid) OR EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE relowner=role_oid) OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspowner=role_oid) THEN RAISE EXCEPTION 'connector role pin unavailable' USING ERRCODE='23514';END IF;
  END LOOP;
 ELSE
  IF NOT public.connector_identity_role_ok(NEW.root_id,'source') THEN RAISE EXCEPTION 'connector source role unavailable' USING ERRCODE='23514';END IF;
  IF NEW.backing IS DISTINCT FROM OLD.backing THEN
   IF NEW.profiles<>OLD.profiles OR NEW.source_transitions<>OLD.source_transitions OR
    OLD.pending_id IS NULL OR NEW.active_backing_id IS DISTINCT FROM OLD.pending_id OR NEW.pending_id IS NOT NULL OR
    NEW.backing IS DISTINCT FROM OLD.pending_backing OR NEW.backing_digest IS DISTINCT FROM OLD.pending_digest OR
    NEW.policy IS DISTINCT FROM NEW.backing->'Policy' OR NEW.valid_until<>(NEW.policy->>'ValidUntil')::timestamptz OR
    NOT public.connector_backing_can_renew(OLD.backing,NEW.backing) OR
    (to_jsonb(NEW)-ARRAY['backing','backing_digest','policy','valid_until','active_backing_id','pending_id','pending_backing','pending_digest','pending_at','source_transitions']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['backing','backing_digest','policy','valid_until','active_backing_id','pending_id','pending_backing','pending_digest','pending_at','source_transitions']) OR
    NOT EXISTS(SELECT 1 FROM public.connector_backing_transition b JOIN public.operation_audit a ON a.id=b.id AND a.root_id=b.root_id JOIN public.operation_audit_lifecycle l ON l.operation_id=a.id AND l.root_id=a.root_id
      WHERE b.id=OLD.pending_id AND b.root_id=OLD.root_id AND b.previous_backing=OLD.backing AND b.proposed->'Backing'=NEW.backing AND b.activated_at IS NOT NULL AND b.closed_at IS NULL
      AND a.intent_receipt IS NOT NULL AND a.outcome_receipt IS NOT NULL AND l.intent_completion->'Receipt'=a.intent_receipt AND l.outcome_completion->'Receipt'=a.outcome_receipt)
    THEN RAISE EXCEPTION 'connector backing promotion unavailable' USING ERRCODE='23514';END IF;
  ELSIF NEW.pending_id IS DISTINCT FROM OLD.pending_id THEN
   IF (to_jsonb(NEW)-ARRAY['pending_id','pending_backing','pending_digest','pending_at','closed_candidate_id','closed_candidate_digest','closed_candidate_revision','closed_candidate_at','source_transitions']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['pending_id','pending_backing','pending_digest','pending_at','closed_candidate_id','closed_candidate_digest','closed_candidate_revision','closed_candidate_at','source_transitions']) OR NEW.source_transitions<>OLD.source_transitions+(CASE WHEN OLD.pending_id IS NULL THEN 2 ELSE 0 END) OR NEW.source_transitions>OLD.source_transition_limit THEN RAISE EXCEPTION 'connector candidate mutation unavailable' USING ERRCODE='23514';END IF;
   IF OLD.pending_id IS NULL THEN
    IF NEW.pending_id IS NULL OR NEW.pending_at>n OR n>=OLD.valid_until OR NEW.pending_id IS NOT DISTINCT FROM OLD.closed_candidate_id OR ROW(NEW.closed_candidate_id,NEW.closed_candidate_digest,NEW.closed_candidate_revision,NEW.closed_candidate_at) IS DISTINCT FROM ROW(OLD.closed_candidate_id,OLD.closed_candidate_digest,OLD.closed_candidate_revision,OLD.closed_candidate_at) OR NOT public.connector_backing_can_renew(OLD.backing,NEW.pending_backing) THEN RAISE EXCEPTION 'connector candidate backing unavailable' USING ERRCODE='23514';END IF;
   ELSIF NEW.pending_id IS NOT NULL OR NEW.closed_candidate_id IS DISTINCT FROM OLD.pending_id OR NEW.closed_candidate_digest IS DISTINCT FROM OLD.pending_digest OR NEW.closed_candidate_revision<>(OLD.pending_backing->'Policy'->>'BackingRevision')::bigint OR NEW.closed_candidate_at IS NULL OR NEW.closed_candidate_at>n OR
    EXISTS(SELECT 1 FROM public.connector_backing_transition b WHERE b.id=OLD.pending_id AND b.root_id=OLD.root_id AND b.closed_at IS NULL) OR
    EXISTS(SELECT 1 FROM public.operation_audit a WHERE a.id=OLD.pending_id AND NOT EXISTS(SELECT 1 FROM public.connector_backing_transition b WHERE b.id=a.id AND b.root_id=OLD.root_id AND b.closed_at IS NOT NULL)) THEN RAISE EXCEPTION 'connector candidate must be positively closed' USING ERRCODE='23514';END IF;
  ELSIF (to_jsonb(NEW)-ARRAY['profiles','source_transitions']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['profiles','source_transitions']) OR pg_trigger_depth()<2 OR
    NEW.profiles NOT BETWEEN OLD.profiles AND OLD.profiles+1 OR NEW.source_transitions<>OLD.source_transitions+1 THEN RAISE EXCEPTION 'immutable connector role/backing pins' USING ERRCODE='23514';END IF;
 END IF;
 q:=NEW.qualification;
 IF NOT COALESCE(q->>'Layout'='connector-operation-history/v1' AND NEW.policy->'History'=q AND NEW.backing->'Policy'=NEW.policy AND NEW.policy->>'Lane'='identity' AND NEW.policy->>'OverdueTerminal'='overdue-original/v1' AND (NEW.policy->>'RootID')::uuid=NEW.root_id AND (NEW.policy->>'InstallationID')::uuid=NEW.installation_id AND
  (q->>'ID')::uuid IS NOT NULL AND jsonb_array_length(q->'Digest')=32 AND
  (q->>'MaximumRowFootprintBytes')::bigint BETWEEN 1048576 AND 16777216 AND (q->>'MaximumTransitionWALBytes')::bigint BETWEEN 131072 AND 67108864 AND (q->>'BackupCopies')::bigint BETWEEN 1 AND 64 AND (q->>'WALCopies')::bigint BETWEEN 1 AND 64 AND
  NEW.source_backup_bytes/(NEW.profile_limit+1)>=2*(q->>'MaximumRowFootprintBytes')::bigint*(q->>'BackupCopies')::bigint AND NEW.source_wal_bytes/NEW.source_transition_limit>=2*(q->>'MaximumTransitionWALBytes')::bigint*(q->>'WALCopies')::bigint AND NEW.valid_until=(NEW.policy->>'ValidUntil')::timestamptz,false) THEN RAISE EXCEPTION 'connector qualification/backing unavailable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION guard_connector_identity_profile() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.connector_identity_root; n timestamptz; c jsonb; a public.operation_audit; attempt public.connector_credential_attempt; child public.connector_identity_process;
BEGIN
 IF TG_RELID<>'public.connector_identity_profile'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP='DELETE' THEN RAISE EXCEPTION 'connector profile retirement unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT r FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 IF TG_OP='UPDATE' AND public.connector_identity_role_ok(NEW.root_id,'cleanup') THEN
  IF NOT NEW.fenced OR NEW.candidate_id IS NOT NULL OR NEW.accepted_id IS NOT NULL OR (to_jsonb(NEW)-ARRAY['fenced','candidate_id','accepted_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['fenced','candidate_id','accepted_id']) OR
   EXISTS(SELECT 1 FROM public.connector_identity_process p WHERE p.root_id=OLD.root_id AND p.peer_id=OLD.peer_id AND (p.id IN(OLD.candidate_id,OLD.accepted_id) OR EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.process_id=p.id AND a.id IN(OLD.candidate_id,OLD.accepted_id))) AND n<p.run_until+interval '1 minute') THEN RAISE EXCEPTION 'connector accepted source still referenced' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 -- Restrict an already-retained profile even when its backing is no longer
 -- current. This branch can only add a fence/watermark, never clear either.
 IF TG_OP='UPDATE' AND public.connector_identity_role_ok(NEW.root_id,'source') AND NEW.fenced AND (NOT OLD.blocked OR NEW.blocked) AND
  (to_jsonb(NEW)-ARRAY['fenced','blocked'])=(to_jsonb(OLD)-ARRAY['fenced','blocked']) AND ROW(NEW.fenced,NEW.blocked) IS DISTINCT FROM ROW(OLD.fenced,OLD.blocked) THEN
  IF r.source_transitions>=r.source_transition_limit THEN RAISE EXCEPTION 'connector restrictive transition backing exhausted' USING ERRCODE='23514';END IF;
  UPDATE public.connector_identity_root SET source_transitions=source_transitions+1 WHERE root_id=NEW.root_id;
  RETURN NEW;
 END IF;c:=NEW.configuration;
 IF NOT COALESCE(NEW.installation_id=r.installation_id AND NEW.issuer_epoch=r.issuer_epoch AND ((NEW.backing_revision=(r.policy->>'BackingRevision')::bigint AND NEW.backing_digest=r.backing_digest) OR (r.pending_id IS NOT NULL AND NEW.backing_revision=(r.pending_backing->'Policy'->>'BackingRevision')::bigint AND NEW.backing_digest=r.pending_digest)) AND (c->>'RootID')::uuid=NEW.root_id AND (c->'Binding'->>'PeerID')::uuid=NEW.peer_id AND (c->'Binding'->>'InstallationID')::uuid=NEW.installation_id AND (c->'Binding'->>'ClusterID')::uuid=NEW.cluster_id AND (c->'Binding'->>'IssuerEpoch')::uuid=NEW.issuer_epoch AND c->'Binding'->>'Role'='connector' AND public.connector_digest(c->'Revision'->'Digest')=NEW.source_digest AND public.connector_digest(c->'ProtectionDigest')=NEW.protection_digest AND (c->'Revision'->>'UID')::uuid=NEW.source_uid AND (c->'Revision'->>'Generation')::bigint=NEW.source_generation AND (c->>'Suspended')::boolean=NEW.suspended,false) THEN RAISE EXCEPTION 'connector source identity mismatch' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND NEW.configuration=OLD.configuration AND ROW(NEW.complete_digest,NEW.backing_revision,NEW.backing_digest) IS DISTINCT FROM ROW(OLD.complete_digest,OLD.backing_revision,OLD.backing_digest) THEN
  IF NOT public.connector_identity_role_ok(NEW.root_id,'source') OR n>=r.valid_until OR NEW.backing_revision<>OLD.backing_revision+1 OR NOT ((NEW.backing_revision=(r.policy->>'BackingRevision')::bigint AND NEW.backing_digest=r.backing_digest) OR (r.pending_id IS NOT NULL AND NEW.backing_revision=(r.pending_backing->'Policy'->>'BackingRevision')::bigint AND NEW.backing_digest=r.pending_digest)) OR
   (to_jsonb(NEW)-ARRAY['complete_digest','backing_revision','backing_digest']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['complete_digest','backing_revision','backing_digest']) OR r.source_transitions>=r.source_transition_limit THEN RAISE EXCEPTION 'connector complete source revision unavailable' USING ERRCODE='23514';END IF;
  UPDATE public.connector_identity_root SET source_transitions=source_transitions+1 WHERE root_id=NEW.root_id;
  RETURN NEW;
 END IF;
 IF TG_OP='INSERT' OR NEW.configuration IS DISTINCT FROM OLD.configuration THEN
  IF NOT public.connector_identity_role_ok(NEW.root_id,'source') OR n>=r.valid_until OR NEW.candidate_id IS NOT NULL OR NEW.accepted_id IS NOT NULL OR TG_OP='INSERT' AND NEW.account_digest IS NOT NULL OR TG_OP='UPDATE' AND NEW.account_digest IS DISTINCT FROM OLD.account_digest OR NOT NEW.fenced OR NEW.blocked OR r.source_transitions>=r.source_transition_limit OR TG_OP='INSERT' AND r.profiles>=r.profile_limit THEN RAISE EXCEPTION 'connector profile backing unavailable' USING ERRCODE='23514';END IF;
  IF TG_OP='UPDATE' AND (ROW(NEW.root_id,NEW.peer_id,NEW.installation_id,NEW.cluster_id,NEW.issuer_epoch,NEW.source_uid) IS DISTINCT FROM ROW(OLD.root_id,OLD.peer_id,OLD.installation_id,OLD.cluster_id,OLD.issuer_epoch,OLD.source_uid) OR NEW.source_generation<=OLD.source_generation) THEN RAISE EXCEPTION 'connector source rollback or replacement' USING ERRCODE='23514';END IF;
  UPDATE public.connector_identity_root SET profiles=profiles+(CASE WHEN TG_OP='INSERT' THEN 1 ELSE 0 END),source_transitions=source_transitions+1 WHERE root_id=NEW.root_id;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['candidate_id','accepted_id','fenced','blocked','account_digest']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['candidate_id','accepted_id','fenced','blocked','account_digest']) THEN RAISE EXCEPTION 'immutable connector source' USING ERRCODE='23514';END IF;
 IF NEW.account_digest IS DISTINCT FROM OLD.account_digest AND (OLD.account_digest IS NOT NULL OR NOT public.connector_identity_role_ok(NEW.root_id,'journal')) THEN RAISE EXCEPTION 'immutable logical connector account' USING ERRCODE='23514';END IF;
 IF NEW.account_digest IS NOT DISTINCT FROM OLD.account_digest AND NEW.candidate_id IS NOT DISTINCT FROM OLD.candidate_id AND NEW.accepted_id IS NOT DISTINCT FROM OLD.accepted_id AND
   ROW(NEW.fenced,NEW.blocked) IS DISTINCT FROM ROW(OLD.fenced,OLD.blocked) THEN
  IF NOT public.connector_identity_role_ok(NEW.root_id,'source') OR r.source_transitions>=r.source_transition_limit OR
   OLD.blocked AND NOT NEW.blocked OR NEW.blocked AND NOT NEW.fenced OR NOT NEW.fenced AND (NEW.accepted_id IS NULL OR NEW.blocked OR n>=r.valid_until) THEN RAISE EXCEPTION 'connector source transition unavailable' USING ERRCODE='23514';END IF;
  UPDATE public.connector_identity_root SET source_transitions=source_transitions+1 WHERE root_id=NEW.root_id;
  RETURN NEW;
 END IF;
 IF OLD.account_digest IS NOT NULL AND NEW.account_digest IS DISTINCT FROM OLD.account_digest THEN RAISE EXCEPTION 'immutable logical connector account' USING ERRCODE='23514';END IF;
 IF OLD.fenced AND OLD.accepted_id IS NOT NULL OR OLD.blocked THEN RAISE EXCEPTION 'connector current source proof unavailable' USING ERRCODE='23514';END IF;
 IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') OR NEW.suspended OR n>=r.valid_until OR NEW.blocked OR NEW.candidate_id IS NULL THEN RAISE EXCEPTION 'connector candidate unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT a FROM public.operation_audit WHERE id=NEW.candidate_id AND root_id=NEW.root_id AND lane='identity';
 IF NEW.account_digest IS DISTINCT FROM a.principal_digest THEN RAISE EXCEPTION 'connector account changed' USING ERRCODE='23514';END IF;
 IF a.intent->>'Name'='connector_process_enrollment' THEN
  SELECT * INTO STRICT child FROM public.connector_identity_process WHERE id=a.id AND root_id=NEW.root_id AND peer_id=NEW.peer_id;
  IF ROW(child.source_uid,child.source_generation,child.source_digest) IS DISTINCT FROM ROW(NEW.source_uid,NEW.source_generation,NEW.source_digest) THEN RAISE EXCEPTION 'connector process source mismatch' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO STRICT attempt FROM public.connector_credential_attempt WHERE id=a.id AND root_id=NEW.root_id AND peer_id=NEW.peer_id;
  IF ROW(attempt.source_uid,attempt.source_generation,attempt.source_digest) IS DISTINCT FROM ROW(NEW.source_uid,NEW.source_generation,NEW.source_digest) THEN RAISE EXCEPTION 'connector signing source mismatch' USING ERRCODE='23514';END IF;
 END IF;
 IF OLD.accepted_id IS NULL AND NEW.accepted_id IS NULL AND NEW.fenced AND a.intent->>'Name'='connector_process_enrollment' AND child.accepted_at IS NULL AND n<a.request_until THEN RETURN NEW;END IF;
 IF a.intent_receipt IS NULL OR a.outcome_receipt IS NULL OR a.outcome->>'Status' IS DISTINCT FROM 'success' OR NEW.accepted_id IS DISTINCT FROM NEW.candidate_id OR NEW.fenced OR (a.intent->>'Name'='connector_process_enrollment' AND (child.accepted_at IS NULL OR n>=child.run_until)) OR (a.intent->>'Name'<>'connector_process_enrollment' AND n>=attempt.certificate_not_after) THEN RAISE EXCEPTION 'connector candidate acknowledgement unavailable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_connector_identity_root(),guard_connector_identity_profile() FROM PUBLIC;
CREATE TRIGGER connector_identity_root_guard BEFORE INSERT OR UPDATE OR DELETE ON connector_identity_root FOR EACH ROW EXECUTE FUNCTION guard_connector_identity_root();
CREATE TRIGGER connector_identity_profile_guard BEFORE INSERT OR UPDATE OR DELETE ON connector_identity_profile FOR EACH ROW EXECUTE FUNCTION guard_connector_identity_profile();

ALTER TABLE operation_audit_pool DROP CONSTRAINT operation_audit_pool_lane_check;
ALTER TABLE operation_audit_pool ADD CHECK(lane IN ('normal','resolution','identity'));
ALTER TABLE operation_audit_lifecycle DROP CONSTRAINT operation_audit_lifecycle_lane_check;
ALTER TABLE operation_audit_lifecycle ADD CHECK(lane IN ('normal','resolution','identity'));
ALTER TABLE operation_audit_history DROP CONSTRAINT operation_audit_history_lane_check;
ALTER TABLE operation_audit_history ADD CHECK(lane IN ('normal','resolution','identity'));
-- +goose StatementBegin
CREATE FUNCTION connector_operation_actor_valid(i jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE name text:=i->>'Name'; actor jsonb; b jsonb;
BEGIN
 IF public.operation_audit_lane(name)<>'identity' THEN
  RETURN NOT(i ? 'Peer') AND NOT(i ? 'Process') AND public.operation_audit_human_input_valid(name,i->>'InputFormat');
 END IF;
 IF i ? 'Actor' OR (i ? 'Peer')=(i ? 'Process') THEN RETURN false;END IF;
 IF i ? 'Process' THEN
  actor:=i->'Process';b:=actor->'Process'->'Binding';
  IF NOT COALESCE((actor->'Process'->>'PodUID')::uuid IS NOT NULL AND (actor->'Process'->>'ProcessEpoch')::uuid IS NOT NULL AND
   (actor->'Deployment'->>'NamespaceUID')::uuid IS NOT NULL AND (actor->'Deployment'->>'AccountUID')::uuid IS NOT NULL AND (actor->'Deployment'->>'DeploymentUID')::uuid IS NOT NULL AND
   jsonb_array_length(actor->'ClientKeyDigest')=32 AND jsonb_array_length(actor->'ServerKeyDigest')=32 AND actor->'ClientKeyDigest'<>actor->'ServerKeyDigest',false) THEN RETURN false;END IF;
 ELSE
  IF name IN('connector_process_enrollment','connector_backing_acceptance') THEN RETURN false;END IF;
  actor:=i->'Peer';b:=actor->'Binding';
  IF NOT COALESCE(jsonb_array_length(actor->'CertificateDigest')=32,false) THEN RETURN false;END IF;
 END IF;
 RETURN COALESCE(b->>'Role'='connector' AND b->>'NodeUID'='' AND b->>'NodeBootID'='' AND b->>'CollectorEpoch'='' AND
  (b->>'InstallationID')::uuid IS NOT NULL AND (b->>'ClusterID')::uuid IS NOT NULL AND (b->>'IssuerEpoch')::uuid IS NOT NULL AND (b->>'PeerID')::uuid IS NOT NULL AND
  i->>'InputFormat'=(CASE WHEN name='connector_process_enrollment' THEN 'connector-process/v1' WHEN name='connector_backing_acceptance' THEN 'connector-backing/v1' ELSE 'connector-credential/v1' END),false);
END $$;
CREATE OR REPLACE FUNCTION operation_audit_profile_covers(candidate jsonb, prior jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE q jsonb:=candidate->'History'; oldq jsonb:=prior->'History'; k text;
BEGIN
 -- Private purposes may retain their identical independently accepted profile.
 -- They never inherit public-v3 historical coverage or cross private layouts.
 IF candidate IS NOT NULL AND candidate=prior AND q->>'Layout'<>'operation-audit-history/v3' AND public.operation_audit_history_verifier_backed(q->>'Layout') AND public.operation_audit_history_layout_valid(candidate->>'Lane',q->>'Layout') THEN RETURN true;END IF;
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
 IF p->'History' IS NULL OR NOT public.operation_audit_history_verifier_backed(p->'History'->>'Layout') OR NOT public.operation_audit_history_layout_valid(NEW.lane,p->'History'->>'Layout') OR
   NOT(p->'History' ?& ARRAY['ID','Digest','Layout','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies']) OR
   (p->'History'->>'ID')::uuid IS NULL OR jsonb_array_length(p->'History'->'Digest')<>32 OR
   (p->'History'->>'MaximumRowFootprintBytes')::bigint NOT BETWEEN public.operation_audit_history_minimum_row(p->'History'->>'Layout') AND 16777216 OR
   (p->'History'->>'MaximumTransitionWALBytes')::bigint NOT BETWEEN 131072 AND 67108864 OR
   (p->'History'->>'BackupCopies')::bigint NOT BETWEEN 1 AND 64 OR (p->'History'->>'WALCopies')::bigint NOT BETWEEN 1 AND 64 OR
   (p->>'BackupReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'MaximumRowFootprintBytes')::bigint*(p->'History'->>'BackupCopies')::bigint OR
   (p->>'WALReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'MaximumTransitionWALBytes')::bigint*(p->'History'->>'WALCopies')::bigint*(public.operation_audit_history_fixed_transitions(p->'History'->>'Layout')+3*(p->>'MaxPurgeLeases')::bigint) THEN
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
 VALUES(NEW.id,NEW.root_id,NEW.lane,NEW.principal_digest,t.installation_id,t.issuer_epoch,pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()),b,(b->>'OriginalPurgeAt')::timestamptz,(b->>'CertificatePurgeAt')::timestamptz,(b->>'LiveRetireBy')::timestamptz,0);
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
 IF t.recovery_blocked OR t.suspended OR n>=t.fresh_until OR t.observed_at>n OR t.issuer_epoch<>NEW.issuer_epoch OR pg_postmaster_start_time()<>NEW.postmaster_at OR (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())<>NEW.database_oid OR NEW.root_id<>a.root_id OR NEW.lane<>a.lane OR NEW.principal_digest<>a.principal_digest OR NEW.issuer_epoch<>a.issuer_epoch OR NEW.binding IS DISTINCT FROM a.intent->'Lifecycle' THEN RAISE EXCEPTION 'audit lifecycle recovery unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF pg_trigger_depth()<2 OR NEW.certificate_verify_attempts<>0 OR NOT public.operation_audit_history_verifier_backed(NEW.binding->'Policy'->'History'->>'Layout') OR NOT public.operation_audit_history_layout_valid(NEW.lane,NEW.binding->'Policy'->'History'->>'Layout') OR NEW.overdue_selected_at IS NOT NULL OR NEW.overdue_purge IS NOT NULL OR NEW.intent_completion IS NOT NULL OR NEW.outcome_completion IS NOT NULL OR NEW.lease IS NOT NULL OR NEW.retirement IS NOT NULL OR NEW.certificate_started OR NEW.certificate_completion IS NOT NULL OR NEW.certificate_receipt IS NOT NULL OR NEW.terminal_purge IS NOT NULL OR NEW.terminal_acknowledged_at IS NOT NULL OR NEW.finalization_xid IS NOT NULL THEN RAISE EXCEPTION 'audit lifecycle is source managed' USING ERRCODE='23514'; END IF;
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
   NOT public.operation_audit_history_verifier_backed(NEW.binding->'Policy'->'History'->>'Layout') OR NOT public.operation_audit_history_layout_valid(NEW.lane,NEW.binding->'Policy'->'History'->>'Layout') OR
   NEW.overdue_selected_at IS NOT NULL OR NEW.retirement IS NULL OR NOT NEW.certificate_started OR NEW.certificate_completion IS NULL OR
   NEW.certificate_receipt IS NOT NULL OR NEW.certificate_acknowledged_at IS NOT NULL OR
   n>=(NEW.retirement->>'CertificateWriteUntil')::timestamptz THEN
   RAISE EXCEPTION 'audit certificate verification attempt unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.certificate_receipt IS DISTINCT FROM OLD.certificate_receipt OR NEW.certificate_acknowledged_at IS DISTINCT FROM OLD.certificate_acknowledged_at THEN
  IF NOT public.operation_audit_history_verifier_backed(NEW.binding->'Policy'->'History'->>'Layout') OR NOT public.operation_audit_history_layout_valid(NEW.lane,NEW.binding->'Policy'->'History'->>'Layout') OR NEW.certificate_verify_attempts<1 OR NEW.certificate_receipt IS DISTINCT FROM NEW.certificate_completion->'Receipt' OR NEW.certificate_acknowledged_at IS NULL OR NEW.certificate_acknowledged_at>n OR NEW.certificate_acknowledged_at<(NEW.certificate_completion->>'ClosedAt')::timestamptz OR n>=(NEW.retirement->>'CertificateWriteUntil')::timestamptz THEN RAISE EXCEPTION 'audit certificate acknowledgement unavailable' USING ERRCODE='23514'; END IF;
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
   NOT (NEW.intent ?& ARRAY['ID','RootID','MACVersion','AccountVersion','Name','CreatedAt','RequestUntil','WriteUntil','RetainUntil']) OR public.operation_audit_lane(NEW.intent->>'Name') IS NULL OR NOT public.connector_operation_actor_valid(NEW.intent) OR
   (NEW.intent->>'ID')::uuid<>NEW.id OR (NEW.intent->>'RootID')::uuid<>NEW.root_id OR NEW.intent->>'AccountVersion'<>p.account_version OR
   NEW.request_until<>(NEW.intent->>'RequestUntil')::timestamptz OR NEW.write_until<>(NEW.intent->>'WriteUntil')::timestamptz OR NEW.retain_until<>(NEW.intent->>'RetainUntil')::timestamptz OR
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '5 seconds' OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
   NEW.retain_until>(NEW.intent->>'CreatedAt')::timestamptz+make_interval(secs=>p.retained_seconds::double precision) OR
   NEW.lane IS DISTINCT FROM public.operation_audit_lane(NEW.intent->>'Name') THEN
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
-- +goose StatementEnd
REVOKE ALL ON FUNCTION connector_operation_actor_valid(jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION connector_digest(v jsonb) RETURNS bytea LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE item record; encoded text:='';
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'array' OR jsonb_array_length(v)<>32 THEN RAISE EXCEPTION 'invalid connector digest' USING ERRCODE='23514';END IF;
 FOR item IN SELECT value,ordinality FROM jsonb_array_elements_text(v) WITH ORDINALITY LOOP
  IF item.value !~ '^[0-9]{1,3}$' OR item.value::int>255 THEN RAISE EXCEPTION 'invalid connector digest' USING ERRCODE='23514';END IF;
  encoded:=encoded||lpad(to_hex(item.value::int),2,'0');
 END LOOP;
 IF encoded=repeat('0',64) THEN RAISE EXCEPTION 'empty connector digest' USING ERRCODE='23514';END IF;
 RETURN decode(encoded,'hex');
END $$;

-- Row isolation uses authenticated login pins and closed functions, not RLS.
-- Installer/complete-history readers continue to see every base-table row.
CREATE FUNCTION guard_connector_audit_access() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r uuid; l text; source_role boolean; journal_role boolean; ack_role boolean; cleanup_role boolean; verifier_role boolean; finalizer_role boolean;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_TABLE_NAME NOT IN ('operation_audit_pool','operation_audit_account','operation_audit','operation_audit_lifecycle','operation_audit_history') THEN RAISE EXCEPTION 'invalid connector audit boundary' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN r:=OLD.root_id;l:=OLD.lane;ELSE r:=NEW.root_id;l:=NEW.lane;END IF;
 IF l<>'identity' THEN
  IF public.connector_identity_login_is_private() THEN RAISE EXCEPTION 'private connector role cannot use human audit lanes' USING ERRCODE='23514';END IF;
  IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 source_role:=public.connector_identity_role_ok(r,'source');journal_role:=public.connector_identity_role_ok(r,'journal');ack_role:=public.connector_identity_role_ok(r,'acknowledgement');cleanup_role:=public.connector_identity_role_ok(r,'cleanup');verifier_role:=public.connector_identity_role_ok(r,'verifier');finalizer_role:=public.connector_identity_role_ok(r,'finalizer');
 IF TG_TABLE_NAME='operation_audit_pool' THEN
  IF NOT source_role AND NOT(pg_trigger_depth()>1 AND (journal_role OR finalizer_role)) THEN RAISE EXCEPTION 'connector backing role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit_account' THEN
  IF pg_trigger_depth()<2 OR NOT(journal_role OR finalizer_role) THEN RAISE EXCEPTION 'connector account role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit_history' THEN
  IF NOT finalizer_role THEN RAISE EXCEPTION 'connector history role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit' THEN
  IF TG_OP='DELETE' THEN
   IF NOT finalizer_role THEN RAISE EXCEPTION 'connector retirement role unavailable' USING ERRCODE='23514';END IF;
  ELSIF TG_OP='INSERT' THEN
   IF NOT journal_role OR NEW.intent->'Lifecycle'->'Policy'->'History'->>'Layout' IS DISTINCT FROM 'connector-operation-history/v1' THEN RAISE EXCEPTION 'connector admission role unavailable' USING ERRCODE='23514';END IF;
  ELSIF ack_role THEN
   IF (to_jsonb(NEW)-ARRAY['intent_receipt','outcome_receipt']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['intent_receipt','outcome_receipt']) THEN RAISE EXCEPTION 'connector acknowledgement cannot create work' USING ERRCODE='23514';END IF;
  ELSIF NOT journal_role OR ROW(NEW.intent_receipt,NEW.outcome_receipt) IS DISTINCT FROM ROW(OLD.intent_receipt,OLD.outcome_receipt) THEN RAISE EXCEPTION 'connector writer cannot acknowledge itself' USING ERRCODE='23514';END IF;
 ELSE
  IF TG_OP='INSERT' THEN
   IF NOT journal_role OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'connector lifecycle admission unavailable' USING ERRCODE='23514';END IF;
  ELSIF TG_OP='DELETE' THEN
   IF NOT finalizer_role THEN RAISE EXCEPTION 'connector lifecycle retirement unavailable' USING ERRCODE='23514';END IF;
  ELSIF ack_role THEN
   IF (to_jsonb(NEW)-ARRAY['intent_completion','outcome_completion']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['intent_completion','outcome_completion']) THEN RAISE EXCEPTION 'connector writer acknowledgement scope unavailable' USING ERRCODE='23514';END IF;
  ELSIF verifier_role THEN
   IF (to_jsonb(NEW)-ARRAY['certificate_verify_attempts','certificate_receipt','certificate_acknowledged_at','terminal_acknowledged_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['certificate_verify_attempts','certificate_receipt','certificate_acknowledged_at','terminal_acknowledged_at']) THEN RAISE EXCEPTION 'connector verifier cannot create cleanup work' USING ERRCODE='23514';END IF;
  ELSIF finalizer_role THEN
   IF (to_jsonb(NEW)-'finalization_xid') IS DISTINCT FROM (to_jsonb(OLD)-'finalization_xid') THEN RAISE EXCEPTION 'connector finalizer cannot acknowledge cleanup' USING ERRCODE='23514';END IF;
  ELSIF cleanup_role THEN
   IF ROW(NEW.intent_completion,NEW.outcome_completion,NEW.certificate_verify_attempts,NEW.certificate_receipt,NEW.certificate_acknowledged_at,NEW.terminal_acknowledged_at,NEW.finalization_xid) IS DISTINCT FROM ROW(OLD.intent_completion,OLD.outcome_completion,OLD.certificate_verify_attempts,OLD.certificate_receipt,OLD.certificate_acknowledged_at,OLD.terminal_acknowledged_at,OLD.finalization_xid) THEN RAISE EXCEPTION 'connector cleanup cannot acknowledge itself' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'connector lifecycle role unavailable' USING ERRCODE='23514';END IF;
  IF TG_OP='UPDATE' AND NEW.lease IS DISTINCT FROM OLD.lease AND (
   EXISTS(SELECT 1 FROM public.connector_backing_transition b WHERE b.id=NEW.operation_id) OR
   EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.id=NEW.operation_id) OR
   EXISTS(SELECT 1 FROM public.connector_identity_process c WHERE c.id=NEW.operation_id) OR
   EXISTS(SELECT 1 FROM public.connector_identity_profile p WHERE p.candidate_id=NEW.operation_id OR p.accepted_id=NEW.operation_id)) THEN RAISE EXCEPTION 'connector credential dependencies remain charged' USING ERRCODE='23514';END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION connector_digest(jsonb),guard_connector_audit_access() FROM PUBLIC;
CREATE TRIGGER aaa_connector_audit_access BEFORE INSERT OR UPDATE OR DELETE ON operation_audit_pool FOR EACH ROW EXECUTE FUNCTION guard_connector_audit_access();
CREATE TRIGGER aaa_connector_audit_access BEFORE INSERT OR UPDATE OR DELETE ON operation_audit_account FOR EACH ROW EXECUTE FUNCTION guard_connector_audit_access();
CREATE TRIGGER aaa_connector_audit_access BEFORE INSERT OR UPDATE OR DELETE ON operation_audit FOR EACH ROW EXECUTE FUNCTION guard_connector_audit_access();
CREATE TRIGGER aaa_connector_audit_access BEFORE INSERT OR UPDATE OR DELETE ON operation_audit_lifecycle FOR EACH ROW EXECUTE FUNCTION guard_connector_audit_access();
CREATE TRIGGER aaa_connector_audit_access BEFORE INSERT OR UPDATE OR DELETE ON operation_audit_history FOR EACH ROW EXECUTE FUNCTION guard_connector_audit_access();

-- +goose StatementBegin
CREATE FUNCTION stage_connector_identity(r uuid,c jsonb,qualified jsonb) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE source jsonb:=c->'Source'; o jsonb:=source->'Observation'; p jsonb:=o->'Profile'; b jsonb:=c->'Backing'; roles jsonb:=source->'Roles'; policy jsonb:=b->'Policy';
 root public.connector_identity_root; current_profile public.connector_identity_profile; trust public.fleet_current_trust; found_profile boolean;
 peer uuid:=(p->'Binding'->>'PeerID')::uuid; installation uuid:=(p->'Binding'->>'InstallationID')::uuid;
 n timestamptz; first_at timestamptz:=(o->>'ObservedAt')::timestamptz; last_at timestamptz:=(o->>'FreshUntil')::timestamptz;
 pin_source_oid oid; pin_journal_oid oid; pin_ack_oid oid; pin_cleanup_oid oid; pin_verifier_oid oid; pin_finalizer_oid oid;
BEGIN
 IF octet_length(c::text)>196608 OR qualified IS DISTINCT FROM policy->'History' OR p->>'RootID' IS DISTINCT FROM r::text OR roles->>'Source' IS DISTINCT FROM session_user::text THEN RAISE EXCEPTION 'connector protected source mismatch' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=installation FOR SHARE;
 n:=clock_timestamp();
 IF NOT COALESCE(n>=first_at AND n<last_at AND last_at<=first_at+interval '5 seconds' AND NOT trust.recovery_blocked AND NOT trust.suspended AND n<trust.fresh_until AND trust.observed_at<=n AND trust.issuer_epoch=(p->'Binding'->>'IssuerEpoch')::uuid,false) THEN RAISE EXCEPTION 'connector current source unavailable' USING ERRCODE='23514';END IF;
 SELECT oid INTO STRICT pin_source_oid FROM pg_catalog.pg_roles WHERE rolname=roles->>'Source';
 SELECT oid INTO STRICT pin_journal_oid FROM pg_catalog.pg_roles WHERE rolname=roles->>'Journal';
 SELECT oid INTO STRICT pin_ack_oid FROM pg_catalog.pg_roles WHERE rolname=roles->>'Acknowledgement';
 SELECT oid INTO STRICT pin_cleanup_oid FROM pg_catalog.pg_roles WHERE rolname=roles->>'Cleanup';
 SELECT oid INTO STRICT pin_verifier_oid FROM pg_catalog.pg_roles WHERE rolname=roles->>'Verifier';
 SELECT oid INTO STRICT pin_finalizer_oid FROM pg_catalog.pg_roles WHERE rolname=roles->>'Finalizer';
 -- This is a protected post-activation producer; neither migration nor normal
 -- certificate ingress creates role/backing pins. Conflict preserves originals.
 INSERT INTO public.connector_identity_root(root_id,installation_id,issuer_epoch,postmaster_at,database_oid,source_name,source_oid,journal_name,journal_oid,acknowledgement_name,acknowledgement_oid,cleanup_name,cleanup_oid,verifier_name,verifier_oid,finalizer_name,finalizer_oid,profile_limit,source_transition_limit,qualification,policy,backing,backing_digest,source_backup_bytes,source_wal_bytes,valid_until)
 SELECT r,installation,trust.issuer_epoch,pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()),(roles->>'Source')::name,pin_source_oid,(roles->>'Journal')::name,pin_journal_oid,(roles->>'Acknowledgement')::name,pin_ack_oid,(roles->>'Cleanup')::name,pin_cleanup_oid,(roles->>'Verifier')::name,pin_verifier_oid,(roles->>'Finalizer')::name,pin_finalizer_oid,(b->>'ProfileLimit')::bigint,(b->>'SourceTransitionLimit')::bigint,qualified,policy,b,public.connector_digest(o->'Backing'->'Digest'),(b->>'SourceBackupReservedBytes')::bigint,(b->>'SourceWALReservedBytes')::bigint,(policy->>'ValidUntil')::timestamptz
 WHERE NOT EXISTS(SELECT 1 FROM public.connector_identity_root WHERE root_id=r) ON CONFLICT(root_id) DO NOTHING;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 n:=clock_timestamp();
 IF NOT public.connector_identity_role_ok(r,'source') OR n>=last_at OR n>=trust.fresh_until OR n>=root.valid_until OR
  ROW(root.installation_id,root.issuer_epoch,root.source_oid,root.journal_oid,root.acknowledgement_oid,root.cleanup_oid,root.verifier_oid,root.finalizer_oid,root.qualification,root.profile_limit,root.source_transition_limit,root.source_backup_bytes,root.source_wal_bytes) IS DISTINCT FROM
  ROW(installation,trust.issuer_epoch,pin_source_oid,pin_journal_oid,pin_ack_oid,pin_cleanup_oid,pin_verifier_oid,pin_finalizer_oid,qualified,(b->>'ProfileLimit')::bigint,(b->>'SourceTransitionLimit')::bigint,(b->>'SourceBackupReservedBytes')::bigint,(b->>'SourceWALReservedBytes')::bigint) THEN RAISE EXCEPTION 'connector immutable backing changed' USING ERRCODE='23514';END IF;
 IF b IS DISTINCT FROM root.backing OR public.connector_digest(o->'Backing'->'Digest')<>root.backing_digest THEN
  IF NOT public.connector_backing_can_renew(root.backing,b) OR (o->'Backing'->>'Revision')::bigint<>(policy->>'BackingRevision')::bigint THEN
   -- This is a known complete contrary source, not an unavailable read. Commit
   -- its irreversible watermark before reporting denial; rollback must not
   -- permit an A -> old B -> A sequence to resume the old accepted revision.
   UPDATE public.connector_identity_profile SET blocked=true,fenced=true WHERE root_id=r AND peer_id=peer AND NOT(blocked AND fenced);
   IF clock_timestamp()>=last_at OR clock_timestamp()>=trust.fresh_until THEN RAISE EXCEPTION 'connector contrary source expired' USING ERRCODE='23514';END IF;
   RETURN false;
  END IF;
  IF root.pending_id IS NULL THEN
   IF root.closed_candidate_digest=public.connector_digest(o->'Backing'->'Digest') OR EXISTS(SELECT 1 FROM public.connector_backing_transition old_candidate WHERE old_candidate.root_id=r AND old_candidate.proposed->'Backing'=b) THEN RAISE EXCEPTION 'connector backing candidate already spent' USING ERRCODE='23514';END IF;
   UPDATE public.connector_identity_root SET pending_id=gen_random_uuid(),pending_backing=b,pending_digest=public.connector_digest(o->'Backing'->'Digest'),pending_at=n,source_transitions=source_transitions+2 WHERE root_id=r;
   SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r;
  ELSIF root.pending_backing IS DISTINCT FROM b OR root.pending_digest<>public.connector_digest(o->'Backing'->'Digest') THEN
   UPDATE public.connector_identity_profile SET blocked=true,fenced=true WHERE root_id=r AND peer_id=peer AND NOT(blocked AND fenced);
   IF clock_timestamp()>=last_at OR clock_timestamp()>=trust.fresh_until THEN RAISE EXCEPTION 'connector contrary candidate expired' USING ERRCODE='23514';END IF;
   RETURN false;
  END IF;
 END IF;
 INSERT INTO public.operation_audit_pool(root_id,lane,account_version,account_limit,records_per_account,retained_seconds,revision,valid_until)
 SELECT r,'identity',b->>'AccountVersion',(b->>'AccountLimit')::bigint,(b->>'RecordsPerAccount')::bigint,(b->>'RetainedSeconds')::bigint,(root.policy->>'BackingRevision')::bigint,root.valid_until
 WHERE NOT EXISTS(SELECT 1 FROM public.operation_audit_pool WHERE root_id=r AND lane='identity');
 IF NOT EXISTS(SELECT 1 FROM public.operation_audit_pool a WHERE a.root_id=r AND a.lane='identity' AND NOT a.paused AND a.revision=(root.policy->>'BackingRevision')::bigint AND a.account_version=b->>'AccountVersion' AND a.account_limit=(b->>'AccountLimit')::bigint AND a.records_per_account=(b->>'RecordsPerAccount')::bigint AND a.retained_seconds=(b->>'RetainedSeconds')::bigint AND a.valid_until=root.valid_until) THEN RAISE EXCEPTION 'connector pool differs from protected backing' USING ERRCODE='23514';END IF;
 SELECT * INTO current_profile FROM public.connector_identity_profile WHERE root_id=r AND peer_id=peer FOR UPDATE;
 found_profile:=FOUND;
 n:=clock_timestamp();IF n>=last_at OR n>=trust.fresh_until THEN RAISE EXCEPTION 'connector source expired after lock' USING ERRCODE='23514';END IF;
 IF NOT found_profile THEN
  INSERT INTO public.connector_identity_profile(root_id,peer_id,installation_id,cluster_id,issuer_epoch,source_uid,source_generation,source_digest,complete_digest,backing_revision,backing_digest,protection_digest,configuration,suspended)
  VALUES(r,peer,installation,(p->'Binding'->>'ClusterID')::uuid,trust.issuer_epoch,(p->'Revision'->>'UID')::uuid,(p->'Revision'->>'Generation')::bigint,public.connector_digest(p->'Revision'->'Digest'),public.connector_digest(o->'Backing'->'SourceDigest'),(o->'Backing'->>'Revision')::bigint,public.connector_digest(o->'Backing'->'Digest'),public.connector_digest(p->'ProtectionDigest'),p,(p->>'Suspended')::boolean);
 ELSIF current_profile.configuration=p AND current_profile.backing_revision+1=(policy->>'BackingRevision')::bigint AND (root.backing=b OR (root.pending_id IS NOT NULL AND root.pending_backing=b)) THEN
  UPDATE public.connector_identity_profile SET complete_digest=public.connector_digest(o->'Backing'->'SourceDigest'),backing_revision=(o->'Backing'->>'Revision')::bigint,backing_digest=public.connector_digest(o->'Backing'->'Digest') WHERE root_id=r AND peer_id=peer;
 ELSIF current_profile.source_uid<>(p->'Revision'->>'UID')::uuid OR current_profile.source_generation>(p->'Revision'->>'Generation')::bigint OR
  current_profile.source_generation=(p->'Revision'->>'Generation')::bigint AND (current_profile.configuration IS DISTINCT FROM p OR current_profile.complete_digest<>public.connector_digest(o->'Backing'->'SourceDigest')) THEN
  -- Commit the known mutation/rollback fence rather than raising and undoing it.
  IF NOT current_profile.blocked OR NOT current_profile.fenced THEN UPDATE public.connector_identity_profile SET blocked=true,fenced=true WHERE root_id=r AND peer_id=peer;END IF;
  RETURN false;
 ELSIF current_profile.source_generation<(p->'Revision'->>'Generation')::bigint THEN
  UPDATE public.connector_identity_profile SET source_generation=(p->'Revision'->>'Generation')::bigint,source_digest=public.connector_digest(p->'Revision'->'Digest'),complete_digest=public.connector_digest(o->'Backing'->'SourceDigest'),backing_revision=(o->'Backing'->>'Revision')::bigint,backing_digest=public.connector_digest(o->'Backing'->'Digest'),protection_digest=public.connector_digest(p->'ProtectionDigest'),configuration=p,suspended=(p->>'Suspended')::boolean,fenced=true,blocked=false,candidate_id=NULL,accepted_id=NULL WHERE root_id=r AND peer_id=peer;
 ELSIF current_profile.blocked THEN RETURN false;
 ELSIF current_profile.fenced AND current_profile.accepted_id IS NOT NULL AND NOT current_profile.suspended THEN
  -- Exact original accepted facts plus fresh complete source proof can resume
  -- after an outage. This records one backed state transition, not freshness.
  UPDATE public.connector_identity_profile SET fenced=false WHERE root_id=r AND peer_id=peer;
 END IF;
 IF clock_timestamp()>=last_at OR clock_timestamp()>=trust.fresh_until THEN RAISE EXCEPTION 'connector source expired after write' USING ERRCODE='23514';END IF;
 RETURN true;
END $$;
CREATE FUNCTION fence_connector_identity(r uuid,peer uuid,observed timestamptz) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NOT public.connector_identity_role_ok(r,'source') OR observed>clock_timestamp() THEN RAISE EXCEPTION 'connector source fence unavailable' USING ERRCODE='23514';END IF;
 PERFORM 1 FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 UPDATE public.connector_identity_profile SET fenced=true WHERE root_id=r AND peer_id=peer AND NOT fenced;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION stage_connector_identity(uuid,jsonb,jsonb),fence_connector_identity(uuid,uuid,timestamptz) FROM PUBLIC;

-- +goose StatementBegin
-- The business rows are charged children of a purpose-specific encrypted pair.
-- No role can extend the original process or leaf end, reset a period counter,
-- replace an unknown signature, or release its pair while dependent rows remain.
CREATE FUNCTION guard_connector_identity_process() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; backing public.connector_identity_root; event public.operation_audit; n timestamptz; retained bigint;
BEGIN
 IF TG_RELID<>'public.connector_identity_process'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector process boundary' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN
  IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR OLD.serving OR OLD.retired_at IS NULL OR clock_timestamp()<OLD.run_until+interval '1 minute' OR EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.process_id=OLD.id) THEN RAISE EXCEPTION 'connector process still charged' USING ERRCODE='23514';END IF;
  RETURN OLD;
 END IF;
 SELECT * INTO STRICT backing FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=NEW.root_id AND peer_id=NEW.peer_id FOR UPDATE;
 n:=clock_timestamp();
 IF TG_OP='UPDATE' AND public.connector_identity_role_ok(NEW.root_id,'cleanup') THEN
  IF n<OLD.run_until+interval '1 minute' OR NEW.serving OR NEW.retired_at IS NULL OR OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at OR NEW.client_current_id IS NOT NULL OR NEW.client_previous_id IS NOT NULL OR NEW.server_current_id IS NOT NULL OR NEW.server_previous_id IS NOT NULL OR
   (to_jsonb(NEW)-ARRAY['serving','retired_at','client_current_id','client_previous_id','server_current_id','server_previous_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['serving','retired_at','client_current_id','client_previous_id','server_current_id','server_previous_id']) THEN RAISE EXCEPTION 'connector historical detachment unavailable' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') THEN RAISE EXCEPTION 'connector process journal unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT event FROM public.operation_audit WHERE id=NEW.id AND root_id=NEW.root_id AND lane='identity';
  SELECT count(*) INTO retained FROM public.connector_identity_process WHERE root_id=NEW.root_id AND peer_id=NEW.peer_id;
  IF n>=backing.valid_until OR cfg.blocked OR cfg.suspended OR cfg.fenced AND cfg.accepted_id IS NOT NULL OR retained>=(cfg.configuration->'Deployment'->>'RetainedProcesses')::bigint OR NEW.accepted_at IS NOT NULL OR NEW.serving OR NEW.retired_at IS NOT NULL OR NEW.client_epoch<>-1 OR NEW.server_epoch<>-1 OR NEW.client_attempts<>0 OR NEW.server_attempts<>0 OR NEW.client_current_id IS NOT NULL OR NEW.client_previous_id IS NOT NULL OR NEW.server_current_id IS NOT NULL OR NEW.server_previous_id IS NOT NULL OR
   event.intent->>'Name' IS DISTINCT FROM 'connector_process_enrollment' OR event.intent->'Process'->'Process' IS DISTINCT FROM NEW.process->'Attested' OR event.intent->'Process'->'Deployment' IS DISTINCT FROM cfg.configuration->'Deployment' OR
   public.connector_digest(event.intent->'Process'->'ClientKeyDigest')<>NEW.client_key OR public.connector_digest(event.intent->'Process'->'ServerKeyDigest')<>NEW.server_key OR
   NOT COALESCE(NEW.process->>'BootstrapID'='' AND NEW.process->'Binding'=cfg.configuration->'Binding' AND NEW.process->'Attested'->'Binding'=cfg.configuration->'Binding' AND (NEW.process->'Attested'->>'PodUID')::uuid=NEW.pod_uid AND (NEW.process->'Attested'->>'ProcessEpoch')::uuid=NEW.process_epoch AND public.connector_digest(NEW.process->'ClientKeyDigest')=NEW.client_key AND public.connector_digest(NEW.process->'ServerKeyDigest')=NEW.server_key AND (NEW.process->>'ClaimedAt')::timestamptz=NEW.claimed_at AND (NEW.process->>'InitialCertificateNotAfter')::timestamptz=NEW.initial_not_after AND (NEW.process->>'RunUntil')::timestamptz=NEW.run_until,false) OR
   ROW(NEW.source_uid,NEW.source_generation,NEW.source_digest) IS DISTINCT FROM ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest) OR NEW.claimed_at<>(event.intent->>'CreatedAt')::timestamptz OR NEW.run_until>(event.intent->'Lifecycle'->>'OriginalPurgeAt')::timestamptz-interval '1 minute' OR n>=event.request_until THEN RAISE EXCEPTION 'connector process admission unavailable' USING ERRCODE='23514';END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['accepted_at','serving','retired_at','client_epoch','client_attempts','server_epoch','server_attempts','client_current_id','client_previous_id','server_current_id','server_previous_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['accepted_at','serving','retired_at','client_epoch','client_attempts','server_epoch','server_attempts','client_current_id','client_previous_id','server_current_id','server_previous_id']) OR OLD.accepted_at IS NOT NULL AND NEW.accepted_at IS DISTINCT FROM OLD.accepted_at OR OLD.retired_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'immutable connector process' USING ERRCODE='23514';END IF;
  IF NEW.client_epoch<OLD.client_epoch OR NEW.server_epoch<OLD.server_epoch OR NEW.client_epoch=OLD.client_epoch AND NEW.client_attempts<OLD.client_attempts OR NEW.server_epoch=OLD.server_epoch AND NEW.server_attempts<OLD.server_attempts OR NEW.client_attempts>OLD.client_attempts+1 AND NEW.client_epoch=OLD.client_epoch OR NEW.server_attempts>OLD.server_attempts+1 AND NEW.server_epoch=OLD.server_epoch OR NEW.client_epoch>OLD.client_epoch AND NEW.client_attempts<>1 OR NEW.server_epoch>OLD.server_epoch AND NEW.server_attempts<>1 THEN RAISE EXCEPTION 'connector signing counter reset' USING ERRCODE='23514';END IF;
  IF OLD.accepted_at IS NULL AND NEW.accepted_at IS NOT NULL THEN
   SELECT * INTO STRICT event FROM public.operation_audit WHERE id=NEW.id AND root_id=NEW.root_id;
   IF event.intent_receipt IS NULL OR event.outcome_receipt IS NULL OR event.outcome->>'Status' IS DISTINCT FROM 'success' OR event.outcome->>'Effect' IS DISTINCT FROM 'accepted' OR NEW.accepted_at<n-interval '5 seconds' OR NEW.accepted_at>n OR n>=NEW.run_until THEN RAISE EXCEPTION 'connector process audit unavailable' USING ERRCODE='23514';END IF;
  END IF;
  IF OLD.serving AND NOT NEW.serving AND NEW.retired_at IS NULL OR NEW.retired_at IS NOT NULL AND (NEW.serving OR NEW.retired_at<n-interval '5 seconds' OR NEW.retired_at>n) THEN RAISE EXCEPTION 'connector retirement transition unavailable' USING ERRCODE='23514';END IF;
  IF NEW.serving AND NOT OLD.serving THEN
   IF cfg.fenced OR cfg.blocked OR cfg.suspended OR n>=backing.valid_until OR n>=NEW.run_until OR NOT EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.id=NEW.client_current_id AND a.process_id=NEW.id AND a.usage='client' AND a.activated_at IS NOT NULL AND a.detached_at IS NULL AND n<a.certificate_not_after) OR NOT EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.id=NEW.server_current_id AND a.process_id=NEW.id AND a.usage='server' AND a.activated_at IS NOT NULL AND a.detached_at IS NULL AND n<a.certificate_not_after) THEN RAISE EXCEPTION 'paired connector serving identity unavailable' USING ERRCODE='23514';END IF;
   IF NOT OLD.serving AND (SELECT count(*) FROM public.connector_identity_process c WHERE c.root_id=NEW.root_id AND c.peer_id=NEW.peer_id AND c.serving)>=(cfg.configuration->'Deployment'->>'ServingSlots')::bigint THEN RAISE EXCEPTION 'connector serving slots exhausted' USING ERRCODE='23514';END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION guard_connector_credential_attempt() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; child public.connector_identity_process; event public.operation_audit; n timestamptz; period bigint; leaf_end timestamptz; body jsonb;
BEGIN
 IF TG_RELID<>'public.connector_credential_attempt'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector credential boundary' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN
  IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR OLD.detached_at IS NULL OR clock_timestamp()<OLD.certificate_not_after+interval '1 minute' OR EXISTS(SELECT 1 FROM public.connector_identity_process c WHERE OLD.id IN(c.client_current_id,c.client_previous_id,c.server_current_id,c.server_previous_id)) THEN RAISE EXCEPTION 'connector credential still charged' USING ERRCODE='23514';END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' AND public.connector_identity_role_ok(NEW.root_id,'cleanup') THEN
  n:=clock_timestamp();
  IF n<OLD.certificate_not_after+interval '1 minute' OR OLD.detached_at IS NOT NULL AND NEW.detached_at IS DISTINCT FROM OLD.detached_at OR NEW.detached_at IS NULL OR (to_jsonb(NEW)-'detached_at') IS DISTINCT FROM (to_jsonb(OLD)-'detached_at') OR EXISTS(SELECT 1 FROM public.connector_identity_process p WHERE NEW.id IN(p.client_current_id,p.client_previous_id,p.server_current_id,p.server_previous_id)) THEN RAISE EXCEPTION 'connector historical credential detachment unavailable' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') THEN RAISE EXCEPTION 'connector credential journal unavailable' USING ERRCODE='23514';END IF;
 PERFORM 1 FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=NEW.root_id AND peer_id=NEW.peer_id FOR UPDATE;
 SELECT * INTO STRICT child FROM public.connector_identity_process WHERE id=NEW.process_id AND root_id=NEW.root_id AND peer_id=NEW.peer_id FOR UPDATE;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE id=NEW.id AND root_id=NEW.root_id AND lane='identity';
 n:=clock_timestamp();
 IF TG_OP='INSERT' THEN
  period:=floor((extract(epoch FROM NEW.checked_at)+60-extract(epoch FROM child.initial_not_after)+1800)/1800)::bigint;
  leaf_end:=LEAST(child.initial_not_after+make_interval(secs=>(period*1800)::double precision),child.run_until);
  IF cfg.fenced OR cfg.blocked OR cfg.suspended OR child.accepted_at IS NULL OR child.retired_at IS NOT NULL OR n>=child.run_until OR n>=NEW.sign_before OR NEW.provider_started OR NEW.issued IS NOT NULL OR NEW.activated_at IS NOT NULL OR NEW.detached_at IS NOT NULL OR NEW.epoch<>period OR NEW.certificate_not_after<>leaf_end OR NEW.certificate_not_after>(event.intent->'Lifecycle'->>'OriginalPurgeAt')::timestamptz-interval '1 minute' OR NEW.checked_at<>(event.intent->>'CreatedAt')::timestamptz OR NEW.sign_before<>event.request_until OR NEW.public_key<>(CASE WHEN NEW.usage='client' THEN child.client_key ELSE child.server_key END) OR
   ROW(NEW.source_uid,NEW.source_generation,NEW.source_digest) IS DISTINCT FROM ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest) OR event.intent->>'Name' IS DISTINCT FROM 'connector_'||NEW.usage||'_certificate' OR
   NEW.permit->'Process' IS DISTINCT FROM child.process OR NEW.permit->'Configuration'->'Profile' IS DISTINCT FROM cfg.configuration OR (NEW.permit->>'Epoch')::bigint<>NEW.epoch OR (NEW.permit->>'Ordinal')::bigint<>NEW.ordinal OR (NEW.permit->>'ID')::uuid<>NEW.id OR NEW.permit->>'Usage'<>NEW.usage OR (NEW.permit->>'CheckedAt')::timestamptz<>NEW.checked_at OR (NEW.permit->>'SignBefore')::timestamptz<>NEW.sign_before OR (NEW.permit->>'CertificateNotAfter')::timestamptz<>NEW.certificate_not_after OR
   (CASE WHEN NEW.usage='client' THEN child.client_epoch<>NEW.epoch OR child.client_attempts<>NEW.ordinal ELSE child.server_epoch<>NEW.epoch OR child.server_attempts<>NEW.ordinal END) THEN RAISE EXCEPTION 'connector credential admission unavailable' USING ERRCODE='23514';END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['provider_started','issued','certificate_digest','certificate_not_before','activated_at','detached_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['provider_started','issued','certificate_digest','certificate_not_before','activated_at','detached_at']) OR OLD.provider_started AND NOT NEW.provider_started OR OLD.issued IS NOT NULL AND NEW.issued IS DISTINCT FROM OLD.issued OR OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at OR OLD.detached_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'immutable connector signing attempt' USING ERRCODE='23514';END IF;
  IF NOT OLD.provider_started AND NEW.provider_started AND (event.intent_receipt IS NULL OR n>=NEW.sign_before OR cfg.fenced OR cfg.suspended OR cfg.blocked OR child.retired_at IS NOT NULL OR n>=child.run_until) THEN RAISE EXCEPTION 'connector signing intent unavailable' USING ERRCODE='23514';END IF;
  IF OLD.issued IS NULL AND NEW.issued IS NOT NULL THEN
   body:=NEW.issued->'Certificate';
   IF NOT NEW.provider_started OR n>=NEW.sign_before OR NOT COALESCE(body->'Binding'=child.process->'Binding' AND body->>'Usage'=NEW.usage AND public.connector_digest(body->'Digest')=NEW.certificate_digest AND public.connector_digest(body->'PublicKeyDigest')=NEW.public_key AND (body->>'NotBefore')::timestamptz=NEW.certificate_not_before AND (body->>'NotAfter')::timestamptz=NEW.certificate_not_after AND body->>'ServerName'=(CASE WHEN NEW.usage='server' THEN cfg.configuration->>'ServerName' ELSE '' END),false) THEN RAISE EXCEPTION 'connector provider result mismatch' USING ERRCODE='23514';END IF;
  END IF;
  IF OLD.activated_at IS NULL AND NEW.activated_at IS NOT NULL AND (event.intent_receipt IS NULL OR event.outcome_receipt IS NULL OR event.outcome->>'Status' IS DISTINCT FROM 'success' OR event.outcome->'Credential'->'CertificateDigest' IS DISTINCT FROM NEW.issued->'Certificate'->'Digest' OR (event.outcome->'Credential'->>'NotAfter')::timestamptz<>NEW.certificate_not_after OR cfg.fenced OR cfg.suspended OR cfg.blocked OR child.retired_at IS NOT NULL OR n>=child.run_until OR n>=NEW.certificate_not_after OR NEW.activated_at<n-interval '5 seconds' OR NEW.activated_at>n) THEN RAISE EXCEPTION 'connector activation audit unavailable' USING ERRCODE='23514';END IF;
  IF NEW.detached_at IS NOT NULL AND (NEW.detached_at<n-interval '5 seconds' OR NEW.detached_at>n OR EXISTS(SELECT 1 FROM public.connector_identity_process c WHERE NEW.id IN(c.client_current_id,c.client_previous_id,c.server_current_id,c.server_previous_id))) THEN RAISE EXCEPTION 'connector credential remains referenced' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_connector_identity_process(),guard_connector_credential_attempt() FROM PUBLIC;
CREATE TRIGGER connector_identity_process_guard BEFORE INSERT OR UPDATE OR DELETE ON connector_identity_process FOR EACH ROW EXECUTE FUNCTION guard_connector_identity_process();
CREATE TRIGGER connector_credential_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON connector_credential_attempt FOR EACH ROW EXECUTE FUNCTION guard_connector_credential_attempt();

-- +goose StatementBegin
CREATE FUNCTION connector_backing_observed(r public.connector_identity_root,p public.connector_identity_profile,o jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(((p.backing_revision=(r.policy->>'BackingRevision')::bigint AND p.backing_digest=r.backing_digest) OR (r.pending_id IS NOT NULL AND p.backing_revision=(r.pending_backing->'Policy'->>'BackingRevision')::bigint AND p.backing_digest=r.pending_digest))
 AND (o->'Backing'->>'Revision')::bigint=p.backing_revision
 AND public.connector_digest(o->'Backing'->'Digest')=p.backing_digest
 AND public.connector_digest(o->'Backing'->'SourceDigest')=p.complete_digest,false)
$$;
REVOKE ALL ON FUNCTION connector_backing_observed(public.connector_identity_root,public.connector_identity_profile,jsonb) FROM PUBLIC;
CREATE FUNCTION lock_connector_process_current(r uuid,c jsonb,allow_candidate boolean) RETURNS public.connector_identity_profile LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb:=c->'Proof'; source jsonb:=proof->'Configuration'; p jsonb:=source->'Profile'; cfg public.connector_identity_profile; root public.connector_identity_root; trust public.fleet_current_trust; n timestamptz;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'journal') OR octet_length(c::text)>196608 THEN RAISE EXCEPTION 'connector process current authority unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(p->'Binding'->>'InstallationID')::uuid FOR SHARE;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=r AND peer_id=(proof->'Process'->'Binding'->>'PeerID')::uuid FOR UPDATE;
 n:=clock_timestamp();
 IF NOT COALESCE(NOT trust.recovery_blocked AND NOT trust.suspended AND trust.observed_at<=n AND n<trust.fresh_until AND trust.issuer_epoch=root.issuer_epoch AND n<root.valid_until AND root.source_transitions<root.source_transition_limit AND
   NOT cfg.suspended AND NOT cfg.blocked AND (NOT cfg.fenced OR allow_candidate AND cfg.accepted_id IS NULL) AND cfg.configuration=p AND public.connector_backing_observed(root,cfg,source) AND proof->'Process'->'Binding'=p->'Binding' AND (p->>'RootID')::uuid=r AND
   (c->>'ObservedAt')::timestamptz<=n AND (c->>'Until')::timestamptz>n AND (c->>'Until')::timestamptz<=(c->>'ObservedAt')::timestamptz+interval '5 seconds' AND
   (proof->>'ObservedAt')::timestamptz<=n AND (proof->>'FreshUntil')::timestamptz>n AND (proof->>'FreshUntil')::timestamptz<=(proof->>'ObservedAt')::timestamptz+interval '5 seconds' AND
   (source->>'ObservedAt')::timestamptz<=n AND (source->>'FreshUntil')::timestamptz>n AND (source->>'FreshUntil')::timestamptz<=(source->>'ObservedAt')::timestamptz+interval '5 seconds' AND
   (c->>'Until')::timestamptz<=(proof->>'FreshUntil')::timestamptz AND (c->>'Until')::timestamptz<=(source->>'FreshUntil')::timestamptz AND (c->>'Until')::timestamptz<=(c->'Recovery'->>'FreshUntil')::timestamptz AND
   (c->'Recovery'->>'InstallationID')::uuid=root.installation_id AND (c->'Recovery'->>'IssuerEpoch')::uuid=root.issuer_epoch AND (c->'Recovery'->>'ObservedAt')::timestamptz<=n AND (c->'Recovery'->>'FreshUntil')::timestamptz>n AND (c->'Recovery'->>'FreshUntil')::timestamptz<=(c->'Recovery'->>'ObservedAt')::timestamptz+interval '5 seconds' AND (c->'Recovery'->>'FreshUntil')::timestamptz<=trust.fresh_until AND c->'Recovery'->'Revision'->>'UID'=trust.source_uid AND (c->'Recovery'->'Revision'->>'Generation')::bigint=trust.source_generation AND public.connector_digest(c->'Recovery'->'Revision'->'Digest')=trust.source_digest AND
   jsonb_array_length(proof->'WorkloadDigest')=32 AND jsonb_array_length(proof->'ProtectionDigest')=32 AND public.connector_digest(proof->'ClientKeyDigest')<>public.connector_digest(proof->'ServerKeyDigest'),false) THEN RAISE EXCEPTION 'connector process proof unavailable' USING ERRCODE='23514';END IF;
 RETURN cfg;
END $$;
CREATE FUNCTION read_connector_process_admission(r uuid,operation uuid,c jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; child public.connector_identity_process; event public.operation_audit;
BEGIN
 cfg:=public.lock_connector_process_current(r,c,true);
 SELECT * INTO child FROM public.connector_identity_process WHERE id=operation AND root_id=r AND peer_id=cfg.peer_id FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 IF child.process->'Attested' IS DISTINCT FROM c->'Proof'->'Process' OR child.client_key<>public.connector_digest(c->'Proof'->'ClientKeyDigest') OR child.server_key<>public.connector_digest(c->'Proof'->'ServerKeyDigest') OR child.retired_at IS NOT NULL OR clock_timestamp()>=child.run_until OR ROW(child.source_uid,child.source_generation,child.source_digest) IS DISTINCT FROM ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest) THEN RAISE EXCEPTION 'connector process replay mismatch' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE id=operation AND root_id=r AND lane='identity';
 IF clock_timestamp()>=(c->>'Until')::timestamptz THEN RAISE EXCEPTION 'connector process read expired' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Process',child.process,'Intent',event.intent,'Outcome',event.outcome,'Activated',child.accepted_at IS NOT NULL);
END $$;
CREATE FUNCTION admit_connector_process(r uuid,c jsonb,i jsonb,process_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; existing jsonb; operation uuid:=(i->>'ID')::uuid; proof jsonb:=c->'Proof'; n timestamptz;
BEGIN
 cfg:=public.lock_connector_process_current(r,c,true);
 existing:=public.read_connector_process_admission(r,operation,c);IF existing IS NOT NULL THEN RETURN existing;END IF;
 n:=clock_timestamp();
 IF i->>'Name' IS DISTINCT FROM 'connector_process_enrollment' OR i->'Process'->'Process' IS DISTINCT FROM proof->'Process' OR i->'Process'->'Deployment' IS DISTINCT FROM cfg.configuration->'Deployment' OR i->'Process'->'ClientKeyDigest' IS DISTINCT FROM proof->'ClientKeyDigest' OR i->'Process'->'ServerKeyDigest' IS DISTINCT FROM proof->'ServerKeyDigest' OR (i->>'CreatedAt')::timestamptz<>(c->>'ObservedAt')::timestamptz OR (i->>'RequestUntil')::timestamptz>(c->>'Until')::timestamptz OR cfg.account_digest IS NOT NULL AND cfg.account_digest<>public.connector_digest(i->'PrincipalDigest') THEN RAISE EXCEPTION 'connector admission differs from current proof' USING ERRCODE='23514';END IF;
 INSERT INTO public.operation_audit(id,root_id,lane,issuer_epoch,principal_digest,intent,request_until,write_until,retain_until)
 VALUES(operation,r,'identity',cfg.issuer_epoch,public.connector_digest(i->'PrincipalDigest'),i,(i->>'RequestUntil')::timestamptz,(i->>'WriteUntil')::timestamptz,(i->>'RetainUntil')::timestamptz);
 -- Fresh attested same-Pod replacement may fence an unserved pending epoch;
 -- its keys, possible leaves and audit charges are retained under original ends.
 UPDATE public.connector_identity_process SET retired_at=clock_timestamp() WHERE root_id=r AND peer_id=cfg.peer_id AND pod_uid=(proof->'Process'->>'PodUID')::uuid AND NOT serving AND retired_at IS NULL AND process_epoch<>(proof->'Process'->>'ProcessEpoch')::uuid;
 INSERT INTO public.connector_identity_process(id,root_id,peer_id,pod_uid,process_epoch,client_key,server_key,process,source_uid,source_generation,source_digest,claimed_at,initial_not_after,run_until)
 VALUES(operation,r,cfg.peer_id,(proof->'Process'->>'PodUID')::uuid,(proof->'Process'->>'ProcessEpoch')::uuid,public.connector_digest(proof->'ClientKeyDigest'),public.connector_digest(proof->'ServerKeyDigest'),process_value,cfg.source_uid,cfg.source_generation,cfg.source_digest,(i->>'CreatedAt')::timestamptz,(process_value->>'InitialCertificateNotAfter')::timestamptz,(process_value->>'RunUntil')::timestamptz);
 IF cfg.account_digest IS NULL THEN UPDATE public.connector_identity_profile SET account_digest=public.connector_digest(i->'PrincipalDigest'),candidate_id=operation WHERE root_id=r AND peer_id=cfg.peer_id;END IF;
 IF clock_timestamp()>=(c->>'Until')::timestamptz THEN RAISE EXCEPTION 'connector process admission expired' USING ERRCODE='23514';END IF;
 RETURN public.read_connector_process_admission(r,operation,c);
END $$;
CREATE FUNCTION store_connector_process_outcome(r uuid,operation uuid,i jsonb,o jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE event public.operation_audit; child public.connector_identity_process; trust public.fleet_current_trust; backing public.connector_identity_root; started timestamptz:=clock_timestamp(); n timestamptz;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'journal') THEN RAISE EXCEPTION 'connector process writer unavailable' USING ERRCODE='23514';END IF;
 SELECT t.* INTO STRICT trust FROM public.fleet_current_trust t JOIN public.connector_identity_root x ON x.installation_id=t.installation_id WHERE x.root_id=r FOR SHARE OF t;
 SELECT * INTO STRICT backing FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT child FROM public.connector_identity_process WHERE id=operation AND root_id=r FOR UPDATE;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE id=operation AND root_id=r FOR UPDATE;
 n:=clock_timestamp();
 IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR n>=started+interval '5 seconds' OR trust.issuer_epoch<>backing.issuer_epoch OR event.issuer_epoch<>trust.issuer_epoch THEN RAISE EXCEPTION 'connector process outcome recovery unavailable' USING ERRCODE='23514';END IF;
 IF event.intent IS DISTINCT FROM i OR o->'Intent' IS DISTINCT FROM i OR o->>'Status' IS DISTINCT FROM 'success' OR o->>'Effect' IS DISTINCT FROM 'accepted' OR o ? 'Credential' OR event.intent_receipt IS NULL OR child.retired_at IS NOT NULL OR clock_timestamp()>=event.request_until THEN RAISE EXCEPTION 'connector process outcome unavailable' USING ERRCODE='23514';END IF;
 IF event.outcome IS NOT NULL THEN IF event.outcome IS DISTINCT FROM o THEN RAISE EXCEPTION 'immutable connector process outcome' USING ERRCODE='23514';END IF;RETURN;END IF;
 UPDATE public.operation_audit SET outcome=o WHERE id=operation AND root_id=r;
END $$;
CREATE FUNCTION accept_connector_process(r uuid,operation uuid,c jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; child public.connector_identity_process; event public.operation_audit; result jsonb;
BEGIN
 cfg:=public.lock_connector_process_current(r,c,true);
 result:=public.read_connector_process_admission(r,operation,c);
 IF result IS NULL THEN RAISE EXCEPTION 'connector process admission missing' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT child FROM public.connector_identity_process WHERE id=operation AND root_id=r FOR UPDATE;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE id=operation AND root_id=r FOR UPDATE;
 IF event.intent_receipt IS NULL OR event.outcome_receipt IS NULL OR event.outcome->>'Status' IS DISTINCT FROM 'success' OR event.outcome->>'Effect' IS DISTINCT FROM 'accepted' OR clock_timestamp()>=child.run_until OR cfg.account_digest IS NOT NULL AND cfg.account_digest<>event.principal_digest THEN RAISE EXCEPTION 'connector process acknowledgements unavailable' USING ERRCODE='23514';END IF;
 IF child.accepted_at IS NULL THEN UPDATE public.connector_identity_process SET accepted_at=clock_timestamp() WHERE id=operation AND root_id=r;END IF;
 -- This acceptance changes no source timestamp and grants no certificate/bytes.
 UPDATE public.connector_identity_profile SET account_digest=event.principal_digest,candidate_id=operation,accepted_id=operation,fenced=false WHERE root_id=r AND peer_id=cfg.peer_id;
 IF clock_timestamp()>=(c->>'Until')::timestamptz THEN RAISE EXCEPTION 'connector process acceptance expired' USING ERRCODE='23514';END IF;
 RETURN child.process;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION lock_connector_process_current(uuid,jsonb,boolean),read_connector_process_admission(uuid,uuid,jsonb),admit_connector_process(uuid,jsonb,jsonb,jsonb),store_connector_process_outcome(uuid,uuid,jsonb,jsonb),accept_connector_process(uuid,uuid,jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION lock_connector_credential_candidate(r uuid,candidate jsonb) RETURNS public.connector_identity_process LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cur jsonb:=candidate->'Current'; source jsonb:=cur->'Source'->'Observation'; p jsonb:=source->'Profile'; proof jsonb:=cur->'ProcessProof'; actor jsonb:=cur->'Peer'; cfg public.connector_identity_profile; root public.connector_identity_root; trust public.fleet_current_trust; child public.connector_identity_process; leaf public.connector_credential_attempt; n timestamptz;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'journal') OR octet_length(candidate::text)>262144 OR candidate->>'BootstrapID' IS DISTINCT FROM '' OR candidate->>'Usage' NOT IN('client','server') OR candidate->'Attested' IS NULL THEN RAISE EXCEPTION 'connector credential origin unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(p->'Binding'->>'InstallationID')::uuid FOR SHARE;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=r AND peer_id=(candidate->'Attested'->'Binding'->>'PeerID')::uuid FOR UPDATE;
 SELECT * INTO STRICT child FROM public.connector_identity_process WHERE root_id=r AND peer_id=cfg.peer_id AND pod_uid=(candidate->'Attested'->>'PodUID')::uuid AND process_epoch=(candidate->'Attested'->>'ProcessEpoch')::uuid FOR UPDATE;
 n:=clock_timestamp();
 IF NOT COALESCE(NOT trust.recovery_blocked AND NOT trust.suspended AND trust.observed_at<=n AND n<trust.fresh_until AND trust.issuer_epoch=root.issuer_epoch AND n<root.valid_until AND root.source_transitions<root.source_transition_limit AND NOT cfg.fenced AND NOT cfg.blocked AND NOT cfg.suspended AND cfg.accepted_id IS NOT NULL AND cfg.configuration=p AND public.connector_backing_observed(root,cfg,source) AND
   child.accepted_at IS NOT NULL AND child.retired_at IS NULL AND n<child.run_until AND child.process->'Attested'=candidate->'Attested' AND
   ROW(child.source_uid,child.source_generation,child.source_digest)=ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest) AND
   (cur->>'ObservedAt')::timestamptz<=n AND (cur->>'Until')::timestamptz>n AND (cur->>'Until')::timestamptz<=(cur->>'ObservedAt')::timestamptz+interval '5 seconds' AND
   (source->>'ObservedAt')::timestamptz<=n AND (source->>'FreshUntil')::timestamptz>n AND (source->>'FreshUntil')::timestamptz<=(source->>'ObservedAt')::timestamptz+interval '5 seconds' AND (cur->>'Until')::timestamptz<=(source->>'FreshUntil')::timestamptz AND
   (cur->'Recovery'->>'InstallationID')::uuid=root.installation_id AND (cur->'Recovery'->>'IssuerEpoch')::uuid=root.issuer_epoch AND cur->'Recovery'->'Revision'->>'UID'=trust.source_uid AND (cur->'Recovery'->'Revision'->>'Generation')::bigint=trust.source_generation AND public.connector_digest(cur->'Recovery'->'Revision'->'Digest')=trust.source_digest AND (cur->>'Until')::timestamptz<=(cur->'Recovery'->>'FreshUntil')::timestamptz AND (cur->'Recovery'->>'FreshUntil')::timestamptz<=trust.fresh_until AND
   (cur->'Recovery'->>'ObservedAt')::timestamptz<=n AND (cur->'Recovery'->>'FreshUntil')::timestamptz<=(cur->'Recovery'->>'ObservedAt')::timestamptz+interval '5 seconds' AND
   public.connector_digest(candidate->'PublicKeyDigest')=(CASE WHEN candidate->>'Usage'='client' THEN child.client_key ELSE child.server_key END),false) THEN RAISE EXCEPTION 'connector credential current authority unavailable' USING ERRCODE='23514';END IF;
 IF proof IS NOT NULL AND proof<>'null'::jsonb THEN
  PERFORM public.lock_connector_process_current(r,jsonb_build_object('Proof',proof,'Recovery',cur->'Recovery','ObservedAt',cur->'ObservedAt','Until',cur->'Until'),false);
  IF proof->'Process' IS DISTINCT FROM candidate->'Attested' OR public.connector_digest(proof->'ClientKeyDigest')<>child.client_key OR public.connector_digest(proof->'ServerKeyDigest')<>child.server_key OR actor->'Certificate'->'Binding'->>'PeerID' IS DISTINCT FROM '' THEN RAISE EXCEPTION 'connector proof/key origin mismatch' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO STRICT leaf FROM public.connector_credential_attempt WHERE root_id=r AND process_id=child.id AND usage='client' AND certificate_digest=public.connector_digest(actor->'Certificate'->'Digest') AND id IN(child.client_current_id,child.client_previous_id);
  IF NOT COALESCE(child.serving AND leaf.activated_at IS NOT NULL AND leaf.detached_at IS NULL AND n>=leaf.certificate_not_before AND n<leaf.certificate_not_after AND actor->'Certificate'->'Binding'=child.process->'Binding' AND (actor->>'VerifiedAt')::timestamptz<=n AND (actor->>'ValidUntil')::timestamptz>n AND (actor->>'ValidUntil')::timestamptz<=(actor->>'VerifiedAt')::timestamptz+interval '5 seconds' AND (cur->>'Until')::timestamptz<=(actor->>'ValidUntil')::timestamptz,false) THEN RAISE EXCEPTION 'connector actual client leaf unavailable' USING ERRCODE='23514';END IF;
 END IF;
 RETURN child;
END $$;
CREATE FUNCTION read_connector_credential_process(r uuid,c jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE child public.connector_identity_process;
BEGIN
 child:=public.lock_connector_credential_candidate(r,c);
 RETURN jsonb_build_object('Backing',(SELECT backing FROM public.connector_identity_root WHERE root_id=r),'Process',child.process,'ClientEpoch',child.client_epoch,'ClientAttempts',child.client_attempts,'ServerEpoch',child.server_epoch,'ServerAttempts',child.server_attempts);
END $$;
CREATE FUNCTION read_connector_credential_attempt(r uuid,operation uuid,c jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE child public.connector_identity_process; attempt public.connector_credential_attempt; event public.operation_audit;
BEGIN
 child:=public.lock_connector_credential_candidate(r,c);
 SELECT * INTO attempt FROM public.connector_credential_attempt WHERE id=operation AND root_id=r FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 IF attempt.process_id<>child.id OR attempt.usage IS DISTINCT FROM c->>'Usage' OR attempt.public_key<>public.connector_digest(c->'PublicKeyDigest') OR attempt.detached_at IS NOT NULL OR clock_timestamp()>=attempt.certificate_not_after THEN RAISE EXCEPTION 'connector credential replay mismatch' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE id=operation AND root_id=r AND lane='identity';
 IF clock_timestamp()>=(c->'Current'->>'Until')::timestamptz THEN RAISE EXCEPTION 'connector credential lookup expired' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Permit',attempt.permit,'Intent',event.intent,'ProviderStarted',attempt.provider_started,'Certificate',attempt.issued,'Outcome',event.outcome,'Activated',attempt.activated_at IS NOT NULL);
END $$;
CREATE FUNCTION admit_connector_credential(r uuid,c jsonb,i jsonb,permit_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE child public.connector_identity_process; cfg public.connector_identity_profile; old_result jsonb; operation uuid:=(i->>'ID')::uuid; wanted_epoch bigint:=(permit_value->>'Epoch')::bigint; wanted_ordinal bigint:=(permit_value->>'Ordinal')::bigint;
BEGIN
 child:=public.lock_connector_credential_candidate(r,c);
 old_result:=public.read_connector_credential_attempt(r,operation,c);IF old_result IS NOT NULL THEN RETURN old_result;END IF;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=r AND peer_id=child.peer_id;
 IF cfg.account_digest IS DISTINCT FROM public.connector_digest(i->'PrincipalDigest') OR i->>'Name' IS DISTINCT FROM 'connector_'||(c->>'Usage')||'_certificate' OR permit_value->'Configuration' IS DISTINCT FROM c->'Current'->'Source'->'Observation' OR permit_value->'CurrentPeer' IS DISTINCT FROM c->'Current'->'Peer' OR permit_value->'ProcessProof' IS DISTINCT FROM (CASE WHEN c->'Current'->'ProcessProof'='null'::jsonb THEN NULL ELSE c->'Current'->'ProcessProof' END) OR (i->>'RequestUntil')::timestamptz>(c->'Current'->>'Until')::timestamptz THEN RAISE EXCEPTION 'connector credential intent mismatch' USING ERRCODE='23514';END IF;
 IF c->>'Usage'='client' THEN
  UPDATE public.connector_identity_process SET client_epoch=wanted_epoch,client_attempts=wanted_ordinal WHERE id=child.id;
 ELSE UPDATE public.connector_identity_process SET server_epoch=wanted_epoch,server_attempts=wanted_ordinal WHERE id=child.id;END IF;
 INSERT INTO public.operation_audit(id,root_id,lane,issuer_epoch,principal_digest,intent,request_until,write_until,retain_until)
 VALUES(operation,r,'identity',cfg.issuer_epoch,public.connector_digest(i->'PrincipalDigest'),i,(i->>'RequestUntil')::timestamptz,(i->>'WriteUntil')::timestamptz,(i->>'RetainUntil')::timestamptz);
 INSERT INTO public.connector_credential_attempt(id,root_id,peer_id,process_id,usage,epoch,ordinal,public_key,source_uid,source_generation,source_digest,permit,checked_at,sign_before,certificate_not_after)
 VALUES(operation,r,child.peer_id,child.id,c->>'Usage',wanted_epoch,wanted_ordinal,public.connector_digest(c->'PublicKeyDigest'),cfg.source_uid,cfg.source_generation,cfg.source_digest,permit_value,(permit_value->>'CheckedAt')::timestamptz,(permit_value->>'SignBefore')::timestamptz,(permit_value->>'CertificateNotAfter')::timestamptz);
 RETURN public.read_connector_credential_attempt(r,operation,c);
END $$;
CREATE FUNCTION claim_connector_credential(r uuid,operation uuid,c jsonb,permit_value jsonb) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE child public.connector_identity_process; attempt public.connector_credential_attempt;
BEGIN
 child:=public.lock_connector_credential_candidate(r,c);
 SELECT * INTO STRICT attempt FROM public.connector_credential_attempt WHERE root_id=r AND id=operation AND process_id=child.id FOR UPDATE;
 IF attempt.permit IS DISTINCT FROM permit_value OR clock_timestamp()>=(c->'Current'->>'Until')::timestamptz OR clock_timestamp()>=attempt.sign_before THEN RAISE EXCEPTION 'connector signing claim unavailable' USING ERRCODE='23514';END IF;
 IF attempt.provider_started THEN RETURN false;END IF;
 UPDATE public.connector_credential_attempt SET provider_started=true WHERE id=operation AND root_id=r;
 RETURN true;
END $$;
CREATE FUNCTION store_connector_credential(r uuid,operation uuid,permit_value jsonb,issued_value jsonb,outcome_value jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE attempt public.connector_credential_attempt; event public.operation_audit; trust public.fleet_current_trust;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'journal') THEN RAISE EXCEPTION 'connector result writer unavailable' USING ERRCODE='23514';END IF;
 SELECT t.* INTO STRICT trust FROM public.fleet_current_trust t JOIN public.connector_identity_root x ON x.installation_id=t.installation_id WHERE x.root_id=r FOR SHARE OF t;
 PERFORM 1 FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT attempt FROM public.connector_credential_attempt WHERE root_id=r AND id=operation FOR UPDATE;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE root_id=r AND id=operation FOR UPDATE;
 IF trust.recovery_blocked OR trust.suspended OR clock_timestamp()>=trust.fresh_until OR trust.issuer_epoch<>event.issuer_epoch OR attempt.permit IS DISTINCT FROM permit_value OR NOT attempt.provider_started OR event.intent_receipt IS NULL OR outcome_value->'Intent' IS DISTINCT FROM event.intent OR outcome_value->>'Status' IS DISTINCT FROM 'success' OR outcome_value->>'Effect' IS DISTINCT FROM 'accepted' OR clock_timestamp()>=attempt.sign_before THEN RAISE EXCEPTION 'connector result storage unavailable' USING ERRCODE='23514';END IF;
 IF attempt.issued IS NOT NULL THEN IF attempt.issued IS DISTINCT FROM issued_value OR event.outcome IS DISTINCT FROM outcome_value THEN RAISE EXCEPTION 'immutable connector provider result' USING ERRCODE='23514';END IF;RETURN;END IF;
 UPDATE public.connector_credential_attempt SET issued=issued_value,certificate_digest=public.connector_digest(issued_value->'Certificate'->'Digest'),certificate_not_before=(issued_value->'Certificate'->>'NotBefore')::timestamptz WHERE id=operation AND root_id=r;
 UPDATE public.operation_audit SET outcome=outcome_value WHERE id=operation AND root_id=r;
END $$;
CREATE FUNCTION activate_connector_credential(r uuid,operation uuid,c jsonb,permit_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE child public.connector_identity_process; attempt public.connector_credential_attempt; cfg public.connector_identity_profile; event public.operation_audit; n timestamptz;
BEGIN
 child:=public.lock_connector_credential_candidate(r,c);
 SELECT * INTO STRICT attempt FROM public.connector_credential_attempt WHERE root_id=r AND id=operation AND process_id=child.id FOR UPDATE;
 IF attempt.permit IS DISTINCT FROM permit_value OR attempt.issued IS NULL OR clock_timestamp()>=(c->'Current'->>'Until')::timestamptz THEN RAISE EXCEPTION 'connector activation result unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE id=operation AND root_id=r AND lane='identity';
 IF event.intent_receipt IS NULL OR event.outcome_receipt IS NULL OR event.outcome->>'Status' IS DISTINCT FROM 'success' OR event.outcome->'Credential'->'CertificateDigest' IS DISTINCT FROM attempt.issued->'Certificate'->'Digest' OR (event.outcome->'Credential'->>'NotAfter')::timestamptz IS DISTINCT FROM attempt.certificate_not_after OR attempt.detached_at IS NOT NULL OR clock_timestamp()>=attempt.certificate_not_after THEN RAISE EXCEPTION 'connector original activation audit unavailable' USING ERRCODE='23514';END IF;
 -- Reconcile an acknowledged result without rolling current leaf references
 -- back after a later renewal. Current source/process/recovery was checked above.
 IF attempt.activated_at IS NOT NULL THEN RETURN attempt.issued;END IF;
 UPDATE public.connector_credential_attempt SET activated_at=clock_timestamp() WHERE id=operation AND root_id=r;
 IF attempt.usage='client' AND child.client_current_id IS DISTINCT FROM operation THEN
  UPDATE public.connector_identity_process SET client_previous_id=client_current_id,client_current_id=operation WHERE id=child.id;
 ELSIF attempt.usage='server' AND child.server_current_id IS DISTINCT FROM operation THEN
  UPDATE public.connector_identity_process SET server_previous_id=server_current_id,server_current_id=operation WHERE id=child.id;
 END IF;
 SELECT updated.* INTO STRICT child FROM public.connector_identity_process updated WHERE updated.id=child.id;
 IF NOT child.serving AND child.client_current_id IS NOT NULL AND child.server_current_id IS NOT NULL THEN
  -- Same-Pod epoch replacement has one pending slot and retires the previous
  -- serving epoch only when both new leaves have independently audited results.
  UPDATE public.connector_identity_process SET serving=false,retired_at=clock_timestamp() WHERE root_id=r AND peer_id=child.peer_id AND pod_uid=child.pod_uid AND serving AND id<>child.id;
  UPDATE public.connector_identity_process SET serving=true WHERE id=child.id;
 END IF;
 UPDATE public.connector_identity_profile SET candidate_id=operation,accepted_id=operation WHERE root_id=r AND peer_id=child.peer_id;
 IF clock_timestamp()>=(c->'Current'->>'Until')::timestamptz OR clock_timestamp()>=attempt.certificate_not_after THEN RAISE EXCEPTION 'connector activation expired' USING ERRCODE='23514';END IF;
 RETURN attempt.issued;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION lock_connector_credential_candidate(uuid,jsonb),read_connector_credential_process(uuid,jsonb),read_connector_credential_attempt(uuid,uuid,jsonb),admit_connector_credential(uuid,jsonb,jsonb,jsonb),claim_connector_credential(uuid,uuid,jsonb,jsonb),store_connector_credential(uuid,uuid,jsonb,jsonb,jsonb),activate_connector_credential(uuid,uuid,jsonb,jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION connector_audit_current(r uuid,operation uuid) RETURNS public.operation_audit LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE event public.operation_audit; trust public.fleet_current_trust; root public.connector_identity_root; n timestamptz;
BEGIN
 IF NOT(public.connector_identity_role_ok(r,'journal') OR public.connector_identity_role_ok(r,'acknowledgement')) THEN RAISE EXCEPTION 'connector audit role unavailable' USING ERRCODE='23514';END IF;
 SELECT t.* INTO STRICT trust FROM public.fleet_current_trust t JOIN public.connector_identity_root x ON x.installation_id=t.installation_id WHERE x.root_id=r FOR SHARE OF t;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE root_id=r AND id=operation AND lane='identity' FOR UPDATE;
 n:=clock_timestamp();
 IF trust.recovery_blocked OR trust.suspended OR n>=trust.fresh_until OR trust.observed_at>n OR trust.issuer_epoch<>root.issuer_epoch OR event.issuer_epoch<>trust.issuer_epoch OR n>=event.write_until THEN RAISE EXCEPTION 'connector audit current interval unavailable' USING ERRCODE='23514';END IF;
 RETURN event;
END $$;
CREATE FUNCTION connector_audit_snapshot(event public.operation_audit) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object('Intent',event.intent,'IntentStarted',event.intent_started,'OutcomeStarted',event.outcome_started,'IntentReceipt',event.intent_receipt,'Outcome',event.outcome,'OutcomeReceipt',event.outcome_receipt)
$$;
CREATE FUNCTION connector_audit_journal(r uuid,i jsonb,verb text,o jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE event public.operation_audit; fresh boolean:=false; operation uuid:=(i->>'ID')::uuid; n timestamptz;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'journal') OR verb NOT IN('reserve','claim-intent','claim-outcome','freeze-outcome') THEN RAISE EXCEPTION 'connector audit writer operation unavailable' USING ERRCODE='23514';END IF;
 event:=public.connector_audit_current(r,operation);n:=clock_timestamp();
 IF event.intent IS DISTINCT FROM i THEN RAISE EXCEPTION 'immutable connector audit identity' USING ERRCODE='23514';END IF;
 IF verb IN('reserve','claim-intent') AND n>=event.request_until THEN RAISE EXCEPTION 'connector audit initial interval expired' USING ERRCODE='23514';END IF;
 IF verb='claim-intent' AND NOT event.intent_started THEN UPDATE public.operation_audit SET intent_started=true WHERE id=operation AND root_id=r RETURNING * INTO event;fresh:=true;
 ELSIF verb='claim-outcome' AND NOT event.outcome_started THEN
  IF event.intent_receipt IS NULL OR event.outcome IS NULL THEN RAISE EXCEPTION 'connector audit outcome not prepared' USING ERRCODE='23514';END IF;
  UPDATE public.operation_audit SET outcome_started=true WHERE id=operation AND root_id=r RETURNING * INTO event;fresh:=true;
 ELSIF verb='freeze-outcome' THEN
  -- The credential/process transaction already froze the exact business result.
  -- Audit cannot invent a successful signature or process admission.
  IF event.outcome IS NULL OR event.outcome IS DISTINCT FROM o OR event.intent_receipt IS NULL THEN RAISE EXCEPTION 'connector business result not frozen' USING ERRCODE='23514';END IF;
 END IF;
 IF clock_timestamp()>=event.write_until OR verb IN('reserve','claim-intent') AND clock_timestamp()>=event.request_until THEN RAISE EXCEPTION 'connector audit writer interval expired' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Snapshot',public.connector_audit_snapshot(event),'Fresh',fresh);
END $$;
CREATE FUNCTION connector_audit_acknowledge(r uuid,i jsonb,phase text,completion jsonb,receipt jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE event public.operation_audit; lifecycle public.operation_audit_lifecycle; operation uuid:=(i->>'ID')::uuid; existing jsonb; started boolean;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'acknowledgement') OR phase NOT IN('intent','outcome') THEN RAISE EXCEPTION 'connector audit acknowledgement unavailable' USING ERRCODE='23514';END IF;
 event:=public.connector_audit_current(r,operation);
 SELECT * INTO STRICT lifecycle FROM public.operation_audit_lifecycle WHERE root_id=r AND operation_id=operation FOR UPDATE;
 IF event.intent IS DISTINCT FROM i THEN RAISE EXCEPTION 'connector audit acknowledgement mismatch' USING ERRCODE='23514';END IF;
 IF phase='intent' THEN existing:=lifecycle.intent_completion;started:=event.intent_started;ELSE existing:=lifecycle.outcome_completion;started:=event.outcome_started;END IF;
 IF NOT started THEN RAISE EXCEPTION 'connector audit writer not admitted' USING ERRCODE='23514';END IF;
 IF completion IS NOT NULL THEN
  IF existing IS NOT NULL AND existing IS DISTINCT FROM completion THEN RAISE EXCEPTION 'immutable joined connector audit completion' USING ERRCODE='23514';END IF;
  IF existing IS NULL THEN
   IF phase='intent' THEN UPDATE public.operation_audit_lifecycle SET intent_completion=completion WHERE root_id=r AND operation_id=operation;
   ELSE UPDATE public.operation_audit_lifecycle SET outcome_completion=completion WHERE root_id=r AND operation_id=operation;END IF;
   existing:=completion;
  END IF;
 END IF;
 IF receipt IS NOT NULL THEN
  IF existing IS NULL OR existing->'Receipt' IS DISTINCT FROM receipt THEN RAISE EXCEPTION 'connector receipt has no positive joined completion' USING ERRCODE='23514';END IF;
  IF phase='intent' THEN
   IF event.intent_receipt IS NOT NULL AND event.intent_receipt IS DISTINCT FROM receipt THEN RAISE EXCEPTION 'immutable connector intent receipt' USING ERRCODE='23514';END IF;
   IF event.intent_receipt IS NULL THEN UPDATE public.operation_audit SET intent_receipt=receipt WHERE root_id=r AND id=operation;END IF;
  ELSE
   IF event.outcome_receipt IS NOT NULL AND event.outcome_receipt IS DISTINCT FROM receipt THEN RAISE EXCEPTION 'immutable connector outcome receipt' USING ERRCODE='23514';END IF;
   IF event.outcome_receipt IS NULL THEN UPDATE public.operation_audit SET outcome_receipt=receipt WHERE root_id=r AND id=operation;END IF;
  END IF;
 END IF;
 IF clock_timestamp()>=event.write_until THEN RAISE EXCEPTION 'connector acknowledgement expired' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Snapshot',public.connector_audit_snapshot(event),'Completion',existing);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION connector_audit_current(uuid,uuid),connector_audit_snapshot(public.operation_audit),connector_audit_journal(uuid,jsonb,text,jsonb),connector_audit_acknowledge(uuid,jsonb,text,jsonb,jsonb) FROM PUBLIC;

-- Fixed invoker-filtered lifecycle projections. The owner has base-table rights;
-- the actual session role has view rights only. These do not alter complete
-- historical installation/restore scans, which still read the original tables.
CREATE VIEW connector_operation_pool WITH (security_barrier=true) AS
SELECT root_id, lane, account_version, revision, paused, valid_until, account_limit, records_per_account, accounts, retained_seconds, history_profile, history_backing_until, proof_window_missed FROM public.operation_audit_pool
WHERE lane='identity' AND current_user=session_user AND (
 public.connector_identity_role_ok(root_id,'cleanup') OR
 public.connector_identity_role_ok(root_id,'verifier') OR
 public.connector_identity_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;
REVOKE ALL ON connector_operation_pool FROM PUBLIC;
CREATE VIEW connector_operation_account WITH (security_barrier=true) AS
SELECT root_id, lane, principal_digest, charged FROM public.operation_audit_account
WHERE lane='identity' AND current_user=session_user AND (
 public.connector_identity_role_ok(root_id,'cleanup') OR
 public.connector_identity_role_ok(root_id,'verifier') OR
 public.connector_identity_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;
REVOKE ALL ON connector_operation_account FROM PUBLIC;
CREATE VIEW connector_operation_audit WITH (security_barrier=true) AS
SELECT id, root_id, lane, issuer_epoch, principal_digest, intent, request_until, write_until, retain_until, intent_started, intent_receipt, outcome, outcome_started, outcome_receipt FROM public.operation_audit
WHERE lane='identity' AND current_user=session_user AND (
 public.connector_identity_role_ok(root_id,'cleanup') OR
 public.connector_identity_role_ok(root_id,'verifier') OR
 public.connector_identity_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;
REVOKE ALL ON connector_operation_audit FROM PUBLIC;
CREATE VIEW connector_operation_lifecycle WITH (security_barrier=true) AS
SELECT operation_id, root_id, lane, principal_digest, installation_id, issuer_epoch, postmaster_at, database_oid, binding, original_purge_at, certificate_purge_at, live_retire_by, intent_completion, outcome_completion, lease_fence, lease, retirement, certificate_started, certificate_completion, certificate_receipt, certificate_acknowledged_at, terminal_purge, terminal_acknowledged_at, finalization_xid, overdue_selected_at, overdue_purge, certificate_verify_attempts FROM public.operation_audit_lifecycle
WHERE lane='identity' AND current_user=session_user AND (
 public.connector_identity_role_ok(root_id,'cleanup') OR
 public.connector_identity_role_ok(root_id,'verifier') OR
 public.connector_identity_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;
REVOKE ALL ON connector_operation_lifecycle FROM PUBLIC;
CREATE VIEW connector_operation_history WITH (security_barrier=true) AS
SELECT root_id,lane,principal_digest,release_at,delete_by,hard_delete_by,eligible_at,installation_id,issuer_epoch,postmaster_at,database_oid,horizon_seconds,history_policy,records,overdue,drain_xid FROM public.operation_audit_history
WHERE lane='identity' AND current_user=session_user AND (
 public.connector_identity_role_ok(root_id,'cleanup') OR
 public.connector_identity_role_ok(root_id,'verifier') OR
 public.connector_identity_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;
REVOKE ALL ON connector_operation_history FROM PUBLIC;

-- Separate transport read role: EXECUTE only. No list, source acceptance,
-- signing, audit, mutation, human metadata or certificate body is exposed.
-- +goose StatementBegin
CREATE FUNCTION read_connector_activated_leaf(r uuid,peer uuid,usage_value text,digest_value bytea,source_value jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE started timestamptz:=clock_timestamp(); n timestamptz; until_at timestamptz; cfg public.connector_identity_profile; backing public.connector_identity_root; trust public.fleet_current_trust; child public.connector_identity_process; leaf public.connector_credential_attempt; event public.operation_audit; matched record;
BEGIN
 IF usage_value NOT IN('client','server') OR octet_length(digest_value)<>32 OR octet_length(source_value::text)>196608 THEN RAISE EXCEPTION 'connector leaf unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT backing FROM public.connector_identity_root WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=backing.installation_id;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=r AND peer_id=peer;
 SELECT a AS leaf,p AS child INTO STRICT matched FROM public.connector_credential_attempt a JOIN public.connector_identity_process p ON p.id=a.process_id AND p.root_id=a.root_id
  WHERE a.root_id=r AND a.peer_id=peer AND a.usage=usage_value AND a.certificate_digest=digest_value
    AND ((usage_value='client' AND a.id IN(p.client_current_id,p.client_previous_id)) OR (usage_value='server' AND a.id IN(p.server_current_id,p.server_previous_id)));
 leaf:=matched.leaf;child:=matched.child;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE id=leaf.id AND root_id=r AND lane='identity';
 n:=clock_timestamp();until_at:=least(started+interval '5 seconds',trust.fresh_until,backing.valid_until,(source_value->>'FreshUntil')::timestamptz,child.run_until,leaf.certificate_not_after);
 IF NOT COALESCE(NOT trust.recovery_blocked AND NOT trust.suspended AND trust.observed_at<=n AND trust.issuer_epoch=backing.issuer_epoch AND backing.postmaster_at=pg_postmaster_start_time() AND backing.database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AND
  backing.source_transitions<backing.source_transition_limit AND NOT cfg.fenced AND NOT cfg.blocked AND NOT cfg.suspended AND cfg.accepted_id IS NOT NULL AND cfg.configuration=source_value->'Profile' AND public.connector_backing_observed(backing,cfg,source_value) AND (source_value->>'ObservedAt')::timestamptz<=n AND (source_value->>'FreshUntil')::timestamptz<=(source_value->>'ObservedAt')::timestamptz+interval '5 seconds' AND
  child.serving AND child.retired_at IS NULL AND child.accepted_at IS NOT NULL AND ROW(child.source_uid,child.source_generation,child.source_digest)=ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest) AND
  ((usage_value='client' AND leaf.id IN(child.client_current_id,child.client_previous_id)) OR (usage_value='server' AND leaf.id IN(child.server_current_id,child.server_previous_id))) AND leaf.activated_at IS NOT NULL AND leaf.detached_at IS NULL AND n>=leaf.certificate_not_before AND n<until_at AND ROW(leaf.source_uid,leaf.source_generation,leaf.source_digest)=ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest) AND
  event.intent_receipt IS NOT NULL AND event.outcome_receipt IS NOT NULL AND event.outcome->>'Status'='success',false) THEN RAISE EXCEPTION 'connector activated leaf unavailable' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Certificate',leaf.issued->'Certificate','Process',child.process->'Attested','Revision',cfg.configuration->'Revision','ObservedAt',started,'FreshUntil',until_at);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_connector_activated_leaf(uuid,uuid,text,bytea,jsonb) FROM PUBLIC;


-- Detach at most sixteen expired process children. Possible leaves retain
-- their full original expiry plus overlap; no 404/lease expiry refunds spend.
-- The audit pairs remain charged until their separate verified lifecycle ends.
-- +goose StatementBegin
CREATE FUNCTION detach_connector_identity(r uuid,peer uuid) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE started timestamptz:=clock_timestamp(); n timestamptz; until_at timestamptz; trust public.fleet_current_trust; backing public.connector_identity_root; cfg public.connector_identity_profile; child public.connector_identity_process; removed bigint:=0;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'cleanup') THEN RAISE EXCEPTION 'connector cleanup role unavailable' USING ERRCODE='23514';END IF;
 SELECT t.* INTO STRICT trust FROM public.fleet_current_trust t JOIN public.connector_identity_root x ON x.installation_id=t.installation_id WHERE x.root_id=r FOR SHARE OF t;
 SELECT * INTO STRICT backing FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=r AND peer_id=peer FOR UPDATE;
 n:=clock_timestamp();until_at:=least(started+interval '5 seconds',trust.fresh_until);
 IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=until_at OR trust.issuer_epoch<>backing.issuer_epoch THEN RAISE EXCEPTION 'connector cleanup recovery unavailable' USING ERRCODE='23514';END IF;
 FOR child IN SELECT p.* FROM public.connector_identity_process p WHERE p.root_id=r AND p.peer_id=peer AND p.run_until+interval '1 minute'<=n ORDER BY p.run_until,p.id LIMIT 16 FOR UPDATE LOOP
  IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'connector cleanup deadline expired' USING ERRCODE='23514';END IF;
  UPDATE public.connector_identity_process SET serving=false,retired_at=COALESCE(retired_at,clock_timestamp()),client_current_id=NULL,client_previous_id=NULL,server_current_id=NULL,server_previous_id=NULL WHERE id=child.id;
  IF cfg.candidate_id=child.id OR cfg.accepted_id=child.id OR EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.process_id=child.id AND a.id IN(cfg.candidate_id,cfg.accepted_id)) THEN
   UPDATE public.connector_identity_profile SET fenced=true,candidate_id=NULL,accepted_id=NULL WHERE root_id=r AND peer_id=peer;
  END IF;
  UPDATE public.connector_credential_attempt SET detached_at=COALESCE(detached_at,clock_timestamp()) WHERE process_id=child.id AND root_id=r;
  DELETE FROM public.connector_credential_attempt WHERE process_id=child.id AND root_id=r;
  DELETE FROM public.connector_identity_process WHERE id=child.id AND root_id=r;
  removed:=removed+1;
 END LOOP;
 IF clock_timestamp()>=until_at OR NOT public.connector_identity_role_ok(r,'cleanup') THEN RAISE EXCEPTION 'connector cleanup expired' USING ERRCODE='23514';END IF;
 RETURN removed;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION detach_connector_identity(uuid,uuid) FROM PUBLIC;

-- Only these purpose-fixed wrappers are granted to the private finalizer.
-- Generic retirement functions may read human state before mutation triggers;
-- private callers must not obtain even a state-dependent outcome from them.
-- +goose StatementBegin
CREATE FUNCTION finish_connector_operation_retirement(r uuid,i uuid,installation uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NOT public.connector_identity_role_ok(r,'finalizer') OR NOT EXISTS(SELECT 1 FROM public.connector_identity_root p WHERE p.root_id=r AND p.installation_id=installation) THEN RAISE EXCEPTION 'connector finalizer unavailable' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.operation_audit a WHERE a.root_id=r AND a.id=i AND a.lane='identity') THEN RETURN false;END IF;
 RETURN public.finish_operation_audit_retirement(r,i,installation);
END $$;
CREATE FUNCTION finish_connector_operation_history(r uuid,l text,p bytea,releases timestamptz,deletes timestamptz,installation uuid) RETURNS TABLE(records bigint,overdue boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF l IS DISTINCT FROM 'identity' OR NOT public.connector_identity_role_ok(r,'finalizer') OR NOT EXISTS(SELECT 1 FROM public.connector_identity_root x WHERE x.root_id=r AND x.installation_id=installation) THEN RAISE EXCEPTION 'connector history finalizer unavailable' USING ERRCODE='23514';END IF;
 RETURN QUERY SELECT h.records,h.overdue FROM public.finish_operation_audit_history(r,'identity',p,releases,deletes,installation) h;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION finish_connector_operation_retirement(uuid,uuid,uuid),finish_connector_operation_history(uuid,text,bytea,timestamptz,timestamptz,uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION lock_connector_backing_current(r uuid,c jsonb) RETURNS public.connector_identity_profile LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb:=c->'Proof'; source jsonb:=proof->'Configuration'; p jsonb:=source->'Profile'; cfg public.connector_identity_profile; root public.connector_identity_root; trust public.fleet_current_trust; n timestamptz;
BEGIN
 IF NOT(public.connector_identity_role_ok(r,'journal') OR public.connector_identity_role_ok(r,'source')) OR octet_length(c::text)>393216 THEN RAISE EXCEPTION 'connector process current authority unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(p->'Binding'->>'InstallationID')::uuid FOR SHARE;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=r AND peer_id=(proof->'Process'->'Binding'->>'PeerID')::uuid FOR UPDATE;
 n:=clock_timestamp();
 IF NOT COALESCE(NOT trust.recovery_blocked AND NOT trust.suspended AND trust.observed_at<=n AND n<trust.fresh_until AND trust.issuer_epoch=root.issuer_epoch AND n<root.valid_until AND
   NOT cfg.suspended AND NOT cfg.blocked AND NOT cfg.fenced AND cfg.accepted_id IS NOT NULL AND cfg.configuration=p AND public.connector_backing_observed(root,cfg,source) AND proof->'Process'->'Binding'=p->'Binding' AND (p->>'RootID')::uuid=r AND
   (c->>'ObservedAt')::timestamptz<=n AND (c->>'Until')::timestamptz>n AND (c->>'Until')::timestamptz<=(c->>'ObservedAt')::timestamptz+interval '5 seconds' AND
   (proof->>'ObservedAt')::timestamptz<=n AND (proof->>'FreshUntil')::timestamptz>n AND (proof->>'FreshUntil')::timestamptz<=(proof->>'ObservedAt')::timestamptz+interval '5 seconds' AND
   (source->>'ObservedAt')::timestamptz<=n AND (source->>'FreshUntil')::timestamptz>n AND (source->>'FreshUntil')::timestamptz<=(source->>'ObservedAt')::timestamptz+interval '5 seconds' AND
   (c->>'Until')::timestamptz<=(proof->>'FreshUntil')::timestamptz AND (c->>'Until')::timestamptz<=(source->>'FreshUntil')::timestamptz AND (c->>'Until')::timestamptz<=(c->'Recovery'->>'FreshUntil')::timestamptz AND
   (c->'Recovery'->>'InstallationID')::uuid=root.installation_id AND (c->'Recovery'->>'IssuerEpoch')::uuid=root.issuer_epoch AND (c->'Recovery'->>'ObservedAt')::timestamptz<=n AND (c->'Recovery'->>'FreshUntil')::timestamptz>n AND (c->'Recovery'->>'FreshUntil')::timestamptz<=(c->'Recovery'->>'ObservedAt')::timestamptz+interval '5 seconds' AND (c->'Recovery'->>'FreshUntil')::timestamptz<=trust.fresh_until AND c->'Recovery'->'Revision'->>'UID'=trust.source_uid AND (c->'Recovery'->'Revision'->>'Generation')::bigint=trust.source_generation AND public.connector_digest(c->'Recovery'->'Revision'->'Digest')=trust.source_digest AND
   jsonb_array_length(proof->'WorkloadDigest')=32 AND jsonb_array_length(proof->'ProtectionDigest')=32 AND public.connector_digest(proof->'ClientKeyDigest')<>public.connector_digest(proof->'ServerKeyDigest'),false) THEN RAISE EXCEPTION 'connector process proof unavailable' USING ERRCODE='23514';END IF;
 IF c->'Configuration'->'Source'->'Observation'->'Profile' IS DISTINCT FROM p OR c->'Configuration'->'Source'->'Observation'->'Backing' IS DISTINCT FROM source->'Backing' OR
   ((c->'Configuration'->'Backing') IS DISTINCT FROM root.backing AND (root.pending_id IS NULL OR (c->'Configuration'->'Backing') IS DISTINCT FROM root.pending_backing)) OR
   (c->>'Until')::timestamptz>(c->'Configuration'->'Source'->'Observation'->>'FreshUntil')::timestamptz OR
   (c->'Configuration'->'Source'->'Observation'->>'ObservedAt')::timestamptz>clock_timestamp() OR
   (c->'Configuration'->'Source'->'Observation'->>'FreshUntil')::timestamptz>(c->'Configuration'->'Source'->'Observation'->>'ObservedAt')::timestamptz+interval '5 seconds' OR clock_timestamp()>=(c->>'Until')::timestamptz THEN RAISE EXCEPTION 'connector complete backing observation unavailable' USING ERRCODE='23514';END IF;
 RETURN cfg;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION lock_connector_backing_current(uuid,jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_connector_backing_transition() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE root public.connector_identity_root; event public.operation_audit; n timestamptz; cfg public.connector_identity_profile;
BEGIN
 IF TG_RELID<>'public.connector_backing_transition'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector backing boundary' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN
  IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR clock_timestamp()<OLD.detach_after OR
   EXISTS(SELECT 1 FROM public.connector_identity_root r WHERE r.root_id=OLD.root_id AND OLD.id IN(r.pending_id,r.active_backing_id)) THEN RAISE EXCEPTION 'connector backing dependency remains charged' USING ERRCODE='23514';END IF;
  RETURN OLD;
 END IF;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=NEW.root_id AND peer_id=NEW.peer_id FOR UPDATE;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE id=NEW.id AND root_id=NEW.root_id AND lane='identity' FOR UPDATE;
 n:=clock_timestamp();
 IF TG_OP='INSERT' THEN
  IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') OR NEW.id IS DISTINCT FROM root.pending_id OR NEW.previous_backing IS DISTINCT FROM root.backing OR NEW.proposed->'Backing' IS DISTINCT FROM root.pending_backing OR
   NEW.proposed->'Source'->'Observation'->'Profile' IS DISTINCT FROM cfg.configuration OR public.connector_digest(NEW.proposed->'Source'->'Observation'->'Backing'->'SourceDigest')<>cfg.complete_digest OR
   event.intent->>'Name' IS DISTINCT FROM 'connector_backing_acceptance' OR event.intent->'Lifecycle'->'Policy' IS DISTINCT FROM root.policy OR
   NEW.authority_until<>(NEW.proposed->'Backing'->'Policy'->>'ValidUntil')::timestamptz OR NEW.detach_after>(event.intent->'Lifecycle'->>'OriginalPurgeAt')::timestamptz OR
   NEW.activated_at IS NOT NULL OR NEW.closed_at IS NOT NULL OR n>=root.valid_until OR n>=event.request_until OR NOT public.connector_backing_can_renew(NEW.previous_backing,NEW.proposed->'Backing') THEN RAISE EXCEPTION 'connector backing admission unavailable' USING ERRCODE='23514';END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['activated_at','closed_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['activated_at','closed_at']) OR OLD.closed_at IS NOT NULL OR OLD.activated_at IS NOT NULL OR NOT public.connector_identity_role_ok(NEW.root_id,'source') OR NEW.id IS DISTINCT FROM root.pending_id THEN RAISE EXCEPTION 'immutable connector backing candidate' USING ERRCODE='23514';END IF;
  IF NEW.activated_at IS NOT NULL THEN
   IF NEW.activated_at>n OR NEW.closed_at IS NOT NULL OR n>=root.valid_until OR n>=NEW.authority_until OR root.backing IS DISTINCT FROM NEW.previous_backing OR root.pending_backing IS DISTINCT FROM NEW.proposed->'Backing' OR
    event.intent_receipt IS NULL OR event.outcome_receipt IS NULL OR event.outcome->>'Status' IS DISTINCT FROM 'success' OR event.outcome->>'Effect' IS DISTINCT FROM 'accepted' OR
    NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle l WHERE l.operation_id=NEW.id AND l.root_id=NEW.root_id AND l.intent_completion->'Receipt'=event.intent_receipt AND l.outcome_completion->'Receipt'=event.outcome_receipt) THEN RAISE EXCEPTION 'connector backing independent acknowledgements unavailable' USING ERRCODE='23514';END IF;
  ELSIF NEW.closed_at IS NULL OR NEW.closed_at>n THEN RAISE EXCEPTION 'connector backing closure unavailable' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION read_connector_backing_candidate(r uuid,c jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; root public.connector_identity_root;
BEGIN
 cfg:=public.lock_connector_backing_current(r,c);
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 IF root.pending_id IS NULL OR root.pending_backing IS DISTINCT FROM c->'Configuration'->'Backing' OR clock_timestamp()>=(c->>'Until')::timestamptz THEN RAISE EXCEPTION 'connector backing candidate unavailable' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('ID',root.pending_id,'Before',root.backing);
END $$;
CREATE FUNCTION read_connector_backing_admission(r uuid,operation uuid,c jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; child public.connector_backing_transition; event public.operation_audit;
BEGIN
 cfg:=public.lock_connector_backing_current(r,c);
 SELECT * INTO child FROM public.connector_backing_transition WHERE id=operation AND root_id=r AND peer_id=cfg.peer_id FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE id=operation AND root_id=r AND lane='identity';
 IF event.intent->'Process'->'Process' IS DISTINCT FROM c->'Proof'->'Process' OR event.intent->'Process'->'ClientKeyDigest' IS DISTINCT FROM c->'Proof'->'ClientKeyDigest' OR event.intent->'Process'->'ServerKeyDigest' IS DISTINCT FROM c->'Proof'->'ServerKeyDigest' OR
  child.proposed->'Backing' IS DISTINCT FROM c->'Configuration'->'Backing' OR child.proposed->'Source'->'Observation'->'Profile' IS DISTINCT FROM cfg.configuration OR public.connector_digest(child.proposed->'Source'->'Observation'->'Backing'->'SourceDigest')<>cfg.complete_digest OR
  clock_timestamp()>=(c->>'Until')::timestamptz OR clock_timestamp()>=child.authority_until THEN RAISE EXCEPTION 'connector backing replay differs from current candidate' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Before',child.previous_backing,'Proposed',child.proposed,'Intent',event.intent,'Outcome',event.outcome,'Activated',child.activated_at IS NOT NULL,'Closed',child.closed_at IS NOT NULL);
END $$;
CREATE FUNCTION admit_connector_backing(r uuid,c jsonb,i jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; root public.connector_identity_root; existing jsonb; operation uuid:=(i->>'ID')::uuid; proof jsonb:=c->'Proof'; n timestamptz;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'journal') THEN RAISE EXCEPTION 'connector backing journal unavailable' USING ERRCODE='23514';END IF;
 cfg:=public.lock_connector_backing_current(r,c);
 existing:=public.read_connector_backing_admission(r,operation,c);IF existing IS NOT NULL THEN RETURN existing;END IF;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 n:=clock_timestamp();
 IF operation IS DISTINCT FROM root.pending_id OR root.pending_backing IS DISTINCT FROM c->'Configuration'->'Backing' OR i->>'Name' IS DISTINCT FROM 'connector_backing_acceptance' OR i->'Lifecycle'->'Policy' IS DISTINCT FROM root.policy OR
  i->'Process'->'Process' IS DISTINCT FROM proof->'Process' OR i->'Process'->'Deployment' IS DISTINCT FROM cfg.configuration->'Deployment' OR i->'Process'->'ClientKeyDigest' IS DISTINCT FROM proof->'ClientKeyDigest' OR i->'Process'->'ServerKeyDigest' IS DISTINCT FROM proof->'ServerKeyDigest' OR
  (i->>'CreatedAt')::timestamptz<>(c->>'ObservedAt')::timestamptz OR (i->>'RequestUntil')::timestamptz>least((c->>'Until')::timestamptz,root.valid_until) OR cfg.account_digest IS NULL OR cfg.account_digest<>public.connector_digest(i->'PrincipalDigest') OR n>=root.valid_until THEN RAISE EXCEPTION 'connector backing intent differs from current candidate' USING ERRCODE='23514';END IF;
 INSERT INTO public.operation_audit(id,root_id,lane,issuer_epoch,principal_digest,intent,request_until,write_until,retain_until)
 VALUES(operation,r,'identity',cfg.issuer_epoch,cfg.account_digest,i,(i->>'RequestUntil')::timestamptz,(i->>'WriteUntil')::timestamptz,(i->>'RetainUntil')::timestamptz);
 INSERT INTO public.connector_backing_transition(id,root_id,peer_id,previous_backing,proposed,authority_until,detach_after)
 VALUES(operation,r,cfg.peer_id,root.backing,c->'Configuration',(root.pending_backing->'Policy'->>'ValidUntil')::timestamptz,(root.pending_backing->'Policy'->>'ValidUntil')::timestamptz+interval '1 minute');
 IF clock_timestamp()>=(c->>'Until')::timestamptz OR clock_timestamp()>=root.valid_until THEN RAISE EXCEPTION 'connector backing admission expired after locks' USING ERRCODE='23514';END IF;
 RETURN public.read_connector_backing_admission(r,operation,c);
END $$;
CREATE FUNCTION store_connector_backing_outcome(r uuid,operation uuid,i jsonb,o jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE event public.operation_audit; child public.connector_backing_transition;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'journal') THEN RAISE EXCEPTION 'connector backing writer unavailable' USING ERRCODE='23514';END IF;
 event:=public.connector_audit_current(r,operation);
 SELECT * INTO STRICT child FROM public.connector_backing_transition WHERE id=operation AND root_id=r FOR UPDATE;
 IF child.closed_at IS NOT NULL OR event.intent IS DISTINCT FROM i OR o->'Intent' IS DISTINCT FROM i OR o->>'Status' IS DISTINCT FROM 'success' OR o->>'Effect' IS DISTINCT FROM 'accepted' OR o ? 'Credential' OR event.intent_receipt IS NULL OR clock_timestamp()>=event.request_until THEN RAISE EXCEPTION 'connector backing outcome unavailable' USING ERRCODE='23514';END IF;
 IF event.outcome IS NOT NULL THEN IF event.outcome IS DISTINCT FROM o THEN RAISE EXCEPTION 'immutable connector backing outcome' USING ERRCODE='23514';END IF;RETURN;END IF;
 UPDATE public.operation_audit SET outcome=o WHERE id=operation AND root_id=r;
 IF clock_timestamp()>=event.request_until THEN RAISE EXCEPTION 'connector backing outcome expired' USING ERRCODE='23514';END IF;
END $$;
CREATE FUNCTION promote_connector_backing(r uuid,operation uuid,c jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; root public.connector_identity_root; child public.connector_backing_transition; pool public.operation_audit_pool; n timestamptz; result jsonb;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'source') THEN RAISE EXCEPTION 'connector backing source unavailable' USING ERRCODE='23514';END IF;
 cfg:=public.lock_connector_backing_current(r,c);
 result:=public.read_connector_backing_admission(r,operation,c);IF result IS NULL THEN RAISE EXCEPTION 'connector backing acceptance missing' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=r AND lane='identity' FOR UPDATE;
 SELECT * INTO STRICT child FROM public.connector_backing_transition WHERE id=operation AND root_id=r FOR UPDATE;
 n:=clock_timestamp();
 IF child.closed_at IS NOT NULL OR n>=least((c->>'Until')::timestamptz,root.valid_until,child.authority_until) THEN RAISE EXCEPTION 'connector backing promotion expired' USING ERRCODE='23514';END IF;
 IF child.activated_at IS NOT NULL THEN
  IF root.active_backing_id IS DISTINCT FROM operation OR root.backing IS DISTINCT FROM child.proposed->'Backing' THEN RAISE EXCEPTION 'connector backing superseded' USING ERRCODE='23514';END IF;RETURN root.backing;
 END IF;
 IF root.pending_id IS DISTINCT FROM operation OR root.backing IS DISTINCT FROM child.previous_backing OR pool.revision<>(root.policy->>'BackingRevision')::bigint OR pool.valid_until<>root.valid_until OR pool.paused THEN RAISE EXCEPTION 'connector backing old revision changed' USING ERRCODE='23514';END IF;
 -- Child trigger checks both independently acknowledged joined writers. Updating
 -- the root/pool follows in the same transaction and cannot change old bindings.
 UPDATE public.connector_backing_transition SET activated_at=n WHERE id=operation AND root_id=r;
 UPDATE public.connector_identity_root SET backing=child.proposed->'Backing',backing_digest=pending_digest,policy=child.proposed->'Backing'->'Policy',valid_until=child.authority_until,active_backing_id=operation,pending_id=NULL,pending_backing=NULL,pending_digest=NULL,pending_at=NULL WHERE root_id=r;
 UPDATE public.operation_audit_pool SET revision=revision+1,valid_until=child.authority_until WHERE root_id=r AND lane='identity';
 IF clock_timestamp()>=(c->>'Until')::timestamptz OR clock_timestamp()>=root.valid_until THEN RAISE EXCEPTION 'connector backing promotion expired after writes' USING ERRCODE='23514';END IF;
 RETURN child.proposed->'Backing';
END $$;
-- +goose StatementEnd
CREATE TRIGGER connector_backing_transition_guard BEFORE INSERT OR UPDATE OR DELETE ON connector_backing_transition FOR EACH ROW EXECUTE FUNCTION guard_connector_backing_transition();
REVOKE ALL ON FUNCTION guard_connector_backing_transition(),read_connector_backing_candidate(uuid,jsonb),read_connector_backing_admission(uuid,uuid,jsonb),admit_connector_backing(uuid,jsonb,jsonb),store_connector_backing_outcome(uuid,uuid,jsonb,jsonb),promote_connector_backing(uuid,uuid,jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION read_connector_process_backing(r uuid,c jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; root public.connector_identity_root;
BEGIN
 cfg:=public.lock_connector_process_current(r,c,true);
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 IF clock_timestamp()>=(c->>'Until')::timestamptz OR clock_timestamp()>=root.valid_until THEN RAISE EXCEPTION 'connector current backing expired' USING ERRCODE='23514';END IF;
 RETURN root.backing;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_connector_process_backing(uuid,jsonb) FROM PUBLIC;

-- A restrictive close never needs a live connector, signature or a new actor.
-- Root serialization fences delayed admission before the singleton is cleared.
-- Closed admitted rows remain charged through their original pair/history.
-- +goose StatementBegin
CREATE FUNCTION close_connector_backing_candidate(r uuid,operation uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE root public.connector_identity_root; trust public.fleet_current_trust; started timestamptz:=clock_timestamp(); until_at timestamptz; n timestamptz;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'source') THEN RAISE EXCEPTION 'connector candidate close role unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(SELECT installation_id FROM public.connector_identity_root WHERE root_id=r) FOR SHARE;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 until_at:=least(started+interval '5 seconds',trust.fresh_until);n:=clock_timestamp();
 IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=until_at OR trust.issuer_epoch<>root.issuer_epoch THEN RAISE EXCEPTION 'connector candidate close recovery unavailable' USING ERRCODE='23514';END IF;
 IF root.pending_id IS DISTINCT FROM operation THEN
  RETURN root.closed_candidate_id=operation OR EXISTS(SELECT 1 FROM public.connector_backing_transition b WHERE b.id=operation AND b.root_id=r AND b.closed_at IS NOT NULL);
 END IF;
 -- Same root lock is held by every admission; no row here is a positive SQL
 -- non-admission fact only within this irreversible closing transaction.
 UPDATE public.connector_backing_transition SET closed_at=n WHERE id=operation AND root_id=r AND activated_at IS NULL AND closed_at IS NULL;
 UPDATE public.connector_identity_root SET closed_candidate_id=pending_id,closed_candidate_digest=pending_digest,closed_candidate_revision=(pending_backing->'Policy'->>'BackingRevision')::bigint,closed_candidate_at=n,pending_id=NULL,pending_backing=NULL,pending_digest=NULL,pending_at=NULL WHERE root_id=r;
 IF clock_timestamp()>=until_at OR NOT public.connector_identity_role_ok(r,'source') THEN RAISE EXCEPTION 'connector candidate close expired' USING ERRCODE='23514';END IF;
 RETURN true;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION close_connector_backing_candidate(uuid,uuid) FROM PUBLIC;
