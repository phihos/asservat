-- +goose Up
-- Unreleased unlinked rows have no provable original funding/deletion bound.
-- Refuse them atomically; never infer a creator or adopt existing spend.
LOCK TABLE public.evidence_share IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.evidence_share) THEN
  RAISE EXCEPTION 'unsupported retained unlinked share history; this development layout cannot be upgraded in place' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
-- Recipient lookups only expose unrevoked rows. Do not add wide recipient
-- keys for a new revoked row version during the bounded revoke-all update.
DROP INDEX public.evidence_share_recipient;
CREATE INDEX evidence_share_recipient ON public.evidence_share USING gin(recipient_keys) WHERE revoked_at IS NULL;
-- +goose StatementBegin
DO $$ BEGIN
 EXECUTE 'COMMENT ON TABLE public.goose_db_version IS ''asservat:oldest-binary-schema=153''';
END $$;
-- +goose StatementEnd
ALTER TABLE public.evidence_share
 ADD COLUMN creating_operation_id uuid NOT NULL UNIQUE REFERENCES public.operation_audit(id) DEFERRABLE INITIALLY DEFERRED,
 ADD COLUMN retire_by timestamptz NOT NULL CHECK(isfinite(retire_by) AND expires_at<retire_by),
 ADD COLUMN last_operation_id uuid NOT NULL;
-- One fixed private effect marker belongs to the already paid operation.
-- It is retired with that lifecycle; it creates no journal or refillable quota.
ALTER TABLE public.operation_audit_lifecycle
 ADD COLUMN share_effect_target uuid,
 ADD COLUMN share_effect_xid xid8,
 ADD CONSTRAINT operation_share_effect_pair CHECK((share_effect_target IS NULL)=(share_effect_xid IS NULL));

-- +goose StatementBegin
CREATE FUNCTION begin_share_effect(r uuid,i uuid,action text,issuer text,subject text,client text,target uuid)
RETURNS TABLE(effect_available boolean,retire_by timestamptz,effect_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit; d public.operation_audit_lifecycle; t public.fleet_current_trust; started timestamptz:=clock_timestamp(); n timestamptz;
BEGIN
 IF action NOT IN ('create_share','revoke_share','transfer_share','stop_future_sharing') OR target IS NULL THEN
  RAISE EXCEPTION 'invalid share operation' USING ERRCODE='23514';
 END IF;
 -- The initial projection supplies immutable lock keys, never authority.
 SELECT * INTO STRICT d FROM public.operation_audit_lifecycle WHERE root_id=r AND operation_id=i;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=d.installation_id FOR SHARE;
 PERFORM 1 FROM public.operation_audit_pool WHERE root_id=r AND lane='normal' FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_account WHERE root_id=r AND lane='normal' AND principal_digest=d.principal_digest FOR UPDATE;
 SELECT * INTO STRICT a FROM public.operation_audit WHERE root_id=r AND id=i FOR UPDATE;
 SELECT * INTO STRICT d FROM public.operation_audit_lifecycle WHERE root_id=r AND operation_id=i FOR UPDATE;
 n:=clock_timestamp();
 IF d.binding->'Policy'->'History'->>'Layout' IS DISTINCT FROM 'operation-audit-history/v4' THEN
  RAISE EXCEPTION 'original operation backing is not qualified for share effects' USING ERRCODE='P1530';
 END IF;
 IF n>=started+interval '5 seconds' OR n>=t.fresh_until OR t.observed_at>n OR t.suspended OR t.recovery_blocked OR t.issuer_epoch<>d.issuer_epoch OR
  NOT public.incarnation_current(d.postmaster_at) OR (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())<>d.database_oid OR
  a.lane<>'normal' OR d.lane<>'normal' OR a.intent->>'Name' IS DISTINCT FROM action OR a.intent->>'InputFormat' IS DISTINCT FROM 'context-input/v1' OR
  a.intent#>>'{Actor,Issuer}' IS DISTINCT FROM issuer OR a.intent#>>'{Actor,Subject}' IS DISTINCT FROM subject OR a.intent#>>'{Actor,ClientID}' IS DISTINCT FROM client OR
  a.intent_receipt IS NULL OR d.intent_completion IS NULL OR d.intent_completion->'Receipt' IS DISTINCT FROM a.intent_receipt OR
  a.outcome_started OR a.outcome_receipt IS NOT NULL OR n>=a.request_until OR n>=d.original_purge_at OR
  d.lease IS NOT NULL OR d.retirement IS NOT NULL OR d.finalization_xid IS NOT NULL THEN
  RAISE EXCEPTION 'current paid share operation unavailable' USING ERRCODE='23514';
 END IF;
 effect_available:=d.share_effect_target IS NULL;
 IF effect_available THEN
  UPDATE public.operation_audit_lifecycle SET share_effect_target=target,share_effect_xid=pg_current_xact_id() WHERE operation_id=i;
 END IF;
 retire_by:=d.live_retire_by;
 -- Healthy and overdue retirement both start after the original purge bound.
 -- Effects must end before either path can remove their identifying child.
 effect_until:=d.original_purge_at;
 RETURN NEXT;
END $$;

CREATE OR REPLACE FUNCTION protect_evidence_share() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.operation_audit; d public.operation_audit_lifecycle; c public.context_capture; instruction jsonb; expected uuid; n timestamptz:=clock_timestamp();
BEGIN
 IF TG_OP='DELETE' THEN
  IF NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle l WHERE l.root_id=OLD.root_id AND l.operation_id=OLD.creating_operation_id
   AND l.finalization_xid=pg_current_xact_id() AND l.terminal_acknowledged_at IS NOT NULL AND clock_timestamp()<(l.lease->>'Until')::timestamptz)
   OR clock_timestamp()<OLD.expires_at THEN
   RAISE EXCEPTION 'share retirement requires original operation finalization' USING ERRCODE='23514';
  END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  -- Conflicts with the finalizer's original-operation FOR UPDATE. No capture,
  -- storage, permission or artifact advisory lock is acquired by retirement.
  SELECT * INTO STRICT a FROM public.operation_audit WHERE root_id=NEW.root_id AND id=NEW.creating_operation_id FOR KEY SHARE;
  SELECT * INTO STRICT d FROM public.operation_audit_lifecycle WHERE root_id=NEW.root_id AND operation_id=a.id;
  n:=clock_timestamp();
  IF d.lease IS NOT NULL OR d.retirement IS NOT NULL OR d.finalization_xid IS NOT NULL OR n>=d.original_purge_at OR
   NEW.retire_by IS NOT NULL OR NEW.last_operation_id<>NEW.creating_operation_id OR NEW.expires_at>d.original_purge_at THEN
   RAISE EXCEPTION 'share exceeds original operation backing' USING ERRCODE='23514';
  END IF;
  NEW.retire_by:=d.live_retire_by;
  IF NOT EXISTS(SELECT 1 FROM public.context_case_locator r JOIN public.context_capture source ON source.root_id=r.root_id AND source.id=r.capture_id
   JOIN public.context_verification v ON v.root_id=r.root_id AND v.capture_id=r.capture_id
   JOIN public.custody_attempt attempt ON attempt.id=source.attempt_id
   WHERE r.root_id=NEW.root_id AND r.artifact_id=NEW.artifact_id AND r.case_id=NEW.case_id AND r.cluster_id=NEW.cluster_id
    AND r.namespace_uid=NEW.namespace_uid AND r.workload_uid=NEW.workload_uid AND r.pod_uid=NEW.pod_uid
    AND v.audit_acknowledged_at IS NOT NULL AND v.copies_digest=NEW.version AND NEW.expires_at<=attempt.effective_expires_at) THEN
   RAISE EXCEPTION 'share differs from exact published source' USING ERRCODE='23514';
  END IF;
  IF a.lane='normal' THEN
   IF a.intent->>'Name' IS DISTINCT FROM 'create_share' OR d.binding->'Policy'->'History'->>'Layout' IS DISTINCT FROM 'operation-audit-history/v4' OR
    d.share_effect_target IS DISTINCT FROM NEW.id OR d.share_effect_xid IS DISTINCT FROM pg_current_xact_id() OR
    a.intent#>>'{Actor,Issuer}' IS DISTINCT FROM NEW.creator_issuer OR a.intent#>>'{Actor,Subject}' IS DISTINCT FROM NEW.creator_subject OR
    a.intent#>>'{Actor,ClientID}' IS DISTINCT FROM NEW.creator_client OR NEW.policy_acceptance_id IS NOT NULL THEN
    RAISE EXCEPTION 'share creation lacks exact paid effect' USING ERRCODE='23514';
   END IF;
  ELSIF a.lane='capture' THEN
   SELECT * INTO STRICT c FROM public.context_capture WHERE root_id=NEW.root_id AND intent_operation_id=a.id;
   instruction:=c.share_instruction;
   IF d.binding->'Policy'->'History'->>'Layout' IS DISTINCT FROM 'capture-intent-history/v2' OR
    instruction IS NULL OR (instruction->>'share_id')::uuid IS DISTINCT FROM NEW.id OR
    NOT EXISTS(SELECT 1 FROM public.context_case_locator route WHERE route.root_id=c.root_id AND route.capture_id=c.id AND route.artifact_id=NEW.artifact_id) OR
    instruction->'management' IS DISTINCT FROM NEW.management OR instruction->'recipients' IS DISTINCT FROM NEW.recipients OR
    ARRAY(SELECT jsonb_array_elements_text(instruction->'recipient_keys')) IS DISTINCT FROM NEW.recipient_keys OR
    decode(instruction->>'request_digest','hex') IS DISTINCT FROM NEW.request_digest OR
    NEW.expires_at>COALESCE((instruction->>'not_after')::timestamptz,NEW.created_at+interval '24 hours') OR
    instruction#>>'{creator,issuer}' IS DISTINCT FROM NEW.creator_issuer OR instruction#>>'{creator,subject}' IS DISTINCT FROM NEW.creator_subject OR
    instruction#>>'{creator,client}' IS DISTINCT FROM NEW.creator_client OR
    (instruction->>'policy_acceptance_id')::uuid IS DISTINCT FROM NEW.policy_acceptance_id OR NEW.idempotency_key IS DISTINCT FROM 'capture:'||c.id::text THEN
    RAISE EXCEPTION 'share differs from original capture instruction' USING ERRCODE='23514';
   END IF;
  ELSE RAISE EXCEPTION 'unsupported share creator lane' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF OLD.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1 OR NEW.last_operation_id=OLD.last_operation_id OR n>=OLD.retire_by THEN
  RAISE EXCEPTION 'share mutation is unavailable or already spent' USING ERRCODE='23514';
 END IF;
 SELECT * INTO STRICT a FROM public.operation_audit WHERE root_id=NEW.root_id AND id=NEW.last_operation_id;
 SELECT * INTO STRICT d FROM public.operation_audit_lifecycle WHERE root_id=NEW.root_id AND operation_id=a.id;
 expected:=NEW.id;
 IF NEW.revoked_at IS NOT NULL AND NEW.policy_acceptance_id IS NOT NULL AND d.share_effect_target=NEW.policy_acceptance_id THEN expected:=NEW.policy_acceptance_id; END IF;
 IF d.share_effect_target IS DISTINCT FROM expected OR d.share_effect_xid IS DISTINCT FROM pg_current_xact_id() OR a.lane<>'normal' OR n>=a.request_until THEN
  RAISE EXCEPTION 'share mutation lacks exact paid effect' USING ERRCODE='23514';
 END IF;
 -- Compare the exact stored columns without serializing/detoasting the whole
 -- NEW composite into JSON. All source, recipient and original-bound fields
 -- are immutable for both supported mutations.
 IF ROW(NEW.id,NEW.root_id,NEW.artifact_id,NEW.case_id,NEW.cluster_id,NEW.namespace_uid,NEW.workload_uid,NEW.pod_uid,
   NEW.version,NEW.creator_issuer,NEW.creator_subject,NEW.creator_client,NEW.recipients,NEW.recipient_keys,NEW.idempotency_key,
   NEW.request_digest,NEW.created_at,NEW.expires_at,NEW.policy_acceptance_id,NEW.creating_operation_id,NEW.retire_by)
  IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.artifact_id,OLD.case_id,OLD.cluster_id,OLD.namespace_uid,OLD.workload_uid,OLD.pod_uid,
   OLD.version,OLD.creator_issuer,OLD.creator_subject,OLD.creator_client,OLD.recipients,OLD.recipient_keys,OLD.idempotency_key,
   OLD.request_digest,OLD.created_at,OLD.expires_at,OLD.policy_acceptance_id,OLD.creating_operation_id,OLD.retire_by) THEN
  RAISE EXCEPTION 'share mutation changes immutable source or original bounds' USING ERRCODE='23514';
 END IF;
 IF NEW.revoked_at IS NOT NULL THEN
  IF a.intent->>'Name' IS DISTINCT FROM 'revoke_share' OR
   ROW(NEW.management,NEW.transfer_key,NEW.transfer_digest) IS DISTINCT FROM ROW(OLD.management,OLD.transfer_key,OLD.transfer_digest) THEN
   RAISE EXCEPTION 'share revocation changes only the revocation' USING ERRCODE='23514';
  END IF;
 ELSIF a.intent->>'Name' IS DISTINCT FROM 'transfer_share' OR NEW.transfer_key IS NULL OR OLD.expires_at<=n OR
  ROW(NEW.revoked_at,NEW.revoke_key) IS DISTINCT FROM ROW(OLD.revoked_at,OLD.revoke_key) THEN
  RAISE EXCEPTION 'share transfer changes only live management' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER evidence_share_immutable ON public.evidence_share;
CREATE TRIGGER evidence_share_immutable BEFORE INSERT OR UPDATE OR DELETE ON public.evidence_share FOR EACH ROW EXECUTE FUNCTION protect_evidence_share();

CREATE FUNCTION retire_operation_share_dependency() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.evidence_share WHERE creating_operation_id=OLD.id) THEN
  IF NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle l WHERE l.operation_id=OLD.id AND l.root_id=OLD.root_id
   AND l.finalization_xid=pg_current_xact_id() AND l.terminal_acknowledged_at IS NOT NULL) THEN
   RAISE EXCEPTION 'share dependency requires original audit finalization' USING ERRCODE='23514';
  END IF;
  DELETE FROM public.evidence_share WHERE root_id=OLD.root_id AND creating_operation_id=OLD.id;
 END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER operation_audit_share_dependency BEFORE DELETE ON public.operation_audit FOR EACH ROW EXECUTE FUNCTION retire_operation_share_dependency();

CREATE FUNCTION protect_share_effect_marker() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.share_effect_target IS NOT NULL OR NEW.share_effect_xid IS NOT NULL THEN RAISE EXCEPTION 'share effect marker is source owned' USING ERRCODE='23514'; END IF;
 ELSIF ROW(NEW.share_effect_target,NEW.share_effect_xid) IS DISTINCT FROM ROW(OLD.share_effect_target,OLD.share_effect_xid) AND
  (OLD.share_effect_target IS NOT NULL OR NEW.share_effect_target IS NULL OR NEW.share_effect_xid IS DISTINCT FROM pg_current_xact_id() OR NEW.lane<>'normal') THEN
  RAISE EXCEPTION 'share effect cannot be reset or renewed' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER operation_audit_share_effect_marker BEFORE INSERT OR UPDATE ON public.operation_audit_lifecycle FOR EACH ROW EXECUTE FUNCTION protect_share_effect_marker();

CREATE FUNCTION guard_policy_share_effect() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE action text;
BEGIN
 IF ROW(NEW.sharing_revoked_at,NEW.sharing_revoke_key,NEW.sharing_stopped_at,NEW.sharing_stop_key) IS NOT DISTINCT FROM ROW(OLD.sharing_revoked_at,OLD.sharing_revoke_key,OLD.sharing_stopped_at,OLD.sharing_stop_key) THEN RETURN NEW; END IF;
 action:=CASE WHEN NEW.sharing_revoked_at IS DISTINCT FROM OLD.sharing_revoked_at THEN 'revoke_share' ELSE 'stop_future_sharing' END;
 IF NEW.sharing_revoked_at IS DISTINCT FROM OLD.sharing_revoked_at AND NEW.sharing_stopped_at IS DISTINCT FROM OLD.sharing_stopped_at THEN
  RAISE EXCEPTION 'one paid policy sharing effect per operation' USING ERRCODE='23514';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle l JOIN public.operation_audit a ON a.id=l.operation_id AND a.root_id=l.root_id
  WHERE l.root_id=NEW.root_id AND l.share_effect_target=NEW.id AND l.share_effect_xid=pg_current_xact_id() AND a.intent->>'Name'=action AND clock_timestamp()<a.request_until) THEN
  RAISE EXCEPTION 'policy sharing mutation lacks exact paid effect' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER policy_acceptance_share_effect BEFORE UPDATE OF sharing_revoked_at,sharing_stopped_at ON public.policy_acceptance FOR EACH ROW EXECUTE FUNCTION guard_policy_share_effect();
-- +goose StatementEnd
REVOKE ALL ON FUNCTION begin_share_effect(uuid,uuid,text,text,text,text,uuid),retire_operation_share_dependency(),guard_policy_share_effect(),protect_share_effect_marker() FROM PUBLIC;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION materialize_capture_share() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s jsonb; access_until timestamptz; version bytea; ends timestamptz; acceptance uuid; original_operation uuid; original_purge timestamptz; at timestamptz:=clock_timestamp();
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_case_locator'::regclass THEN
  RAISE EXCEPTION 'invalid capture share source' USING ERRCODE='23514';
 END IF;
 SELECT c.share_instruction,a.effective_expires_at,c.intent_operation_id INTO s,access_until,original_operation FROM public.context_capture c JOIN public.custody_attempt a ON a.id=c.attempt_id
 WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF s IS NULL THEN
  RETURN NEW;
 END IF;
 BEGIN
  acceptance:=(s->>'policy_acceptance_id')::uuid;
 EXCEPTION WHEN invalid_text_representation THEN
  RETURN NEW;
 END;
 -- The original parent lock precedes acceptance/share locks and conflicts
 -- with finalization. Missing/retiring/unqualified parents never rematerialize.
 SELECT d.original_purge_at INTO original_purge FROM public.operation_audit o
 JOIN public.operation_audit_lifecycle d ON d.operation_id=o.id AND d.root_id=o.root_id
 WHERE o.id=original_operation AND o.root_id=NEW.root_id AND o.lane='capture'
  AND d.binding->'Policy'->'History'->>'Layout'='capture-intent-history/v2'
  AND d.lease IS NULL AND d.retirement IS NULL AND d.finalization_xid IS NULL
  AND clock_timestamp()<d.original_purge_at
 FOR KEY SHARE OF o;
 IF NOT FOUND THEN RETURN NEW; END IF;
 IF acceptance IS NOT NULL THEN
  PERFORM 1 FROM public.policy_acceptance p WHERE p.id=acceptance AND p.root_id=NEW.root_id AND p.sharing_revoked_at IS NULL FOR KEY SHARE;
  IF NOT FOUND THEN
   RETURN NEW;
  END IF;
 END IF;
 SELECT v.copies_digest INTO version FROM public.context_verification v WHERE v.capture_id=NEW.capture_id AND v.root_id=NEW.root_id;
 ends:=LEAST(COALESCE((s->>'not_after')::timestamptz,at+interval '24 hours'),at+interval '7 days',access_until);
 IF version IS NULL OR ends IS NULL OR ends<=at OR ends>original_purge OR NOT EXISTS(
  SELECT 1 FROM public.permission_assignment p
  WHERE p.retired_at IS NULL AND p.role='evidence-owner' AND p.id::text IN (SELECT m->>'AssignmentID' FROM jsonb_array_elements(s->'management') m)) THEN
  RETURN NEW;
 END IF;
 BEGIN
  INSERT INTO public.evidence_share(id,root_id,artifact_id,case_id,cluster_id,namespace_uid,workload_uid,pod_uid,version,creator_issuer,creator_subject,creator_client,
   management,recipients,recipient_keys,idempotency_key,request_digest,created_at,expires_at,policy_acceptance_id,creating_operation_id,last_operation_id)
  VALUES((s->>'share_id')::uuid,NEW.root_id,NEW.artifact_id,NEW.case_id,NEW.cluster_id,NEW.namespace_uid,NEW.workload_uid,NEW.pod_uid,version,
   s#>>'{creator,issuer}',s#>>'{creator,subject}',s#>>'{creator,client}',s->'management',s->'recipients',
   ARRAY(SELECT jsonb_array_elements_text(s->'recipient_keys')),'capture:'||NEW.capture_id::text,decode(s->>'request_digest','hex'),at,ends,acceptance,original_operation,original_operation)
  ON CONFLICT DO NOTHING;
 EXCEPTION WHEN check_violation OR not_null_violation OR invalid_text_representation OR foreign_key_violation THEN
  -- A malformed instruction never blocks publication; the share is
  -- reported unavailable instead.
  RETURN NEW;
 END;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
LOCK TABLE public.evidence_share,public.operation_audit_lifecycle IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.evidence_share) OR EXISTS(SELECT 1 FROM public.operation_audit_lifecycle WHERE share_effect_target IS NOT NULL) THEN
  RAISE EXCEPTION 'retained share dependencies or paid effects prevent rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP INDEX public.evidence_share_recipient;
CREATE INDEX evidence_share_recipient ON public.evidence_share USING gin(recipient_keys);
DROP TRIGGER policy_acceptance_share_effect ON public.policy_acceptance;
DROP FUNCTION public.guard_policy_share_effect();
DROP TRIGGER operation_audit_share_dependency ON public.operation_audit;
DROP FUNCTION public.retire_operation_share_dependency();
DROP FUNCTION public.begin_share_effect(uuid,uuid,text,text,text,text,uuid);
ALTER TABLE public.operation_audit_lifecycle DROP COLUMN share_effect_target,DROP COLUMN share_effect_xid;
ALTER TABLE public.evidence_share DROP COLUMN creating_operation_id,DROP COLUMN retire_by,DROP COLUMN last_operation_id;

DROP TRIGGER operation_audit_share_effect_marker ON public.operation_audit_lifecycle;
DROP FUNCTION public.protect_share_effect_marker();
DROP TRIGGER evidence_share_immutable ON public.evidence_share;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_evidence_share() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' OR OLD.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1 THEN
  RAISE EXCEPTION 'evidence share is immutable except for revocation and management transfer' USING ERRCODE='23514';
 END IF;
 IF NEW.revoked_at IS NOT NULL THEN
  IF (to_jsonb(NEW)-ARRAY['revoked_at','revoke_key','revision'])<>(to_jsonb(OLD)-ARRAY['revoked_at','revoke_key','revision']) THEN
   RAISE EXCEPTION 'evidence share revocation changes only the revocation' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.transfer_key IS NULL OR OLD.expires_at<=clock_timestamp() OR
  (to_jsonb(NEW)-ARRAY['management','transfer_key','transfer_digest','revision'])<>(to_jsonb(OLD)-ARRAY['management','transfer_key','transfer_digest','revision']) THEN
  RAISE EXCEPTION 'evidence share transfer changes only the management of a live share' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION materialize_capture_share() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s jsonb; access_until timestamptz; version bytea; ends timestamptz; acceptance uuid; at timestamptz:=clock_timestamp();
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_case_locator'::regclass THEN
  RAISE EXCEPTION 'invalid capture share source' USING ERRCODE='23514';
 END IF;
 SELECT c.share_instruction,a.effective_expires_at INTO s,access_until FROM public.context_capture c JOIN public.custody_attempt a ON a.id=c.attempt_id
 WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF s IS NULL THEN
  RETURN NEW;
 END IF;
 BEGIN
  acceptance:=(s->>'policy_acceptance_id')::uuid;
 EXCEPTION WHEN invalid_text_representation THEN
  RETURN NEW;
 END;
 IF acceptance IS NOT NULL THEN
  PERFORM 1 FROM public.policy_acceptance p WHERE p.id=acceptance AND p.root_id=NEW.root_id AND p.sharing_revoked_at IS NULL FOR KEY SHARE;
  IF NOT FOUND THEN
   RETURN NEW;
  END IF;
 END IF;
 SELECT v.copies_digest INTO version FROM public.context_verification v WHERE v.capture_id=NEW.capture_id AND v.root_id=NEW.root_id;
 ends:=LEAST(COALESCE((s->>'not_after')::timestamptz,at+interval '24 hours'),at+interval '7 days',access_until);
 IF version IS NULL OR ends IS NULL OR ends<=at OR NOT EXISTS(
  SELECT 1 FROM public.permission_assignment p
  WHERE p.retired_at IS NULL AND p.role='evidence-owner' AND p.id::text IN (SELECT m->>'AssignmentID' FROM jsonb_array_elements(s->'management') m)) THEN
  RETURN NEW;
 END IF;
 BEGIN
  INSERT INTO public.evidence_share(id,root_id,artifact_id,case_id,cluster_id,namespace_uid,workload_uid,pod_uid,version,creator_issuer,creator_subject,creator_client,
   management,recipients,recipient_keys,idempotency_key,request_digest,created_at,expires_at,policy_acceptance_id)
  VALUES((s->>'share_id')::uuid,NEW.root_id,NEW.artifact_id,NEW.case_id,NEW.cluster_id,NEW.namespace_uid,NEW.workload_uid,NEW.pod_uid,version,
   s#>>'{creator,issuer}',s#>>'{creator,subject}',s#>>'{creator,client}',s->'management',s->'recipients',
   ARRAY(SELECT jsonb_array_elements_text(s->'recipient_keys')),'capture:'||NEW.capture_id::text,decode(s->>'request_digest','hex'),at,ends,acceptance)
  ON CONFLICT DO NOTHING;
 EXCEPTION WHEN check_violation OR not_null_violation OR invalid_text_representation OR foreign_key_violation THEN
  -- A malformed instruction never blocks publication; the share is
  -- reported unavailable instead.
  RETURN NEW;
 END;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER evidence_share_immutable BEFORE UPDATE OR DELETE ON public.evidence_share FOR EACH ROW EXECUTE FUNCTION protect_evidence_share();
-- +goose StatementBegin
DO $$ BEGIN
 EXECUTE 'COMMENT ON TABLE public.goose_db_version IS ''asservat:oldest-binary-schema=149''';
END $$;
-- +goose StatementEnd
