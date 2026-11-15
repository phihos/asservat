-- +goose Up
-- REQ-AUT-005 / ADR-330 D6: share effects write their own audit_event row in
-- the effect transaction. They no longer read or mark the operation audit,
-- and their expiry is no longer bound to an audit purge window. Idempotency
-- stays on evidence_share (creator key) and policy_acceptance (sharing keys).
DROP TRIGGER IF EXISTS policy_acceptance_share_effect ON policy_acceptance;
DROP FUNCTION IF EXISTS guard_policy_share_effect();
DROP TRIGGER IF EXISTS operation_audit_share_effect_marker ON operation_audit_lifecycle;
DROP FUNCTION IF EXISTS protect_share_effect_marker();
DROP TRIGGER IF EXISTS operation_audit_share_dependency ON operation_audit;
DROP FUNCTION IF EXISTS retire_operation_share_dependency();
DROP FUNCTION IF EXISTS begin_share_effect(uuid,uuid,text,text,text,text,uuid);

ALTER TABLE evidence_share
 DROP COLUMN IF EXISTS creating_operation_id,
 DROP COLUMN IF EXISTS last_operation_id,
 DROP COLUMN IF EXISTS retire_by;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_evidence_share() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE n timestamptz:=clock_timestamp();
BEGIN
 IF TG_OP='DELETE' THEN
  IF n<OLD.expires_at THEN RAISE EXCEPTION 'an unexpired share is revoked, not deleted' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  IF NOT EXISTS(SELECT 1 FROM public.context_case_locator r JOIN public.context_capture source ON source.root_id=r.root_id AND source.id=r.capture_id
   JOIN public.context_verification v ON v.root_id=r.root_id AND v.capture_id=r.capture_id
   JOIN public.custody_attempt attempt ON attempt.id=source.attempt_id
   WHERE r.root_id=NEW.root_id AND r.artifact_id=NEW.artifact_id AND r.case_id=NEW.case_id AND r.cluster_id=NEW.cluster_id
    AND r.namespace_uid=NEW.namespace_uid AND r.workload_uid=NEW.workload_uid AND r.pod_uid=NEW.pod_uid
    AND v.audit_acknowledged_at IS NOT NULL AND v.copies_digest=NEW.version AND NEW.expires_at<=attempt.effective_expires_at) THEN
   RAISE EXCEPTION 'share differs from exact published source' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF OLD.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1 THEN
  RAISE EXCEPTION 'share mutation is unavailable or already spent' USING ERRCODE='23514';
 END IF;
 IF ROW(NEW.id,NEW.root_id,NEW.artifact_id,NEW.case_id,NEW.cluster_id,NEW.namespace_uid,NEW.workload_uid,NEW.pod_uid,
   NEW.version,NEW.creator_issuer,NEW.creator_subject,NEW.creator_client,NEW.recipients,NEW.recipient_keys,NEW.idempotency_key,
   NEW.request_digest,NEW.created_at,NEW.expires_at,NEW.policy_acceptance_id)
  IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.artifact_id,OLD.case_id,OLD.cluster_id,OLD.namespace_uid,OLD.workload_uid,OLD.pod_uid,
   OLD.version,OLD.creator_issuer,OLD.creator_subject,OLD.creator_client,OLD.recipients,OLD.recipient_keys,OLD.idempotency_key,
   OLD.request_digest,OLD.created_at,OLD.expires_at,OLD.policy_acceptance_id) THEN
  RAISE EXCEPTION 'share mutation changes immutable source or original bounds' USING ERRCODE='23514';
 END IF;
 IF NEW.revoked_at IS NOT NULL THEN
  IF ROW(NEW.management,NEW.transfer_key,NEW.transfer_digest) IS DISTINCT FROM ROW(OLD.management,OLD.transfer_key,OLD.transfer_digest) THEN
   RAISE EXCEPTION 'share revocation changes only the revocation' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.transfer_key IS NULL OR OLD.expires_at<=n THEN
  RAISE EXCEPTION 'share transfer changes only live management' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS evidence_share_immutable ON evidence_share;
CREATE TRIGGER evidence_share_immutable BEFORE INSERT OR DELETE OR UPDATE ON evidence_share FOR EACH ROW EXECUTE FUNCTION protect_evidence_share();

-- Publication materializes a capture's sharing instruction. The share lasts
-- until the artifact's access ends or the instruction's earlier end
-- (ADR-335 D7), and writes its audit row in the publication transaction.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION materialize_capture_share() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s jsonb; access_until timestamptz; version bytea; ends timestamptz; acceptance uuid; share uuid; at timestamptz:=clock_timestamp();
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
 ends:=LEAST(COALESCE((s->>'not_after')::timestamptz,access_until),access_until);
 IF version IS NULL OR ends IS NULL OR ends<=at THEN
  RETURN NEW;
 END IF;
 BEGIN
  INSERT INTO public.evidence_share(id,root_id,artifact_id,case_id,cluster_id,namespace_uid,workload_uid,pod_uid,version,creator_issuer,creator_subject,creator_client,
   management,recipients,recipient_keys,idempotency_key,request_digest,created_at,expires_at,policy_acceptance_id)
  VALUES((s->>'share_id')::uuid,NEW.root_id,NEW.artifact_id,NEW.case_id,NEW.cluster_id,NEW.namespace_uid,NEW.workload_uid,NEW.pod_uid,version,
   s#>>'{creator,issuer}',s#>>'{creator,subject}',s#>>'{creator,client}',s->'management',s->'recipients',
   ARRAY(SELECT jsonb_array_elements_text(s->'recipient_keys')),'capture:'||NEW.capture_id::text,decode(s->>'request_digest','hex'),at,ends,acceptance)
  ON CONFLICT DO NOTHING RETURNING id INTO share;
 EXCEPTION WHEN check_violation OR not_null_violation OR invalid_text_representation OR foreign_key_violation THEN
  -- A malformed instruction never blocks publication; the share is
  -- reported unavailable instead.
  RETURN NEW;
 END;
 IF share IS NOT NULL THEN
  INSERT INTO public.audit_event(event_id,operation_id,kind,operation,issuer,subject,client_id,identity_type,status,effect,case_ids,artifact_ids,capture_ids,share_ids)
  VALUES(gen_random_uuid(),NEW.capture_id,'share.create','publish_capture',s#>>'{creator,issuer}',s#>>'{creator,subject}',s#>>'{creator,client}','human','success','accepted',
   ARRAY[NEW.case_id::text],ARRAY[NEW.artifact_id::text],ARRAY[NEW.capture_id::text],ARRAY[share::text]);
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
