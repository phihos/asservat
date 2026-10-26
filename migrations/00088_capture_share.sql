-- +goose Up
-- ADR-235 (S-06 increment 5): capture-time sharing. A reviewed request may
-- carry one sharing instruction; admission pins the requester's
-- evidence-owner management into it and publication materializes exactly one
-- evidence_share row in the catalog publication transaction. Additive: an
-- older binary neither writes nor reads the column, and the trigger only acts
-- on rows that carry an instruction, so the ADR-227 compatibility floor stays
-- at 81.
ALTER TABLE context_capture ADD COLUMN share_instruction jsonb
 CHECK(share_instruction IS NULL OR (jsonb_typeof(share_instruction)='object' AND octet_length(share_instruction::text)<=65536));

-- The capture audit view keeps exposing whole accepted rows (it was created
-- with c.*, which froze its columns); replacing it appends the new column and
-- keeps its grants.
CREATE OR REPLACE VIEW capture_operation_intents WITH(security_barrier=true) AS
SELECT c.* FROM public.context_capture c WHERE c.intent_operation_id=c.id AND
 public.capture_audit_role_ok(c.root_id,'reader');

-- The instruction is part of the immutable accepted request.
-- +goose StatementBegin
CREATE FUNCTION protect_capture_share_instruction() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.share_instruction IS DISTINCT FROM OLD.share_instruction THEN
  RAISE EXCEPTION 'capture sharing instruction is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_capture_share_instruction() FROM PUBLIC;
CREATE TRIGGER context_capture_share_instruction_immutable BEFORE UPDATE ON context_capture
 FOR EACH ROW EXECUTE FUNCTION protect_capture_share_instruction();

-- Only the exact case-locator INSERT of a catalog publication invokes this
-- owner-privileged materialization, so publishers need no evidence_share
-- grant. It runs once per published artifact (the locator's primary key) and
-- the share's primary key makes any replay a no-op: exactly one share.
-- When the share cannot be materialized (the instruction's end has passed,
-- the artifact's access ends first, or no pinned management assignment is
-- still unretired) the capture still publishes and get_capture reports
-- SharingUnavailable. Readers re-check management, denies, recipients and
-- expiry at every read; this is not authority.
-- +goose StatementBegin
CREATE FUNCTION materialize_capture_share() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s jsonb; access_until timestamptz; version bytea; ends timestamptz; at timestamptz:=clock_timestamp();
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_case_locator'::regclass THEN
  RAISE EXCEPTION 'invalid capture share source' USING ERRCODE='23514';
 END IF;
 SELECT c.share_instruction,a.effective_expires_at INTO s,access_until FROM public.context_capture c JOIN public.custody_attempt a ON a.id=c.attempt_id
 WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF s IS NULL THEN
  RETURN NEW;
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
   management,recipients,recipient_keys,idempotency_key,request_digest,created_at,expires_at)
  VALUES((s->>'share_id')::uuid,NEW.root_id,NEW.artifact_id,NEW.case_id,NEW.cluster_id,NEW.namespace_uid,NEW.workload_uid,NEW.pod_uid,version,
   s#>>'{creator,issuer}',s#>>'{creator,subject}',s#>>'{creator,client}',s->'management',s->'recipients',
   ARRAY(SELECT jsonb_array_elements_text(s->'recipient_keys')),'capture:'||NEW.capture_id::text,decode(s->>'request_digest','hex'),at,ends)
  ON CONFLICT DO NOTHING;
 EXCEPTION WHEN check_violation OR not_null_violation OR invalid_text_representation THEN
  -- A malformed instruction never blocks publication; the share is
  -- reported unavailable instead.
  RETURN NEW;
 END;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION materialize_capture_share() FROM PUBLIC;
CREATE TRIGGER capture_share_from_case_locator AFTER INSERT ON context_case_locator
 FOR EACH ROW EXECUTE FUNCTION materialize_capture_share();
-- No destructive Down: accepted instructions and shares are audit-relevant history.
