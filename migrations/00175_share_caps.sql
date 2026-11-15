-- +goose Up
-- Shares last until the artifact's access ends (ADR-335 D7) and have no
-- Suspended state or management-assignment continuity (ADR-330 D11). Drop
-- the share caps without a stated reason: seven-day lifetime, eight
-- recipients/managers and the 100-capture policy limit. Recurring sharing
-- may name no capture limit (MaxCaptures 0).
-- No Down: the caps are not restored. Every statement tolerates a re-Up
-- after a downgrade probe, as in 00167.
-- +goose StatementBegin
DO $$
DECLARE c text;
BEGIN
 FOR c IN SELECT conname FROM pg_constraint WHERE conrelid='public.evidence_share'::regclass AND contype='c'
  AND (pg_get_constraintdef(oid) LIKE '%7 days%' OR pg_get_constraintdef(oid) LIKE '%jsonb_array_length(management)%'
   OR pg_get_constraintdef(oid) LIKE '%jsonb_array_length(recipients)%' OR pg_get_constraintdef(oid) LIKE '%cardinality(recipient_keys)%') LOOP
  EXECUTE format('ALTER TABLE public.evidence_share DROP CONSTRAINT %I', c);
 END LOOP;
END $$;
-- +goose StatementEnd
ALTER TABLE public.evidence_share
 DROP CONSTRAINT IF EXISTS evidence_share_lifetime,
 DROP CONSTRAINT IF EXISTS evidence_share_management_shape,
 DROP CONSTRAINT IF EXISTS evidence_share_recipients_shape,
 ADD CONSTRAINT evidence_share_lifetime CHECK (expires_at>created_at),
 ADD CONSTRAINT evidence_share_management_shape CHECK (jsonb_typeof(management)='array' AND jsonb_array_length(management)>=1),
 ADD CONSTRAINT evidence_share_recipients_shape CHECK (jsonb_typeof(recipients)='array' AND jsonb_array_length(recipients)>=1 AND cardinality(recipient_keys)>=1);
ALTER TABLE public.policy_acceptance DROP CONSTRAINT IF EXISTS policy_acceptance_shares;
ALTER TABLE public.policy_acceptance ADD CONSTRAINT policy_acceptance_shares CHECK (shares_spent>=0 AND (COALESCE((record#>>'{Sharing,MaxCaptures}')::integer,0)=0 AND (shares_spent=0 OR record ? 'Sharing') OR shares_spent<=(record#>>'{Sharing,MaxCaptures}')::integer));

-- +goose StatementBegin
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
    NEW.expires_at>COALESCE((instruction->>'not_after')::timestamptz,'infinity') OR
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
-- +goose StatementEnd

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
 -- A share lasts until the artifact's access ends (ADR-335 D7), or the
 -- instruction's earlier end, and never past its audit backing.
 ends:=LEAST(COALESCE((s->>'not_after')::timestamptz,access_until),access_until,original_purge);
 IF version IS NULL OR ends IS NULL OR ends<=at THEN
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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION claim_policy_capture_share() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s jsonb; policy text; src public.policy_source; acc public.policy_acceptance; i jsonb; at timestamptz:=clock_timestamp();
BEGIN
 IF TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_capture'::regclass THEN
  RAISE EXCEPTION 'invalid policy share source' USING ERRCODE='23514';
 END IF;
 IF NEW.share_instruction IS NOT NULL THEN
  RETURN NEW;
 END IF;
 s:=convert_from(NEW.scope_json,'UTF8')::jsonb;
 -- Manual saves never inherit/debit an automatic recurring sharing intent.
 IF s->>'schemaVersion'='recording-save/v1' AND s->>'operation'='recordingSave' THEN RETURN NEW; END IF;
 IF s#>>'{executor,identityType}' IS DISTINCT FROM 'workload' OR s#>>'{executor,clientID}' IS DISTINCT FROM 'policy-executor' OR s#>>'{executor,subject}' NOT LIKE 'policy:%' THEN
  RETURN NEW;
 END IF;
 policy:=substr(s#>>'{executor,subject}',8);
 SELECT * INTO src FROM public.policy_source WHERE root_id=NEW.root_id AND policy_uid=policy;
 IF NOT FOUND OR src.active_id IS NULL OR src.deleted OR src.suspended THEN
  RETURN NEW;
 END IF;
 UPDATE public.policy_acceptance a SET shares_spent=a.shares_spent+1
 WHERE a.id=src.active_id AND a.root_id=NEW.root_id AND a.policy_uid=policy AND a.record ? 'Sharing' AND a.sharing_revoked_at IS NULL AND a.sharing_stopped_at IS NULL
  AND a.generation=src.generation AND (COALESCE((a.record#>>'{Sharing,MaxCaptures}')::integer,0)=0 OR a.shares_spent<(a.record#>>'{Sharing,MaxCaptures}')::integer) AND (a.record#>>'{Sharing,NotAfter}' IS NULL OR (a.record#>>'{Sharing,NotAfter}')::timestamptz>at)
 RETURNING * INTO acc;
 IF NOT FOUND THEN
  RETURN NEW;
 END IF;
 i:=acc.record->'Sharing';
 NEW.share_instruction:=jsonb_build_object(
  'share_id',gen_random_uuid(),
  'creator',jsonb_build_object('issuer',i#>>'{Creator,Issuer}','subject',i#>>'{Creator,Subject}','client',i#>>'{Creator,ClientID}'),
  'management',i->'Management',
  'recipients',(SELECT jsonb_agg(jsonb_build_object('kind',r->>'Kind','issuer',r->>'Issuer','id',r->>'ID') ORDER BY n) FROM jsonb_array_elements(i->'Recipients') WITH ORDINALITY x(r,n)),
  'recipient_keys',(SELECT jsonb_agg((r->>'Kind')||E'\n'||(r->>'Issuer')||E'\n'||(r->>'ID') ORDER BY n) FROM jsonb_array_elements(i->'Recipients') WITH ORDINALITY x(r,n)),
  'not_after',i->'NotAfter',
  'request_digest',encode(sha256(convert_to('policy-share/v1:'||acc.id::text||':'||NEW.id::text,'UTF8')),'hex'),
  'policy_acceptance_id',acc.id);
 RETURN NEW;
END $$;
-- +goose StatementEnd
