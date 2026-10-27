-- +goose Up
-- ADR-239 (S-06 increment 8): bounded recurring-policy sharing. A policy
-- acceptance may carry one immutable sharing instruction in its record
-- (record->'Sharing', audited with the acceptance). Each admitted capture of
-- that acceptance atomically consumes one slot of a counter beside the record
-- and copies an ADR-235 capture instruction, while under both the capture
-- limit and the absolute end. Publication then materializes one ordinary
-- evidence_share through the existing trigger. Additive: an older binary
-- neither writes the record field nor reads the new columns, and its policy
-- captures are shared by the owner-privileged triggers below exactly as this
-- binary's, so the ADR-227 compatibility floor stays at 81.

-- shares_spent only rises (one slot per admitted capture, never refunded) and
-- never exceeds the accepted limit; a revocation is terminal and happens once.
ALTER TABLE policy_acceptance ADD COLUMN shares_spent integer NOT NULL DEFAULT 0;
ALTER TABLE policy_acceptance ADD COLUMN sharing_revoked_at timestamptz;
ALTER TABLE policy_acceptance ADD COLUMN sharing_revoke_key text CHECK (octet_length(sharing_revoke_key) BETWEEN 1 AND 128);
ALTER TABLE policy_acceptance ADD CONSTRAINT policy_acceptance_shares CHECK (shares_spent>=0 AND shares_spent<=COALESCE((record#>>'{Sharing,MaxCaptures}')::integer,0) AND COALESCE((record#>>'{Sharing,MaxCaptures}')::integer,0)<=100);
ALTER TABLE policy_acceptance ADD CONSTRAINT policy_acceptance_sharing_revocation CHECK ((sharing_revoked_at IS NULL)=(sharing_revoke_key IS NULL) AND (sharing_revoked_at IS NULL OR record ? 'Sharing'));

-- +goose StatementBegin
CREATE FUNCTION protect_policy_sharing() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.shares_spent<OLD.shares_spent OR (OLD.sharing_revoked_at IS NOT NULL AND ROW(NEW.sharing_revoked_at,NEW.sharing_revoke_key) IS DISTINCT FROM ROW(OLD.sharing_revoked_at,OLD.sharing_revoke_key)) THEN
  RAISE EXCEPTION 'policy sharing spend and revocation are monotonic' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_policy_sharing() FROM PUBLIC;
CREATE TRIGGER policy_acceptance_sharing_monotonic BEFORE UPDATE ON policy_acceptance
 FOR EACH ROW EXECUTE FUNCTION protect_policy_sharing();

-- Shares materialized from a policy acceptance name it, so revoke-all finds
-- exactly that acceptance's shares. Immutable like every other share column.
ALTER TABLE evidence_share ADD COLUMN policy_acceptance_id uuid REFERENCES policy_acceptance(id);
CREATE INDEX evidence_share_policy_acceptance ON evidence_share(root_id,policy_acceptance_id) WHERE policy_acceptance_id IS NOT NULL;

-- A policy executor's capture claims one sharing slot of the policy's current
-- acceptance at insert, inside the admission transaction, so a replayed
-- admission (which inserts nothing) never spends twice and a restarted hub
-- continues the stored counter. No slot is claimed after the end, at the
-- limit, after revoke-all, or once the DebugPolicy has a newer generation than
-- the acceptance (Stop by editing the policy; a new activation starts its own
-- counter and never backfills earlier captures). Human captures and
-- reviewed capture-time instructions (ADR-235) are untouched. The runtime
-- admission role needs no policy_acceptance grant.
-- +goose StatementBegin
CREATE FUNCTION claim_policy_capture_share() RETURNS trigger
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
 IF s#>>'{executor,identityType}' IS DISTINCT FROM 'workload' OR s#>>'{executor,clientID}' IS DISTINCT FROM 'policy-executor' OR s#>>'{executor,subject}' NOT LIKE 'policy:%' THEN
  RETURN NEW;
 END IF;
 policy:=substr(s#>>'{executor,subject}',8);
 SELECT * INTO src FROM public.policy_source WHERE root_id=NEW.root_id AND policy_uid=policy;
 IF NOT FOUND OR src.active_id IS NULL OR src.deleted OR src.suspended THEN
  RETURN NEW;
 END IF;
 UPDATE public.policy_acceptance a SET shares_spent=a.shares_spent+1
 WHERE a.id=src.active_id AND a.root_id=NEW.root_id AND a.policy_uid=policy AND a.record ? 'Sharing' AND a.sharing_revoked_at IS NULL
  AND a.generation=src.generation AND a.shares_spent<(a.record#>>'{Sharing,MaxCaptures}')::integer AND (a.record#>>'{Sharing,NotAfter}')::timestamptz>at
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
REVOKE ALL ON FUNCTION claim_policy_capture_share() FROM PUBLIC;
CREATE TRIGGER context_capture_policy_share BEFORE INSERT ON context_capture
 FOR EACH ROW EXECUTE FUNCTION claim_policy_capture_share();

-- ADR-235's materialization, extended: a policy instruction's share names its
-- acceptance, and nothing is materialized once that acceptance's sharing was
-- revoked (revoke-all is terminal for pending captures too). The KEY SHARE
-- lock orders publication against a concurrent revoke-all, which locks the
-- acceptance FOR UPDATE before revoking its shares.
-- +goose StatementBegin
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
REVOKE ALL ON FUNCTION materialize_capture_share() FROM PUBLIC;
-- No destructive Down: spend, revocations and shares are audit-relevant history.
