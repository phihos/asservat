-- +goose Up
-- ADR-252: keep one bounded immutable blueprint through independent review.
-- These purpose-specific functions expose no grant row or mutation privilege.
-- +goose StatementBegin
CREATE FUNCTION context_preview_read_until(p_root uuid,p_preview uuid) RETURNS timestamptz
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT GREATEST(p.deadline,COALESCE((SELECT GREATEST(g.review_until,g.expires_at)
 FROM public.access_grant g WHERE g.root_id=p.root_id AND g.preview_id=p.id
 AND g.capture_id=p.capture_id
 AND g.scope=decode(convert_from(p.blueprint_json,'UTF8')::jsonb->>'CanonicalScope','base64')
 AND g.requester_issuer=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'Issuer'
 AND g.requester_subject=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'Subject'
 AND g.requester_client=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'ClientID'),p.deadline))
 FROM public.context_preview p WHERE p.root_id=p_root AND p.id=p_preview
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION lock_approved_context_grant(p_root uuid,p_preview uuid,p_capture uuid,p_issuer text,p_subject text,p_client text,p_digest bytea)
RETURNS timestamptz LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE g public.access_grant;
BEGIN
 SELECT * INTO g FROM public.access_grant WHERE root_id=p_root AND preview_id=p_preview AND capture_id=p_capture FOR SHARE;
 IF NOT FOUND OR g.requester_issuer<>p_issuer OR g.requester_subject<>p_subject OR g.requester_client<>p_client
 OR g.execution_digest<>p_digest OR g.decision IS DISTINCT FROM 'approved' OR g.revoked_at IS NOT NULL
 OR g.expires_at<=clock_timestamp() OR convert_from(g.scope,'UTF8')::jsonb->>'timing' IS DISTINCT FROM 'approvedAcceptance/v1' THEN
  RETURN NULL;
 END IF;
 RETURN g.expires_at;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_preview_read_until(uuid,uuid),lock_approved_context_grant(uuid,uuid,uuid,text,text,text,bytea) FROM PUBLIC;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_preview_immutable() RETURNS trigger LANGUAGE plpgsql
 SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.closed_at IS NOT NULL OR NEW.closed_request_key IS NOT NULL OR NEW.closed_submission_digest IS NOT NULL THEN
   RAISE EXCEPTION 'preview cannot begin closed' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 ELSIF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-ARRAY['closed_at','closed_request_key','closed_submission_digest']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['closed_at','closed_request_key','closed_submission_digest']) THEN
   RAISE EXCEPTION 'context preview is immutable' USING ERRCODE='23514';
  END IF;
  IF OLD.closed_at IS NOT NULL THEN
   IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'context preview closure is immutable' USING ERRCODE='23514'; END IF;
  ELSIF NEW.closed_at IS NOT NULL THEN
   NEW.closed_at:=clock_timestamp();
  END IF;
  RETURN NEW;
 END IF;
 IF public.context_preview_read_until(OLD.root_id,OLD.id)>clock_timestamp() THEN
  RAISE EXCEPTION 'context preview is not expired' USING ERRCODE='23514';
 END IF;
 RETURN OLD;
END $$;
-- +goose StatementEnd

-- +goose Down
-- No blueprint is rewritten; rollback restores the old expiry-only contract.
-- Pending/approved rows remain ordinary immutable previews.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_preview_immutable() RETURNS trigger LANGUAGE plpgsql
 SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.closed_at IS NOT NULL OR NEW.closed_request_key IS NOT NULL OR NEW.closed_submission_digest IS NOT NULL THEN
   RAISE EXCEPTION 'preview cannot begin closed' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 ELSIF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-ARRAY['closed_at','closed_request_key','closed_submission_digest']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['closed_at','closed_request_key','closed_submission_digest']) THEN
   RAISE EXCEPTION 'context preview is immutable' USING ERRCODE='23514';
  END IF;
  IF OLD.closed_at IS NOT NULL THEN
   IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'context preview closure is immutable' USING ERRCODE='23514'; END IF;
  ELSIF NEW.closed_at IS NOT NULL THEN
   NEW.closed_at:=clock_timestamp();
  END IF;
  RETURN NEW;
 END IF;
 IF OLD.deadline>clock_timestamp() THEN
  RAISE EXCEPTION 'context preview is not expired' USING ERRCODE='23514';
 END IF;
 RETURN OLD;
END $$;
-- +goose StatementEnd
DROP FUNCTION lock_approved_context_grant(uuid,uuid,uuid,text,text,text,bytea);
DROP FUNCTION context_preview_read_until(uuid,uuid);
