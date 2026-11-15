-- +goose Up
-- REQ-AUT-003 (ADR-335 D9): a pending review stays decidable until it is
-- cancelled, changes or passes its optional notAfter. 00176 removed the fixed
-- review window, so the preview blueprint behind a pending grant stays
-- readable until that bound instead of expiring with the preview deadline.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_preview_read_until(p_root uuid,p_preview uuid) RETURNS timestamptz
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT GREATEST(p.deadline,COALESCE((SELECT CASE WHEN g.decision IS NULL AND g.revoked_at IS NULL THEN COALESCE(g.not_after,'infinity'::timestamptz) ELSE COALESCE(g.expires_at,g.review_until) END
 FROM public.access_grant g WHERE p.preview_kind IN ('context','compositionGroup') AND g.root_id=p.root_id AND g.preview_id=p.id
 AND g.capture_id=p.capture_id
 AND g.scope=decode(convert_from(p.blueprint_json,'UTF8')::jsonb->>'CanonicalScope','base64')
 AND g.requester_issuer=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'Issuer'
 AND g.requester_subject=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'Subject'
 AND g.requester_client=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'ClientID'),p.deadline))
 FROM public.context_preview p WHERE p.root_id=p_root AND p.id=p_preview
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_preview_read_until(p_root uuid,p_preview uuid) RETURNS timestamptz
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT GREATEST(p.deadline,COALESCE((SELECT GREATEST(g.review_until,g.expires_at)
 FROM public.access_grant g WHERE p.preview_kind IN ('context','compositionGroup') AND g.root_id=p.root_id AND g.preview_id=p.id
 AND g.capture_id=p.capture_id
 AND g.scope=decode(convert_from(p.blueprint_json,'UTF8')::jsonb->>'CanonicalScope','base64')
 AND g.requester_issuer=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'Issuer'
 AND g.requester_subject=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'Subject'
 AND g.requester_client=convert_from(p.blueprint_json,'UTF8')::jsonb->'Actor'->>'ClientID'),p.deadline))
 FROM public.context_preview p WHERE p.root_id=p_root AND p.id=p_preview
$$;
-- +goose StatementEnd
