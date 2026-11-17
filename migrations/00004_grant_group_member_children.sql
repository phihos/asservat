-- +goose Up
-- REQ-INV-001/002: one approval of a composition capture covers the
-- published outputs of its group members. The baseline child guard only
-- accepts the grant's own capture (an older copy restored by the former
-- 00176), so registering a member output fails with 'child capture differs
-- from parent' although RegisterGrantArtifact and
-- context_packet_query_scope_grant_current accept members of the exact
-- approved group. This restores the member case: the child capture is a
-- member of the parent's approved composition group, runs the registered
-- action and has the catalog row of exactly this artifact version.
-- CREATE OR REPLACE keeps the function's grants and only widens what the
-- previous release accepted (expand-only, ADR-335 D13).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_access_grant_child_scope() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE parent public.access_grant%ROWTYPE; item jsonb; matched boolean:=false;
BEGIN
 SELECT * INTO STRICT parent FROM public.access_grant WHERE root_id=NEW.root_id AND id=NEW.parent_id;
 IF parent.kind='adHocCapture' THEN
  IF NEW.capture_id IS DISTINCT FROM parent.capture_id AND NOT EXISTS(
   SELECT 1 FROM public.context_capture member
   JOIN public.recording_save_group rg ON rg.root_id=member.root_id AND rg.id=member.group_id
   JOIN public.context_case_locator l ON l.root_id=member.root_id AND l.capture_id=member.id AND l.artifact_id=NEW.artifact_id
   JOIN public.context_catalog published ON published.root_id=member.root_id AND published.capture_id=member.id AND published.copies_digest=NEW.artifact_digest
   WHERE member.root_id=NEW.root_id AND member.id=NEW.capture_id AND rg.id=parent.capture_id AND rg.scope_digest=parent.execution_digest
    AND rg.group_kind='composition' AND member.group_ordinal>=0 AND rg.child_ids[member.group_ordinal+1]=member.id
    AND convert_from(member.expectation_json,'UTF8')::jsonb->>'ActionID'=NEW.action_id) THEN
   RAISE EXCEPTION 'child capture differs from exact accepted parent group' USING ERRCODE='23514';
  END IF;
 ELSIF parent.kind='rawQuery' THEN
  FOR item IN SELECT jsonb_array_elements(parent.raw_query->'Artifacts') LOOP
   IF item#>>'{Output,ArtifactID}'=NEW.artifact_id::text
    AND item#>>'{Output,CaptureID}'=NEW.capture_id::text
    AND item#>>'{Output,ActionID}'=NEW.action_id
    AND item#>'{Output,ArtifactDigest}'=to_jsonb(ARRAY(SELECT get_byte(NEW.artifact_digest,i)::integer FROM generate_series(0,31) i)) THEN matched:=true; END IF;
  END LOOP;
  IF NOT matched THEN RAISE EXCEPTION 'raw child is not an exact reviewed member' USING ERRCODE='23514'; END IF;
 ELSE RAISE EXCEPTION 'grant cannot parent artifact children' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
-- No Down: the schema is never downgraded (see 00001).
