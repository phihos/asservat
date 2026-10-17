-- +goose Up

-- Keep the original composite audit variable separate from the nested credential
-- table alias. The cleanup UPDATE otherwise fails SQL compilation before its
-- original live-reference denial. No grants, deadlines or accounting change.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_connector_identity_profile() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.connector_identity_root; n timestamptz; c jsonb; a public.operation_audit; attempt public.connector_credential_attempt; child public.connector_identity_process;
BEGIN
 IF TG_RELID<>'public.connector_identity_profile'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP='DELETE' THEN RAISE EXCEPTION 'connector profile retirement unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT r FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 IF TG_OP='INSERT' AND (NEW.retirement_ticket IS NOT NULL OR NEW.retirement_at IS NOT NULL) THEN RAISE EXCEPTION 'new profile cannot invent retirement' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND OLD.retirement_ticket IS NULL AND NEW.retirement_ticket IS NOT NULL THEN
  IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') OR NOT NEW.fenced OR NEW.retirement_at IS NULL OR NEW.retirement_at>n OR NEW.retirement_at<n-interval '5 seconds' OR
   (to_jsonb(NEW)-ARRAY['fenced','retirement_ticket','retirement_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['fenced','retirement_ticket','retirement_at']) OR
   NOT EXISTS(SELECT 1 FROM public.connector_retirement_ticket t WHERE t.id=NEW.retirement_ticket AND t.root_id=NEW.root_id AND t.peer_id=NEW.peer_id AND t.activated_at IS NOT NULL AND t.superseded_at IS NULL AND t.restriction_at=NEW.retirement_at AND
    t.behavior_uid=NEW.source_uid AND t.backing_revision=NEW.backing_revision AND t.backing_digest=NEW.backing_digest AND t.principal_digest=NEW.account_digest) THEN RAISE EXCEPTION 'connector restriction is not prepaid for this cohort' USING ERRCODE='23514';END IF;
  -- Its original ticket prepaid this fixed control transition. Exhaustion of
  -- ordinary source/admission counters cannot block a restrictive close.
  RETURN NEW;
 END IF;
 IF TG_OP='UPDATE' AND (ROW(NEW.retirement_ticket,NEW.retirement_at) IS DISTINCT FROM ROW(OLD.retirement_ticket,OLD.retirement_at) OR
  OLD.retirement_ticket IS NOT NULL AND (NOT NEW.fenced OR NOT public.connector_identity_role_ok(NEW.root_id,'cleanup'))) THEN RAISE EXCEPTION 'irreversible connector retirement fence' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND public.connector_identity_role_ok(NEW.root_id,'cleanup') THEN
  IF NOT NEW.fenced OR NEW.candidate_id IS NOT NULL OR NEW.accepted_id IS NOT NULL OR (to_jsonb(NEW)-ARRAY['fenced','candidate_id','accepted_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['fenced','candidate_id','accepted_id']) OR
   EXISTS(SELECT 1 FROM public.connector_identity_process p WHERE p.root_id=OLD.root_id AND p.peer_id=OLD.peer_id AND (p.id IN(OLD.candidate_id,OLD.accepted_id) OR EXISTS(SELECT 1 FROM public.connector_credential_attempt credential_attempt_row WHERE credential_attempt_row.process_id=p.id AND credential_attempt_row.id IN(OLD.candidate_id,OLD.accepted_id))) AND n<p.run_until+interval '1 minute') THEN RAISE EXCEPTION 'connector accepted source still referenced' USING ERRCODE='23514';END IF;
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
