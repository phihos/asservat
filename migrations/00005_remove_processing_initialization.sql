-- +goose Up
-- Roots initialize at creation. The manual action has no usable effect;
-- retain existing decision history while refusing new initialization actions.
ALTER TABLE processing_decision DROP CONSTRAINT processing_decision_action_check;
ALTER TABLE processing_decision ADD CONSTRAINT processing_decision_action_check
 CHECK (action IN ('restrict_processing','release_processing','request_early_erasure')) NOT VALID;
ALTER TABLE processing_decision DROP CONSTRAINT processing_decision_rule_action;
ALTER TABLE processing_decision ADD CONSTRAINT processing_decision_rule_action
 CHECK ((rule_id IS NULL) = (action = 'request_early_erasure')) NOT VALID;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_processing_decision() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE p public.processing_root; r public.processing_rule; n timestamptz; a_erasure public.custody_attempt;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'processing decision retirement requires independent completion' USING ERRCODE='23514'; END IF;
 -- Lock recovery before the permission/processing and storage locks for the erasure action.
 IF NEW.action='request_early_erasure' THEN
  PERFORM 1 FROM public.fleet_current_trust f WHERE f.installation_id=(SELECT installation_id FROM public.processing_root WHERE root_id=NEW.root_id) FOR SHARE;
 END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 IF NEW.rule_id IS NOT NULL THEN SELECT * INTO STRICT r FROM public.processing_rule WHERE root_id=NEW.root_id AND id=NEW.rule_id FOR UPDATE; END IF;
 n:=clock_timestamp();
 IF TG_OP='INSERT' THEN
  IF NEW.valid_until IS NOT NULL OR NEW.retire_by IS NOT NULL THEN RAISE EXCEPTION 'processing decision dates are source owned' USING ERRCODE='23514'; END IF;
  NEW.valid_until:=p.valid_until; NEW.retire_by:=p.retire_by;
  IF NEW.rule_id IS NOT NULL THEN NEW.valid_until:=r.valid_until; NEW.retire_by:=r.retire_by; END IF;
  IF n>=NEW.valid_until OR NEW.request_until>NEW.valid_until OR n<NEW.created_at OR n>=NEW.request_until OR n>=p.valid_until OR NEW.applied_at IS NOT NULL OR NEW.result_revision IS NOT NULL OR NEW.result_sequence IS NOT NULL THEN
   RAISE EXCEPTION 'invalid prepared processing decision' USING ERRCODE='23514'; END IF;
  IF NEW.action='request_early_erasure' THEN
   IF p.root_transitions+2>=p.max_root_transitions THEN RAISE EXCEPTION 'processing erasure capacity unavailable' USING ERRCODE='23514'; END IF;
   IF EXISTS(SELECT 1 FROM public.processing_decision d WHERE d.root_id=NEW.root_id AND d.action=NEW.action
       AND d.scope#>>'{Location,AttemptID}'=NEW.scope#>>'{Location,AttemptID}' AND (d.applied_at IS NOT NULL OR d.request_until>n)) THEN
    RAISE EXCEPTION 'processing erasure already requested' USING ERRCODE='23505'; END IF;
   PERFORM public.processing_erasure_attempt(NEW,p);
   SELECT LEAST(p.retire_by,l.retire_by) INTO STRICT NEW.retire_by FROM public.context_processing l
    WHERE l.root_id=NEW.root_id AND l.artifact_id=(NEW.scope#>>'{Location,ArtifactID}')::uuid;
   NEW.valid_until:=LEAST(p.valid_until,NEW.retire_by-interval '1 microsecond');
   IF NEW.request_until>NEW.valid_until THEN RAISE EXCEPTION 'processing erasure original retention ended' USING ERRCODE='23514'; END IF;
   -- Two backed root-transition units cover the decision and cutoff. Keep one existing unit for backed root renewal.
   UPDATE public.processing_root SET root_transitions=root_transitions+2 WHERE root_id=NEW.root_id;
   IF clock_timestamp()>=NEW.request_until THEN RAISE EXCEPTION 'processing erasure expired after reserve' USING ERRCODE='23514'; END IF;
  ELSE
   IF p.initialized_at IS NULL OR NOT public.processing_scope_valid(NEW.scope) OR NEW.scope IS DISTINCT FROM r.scope OR NEW.expected_revision<>r.revision OR r.decisions>=16 OR
      (NEW.action='restrict_processing' AND (r.revision%2<>0 OR r.decisions>=15)) OR
      (NEW.action='release_processing' AND (r.revision%2<>1 OR r.state<>'restricted')) OR
      (NEW.action='restrict_processing' AND EXISTS(SELECT 1 FROM public.context_processing c WHERE c.root_id=NEW.root_id AND c.delete_by>r.valid_until AND
       ((r.scope->>'Kind'='artifact' AND c.artifact_id=(r.scope#>>'{Location,ArtifactID}')::uuid AND c.attempt_id=(r.scope#>>'{Location,AttemptID}')::uuid AND c.cluster_id=(r.scope#>>'{Location,ClusterID}')::uuid) OR
        (r.scope->>'Kind'='workloadInterval' AND c.cluster_id=(r.scope->>'ClusterID')::uuid AND c.namespace_uid=r.scope->>'NamespaceUID' AND c.workload_uid=r.scope->>'WorkloadUID' AND c.anchor_at>=(r.scope->>'AcquiredFrom')::timestamptz AND c.anchor_at<(r.scope->>'AcquiredUntil')::timestamptz)))) OR
      EXISTS(SELECT 1 FROM public.processing_decision d WHERE d.root_id=NEW.root_id AND d.rule_id=NEW.rule_id AND d.applied_at IS NULL AND d.request_until>n) THEN
    RAISE EXCEPTION 'processing decision scope or capacity unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_rule SET decisions=decisions+1 WHERE root_id=NEW.root_id AND id=NEW.rule_id;
  END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['applied_at','result_revision','result_sequence']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['applied_at','result_revision','result_sequence']) OR OLD.applied_at IS NOT NULL OR NEW.applied_at IS NULL OR n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until THEN
   RAISE EXCEPTION 'immutable or expired processing decision' USING ERRCODE='23514'; END IF;
  IF NEW.action='request_early_erasure' THEN a_erasure:=public.processing_erasure_attempt(NEW,p); END IF;
  n:=clock_timestamp();
  IF NEW.action='request_early_erasure' THEN
   INSERT INTO public.retention_decision(id,root_id,attempt_id,sequence,previous_expires_at,previous_delete_by,expires_at,delete_by,decision_digest,decision_json)
    VALUES(NEW.id,NEW.root_id,a_erasure.id,a_erasure.retention_sequence+1,a_erasure.effective_expires_at,a_erasure.effective_delete_by,
           a_erasure.anchor_at,a_erasure.effective_delete_by,sha256(NEW.erasure_decision),NEW.erasure_decision);
   UPDATE public.custody_attempt SET effective_expires_at=a_erasure.anchor_at,retention_sequence=a_erasure.retention_sequence+1 WHERE id=a_erasure.id;
   NEW.result_revision:=0;
  ELSE
   IF p.initialized_at IS NULL OR r.revision<>NEW.expected_revision OR r.scope IS DISTINCT FROM NEW.scope OR
      (NEW.action='release_processing' AND r.state<>'restricted') OR (NEW.action='restrict_processing' AND r.state NOT IN ('reserved','released')) THEN
    RAISE EXCEPTION 'processing decision CAS changed' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_rule SET revision=revision+1,state=CASE WHEN NEW.action='release_processing' THEN 'released' ELSE 'restricted' END,current_decision=NEW.id WHERE root_id=NEW.root_id AND id=NEW.rule_id;
   UPDATE public.processing_root SET sequence=sequence+1 WHERE root_id=NEW.root_id;
   NEW.result_revision:=r.revision+1;
  END IF;
  -- Nested counter/rule triggers can wait. Recheck the original decision interval after those writes as well;
  -- an expiry rolls back every nested effect in this transaction.
  n:=clock_timestamp();
  IF n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until THEN RAISE EXCEPTION 'processing decision expired after nested locks' USING ERRCODE='23514'; END IF;
  IF NEW.action='request_early_erasure' AND NOT EXISTS(SELECT 1 FROM public.fleet_current_trust t
      WHERE t.installation_id=p.installation_id AND t.issuer_epoch=p.issuer_epoch AND NOT t.suspended
       AND t.observed_at<=n AND n<t.fresh_until) THEN
   RAISE EXCEPTION 'processing erasure recovery expired after apply' USING ERRCODE='23514'; END IF;
  NEW.applied_at:=n; NEW.result_sequence:=CASE WHEN NEW.action='request_early_erasure' THEN p.sequence ELSE p.sequence+1 END;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
