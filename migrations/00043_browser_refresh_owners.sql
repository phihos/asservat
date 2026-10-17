-- +goose Up
-- Explicit POST admits refresh scheduling only. Rows carry no credentials,
-- group claims, evidence/native metadata, URLs or callbacks. Owner capacity
-- survives logout DELETE until positive joined closure, never lease expiry.
CREATE TABLE browser_refresh_owner (
 root_id uuid NOT NULL REFERENCES browser_session_root(id),
 session_id bytea NOT NULL CHECK(octet_length(session_id)=32),
 epoch uuid NOT NULL,owner_id uuid NOT NULL,generation bigint NOT NULL CHECK(generation>0),
 installation_id uuid NOT NULL,cluster_id uuid NOT NULL,pod_uid uuid NOT NULL,process_epoch uuid NOT NULL,
 actor_key bytea NOT NULL CHECK(octet_length(actor_key)=32),
 provider_session_key bytea NOT NULL CHECK(octet_length(provider_session_key)=32),
 session_created_at timestamptz NOT NULL,authenticated_at timestamptz NOT NULL,
 session_expires_at timestamptz NOT NULL,started_at timestamptz NOT NULL,lease_until timestamptz NOT NULL,
 joined_at timestamptz,
 claim bytea CHECK(claim IS NULL OR octet_length(claim)=32),
 claim_version bigint CHECK(claim_version IS NULL OR claim_version>0),
 claim_until timestamptz,claim_joined_at timestamptz,claim_download_id uuid,claim_response_id uuid,
 claim_response_owner uuid,claim_response_generation bigint,
 PRIMARY KEY(root_id,session_id),UNIQUE(owner_id,generation),
 CHECK(isfinite(session_created_at) AND authenticated_at<=session_created_at AND session_expires_at>session_created_at AND session_expires_at<=session_created_at+interval '24 hours'),
 CHECK(started_at>=session_created_at AND lease_until>started_at AND lease_until<=session_expires_at),
 CHECK(joined_at IS NULL OR isfinite(joined_at) AND joined_at>=started_at),
 CHECK((claim IS NULL)=(claim_version IS NULL) AND (claim IS NULL)=(claim_until IS NULL) AND (claim IS NULL)=(claim_download_id IS NULL)),
 CHECK((claim_response_id IS NULL)=(claim_response_owner IS NULL) AND (claim_response_id IS NULL)=(claim_response_generation IS NULL)),
 CHECK(claim_response_id IS NULL OR claim IS NOT NULL AND claim_response_generation>0),
 CHECK(claim_joined_at IS NULL OR claim IS NOT NULL AND isfinite(claim_joined_at)),
 CHECK(claim_until IS NULL OR claim_until<=lease_until AND claim_until<=session_expires_at)
);
CREATE INDEX browser_refresh_owner_actor ON browser_refresh_owner(root_id,actor_key);
CREATE INDEX browser_refresh_owner_process ON browser_refresh_owner(installation_id,cluster_id,pod_uid,process_epoch);

-- One retained row per already charged download session. First dates never
-- reset; a joined owner detaches its binding, not this immutable grace history.
-- Sixteen bounds active bindings per owner. Detached history remains backed by
-- artifact_download/download_allocation reserved_sessions (no refund here).
CREATE TABLE browser_refresh_consumer (
 download_id uuid PRIMARY KEY,download_root_id uuid NOT NULL,
 FOREIGN KEY(download_id,download_root_id) REFERENCES artifact_download(id,root_id),
 first_admitted_at timestamptz NOT NULL,grace_until timestamptz NOT NULL,hard_until timestamptz NOT NULL,
 actor_key bytea NOT NULL CHECK(octet_length(actor_key)=32),
 owner_id uuid,owner_generation bigint,
 FOREIGN KEY(owner_id,owner_generation) REFERENCES browser_refresh_owner(owner_id,generation),
 CHECK(isfinite(first_admitted_at) AND hard_until>first_admitted_at AND hard_until<=first_admitted_at+interval '8 hours'),
 CHECK(grace_until>first_admitted_at AND grace_until<=first_admitted_at+interval '30 seconds' AND grace_until<=hard_until),
 CHECK((owner_id IS NULL)=(owner_generation IS NULL))
);
CREATE INDEX browser_refresh_consumer_owner ON browser_refresh_consumer(owner_id,owner_generation) WHERE owner_id IS NOT NULL;

-- +goose StatementBegin
CREATE FUNCTION guard_browser_refresh_owner() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.browser_session_root;s public.browser_session;c public.browser_refresh_consumer;d public.artifact_download;v public.download_response;n timestamptz;
BEGIN
 SELECT * INTO STRICT r FROM public.browser_session_root WHERE id=coalesce(NEW.root_id,OLD.root_id) FOR UPDATE;
 n:=clock_timestamp();
 IF TG_OP='DELETE' THEN
  IF OLD.joined_at IS NULL OR EXISTS(SELECT 1 FROM public.browser_refresh_consumer WHERE owner_id=OLD.owner_id AND owner_generation=OLD.generation)
  OR EXISTS(SELECT 1 FROM public.browser_session WHERE root_id=OLD.root_id AND id=OLD.session_id) THEN
   RAISE EXCEPTION 'refresh owner closure incomplete' USING ERRCODE='23514';
  END IF;RETURN OLD;
 END IF;
 IF TG_OP='INSERT' OR NEW.generation<>OLD.generation THEN
  SELECT * INTO STRICT s FROM public.browser_session WHERE root_id=NEW.root_id AND id=NEW.session_id FOR UPDATE;
  IF r.epoch<>NEW.epoch OR s.epoch<>NEW.epoch OR NOT r.enabled OR r.fresh_until<=n OR r.observed_at>n OR r.fresh_until>r.observed_at+interval '5 seconds'
  OR ROW(s.created_at,s.authenticated_at,s.expires_at) IS DISTINCT FROM ROW(NEW.session_created_at,NEW.authenticated_at,NEW.session_expires_at)
  OR s.expires_at<=n OR s.refresh_claim IS NOT NULL OR NEW.started_at>n OR NEW.started_at<n-interval '5 seconds'
  OR NEW.lease_until<=n OR NEW.lease_until>NEW.started_at+interval '15 seconds' OR NEW.joined_at IS NOT NULL OR NEW.claim IS NOT NULL
  OR TG_OP='INSERT' AND NEW.generation<>1 THEN RAISE EXCEPTION 'refresh owner admission unavailable' USING ERRCODE='23514';END IF;
  IF TG_OP='UPDATE' AND (OLD.joined_at IS NULL OR NEW.generation<>OLD.generation+1 OR NEW.owner_id=OLD.owner_id
   OR ROW(NEW.root_id,NEW.session_id,NEW.epoch,NEW.actor_key,NEW.provider_session_key,NEW.session_created_at,NEW.authenticated_at) IS DISTINCT FROM ROW(OLD.root_id,OLD.session_id,OLD.epoch,OLD.actor_key,OLD.provider_session_key,OLD.session_created_at,OLD.authenticated_at)
   OR NEW.session_expires_at>OLD.session_expires_at OR EXISTS(SELECT 1 FROM public.browser_refresh_consumer WHERE owner_id=OLD.owner_id AND owner_generation=OLD.generation)) THEN
   RAISE EXCEPTION 'refresh owner replacement requires joined closure' USING ERRCODE='23514';
  END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['lease_until','joined_at','claim','claim_joined_at','claim_version','claim_until','claim_download_id','claim_response_id','claim_response_owner','claim_response_generation']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['lease_until','joined_at','claim','claim_joined_at','claim_version','claim_until','claim_download_id','claim_response_id','claim_response_owner','claim_response_generation'])
   OR OLD.joined_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'immutable refresh owner binding' USING ERRCODE='23514';END IF;
  IF NEW.joined_at IS NOT NULL THEN
   IF NEW.claim IS NOT NULL AND NEW.claim_joined_at IS NULL THEN RAISE EXCEPTION 'refresh provider work not joined' USING ERRCODE='23514';END IF;
   IF NEW.joined_at>n OR NEW.joined_at<n-interval '5 seconds' OR NEW.lease_until<>OLD.lease_until
    OR ROW(NEW.claim,NEW.claim_version,NEW.claim_until,NEW.claim_joined_at,NEW.claim_download_id,NEW.claim_response_id,NEW.claim_response_owner,NEW.claim_response_generation) IS DISTINCT FROM ROW(OLD.claim,OLD.claim_version,OLD.claim_until,OLD.claim_joined_at,OLD.claim_download_id,OLD.claim_response_id,OLD.claim_response_owner,OLD.claim_response_generation)
    THEN RAISE EXCEPTION 'invalid joined refresh owner closure' USING ERRCODE='23514';END IF;
  ELSIF NEW.claim=OLD.claim AND NEW.claim_joined_at IS DISTINCT FROM OLD.claim_joined_at THEN
   IF OLD.claim_joined_at IS NOT NULL OR OLD.claim IS NULL OR NEW.claim_joined_at>n OR NEW.claim_joined_at<n-interval '5 seconds'
    OR (to_jsonb(NEW)-'claim_joined_at') IS DISTINCT FROM (to_jsonb(OLD)-'claim_joined_at') THEN RAISE EXCEPTION 'invalid joined provider acknowledgement' USING ERRCODE='23514';END IF;
  ELSE
   SELECT * INTO STRICT s FROM public.browser_session WHERE root_id=NEW.root_id AND id=NEW.session_id FOR UPDATE;
   IF s.epoch<>NEW.epoch OR r.epoch<>NEW.epoch OR NOT r.enabled OR r.fresh_until<=n OR r.observed_at>n OR s.expires_at<=n OR OLD.lease_until<=n
    OR NEW.lease_until<OLD.lease_until OR NEW.lease_until>n+interval '15 seconds' OR NEW.lease_until>s.expires_at AND NEW.lease_until>OLD.lease_until THEN
    RAISE EXCEPTION 'refresh owner current session unavailable' USING ERRCODE='23514';END IF;
   IF ROW(NEW.claim,NEW.claim_version,NEW.claim_until,NEW.claim_download_id,NEW.claim_response_id,NEW.claim_response_owner,NEW.claim_response_generation) IS DISTINCT FROM ROW(OLD.claim,OLD.claim_version,OLD.claim_until,OLD.claim_download_id,OLD.claim_response_id,OLD.claim_response_owner,OLD.claim_response_generation) THEN
    IF NEW.claim IS NULL OR NEW.claim_joined_at IS NOT NULL OR OLD.claim IS NOT NULL AND OLD.claim_joined_at IS NULL OR NEW.claim_version<>s.version OR NEW.claim IS DISTINCT FROM s.refresh_claim OR NEW.claim_until IS DISTINCT FROM s.claim_until OR NEW.claim_until<=n OR NEW.claim_until>n+interval '10 seconds'
     OR OLD.claim_version IS NOT NULL AND NEW.claim_version<=OLD.claim_version
     OR NOT EXISTS(SELECT 1 FROM public.browser_refresh_consumer candidate WHERE candidate.download_id=NEW.claim_download_id AND candidate.owner_id=NEW.owner_id AND candidate.owner_generation=NEW.generation AND n<candidate.hard_until) THEN
     RAISE EXCEPTION 'owned refresh requires exact one-use session claim' USING ERRCODE='23514';END IF;
    SELECT * INTO STRICT c FROM public.browser_refresh_consumer WHERE download_id=NEW.claim_download_id;
    SELECT * INTO STRICT d FROM public.artifact_download WHERE id=c.download_id AND root_id=c.download_root_id;
    IF NEW.claim_until>c.hard_until OR d.state IN ('Completed','Cancelled','Expired','Denied','Failed') OR n>=d.deadline THEN RAISE EXCEPTION 'refresh consumer ended' USING ERRCODE='23514';END IF;
    IF NEW.claim_response_id IS NULL THEN
     IF n>=c.grace_until THEN RAISE EXCEPTION 'attachment grace ended' USING ERRCODE='23514';END IF;
    ELSE
     SELECT * INTO STRICT v FROM public.download_response WHERE id=NEW.claim_response_id AND session_id=d.id;
     IF v.closed OR v.generation<>d.generation OR v.generation<>NEW.claim_response_generation OR v.owner_id<>NEW.claim_response_owner OR n>=v.lease_until OR n>=v.until_at THEN RAISE EXCEPTION 'refresh response is not current' USING ERRCODE='23514';END IF;
    END IF;
   END IF;
  END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER browser_refresh_owner_guard BEFORE INSERT OR UPDATE OR DELETE ON browser_refresh_owner FOR EACH ROW EXECUTE FUNCTION guard_browser_refresh_owner();

CREATE FUNCTION guard_browser_refresh_consumer() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE o public.browser_refresh_owner;d public.artifact_download;n timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'download refresh history retirement unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND (to_jsonb(NEW)-ARRAY['owner_id','owner_generation']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['owner_id','owner_generation']) THEN RAISE EXCEPTION 'immutable first refresh admission dates' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND NEW.owner_id IS NULL THEN
  SELECT * INTO STRICT o FROM public.browser_refresh_owner WHERE owner_id=OLD.owner_id AND generation=OLD.owner_generation;
  IF o.joined_at IS NULL THEN
   SELECT * INTO STRICT d FROM public.artifact_download WHERE id=OLD.download_id AND root_id=OLD.download_root_id;
   IF d.state NOT IN ('Completed','Cancelled','Expired','Denied','Failed') AND clock_timestamp()<OLD.hard_until
    OR o.claim_download_id=OLD.download_id AND o.claim_joined_at IS NULL THEN RAISE EXCEPTION 'consumer detachment requires ended demand and joined work' USING ERRCODE='23514';END IF;
  END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT o FROM public.browser_refresh_owner WHERE owner_id=NEW.owner_id AND generation=NEW.owner_generation;
 PERFORM 1 FROM public.browser_session_root WHERE id=o.root_id FOR UPDATE;
 SELECT * INTO STRICT o FROM public.browser_refresh_owner WHERE owner_id=NEW.owner_id AND generation=NEW.owner_generation;
 SELECT * INTO STRICT d FROM public.artifact_download WHERE id=NEW.download_id AND root_id=NEW.download_root_id FOR UPDATE;
 n:=clock_timestamp();
 IF o.joined_at IS NOT NULL OR o.lease_until<=n OR o.session_expires_at<=n OR NEW.actor_key<>o.actor_key OR NEW.actor_key<>d.actor_key
  OR n>=NEW.hard_until OR NEW.hard_until>d.deadline OR NEW.hard_until>o.session_expires_at OR d.state IN ('Completed','Cancelled','Expired','Denied','Failed')
  OR TG_OP='UPDATE' AND OLD.owner_id IS NOT NULL
  OR (SELECT count(*) FROM public.browser_refresh_consumer WHERE owner_id=o.owner_id AND owner_generation=o.generation)>=16 THEN
  RAISE EXCEPTION 'refresh consumer unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' AND (NEW.first_admitted_at>n OR NEW.first_admitted_at<n-interval '5 seconds' OR NEW.grace_until<>least(NEW.first_admitted_at+interval '30 seconds',NEW.hard_until)) THEN RAISE EXCEPTION 'invalid original attachment grace' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER browser_refresh_consumer_guard BEFORE INSERT OR UPDATE OR DELETE ON browser_refresh_consumer FOR EACH ROW EXECUTE FUNCTION guard_browser_refresh_consumer();

-- Same root lock as ordinary session creation. A logout removes authority at
-- once, but cannot refund an owner whose local/provider work has not joined.
CREATE FUNCTION guard_browser_session_owner_capacity() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.browser_session_root;n bigint;
BEGIN
 SELECT * INTO STRICT r FROM public.browser_session_root WHERE id=NEW.root_id FOR UPDATE;
 SELECT count(*) INTO n FROM (SELECT id FROM public.browser_session WHERE root_id=NEW.root_id UNION SELECT session_id FROM public.browser_refresh_owner WHERE root_id=NEW.root_id) occupied;
 IF n>=r.max_sessions OR EXISTS(SELECT 1 FROM public.browser_refresh_owner WHERE root_id=NEW.root_id AND session_id=NEW.id) THEN RAISE EXCEPTION 'browser session capacity unavailable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER browser_session_owner_capacity BEFORE INSERT ON browser_session FOR EACH ROW EXECUTE FUNCTION guard_browser_session_owner_capacity();
REVOKE ALL ON FUNCTION guard_browser_refresh_owner() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_browser_refresh_consumer() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_browser_session_owner_capacity() FROM PUBLIC;
-- Ordinary session refresh needs only a scheduling-busy bit, not authority to
-- read evidence catalog or native metadata through its SQL credential.
CREATE FUNCTION browser_owned_refresh_busy(selected_root uuid,selected_session bytea) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
SELECT EXISTS(SELECT 1 FROM public.browser_refresh_owner o WHERE o.root_id=selected_root AND o.session_id=selected_session AND o.joined_at IS NULL AND
 ((o.claim IS NOT NULL AND o.claim_joined_at IS NULL) OR
 (o.lease_until>clock_timestamp() AND o.session_expires_at>clock_timestamp() AND EXISTS(
 SELECT 1 FROM public.browser_refresh_consumer c JOIN public.artifact_download d ON d.id=c.download_id AND d.root_id=c.download_root_id
 JOIN public.context_catalog cc ON cc.artifact_id=d.artifact_id AND cc.root_id=d.root_id
 JOIN public.context_capture cp ON cp.id=cc.capture_id AND cp.root_id=cc.root_id
 JOIN public.custody_attempt ca ON ca.id=cp.attempt_id AND ca.artifact_id=d.artifact_id
 JOIN public.context_verification cv ON cv.capture_id=cp.id AND cv.root_id=cp.root_id AND cv.audit_acknowledged_at IS NOT NULL AND cv.copies_digest=ca.copies_digest
 WHERE c.owner_id=o.owner_id AND c.owner_generation=o.generation AND c.hard_until>clock_timestamp() AND d.deadline>clock_timestamp() AND d.state NOT IN ('Completed','Cancelled','Expired','Denied','Failed')
 AND ca.state='stored_unpublished' AND ca.effective_expires_at>clock_timestamp() AND (c.grace_until>clock_timestamp() OR EXISTS(
 SELECT 1 FROM public.download_response r WHERE r.session_id=d.id AND r.root_id=d.root_id AND r.generation=d.generation AND NOT r.closed AND r.lease_until>clock_timestamp() AND r.until_at>clock_timestamp()))))));
$$;
REVOKE ALL ON FUNCTION browser_owned_refresh_busy(uuid,bytea) FROM PUBLIC;
-- +goose StatementEnd
-- No destructive down or timeout-derived owner/credential refund.
