-- +goose Up
-- ADR-200 revision (2026-10-23): an accepted root capacity_source observation
-- is current for 30 seconds after its own observation instead of five, like
-- the per-workload context_storage_binding in migration 00072. Slow or failed
-- hub-worker source refreshes no longer make capture, query and download
-- admission (capacity_managed_root_until) flap. Negative and invalidating
-- observations keep their original intervals; trust, permission-stream,
-- recovery and request bounds are unchanged.
-- +goose StatementBegin
DO $$
DECLARE k name;
BEGIN
 SELECT conname INTO STRICT k FROM pg_catalog.pg_constraint WHERE conrelid='public.capacity_source'::regclass AND contype='c' AND
  pg_catalog.pg_get_constraintdef(oid) LIKE '%fresh_until <= (observed_at + ''00:00:05''::interval)%';
 EXECUTE format('ALTER TABLE public.capacity_source DROP CONSTRAINT %I',k);
END $$;
-- +goose StatementEnd
ALTER TABLE capacity_source ADD CONSTRAINT capacity_source_observation_lifetime
 CHECK(observed_at IS NULL OR (isfinite(observed_at) AND isfinite(fresh_until) AND fresh_until>observed_at AND fresh_until<=observed_at+interval '30 seconds'));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION accept_capacity_source(r uuid,expected bigint,observation jsonb,protection jsonb,recovery jsonb,qualification uuid,qualification_digest bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE source public.capacity_source;trust public.fleet_current_trust;stream public.permission_stream;snap jsonb;
 started timestamptz:=clock_timestamp();n timestamptz;observed timestamptz;until_at timestamptz;revision bigint;digest_value bytea;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') OR expected NOT BETWEEN 0 AND 1152921504606846974 OR
  NOT public.capacity_source_observation_valid(observation) OR NOT public.capacity_json_fields(protection,ARRAY['ClusterID','ControlNamespaceUID','Digest','ObservedAt','FreshUntil']) THEN
  RAISE EXCEPTION 'capacity source observation unavailable' USING ERRCODE='23514';END IF;
 snap:=observation->'Snapshot';digest_value:=public.connector_digest(observation->'Digest');
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=source.installation_id FOR SHARE;
 SELECT * INTO STRICT stream FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 observed:=GREATEST((snap->>'ObservedAt')::timestamptz,(protection->>'ObservedAt')::timestamptz,(recovery->>'ObservedAt')::timestamptz);
 until_at:=LEAST(started+interval '5 seconds',(snap->>'FreshUntil')::timestamptz,(protection->>'FreshUntil')::timestamptz,(recovery->>'FreshUntil')::timestamptz,trust.fresh_until,stream.fresh_until,stream.lease_until);
 n:=clock_timestamp();
 IF NOT COALESCE(public.capacity_recovery_current(source,trust,recovery,n) AND NOT stream.suspended AND stream.observed_at<=n AND n<stream.fresh_until AND n<stream.lease_until AND
  observed<=n AND n<until_at AND until_at<=observed+interval '5 seconds' AND isfinite(observed) AND isfinite(until_at) AND
  (snap->>'ClusterID')::uuid=source.control_cluster_id AND snap->'ControlNamespace'->>'UID'=source.control_namespace_uid AND
  (protection->>'ClusterID')::uuid=source.control_cluster_id AND protection->>'ControlNamespaceUID'=source.control_namespace_uid AND public.connector_digest(protection->'Digest')=source.source_guard_digest AND
  (protection->>'ObservedAt')::timestamptz<=n AND (protection->>'FreshUntil')::timestamptz>(protection->>'ObservedAt')::timestamptz AND (protection->>'FreshUntil')::timestamptz<=(protection->>'ObservedAt')::timestamptz+interval '5 seconds' AND
  source.qualification->>'ID'=qualification::text AND source.qualification_digest=qualification_digest,false) THEN
  RAISE EXCEPTION 'capacity source acceptance unavailable' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=stream.initial_audit_id AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=stream.epoch AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) THEN
  RAISE EXCEPTION 'capacity permission root unavailable' USING ERRCODE='23514';END IF;
 IF source.observed_at IS NOT NULL AND observed<source.observed_at THEN RAISE EXCEPTION 'capacity source observation superseded' USING ERRCODE='23514';END IF;
 IF source.observed_at=observed THEN
  IF source.suspended OR source.accepted_digest IS DISTINCT FROM digest_value OR source.accepted_snapshot IS DISTINCT FROM observation OR until_at>source.fresh_until OR source.accepted_revision NOT IN(expected,expected+1) THEN
   RAISE EXCEPTION 'capacity source observation cannot be renewed' USING ERRCODE='23514';END IF;
  RETURN jsonb_build_object('Accepted',true,'Revision',source.accepted_revision,'ObservedAt',source.observed_at,'FreshUntil',LEAST(until_at,source.fresh_until));
 END IF;
 IF source.accepted_revision<>expected THEN RAISE EXCEPTION 'capacity source changed' USING ERRCODE='23514';END IF;
 IF NOT public.capacity_source_monotonic(source.accepted_snapshot,observation) OR NOT public.capacity_source_monotonic(source.negative_snapshot,observation) THEN
  -- Commit this known restrictive result before reporting unavailable. Raising
  -- here would roll back the fence and leave the previous source authorizing.
  UPDATE public.capacity_source SET accepted_revision=accepted_revision+1,
   negative_snapshot=CASE WHEN public.capacity_source_monotonic(source.negative_snapshot,observation) THEN observation ELSE source.negative_snapshot END,
   observed_at=observed,fresh_until=until_at,suspended=true WHERE root_id=r;
  IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity negative source expired before commit' USING ERRCODE='23514';END IF;
  RETURN jsonb_build_object('Accepted',false,'Revision',source.accepted_revision+1,'ObservedAt',observed,'FreshUntil',until_at);
 END IF;
 revision:=source.accepted_revision;
 IF revision=0 OR source.suspended OR source.accepted_digest IS DISTINCT FROM digest_value THEN revision:=revision+1;END IF;
 -- ADR-200 revision: the accepted source observation lives 30 seconds from
 -- its own observation; the caller's receipt below keeps its original interval.
 UPDATE public.capacity_source SET accepted_revision=revision,accepted_snapshot=observation,accepted_digest=digest_value,negative_snapshot=NULL,observed_at=observed,fresh_until=observed+interval '30 seconds',suspended=false WHERE root_id=r;
 n:=clock_timestamp();
 IF n>=until_at OR NOT public.capacity_recovery_current(source,trust,recovery,n) THEN RAISE EXCEPTION 'capacity source expired before commit' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Accepted',true,'Revision',revision,'ObservedAt',observed,'FreshUntil',until_at);
END $$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION accept_capacity_source(r uuid,expected bigint,observation jsonb,protection jsonb,recovery jsonb,qualification uuid,qualification_digest bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE source public.capacity_source;trust public.fleet_current_trust;stream public.permission_stream;snap jsonb;
 started timestamptz:=clock_timestamp();n timestamptz;observed timestamptz;until_at timestamptz;revision bigint;digest_value bytea;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') OR expected NOT BETWEEN 0 AND 1152921504606846974 OR
  NOT public.capacity_source_observation_valid(observation) OR NOT public.capacity_json_fields(protection,ARRAY['ClusterID','ControlNamespaceUID','Digest','ObservedAt','FreshUntil']) THEN
  RAISE EXCEPTION 'capacity source observation unavailable' USING ERRCODE='23514';END IF;
 snap:=observation->'Snapshot';digest_value:=public.connector_digest(observation->'Digest');
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=source.installation_id FOR SHARE;
 SELECT * INTO STRICT stream FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 observed:=GREATEST((snap->>'ObservedAt')::timestamptz,(protection->>'ObservedAt')::timestamptz,(recovery->>'ObservedAt')::timestamptz);
 until_at:=LEAST(started+interval '5 seconds',(snap->>'FreshUntil')::timestamptz,(protection->>'FreshUntil')::timestamptz,(recovery->>'FreshUntil')::timestamptz,trust.fresh_until,stream.fresh_until,stream.lease_until);
 n:=clock_timestamp();
 IF NOT COALESCE(public.capacity_recovery_current(source,trust,recovery,n) AND NOT stream.suspended AND stream.observed_at<=n AND n<stream.fresh_until AND n<stream.lease_until AND
  observed<=n AND n<until_at AND until_at<=observed+interval '5 seconds' AND isfinite(observed) AND isfinite(until_at) AND
  (snap->>'ClusterID')::uuid=source.control_cluster_id AND snap->'ControlNamespace'->>'UID'=source.control_namespace_uid AND
  (protection->>'ClusterID')::uuid=source.control_cluster_id AND protection->>'ControlNamespaceUID'=source.control_namespace_uid AND public.connector_digest(protection->'Digest')=source.source_guard_digest AND
  (protection->>'ObservedAt')::timestamptz<=n AND (protection->>'FreshUntil')::timestamptz>(protection->>'ObservedAt')::timestamptz AND (protection->>'FreshUntil')::timestamptz<=(protection->>'ObservedAt')::timestamptz+interval '5 seconds' AND
  source.qualification->>'ID'=qualification::text AND source.qualification_digest=qualification_digest,false) THEN
  RAISE EXCEPTION 'capacity source acceptance unavailable' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=stream.initial_audit_id AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=stream.epoch AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) THEN
  RAISE EXCEPTION 'capacity permission root unavailable' USING ERRCODE='23514';END IF;
 IF source.observed_at IS NOT NULL AND observed<source.observed_at THEN RAISE EXCEPTION 'capacity source observation superseded' USING ERRCODE='23514';END IF;
 IF source.observed_at=observed THEN
  IF source.suspended OR source.accepted_digest IS DISTINCT FROM digest_value OR source.accepted_snapshot IS DISTINCT FROM observation OR until_at>source.fresh_until OR source.accepted_revision NOT IN(expected,expected+1) THEN
   RAISE EXCEPTION 'capacity source observation cannot be renewed' USING ERRCODE='23514';END IF;
  RETURN jsonb_build_object('Accepted',true,'Revision',source.accepted_revision,'ObservedAt',source.observed_at,'FreshUntil',LEAST(until_at,source.fresh_until));
 END IF;
 IF source.accepted_revision<>expected THEN RAISE EXCEPTION 'capacity source changed' USING ERRCODE='23514';END IF;
 IF NOT public.capacity_source_monotonic(source.accepted_snapshot,observation) OR NOT public.capacity_source_monotonic(source.negative_snapshot,observation) THEN
  -- Commit this known restrictive result before reporting unavailable. Raising
  -- here would roll back the fence and leave the previous source authorizing.
  UPDATE public.capacity_source SET accepted_revision=accepted_revision+1,
   negative_snapshot=CASE WHEN public.capacity_source_monotonic(source.negative_snapshot,observation) THEN observation ELSE source.negative_snapshot END,
   observed_at=observed,fresh_until=until_at,suspended=true WHERE root_id=r;
  IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity negative source expired before commit' USING ERRCODE='23514';END IF;
  RETURN jsonb_build_object('Accepted',false,'Revision',source.accepted_revision+1,'ObservedAt',observed,'FreshUntil',until_at);
 END IF;
 revision:=source.accepted_revision;
 IF revision=0 OR source.suspended OR source.accepted_digest IS DISTINCT FROM digest_value THEN revision:=revision+1;END IF;
 UPDATE public.capacity_source SET accepted_revision=revision,accepted_snapshot=observation,accepted_digest=digest_value,negative_snapshot=NULL,observed_at=observed,fresh_until=until_at,suspended=false WHERE root_id=r;
 n:=clock_timestamp();
 IF n>=until_at OR NOT public.capacity_recovery_current(source,trust,recovery,n) THEN RAISE EXCEPTION 'capacity source expired before commit' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Accepted',true,'Revision',revision,'ObservedAt',observed,'FreshUntil',until_at);
END $$;

-- +goose StatementEnd
-- Narrow observations stored under the 30-second rule to five seconds after
-- their own observation (shortening only; an expired row stays expired). The
-- row guard rejects writes to expired rows, so it is bypassed for this
-- restrictive downgrade alone.
ALTER TABLE capacity_source DISABLE TRIGGER USER;
UPDATE capacity_source SET fresh_until=observed_at+interval '5 seconds' WHERE observed_at IS NOT NULL AND fresh_until>observed_at+interval '5 seconds';
ALTER TABLE capacity_source ENABLE TRIGGER USER;
ALTER TABLE capacity_source DROP CONSTRAINT capacity_source_observation_lifetime;
ALTER TABLE capacity_source ADD CONSTRAINT capacity_source_observation_lifetime
 CHECK(observed_at IS NULL OR (isfinite(observed_at) AND isfinite(fresh_until) AND fresh_until>observed_at AND fresh_until<=observed_at+interval '5 seconds'));
