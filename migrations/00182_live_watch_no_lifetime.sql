-- +goose Up
-- ADR-335 D9: a live watch has no lifetime or total output limit. It ends with
-- its sources (expires_at is the sources' hard end) or after 10 idle minutes.
-- output_bytes_spent stays as accounting. Rates, slots and the per-batch cost
-- stay: they bound hub memory and connector bandwidth.
-- No Down: the earlier schema cannot represent watches without an output
-- limit. IF EXISTS keeps a re-Up after a downgrade probe working, as in
-- 00167. The unused six-argument live_watch_create stays because 00143's
-- Down drops it by name.
UPDATE live_watch_control SET state='Closed' WHERE state='Exhausted';
-- Inline column checks carry generated names; drop the affected ones by
-- definition.
-- +goose StatementBegin
DO $$ DECLARE c record; BEGIN
 FOR c IN SELECT conname FROM pg_constraint WHERE conrelid='public.live_watch_control'::regclass AND contype='c' AND
  (pg_get_constraintdef(oid) ~ 'Exhausted' OR pg_get_constraintdef(oid) ~ '(1 hour|01:00:00)' OR pg_get_constraintdef(oid) ~ 'output_limit' OR pg_get_constraintdef(oid) ~ '262144') LOOP
  EXECUTE format('ALTER TABLE public.live_watch_control DROP CONSTRAINT %I',c.conname);
 END LOOP;
END $$;
-- +goose StatementEnd
ALTER TABLE live_watch_control DROP COLUMN IF EXISTS output_limit;
ALTER TABLE live_watch_control DROP CONSTRAINT IF EXISTS live_watch_control_state_check;
ALTER TABLE live_watch_control ADD CONSTRAINT live_watch_control_state_check CHECK(state IN ('Active','Paused','Closed','Expired','AccessLost','Disconnected','SourceEnded'));
ALTER TABLE live_watch_control DROP CONSTRAINT IF EXISTS live_watch_control_expires_at_check;
ALTER TABLE live_watch_control ADD CONSTRAINT live_watch_control_expires_at_check CHECK(isfinite(expires_at) AND expires_at>accepted_at);
ALTER TABLE live_watch_control DROP CONSTRAINT IF EXISTS live_watch_control_spent_check;
ALTER TABLE live_watch_control ADD CONSTRAINT live_watch_control_spent_check CHECK(spent>=0);
ALTER TABLE live_watch_control DROP CONSTRAINT IF EXISTS live_watch_control_bytes_per_second_check;
ALTER TABLE live_watch_control ADD CONSTRAINT live_watch_control_bytes_per_second_check CHECK(bytes_per_second>=1);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION live_watch_value(w public.live_watch_control) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object('ID',w.id,'OwnerID',w.owner_id,'Fence',w.fence,
 'PrincipalKey',to_jsonb(ARRAY(SELECT get_byte(w.principal_key,g.idx) FROM generate_series(0,31) AS g(idx))),
 'WorkloadKey',to_jsonb(ARRAY(SELECT get_byte(w.workload_key,g.idx) FROM generate_series(0,31) AS g(idx))),
 'RequestDigest',to_jsonb(ARRAY(SELECT get_byte(w.request_digest,g.idx) FROM generate_series(0,31) AS g(idx))),
 'Revision',w.revision,'State',w.state,'AcceptedAt',w.accepted_at,'ExpiresAt',w.expires_at,'IdleUntil',w.idle_until,
 'Spent',w.spent,'BytesPerSecond',w.bytes_per_second)
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION live_watch_configure(r uuid,i uuid,e uuid,d bytea,l jsonb) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.live_watch_root; k text;
BEGIN
 IF octet_length(d)<>32 OR NOT public.capacity_json_fields(l,ARRAY['InstallationSlots','PrincipalSlots','WorkloadSlots','MemoryBytes','InstallationRate','InstallationBurst','PrincipalRate','PrincipalBurst','WorkloadRate','WorkloadBurst','WatchBurst','MaxRate','MaxAccounts','MaxControlRecords']) THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['InstallationSlots','PrincipalSlots','WorkloadSlots'] LOOP IF NOT public.capacity_json_integer(l->k,1,4096) THEN RETURN false; END IF; END LOOP;
 FOREACH k IN ARRAY ARRAY['InstallationRate','PrincipalRate','WorkloadRate'] LOOP IF NOT public.capacity_json_integer(l->k,1,268435456) THEN RETURN false; END IF; END LOOP;
 FOREACH k IN ARRAY ARRAY['InstallationBurst','PrincipalBurst','WorkloadBurst'] LOOP IF NOT public.capacity_json_integer(l->k,24576,1073741824) THEN RETURN false; END IF; END LOOP;
 IF NOT public.capacity_json_integer(l->'MemoryBytes',1048576,4294967296) OR NOT public.capacity_json_integer(l->'WatchBurst',24576,9007199254740991) OR NOT public.capacity_json_integer(l->'MaxRate',1,9007199254740991) OR NOT public.capacity_json_integer(l->'MaxAccounts',3,1048576) OR NOT public.capacity_json_integer(l->'MaxControlRecords',1,1048576) OR
 (l->>'PrincipalSlots')::bigint>(l->>'InstallationSlots')::bigint OR (l->>'WorkloadSlots')::bigint>(l->>'InstallationSlots')::bigint OR (l->>'MemoryBytes')::bigint<(l->>'InstallationSlots')::bigint*1048576 OR (l->>'MaxControlRecords')::bigint<(l->>'InstallationSlots')::bigint THEN RETURN false; END IF;
 INSERT INTO public.live_watch_root(root_id,installation_id,issuer_epoch,limits_digest,limits) VALUES(r,i,e,d,l) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT p FROM public.live_watch_root WHERE root_id=r FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=i AND issuer_epoch=e AND NOT suspended AND observed_at<=clock_timestamp() AND clock_timestamp()<fresh_until) THEN RETURN false; END IF;
 IF p.installation_id<>i THEN RETURN false; END IF;
 IF p.issuer_epoch=e AND p.limits_digest=d AND p.limits=l THEN RETURN true; END IF;
 IF p.limits_digest<>d OR p.limits<>l THEN
  PERFORM public.live_watch_prune(r);
  IF EXISTS(SELECT 1 FROM public.live_watch_control WHERE root_id=r) OR EXISTS(SELECT 1 FROM public.live_watch_account WHERE root_id=r) THEN RETURN false; END IF;
 END IF;
 UPDATE public.live_watch_root SET issuer_epoch=e,limits_digest=d,limits=l WHERE root_id=r;
 RETURN true;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION live_watch_create_cluster(r uuid,o uuid,d bytea,c jsonb,key bytea,bound timestamptz,k bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.live_watch_root; w public.live_watch_control; n timestamptz; counts record; knd text; a bytea; burst bigint; initial_key bytea;
BEGIN
 SELECT * INTO STRICT p FROM public.live_watch_root WHERE root_id=r FOR UPDATE;
 n:=clock_timestamp();
 IF o IS NULL OR d IS NULL OR key IS NULL OR bound IS NULL OR k IS NULL OR NOT isfinite(bound) OR n>=bound OR p.limits_digest<>d OR octet_length(key)<>32 OR octet_length(k)<>32 OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=p.installation_id AND issuer_epoch=p.issuer_epoch AND NOT suspended AND observed_at<=n AND n<fresh_until) THEN RAISE EXCEPTION 'live owner or limits unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO w FROM public.live_watch_control WHERE root_id=r AND key_hash=key;
 IF FOUND THEN
  IF w.principal_key<>public.live_watch_digest(c->'PrincipalKey') OR w.request_digest<>public.live_watch_digest(c->'RequestDigest') THEN RAISE EXCEPTION 'live request conflict' USING ERRCODE='23505'; END IF;
  IF w.owner_id<>o OR w.cluster_key IS DISTINCT FROM k THEN RAISE EXCEPTION 'live owner unavailable' USING ERRCODE='23514'; END IF;
  RETURN jsonb_build_object('control',public.live_watch_value(w),'reused',true);
 END IF;
 PERFORM public.live_watch_prune(r);
 IF NOT public.capacity_json_fields(c,ARRAY['ID','OwnerID','Fence','PrincipalKey','WorkloadKey','RequestDigest','Revision','State','AcceptedAt','ExpiresAt','IdleUntil','Spent','BytesPerSecond']) OR (c->>'OwnerID')::uuid<>o OR (c->>'Revision')::bigint<>1 OR c->>'State'<>'Active' OR (c->>'Spent')::bigint<>0 OR
 (c->>'AcceptedAt')::timestamptz>n OR (c->>'AcceptedAt')::timestamptz<n-interval '5 seconds' OR (c->>'ExpiresAt')::timestamptz<=n OR (c->>'IdleUntil')::timestamptz<=n OR (c->>'IdleUntil')::timestamptz>(c->>'AcceptedAt')::timestamptz+interval '10 minutes' OR (c->>'BytesPerSecond')::bigint>(p.limits->>'MaxRate')::bigint THEN RAISE EXCEPTION 'invalid initial live control' USING ERRCODE='23514'; END IF;
 SELECT count(*) AS total,count(*) FILTER(WHERE state IN ('Active','Paused','Disconnected') AND n<expires_at AND n<idle_until) AS active,
 count(*) FILTER(WHERE state IN ('Active','Paused','Disconnected') AND n<expires_at AND n<idle_until AND principal_key=public.live_watch_digest(c->'PrincipalKey')) AS principal,
 count(*) FILTER(WHERE state IN ('Active','Paused','Disconnected') AND n<expires_at AND n<idle_until AND workload_key=public.live_watch_digest(c->'WorkloadKey')) AS workload INTO counts FROM public.live_watch_control WHERE root_id=r;
 IF counts.total>=(p.limits->>'MaxControlRecords')::bigint OR counts.active>=(p.limits->>'InstallationSlots')::bigint OR counts.principal>=(p.limits->>'PrincipalSlots')::bigint OR counts.workload>=(p.limits->>'WorkloadSlots')::bigint THEN RAISE EXCEPTION 'live capacity unavailable' USING ERRCODE='54000'; END IF;
 initial_key:=decode(replace(r::text,'-','')||repeat('00',16),'hex');
 FOREACH knd IN ARRAY ARRAY['installation','principal','workload'] LOOP
  a:=CASE knd WHEN 'installation' THEN initial_key WHEN 'principal' THEN public.live_watch_digest(c->'PrincipalKey') ELSE public.live_watch_digest(c->'WorkloadKey') END;
  IF NOT EXISTS(SELECT 1 FROM public.live_watch_account WHERE root_id=r AND kind=knd AND account_key=a) THEN
   IF (SELECT count(*) FROM public.live_watch_account WHERE root_id=r)>=(p.limits->>'MaxAccounts')::bigint THEN RAISE EXCEPTION 'live accounts unavailable' USING ERRCODE='54000'; END IF;
   burst:=(p.limits->>(CASE knd WHEN 'installation' THEN 'InstallationBurst' WHEN 'principal' THEN 'PrincipalBurst' ELSE 'WorkloadBurst' END))::bigint;
   INSERT INTO public.live_watch_account VALUES(r,knd,a,burst*1000000,n);
  END IF;
 END LOOP;
 INSERT INTO public.live_watch_control(root_id,id,owner_id,fence,principal_key,workload_key,request_digest,key_hash,revision,state,accepted_at,expires_at,idle_until,spent,bytes_per_second,tokens_micro,refilled_at,cluster_key)
 VALUES(r,(c->>'ID')::uuid,o,(c->>'Fence')::uuid,public.live_watch_digest(c->'PrincipalKey'),public.live_watch_digest(c->'WorkloadKey'),public.live_watch_digest(c->'RequestDigest'),key,1,'Active',(c->>'AcceptedAt')::timestamptz,(c->>'ExpiresAt')::timestamptz,(c->>'IdleUntil')::timestamptz,0,(c->>'BytesPerSecond')::bigint,(p.limits->>'WatchBurst')::bigint*1000000,n,k) RETURNING * INTO w;
 RETURN jsonb_build_object('control',public.live_watch_value(w),'reused',false);
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION live_watch_change(r uuid,o uuid,d bytea,c jsonb,expected bigint,cost bigint,bound timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.live_watch_root; w public.live_watch_control; n timestamptz; k text; a bytea; bucket public.live_watch_account; rate bigint;burst bigint;available bigint;oldjson jsonb;
BEGIN
 SELECT * INTO STRICT p FROM public.live_watch_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT w FROM public.live_watch_control WHERE root_id=r AND id=(c->>'ID')::uuid FOR UPDATE;
 n:=clock_timestamp();oldjson:=public.live_watch_value(w);
 -- cost: one batch, at most the 24 KiB default MCP result.
 IF o IS NULL OR d IS NULL OR expected IS NULL OR cost IS NULL OR bound IS NULL OR NOT isfinite(bound) OR w.owner_id<>o OR p.limits_digest<>d OR w.revision<>expected OR cost<0 OR cost>24576 OR NOT public.capacity_json_fields(c,ARRAY['ID','OwnerID','Fence','PrincipalKey','WorkloadKey','RequestDigest','Revision','State','AcceptedAt','ExpiresAt','IdleUntil','Spent','BytesPerSecond']) OR
 (oldjson-ARRAY['Revision','State','Spent','IdleUntil','AcceptedAt','ExpiresAt']) IS DISTINCT FROM (c-ARRAY['Revision','State','Spent','IdleUntil','AcceptedAt','ExpiresAt']) OR w.accepted_at IS DISTINCT FROM (c->>'AcceptedAt')::timestamptz OR w.expires_at IS DISTINCT FROM (c->>'ExpiresAt')::timestamptz OR (c->>'Spent')::bigint<>w.spent+cost OR (c->>'Revision')::bigint NOT IN (w.revision,w.revision+1) OR
 ((c->>'Revision')::bigint=w.revision AND (cost=0 OR c->>'State'<>w.state AND NOT(w.state IN ('Active','Paused','Disconnected') AND c->>'State' IN ('Disconnected','SourceEnded')))) OR ((c->>'Revision')::bigint=w.revision+1 AND cost<>0) OR
 (w.state NOT IN ('Active','Paused','Disconnected') AND (c->>'State'<>w.state OR cost<>0)) OR (c->>'IdleUntil')::timestamptz>w.expires_at OR (c->>'IdleUntil')::timestamptz>n+interval '10 minutes' THEN RAISE EXCEPTION 'live revision or control conflict' USING ERRCODE='23505'; END IF;
 IF c->>'State'<>'Closed' AND (n>=bound OR n>=w.expires_at OR n>=w.idle_until OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=p.installation_id AND issuer_epoch=p.issuer_epoch AND NOT suspended AND observed_at<=n AND n<fresh_until)) THEN RAISE EXCEPTION 'live owner or original bound unavailable' USING ERRCODE='23514'; END IF;
 IF c->>'State'='Closed' AND ((c->>'IdleUntil')::timestamptz<>w.idle_until OR cost<>0) THEN RAISE EXCEPTION 'live close cannot renew or disclose' USING ERRCODE='23514'; END IF;
 IF cost>0 THEN
  IF n<w.refilled_at THEN RAISE EXCEPTION 'live clock unavailable' USING ERRCODE='23514'; END IF;
  available:=public.live_watch_refilled(w.tokens_micro,w.refilled_at,n,w.bytes_per_second,(p.limits->>'WatchBurst')::bigint);
  IF available<cost*1000000 THEN RAISE EXCEPTION 'live watch rate unavailable' USING ERRCODE='54000'; END IF;
  w.tokens_micro:=available-cost*1000000;w.refilled_at:=n;
  FOREACH k IN ARRAY ARRAY['installation','principal','workload'] LOOP
   a:=CASE k WHEN 'installation' THEN decode(replace(r::text,'-','')||repeat('00',16),'hex') WHEN 'principal' THEN w.principal_key ELSE w.workload_key END;
   SELECT * INTO STRICT bucket FROM public.live_watch_account WHERE root_id=r AND kind=k AND account_key=a FOR UPDATE;
   rate:=(p.limits->>(CASE k WHEN 'installation' THEN 'InstallationRate' WHEN 'principal' THEN 'PrincipalRate' ELSE 'WorkloadRate' END))::bigint;
   burst:=(p.limits->>(CASE k WHEN 'installation' THEN 'InstallationBurst' WHEN 'principal' THEN 'PrincipalBurst' ELSE 'WorkloadBurst' END))::bigint;
   IF n<bucket.refilled_at THEN RAISE EXCEPTION 'live clock unavailable' USING ERRCODE='23514'; END IF;
   available:=public.live_watch_refilled(bucket.tokens_micro,bucket.refilled_at,n,rate,burst);
   IF available<cost*1000000 THEN RAISE EXCEPTION 'live aggregate rate unavailable' USING ERRCODE='54000'; END IF;
   UPDATE public.live_watch_account SET tokens_micro=available-cost*1000000,refilled_at=n WHERE root_id=r AND kind=k AND account_key=a;
  END LOOP;
 END IF;
 UPDATE public.live_watch_control SET revision=(c->>'Revision')::bigint,state=c->>'State',spent=(c->>'Spent')::bigint,idle_until=(c->>'IdleUntil')::timestamptz,tokens_micro=w.tokens_micro,refilled_at=w.refilled_at WHERE id=w.id RETURNING * INTO w;
 RETURN public.live_watch_value(w);
END $$;
-- +goose StatementEnd
