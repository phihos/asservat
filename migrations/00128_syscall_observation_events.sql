-- +goose Up
-- ADR-281: reserve syscall events and input bytes atomically from the same
-- approved ad hoc observation pool; existing packet callers spend zero events.
ALTER TABLE adhoc_observation_spend ADD COLUMN events_spent bigint NOT NULL DEFAULT 0 CHECK(events_spent>=0);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_adhoc_observation_spend() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.root_id<>OLD.root_id OR NEW.grant_id<>OLD.grant_id OR NEW.spent<OLD.spent OR NEW.events_spent<OLD.events_spent THEN
  RAISE EXCEPTION 'ad hoc observation spend is monotonic' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION spend_adhoc_observation(r uuid,g uuid,amount bigint,events bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE grant_row public.access_grant; byte_ceiling bigint; event_ceiling bigint; used public.adhoc_observation_spend;
BEGIN
 IF amount IS NULL OR events IS NULL OR amount<1 OR events<0 THEN RETURN false; END IF;
 SELECT * INTO grant_row FROM public.access_grant WHERE root_id=r AND id=g FOR SHARE;
 IF NOT FOUND OR grant_row.kind<>'adHocCapture' OR grant_row.decision IS DISTINCT FROM 'approved'
  OR grant_row.revoked_at IS NOT NULL OR grant_row.expires_at<=clock_timestamp() THEN RETURN false; END IF;
 byte_ceiling:=(convert_from(grant_row.scope,'UTF8')::jsonb#>>'{approval,observationLimits,maxObservedBytes}')::bigint;
 event_ceiling:=COALESCE((convert_from(grant_row.scope,'UTF8')::jsonb#>>'{approval,observationLimits,maxObservedEvents}')::bigint,0);
 IF byte_ceiling IS NULL OR byte_ceiling<1 OR event_ceiling<0 THEN RETURN false; END IF;
 INSERT INTO public.adhoc_observation_spend(root_id,grant_id,spent,events_spent) VALUES(r,g,0,0) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT used FROM public.adhoc_observation_spend WHERE root_id=r AND grant_id=g FOR UPDATE;
 -- The original grant lock prevents revision changes, not passage of time.
 IF grant_row.expires_at<=clock_timestamp() OR amount>byte_ceiling-used.spent OR events>event_ceiling-used.events_spent THEN RETURN false; END IF;
 UPDATE public.adhoc_observation_spend SET spent=spent+amount,events_spent=events_spent+events WHERE root_id=r AND grant_id=g;
 RETURN true;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION spend_adhoc_observation(uuid,uuid,bigint,bigint) FROM PUBLIC;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION spend_adhoc_observed_bytes(r uuid,g uuid,amount bigint) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.spend_adhoc_observation(r,g,amount,0);
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM adhoc_observation_spend WHERE events_spent<>0) THEN
  RAISE EXCEPTION 'retained syscall observation event spend prevents downgrade';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION spend_adhoc_observed_bytes(r uuid,g uuid,amount bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE grant_row public.access_grant; ceiling bigint; used bigint;
BEGIN
 SELECT * INTO grant_row FROM public.access_grant WHERE root_id=r AND id=g FOR SHARE;
 IF NOT FOUND OR grant_row.kind<>'adHocCapture' OR grant_row.decision IS DISTINCT FROM 'approved'
  OR grant_row.revoked_at IS NOT NULL OR grant_row.expires_at<=clock_timestamp() OR amount<1 THEN
  RETURN false;
 END IF;
 ceiling:=(convert_from(grant_row.scope,'UTF8')::jsonb#>>'{approval,observationLimits,maxObservedBytes}')::bigint;
 IF ceiling IS NULL OR ceiling<1 THEN
  RETURN false;
 END IF;
 INSERT INTO public.adhoc_observation_spend(root_id,grant_id,spent) VALUES(r,g,0) ON CONFLICT DO NOTHING;
 SELECT spent INTO used FROM public.adhoc_observation_spend WHERE root_id=r AND grant_id=g FOR UPDATE;
 IF used+amount>ceiling THEN
  RETURN false;
 END IF;
 UPDATE public.adhoc_observation_spend SET spent=spent+amount WHERE root_id=r AND grant_id=g;
 RETURN true;
END $$;
-- +goose StatementEnd
DROP FUNCTION spend_adhoc_observation(uuid,uuid,bigint,bigint);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_adhoc_observation_spend() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.root_id<>OLD.root_id OR NEW.grant_id<>OLD.grant_id OR NEW.spent<OLD.spent THEN
  RAISE EXCEPTION 'ad hoc observation spend is monotonic' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
ALTER TABLE adhoc_observation_spend DROP COLUMN events_spent;
