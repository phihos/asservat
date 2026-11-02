-- +goose Up
-- ADR-279: manual finite raw packet recordings are metered from their approved
-- ad hoc grant. Each session prepays its credit once into a monotonic per-grant
-- spend row that is never refunded or deleted, so restart, replay or capture
-- deletion cannot refill the grant's reviewed maxObservedBytes.
CREATE TABLE adhoc_observation_spend (
 root_id uuid NOT NULL,
 grant_id uuid NOT NULL,
 spent bigint NOT NULL CHECK(spent>=0),
 PRIMARY KEY(root_id,grant_id),
 FOREIGN KEY(grant_id) REFERENCES access_grant(id)
);
-- +goose StatementBegin
CREATE FUNCTION protect_adhoc_observation_spend() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.root_id<>OLD.root_id OR NEW.grant_id<>OLD.grant_id OR NEW.spent<OLD.spent THEN
  RAISE EXCEPTION 'ad hoc observation spend is monotonic' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_adhoc_observation_spend() FROM PUBLIC;
CREATE TRIGGER adhoc_observation_spend_monotonic BEFORE UPDATE OR DELETE ON adhoc_observation_spend
 FOR EACH ROW EXECUTE FUNCTION protect_adhoc_observation_spend();

-- A session is either a policy session (policy and acceptance) or an ad hoc
-- one bound to its grant's own capture.
ALTER TABLE policy_observation_session ALTER COLUMN policy_uid DROP NOT NULL;
ALTER TABLE policy_observation_session ALTER COLUMN acceptance_id DROP NOT NULL;
ALTER TABLE policy_observation_session ADD CONSTRAINT policy_observation_session_kind CHECK((policy_uid IS NULL)=(acceptance_id IS NULL));
-- Only ad hoc sessions carry this key (a policy grant names no capture).
ALTER TABLE policy_observation_session ADD COLUMN adhoc_capture_id uuid
 GENERATED ALWAYS AS (CASE WHEN acceptance_id IS NULL THEN capture_id END) STORED;
ALTER TABLE policy_observation_session ADD CONSTRAINT policy_observation_session_adhoc_grant
 FOREIGN KEY(root_id,grant_id,adhoc_capture_id) REFERENCES access_grant(root_id,id,capture_id);
CREATE INDEX policy_observation_adhoc_active ON policy_observation_session(root_id,grant_id,lease_until) WHERE ended_at IS NULL AND acceptance_id IS NULL;

-- +goose StatementBegin
-- spend_adhoc_observed_bytes debits an approved, current ad hoc grant's
-- reviewed observation pool; false refuses (no row, not approved, revoked,
-- expired, or the pool would be exceeded).
CREATE FUNCTION spend_adhoc_observed_bytes(r uuid,g uuid,amount bigint) RETURNS boolean
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
REVOKE ALL ON FUNCTION spend_adhoc_observed_bytes(uuid,uuid,bigint) FROM PUBLIC;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM policy_observation_session WHERE acceptance_id IS NULL) OR EXISTS(SELECT 1 FROM adhoc_observation_spend) THEN
  RAISE EXCEPTION 'ad hoc observation state exists; refusing downgrade';
 END IF;
END $$;
-- +goose StatementEnd
DROP FUNCTION spend_adhoc_observed_bytes(uuid,uuid,bigint);
DROP INDEX policy_observation_adhoc_active;
ALTER TABLE policy_observation_session DROP CONSTRAINT policy_observation_session_adhoc_grant;
ALTER TABLE policy_observation_session DROP COLUMN adhoc_capture_id;
ALTER TABLE policy_observation_session DROP CONSTRAINT policy_observation_session_kind;
ALTER TABLE policy_observation_session ALTER COLUMN acceptance_id SET NOT NULL;
ALTER TABLE policy_observation_session ALTER COLUMN policy_uid SET NOT NULL;
DROP TRIGGER adhoc_observation_spend_monotonic ON adhoc_observation_spend;
DROP FUNCTION protect_adhoc_observation_spend();
DROP TABLE adhoc_observation_spend;
