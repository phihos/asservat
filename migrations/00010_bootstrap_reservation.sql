-- +goose Up
-- Internal accepted intent and finite slot reservation. No row is a claimable
-- token until the separate issuance audit/finalization transaction completes.
CREATE TABLE fleet_bootstrap_intent (
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id),
 id uuid NOT NULL,
 actor_digest bytea NOT NULL CHECK(octet_length(actor_digest)=32),
 key_digest bytea NOT NULL CHECK(octet_length(key_digest)=32),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 actor_json bytea NOT NULL CHECK(octet_length(actor_json) BETWEEN 1 AND 4096),
 identity_uid text NOT NULL CHECK(octet_length(identity_uid) BETWEEN 1 AND 64),
 identity_generation bigint NOT NULL CHECK(identity_generation BETWEEN 1 AND 2147483647),
 identity_digest bytea NOT NULL CHECK(octet_length(identity_digest)=32),
 trust_uid text NOT NULL CHECK(octet_length(trust_uid) BETWEEN 1 AND 64),
 trust_generation bigint NOT NULL CHECK(trust_generation BETWEEN 1 AND 2147483647),
 trust_digest bytea NOT NULL CHECK(octet_length(trust_digest)=32),
 cluster_id uuid NOT NULL,
 peer_id uuid NOT NULL,
 issuer_epoch uuid NOT NULL,
 delivery_profile text NOT NULL CHECK(octet_length(delivery_profile) BETWEEN 1 AND 64),
 display_name text NOT NULL CHECK(octet_length(display_name) BETWEEN 1 AND 512 AND char_length(display_name)<=128),
 region text NOT NULL CHECK(octet_length(region) BETWEEN 1 AND 256 AND char_length(region)<=64),
 not_before timestamptz NOT NULL,
 not_after timestamptz NOT NULL,
 CHECK(not_after>not_before AND not_after<=not_before+interval '5 minutes'),
 PRIMARY KEY(installation_id,id),
 UNIQUE(installation_id,actor_digest,key_digest),
 UNIQUE(installation_id,cluster_id),
 UNIQUE(installation_id,peer_id)
);
CREATE INDEX fleet_bootstrap_intent_active ON fleet_bootstrap_intent(installation_id,not_after);

-- +goose StatementBegin
CREATE FUNCTION guard_bootstrap_intent() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.installation_id,NEW.id,NEW.actor_digest,NEW.key_digest,NEW.request_digest,NEW.actor_json,
 NEW.identity_uid,NEW.identity_generation,NEW.identity_digest,NEW.trust_uid,NEW.trust_generation,NEW.trust_digest,
 NEW.cluster_id,NEW.peer_id,NEW.issuer_epoch,NEW.delivery_profile,NEW.display_name,NEW.region,NEW.not_before,NEW.not_after)
 IS DISTINCT FROM ROW(OLD.installation_id,OLD.id,OLD.actor_digest,OLD.key_digest,OLD.request_digest,OLD.actor_json,
 OLD.identity_uid,OLD.identity_generation,OLD.identity_digest,OLD.trust_uid,OLD.trust_generation,OLD.trust_digest,
 OLD.cluster_id,OLD.peer_id,OLD.issuer_epoch,OLD.delivery_profile,OLD.display_name,OLD.region,OLD.not_before,OLD.not_after) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='bootstrap intent binding is immutable';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER bootstrap_intent_guard BEFORE UPDATE ON fleet_bootstrap_intent
 FOR EACH ROW EXECUTE FUNCTION guard_bootstrap_intent();
