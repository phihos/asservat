-- +goose Up
-- Combined-mode installations enroll their own connector with the generated
-- cluster and peer IDs (the hub-api's installation-owned bootstrap). A slot
-- that expired unclaimed is replaced by a new slot for the same peer, so the
-- per-peer uniqueness of slots moves into the reservation transaction: it
-- holds the fleet_trust lock and reserves a fixed peer only when its latest
-- slot expired unclaimed. Claims still require an unexpired slot, and the
-- peer and lineage tables keep one enrollment per peer.
ALTER TABLE IF EXISTS fleet_bootstrap_intent DROP CONSTRAINT IF EXISTS fleet_bootstrap_intent_installation_id_cluster_id_key;
ALTER TABLE IF EXISTS fleet_bootstrap_intent DROP CONSTRAINT IF EXISTS fleet_bootstrap_intent_installation_id_peer_id_key;
ALTER TABLE IF EXISTS fleet_bootstrap DROP CONSTRAINT IF EXISTS fleet_bootstrap_installation_id_peer_id_key;
-- 00169 drops these tables; the guards keep a re-Up after a downgrade probe working.
-- +goose StatementBegin
DO $$ BEGIN
 IF to_regclass('public.fleet_bootstrap_intent') IS NOT NULL THEN
  CREATE INDEX IF NOT EXISTS fleet_bootstrap_intent_peer ON fleet_bootstrap_intent(installation_id,peer_id,not_before);
 END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP INDEX IF EXISTS fleet_bootstrap_intent_peer;
-- +goose StatementBegin
DO $$ BEGIN
 IF to_regclass('public.fleet_bootstrap') IS NOT NULL THEN
  ALTER TABLE fleet_bootstrap ADD UNIQUE(installation_id,peer_id);
  ALTER TABLE fleet_bootstrap_intent ADD UNIQUE(installation_id,peer_id);
  ALTER TABLE fleet_bootstrap_intent ADD UNIQUE(installation_id,cluster_id);
 END IF;
END $$;
-- +goose StatementEnd
