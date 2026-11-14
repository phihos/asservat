-- +goose Up
-- Combined-mode installations enroll their own connector with the generated
-- cluster and peer IDs (the hub-api's installation-owned bootstrap). A slot
-- that expired unclaimed is replaced by a new slot for the same peer, so the
-- per-peer uniqueness of slots moves into the reservation transaction: it
-- holds the fleet_trust lock and reserves a fixed peer only when its latest
-- slot expired unclaimed. Claims still require an unexpired slot, and the
-- peer and lineage tables keep one enrollment per peer.
ALTER TABLE fleet_bootstrap_intent DROP CONSTRAINT fleet_bootstrap_intent_installation_id_cluster_id_key;
ALTER TABLE fleet_bootstrap_intent DROP CONSTRAINT fleet_bootstrap_intent_installation_id_peer_id_key;
ALTER TABLE fleet_bootstrap DROP CONSTRAINT fleet_bootstrap_installation_id_peer_id_key;
CREATE INDEX fleet_bootstrap_intent_peer ON fleet_bootstrap_intent(installation_id,peer_id,not_before);

-- +goose Down
DROP INDEX fleet_bootstrap_intent_peer;
ALTER TABLE fleet_bootstrap ADD UNIQUE(installation_id,peer_id);
ALTER TABLE fleet_bootstrap_intent ADD UNIQUE(installation_id,peer_id);
ALTER TABLE fleet_bootstrap_intent ADD UNIQUE(installation_id,cluster_id);
