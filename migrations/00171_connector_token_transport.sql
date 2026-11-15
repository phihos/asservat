-- +goose Up
-- ADR-334/ADR-330 D2: context starts and key-service wraps authenticate
-- connectors by their ServiceAccount tokens. Nothing reads activated
-- connector leaves or the never-filled peer registry any more.
-- Unreleased product: their rows are dropped without migration.
-- No Down: the removed registry is not restored. IF EXISTS keeps a re-Up
-- after a downgrade probe working, as in 00167.
DROP FUNCTION IF EXISTS read_connector_activated_leaf(uuid,uuid,text,bytea,jsonb);
DROP TABLE IF EXISTS fleet_peer_certificate;
DROP TABLE IF EXISTS fleet_peer;
