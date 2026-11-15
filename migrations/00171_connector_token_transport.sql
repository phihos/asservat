-- +goose Up
-- ADR-334/ADR-330 D2: context starts and key-service wraps authenticate
-- connectors by their ServiceAccount tokens. Nothing reads activated
-- connector leaves or the never-filled peer registry any more.
-- Unreleased product: their rows are dropped without migration.
DROP FUNCTION read_connector_activated_leaf(uuid,uuid,text,bytea,jsonb);
DROP TABLE fleet_peer_certificate;
DROP TABLE fleet_peer;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'connector leaf reads and the peer registry are not restored' USING ERRCODE='0A000'; END $$;
-- +goose StatementEnd
