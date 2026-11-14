-- +goose Up
-- ADR-334: connectors authenticate with their cluster's ServiceAccount
-- tokens; clusters are registered only in the hub's Helm values. The one-use
-- bootstrap records, their issuance reservations and audits, the claimed
-- enrollment certificates and the rotating cluster credential lineage have
-- no producer or consumer any more.
-- Unreleased product: their rows are dropped without migration.
DROP FUNCTION activate_cluster_bootstrap(uuid,uuid,bytea,bytea);
DROP FUNCTION acknowledge_cluster_bootstrap(uuid,uuid,text,text,text,bigint,bytea);
DROP FUNCTION reserve_cluster_bootstrap(uuid,uuid,uuid,bytea,uuid,bigint,bytea,bigint,bigint);
DROP TABLE cluster_bootstrap_activation;
DROP TABLE cluster_enrollment_credential;
DROP TABLE cluster_enrollment_lineage;
DROP TABLE fleet_certificate_issue;
DROP TABLE fleet_bootstrap_intent;
DROP TABLE fleet_bootstrap;
DROP FUNCTION guard_cluster_bootstrap_activation();
DROP FUNCTION require_cluster_bootstrap_lineage();
DROP FUNCTION guard_cluster_enrollment();
DROP FUNCTION guard_certificate_issue();
DROP FUNCTION guard_bootstrap_intent();
DROP FUNCTION guard_bootstrap_issuance();
DROP FUNCTION guard_bootstrap_claim();
DROP FUNCTION guard_enrollment_receipt();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'connector bootstrap and cluster credential tables are not restored' USING ERRCODE='0A000'; END $$;
-- +goose StatementEnd
