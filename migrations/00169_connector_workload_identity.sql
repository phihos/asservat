-- +goose Up
-- ADR-334: connectors authenticate with their cluster's ServiceAccount
-- tokens; clusters are registered only in the hub's Helm values. The one-use
-- bootstrap records, their issuance reservations and audits, the claimed
-- enrollment certificates and the rotating cluster credential lineage have
-- no producer or consumer any more.
-- Unreleased product: their rows are dropped without migration.
-- No Down: the removed tables are not restored. IF EXISTS keeps a re-Up
-- after a downgrade probe working, as in 00167.
DROP FUNCTION IF EXISTS activate_cluster_bootstrap(uuid,uuid,bytea,bytea);
DROP FUNCTION IF EXISTS acknowledge_cluster_bootstrap(uuid,uuid,text,text,text,bigint,bytea);
DROP FUNCTION IF EXISTS reserve_cluster_bootstrap(uuid,uuid,uuid,bytea,uuid,bigint,bytea,bigint,bigint);
DROP TABLE IF EXISTS cluster_bootstrap_activation;
DROP TABLE IF EXISTS cluster_enrollment_credential;
DROP TABLE IF EXISTS cluster_enrollment_lineage;
DROP TABLE IF EXISTS fleet_certificate_issue;
DROP TABLE IF EXISTS fleet_bootstrap_intent;
DROP TABLE IF EXISTS fleet_bootstrap;
DROP FUNCTION IF EXISTS guard_cluster_bootstrap_activation();
DROP FUNCTION IF EXISTS require_cluster_bootstrap_lineage();
DROP FUNCTION IF EXISTS guard_cluster_enrollment();
DROP FUNCTION IF EXISTS guard_certificate_issue();
DROP FUNCTION IF EXISTS guard_bootstrap_intent();
DROP FUNCTION IF EXISTS guard_bootstrap_issuance();
DROP FUNCTION IF EXISTS guard_bootstrap_claim();
DROP FUNCTION IF EXISTS guard_enrollment_receipt();
