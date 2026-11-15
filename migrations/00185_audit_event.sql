-- +goose Up
-- REQ-AUT-005 / REQ-DB-004 (ADR-330 D6): audit is one append-only row per
-- event. The public operation boundary writes one `call` row before it
-- returns output; an effect writes its own row in the effect's transaction.
-- Rows carry no raw arguments, tokens or evidence content. Retention drops
-- whole time partitions; rows without a dated partition land in the default.
CREATE TABLE IF NOT EXISTS audit_event (
 event_id uuid NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 operation_id uuid NOT NULL,
 kind text NOT NULL,
 operation text NOT NULL,
 issuer text NOT NULL,
 subject text NOT NULL,
 client_id text NOT NULL,
 identity_type text NOT NULL,
 input_digest bytea,
 status text NOT NULL,
 reason text NOT NULL DEFAULT '',
 effect text NOT NULL DEFAULT 'none',
 case_ids text[] NOT NULL DEFAULT '{}',
 artifact_ids text[] NOT NULL DEFAULT '{}',
 capture_ids text[] NOT NULL DEFAULT '{}',
 share_ids text[] NOT NULL DEFAULT '{}',
 grant_ids text[] NOT NULL DEFAULT '{}',
 reservation_id uuid,
 output_bytes bigint NOT NULL DEFAULT 0,
 output_digest bytea,
 PRIMARY KEY (event_id, recorded_at)
) PARTITION BY RANGE (recorded_at);
CREATE TABLE IF NOT EXISTS audit_event_default PARTITION OF audit_event DEFAULT;
CREATE INDEX IF NOT EXISTS audit_event_operation ON audit_event(operation_id);
CREATE INDEX IF NOT EXISTS audit_event_recorded ON audit_event(recorded_at);
