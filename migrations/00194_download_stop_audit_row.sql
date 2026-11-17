-- +goose Up
-- ADR-330 D6/D7: stopping a download is an ordinary effect. One transaction
-- fences the session, stores the stop for idempotent replay and writes its
-- audit_event row. The prepaid stop pool, per-allocation slots, encrypted stop
-- objects, acknowledgement columns, lifecycle, history and retirement go.
DROP TRIGGER IF EXISTS download_stop_reservation ON artifact_download;
DROP TRIGGER IF EXISTS download_stop_protocol_guard ON artifact_download;
DROP TABLE IF EXISTS download_stop_history, download_stop_lifecycle, download_stop CASCADE;
DROP TABLE IF EXISTS download_stop_backing, download_stop_pool CASCADE;
DROP FUNCTION IF EXISTS reserve_download_stop(), guard_download_stop(), guard_download_stop_protocol(), guard_download_stop_backing(), guard_download_stop_pool(),
 guard_download_stop_lifecycle(), guard_download_stop_history(), create_download_stop_lifecycle(), release_download_stop_charge(), drain_download_stop_history(),
 require_download_stop_retirement(), require_download_stop_history_retirement(), download_stop_retiring(uuid), download_stop_releasing(uuid), download_stop_charge_releasing(uuid),
 finish_download_stop_retirement(uuid,uuid,uuid), finish_download_stop_history(uuid,uuid,bytea,timestamptz,timestamptz,uuid) CASCADE;
DROP FUNCTION IF EXISTS validate_download_stop_lifecycle_policy CASCADE;
ALTER TABLE artifact_download DROP COLUMN IF EXISTS stop_protocol;

-- One stop per download. A retry with the same key returns this row; another
-- key conflicts. Rows are append-only by grants (SELECT, INSERT).
CREATE TABLE IF NOT EXISTS artifact_download_stop (
 download_id uuid PRIMARY KEY,
 root_id uuid NOT NULL,
 request_id uuid NOT NULL,
 key_digest bytea NOT NULL CHECK (octet_length(key_digest)=32),
 state text NOT NULL CHECK (state IN ('Cancelled','AlreadyTerminal')),
 stopped_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY (download_id, root_id) REFERENCES artifact_download(id, root_id) ON DELETE CASCADE
);

