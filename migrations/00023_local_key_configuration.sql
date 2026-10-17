-- +goose Up
CREATE TABLE local_key_configuration (
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id),
 purpose text NOT NULL CHECK (purpose IN ('artifact','audit','browser-credentials','policy-submission')),
 key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9_-]{1,128}$'),
 snapshot_json bytea NOT NULL CHECK (octet_length(snapshot_json) BETWEEN 1 AND 16384),
 PRIMARY KEY (installation_id,purpose,key_id)
);
CREATE TABLE local_key_version (
 installation_id uuid NOT NULL,
 purpose text NOT NULL,
 key_id text NOT NULL,
 version integer NOT NULL CHECK(version>0),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 PRIMARY KEY(installation_id,purpose,key_id,version),
 UNIQUE(installation_id,fingerprint),
 FOREIGN KEY(installation_id,purpose,key_id) REFERENCES local_key_configuration
);

-- +goose Down
-- Durable key/version identity is not reversibly discarded by downgrade.
SELECT 1;
