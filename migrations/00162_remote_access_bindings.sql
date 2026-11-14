-- +goose Up
-- ADR-329: the latest AccessBinding delivery of each workload cluster joined
-- with mode: cluster. The federation writes it under the delivering
-- connector's authenticated cluster; the hub-worker's permission reconciler
-- reads it. A row is an observation, never an accepted permission.
CREATE TABLE remote_access_binding_delivery (
 root_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 observed_at timestamptz NOT NULL CHECK(isfinite(observed_at) AND observed_at>='2020-01-01' AND observed_at<'10000-01-01'),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 bindings bytea NOT NULL CHECK(octet_length(bindings) BETWEEN 2 AND 33554432),
 PRIMARY KEY(root_id,cluster_id)
);

-- +goose Down
DROP TABLE remote_access_binding_delivery;
