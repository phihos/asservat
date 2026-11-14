-- +goose Up
-- ADR-330: the latest capacity observation of each workload cluster joined
-- with mode: cluster. The federation writes it under the delivering
-- connector's authenticated cluster; the hub-worker's capacity reconciler
-- reads it. A row is an observation, never an accepted capacity fact.
CREATE TABLE remote_capacity_delivery (
 root_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 observed_at timestamptz NOT NULL CHECK(isfinite(observed_at) AND observed_at>='2020-01-01' AND observed_at<'10000-01-01'),
 namespaces bytea NOT NULL CHECK(octet_length(namespaces) BETWEEN 2 AND 8388608),
 PRIMARY KEY(root_id,cluster_id)
);

-- +goose Down
DROP TABLE remote_capacity_delivery;
