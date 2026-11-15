-- +goose Up
-- ADR-335 D4 / REQ-PER-001: an AccessBinding names workloads by kind and
-- name; an optional uid pins one instance. permission_basis.workload_uids
-- holds a pinned uid or "Kind/Name". A workload UID never changes its kind
-- or name, so the hub records both for every Deployment or StatefulSet it
-- resolves, and evaluation matches a "Kind/Name" entry through this table.
CREATE TABLE IF NOT EXISTS workload_name(
 cluster_id uuid NOT NULL,
 workload_uid text NOT NULL,
 ref text NOT NULL,
 PRIMARY KEY(cluster_id,workload_uid));

-- +goose Down
DROP TABLE IF EXISTS workload_name;
