-- +goose Up
-- ADR-330: the latest capacity observation of each workload cluster joined
-- with mode: cluster. The federation writes it under the delivering
-- connector's authenticated cluster; the hub-worker's capacity reconciler
-- reads it. A row is an observation, never an accepted capacity fact.
CREATE TABLE remote_capacity_delivery (
 root_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 observed_at timestamptz NOT NULL CHECK(isfinite(observed_at) AND observed_at>='2020-01-01' AND observed_at<'10000-01-01'),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 namespaces bytea NOT NULL CHECK(octet_length(namespaces) BETWEEN 2 AND 8388608),
 PRIMARY KEY(root_id,cluster_id)
);

-- ADR-329/330: a changed delivery notifies the hub-worker in the writing
-- transaction (LISTEN/NOTIFY), so no reader polls the tables.
-- +goose StatementBegin
CREATE FUNCTION notify_remote_delivery() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM pg_notify(TG_ARGV[0],NEW.cluster_id::text);
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION notify_remote_delivery() FROM PUBLIC;
CREATE TRIGGER remote_access_binding_delivery_notify AFTER INSERT OR UPDATE ON remote_access_binding_delivery
 FOR EACH ROW EXECUTE FUNCTION notify_remote_delivery('asservat_remote_bindings');
CREATE TRIGGER remote_capacity_delivery_notify AFTER INSERT OR UPDATE ON remote_capacity_delivery
 FOR EACH ROW EXECUTE FUNCTION notify_remote_delivery('asservat_remote_capacity');

-- +goose Down
DROP TRIGGER remote_access_binding_delivery_notify ON remote_access_binding_delivery;
DROP TABLE remote_capacity_delivery;
DROP FUNCTION notify_remote_delivery();
