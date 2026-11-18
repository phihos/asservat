-- +goose Up
-- Committed with the permission projection so decisions never use superseded
-- grants when a replacement observation cannot be represented in full.
ALTER TABLE permission_stream ADD COLUMN unavailable_clusters text[] NOT NULL DEFAULT '{}';
-- Older deliveries contain only namespaced AccessBindings. Their digest cannot
-- confirm the complete two-kind observation. Pause the old permission epoch
-- until its worker establishes a new baseline, even on a hub with no rows yet.
UPDATE permission_stream SET suspended=true, lease_until=statement_timestamp(), observed_at=NULL, fresh_until=NULL;
DELETE FROM remote_access_binding_delivery;
-- Require writers to specify whether the two-kind observation is available.
-- A still-running v5 hub omits this column in its upsert.
ALTER TABLE remote_access_binding_delivery
 ADD COLUMN unavailable boolean NOT NULL,
 ADD COLUMN revision uuid NOT NULL DEFAULT gen_random_uuid();
-- +goose StatementBegin
CREATE FUNCTION public.withdraw_remote_bindings(target_root uuid, active_clusters uuid[]) RETURNS void
LANGUAGE plpgsql STRICT SECURITY DEFINER SET search_path TO pg_catalog, pg_temp AS $$
BEGIN
 DELETE FROM public.remote_access_binding_delivery
 WHERE root_id = target_root AND NOT (cluster_id = ANY(active_clusters));
 IF FOUND THEN
  -- End the old reconciler's lease in the same transaction as withdrawal.
  UPDATE public.permission_stream SET suspended=true, lease_until=pg_catalog.clock_timestamp(),
   observed_at=NULL, fresh_until=NULL WHERE id=target_root;
  PERFORM pg_catalog.pg_notify('asservat_remote_bindings', '');
 END IF;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.withdraw_remote_bindings(uuid,uuid[]) FROM PUBLIC;

-- Confirming an unchanged digest advances its concurrency token without
-- waking every permission reader to reload an identical fleet snapshot.
DROP TRIGGER remote_access_binding_delivery_notify ON public.remote_access_binding_delivery;
CREATE TRIGGER remote_access_binding_delivery_insert AFTER INSERT ON public.remote_access_binding_delivery
FOR EACH ROW EXECUTE FUNCTION public.notify_remote_delivery('asservat_remote_bindings');
CREATE TRIGGER remote_access_binding_delivery_update AFTER UPDATE ON public.remote_access_binding_delivery
FOR EACH ROW WHEN (OLD.digest IS DISTINCT FROM NEW.digest)
EXECUTE FUNCTION public.notify_remote_delivery('asservat_remote_bindings');

-- A mounted key Secret is limited to 1 MiB. Each public fingerprint encoded
-- as 32 JSON integers uses less than three times the bytes of its Secret entry.
ALTER TABLE local_key_configuration DROP CONSTRAINT local_key_configuration_snapshot_json_check;
ALTER TABLE local_key_configuration ADD CONSTRAINT local_key_configuration_snapshot_json_check
 CHECK (octet_length(snapshot_json) BETWEEN 1 AND 3 * 1024 * 1024);
