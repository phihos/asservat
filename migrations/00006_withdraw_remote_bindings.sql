-- +goose Up
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
