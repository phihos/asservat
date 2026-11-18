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
