-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION live_watch_viewers(i uuid,c uuid) RETURNS bigint LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT count(*)
 FROM public.live_watch_control w
 JOIN public.live_watch_root b ON b.root_id=w.root_id
 JOIN public.hub_owner_enrollment e ON e.installation_id=b.installation_id AND e.issuer_epoch=b.issuer_epoch AND e.process_epoch=w.owner_id AND e.usage='server'
 WHERE b.installation_id=i AND e.cluster_id=c
 AND w.state IN ('Active','Paused','Disconnected')
 AND clock_timestamp()<w.expires_at AND clock_timestamp()<w.idle_until
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_viewers(uuid,uuid) FROM PUBLIC;

-- +goose Down
DROP FUNCTION public.live_watch_viewers(uuid,uuid);
