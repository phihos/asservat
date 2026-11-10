-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION live_watch_viewers(i uuid,c uuid) RETURNS bigint LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT count(DISTINCT w.id)
 FROM public.live_watch_control w
 JOIN public.live_watch_root b ON b.root_id=w.root_id
 JOIN public.fleet_current_trust t ON t.installation_id=b.installation_id AND t.issuer_epoch=b.issuer_epoch
 JOIN public.hub_owner_enrollment e ON e.installation_id=b.installation_id AND e.issuer_epoch=b.issuer_epoch AND e.process_epoch=w.owner_id AND e.usage='server'
 WHERE b.installation_id=i AND e.cluster_id=c
 AND NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=clock_timestamp() AND clock_timestamp()<t.fresh_until
 AND e.audit_receipt_json IS NOT NULL AND e.retired_at IS NULL AND clock_timestamp()<e.hold_until
 AND EXISTS(SELECT 1 FROM public.hub_owner_certificate a WHERE a.enrollment_id=e.id AND a.activated_at IS NOT NULL AND clock_timestamp()<a.not_after)
 AND w.state IN ('Active','Paused','Disconnected')
 AND clock_timestamp()<w.expires_at AND clock_timestamp()<w.idle_until
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_viewers(uuid,uuid) FROM PUBLIC;

-- +goose Down
DROP FUNCTION public.live_watch_viewers(uuid,uuid);
