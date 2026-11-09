-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION live_watch_read_control(r uuid,p bytea,i uuid) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE w public.live_watch_control;
BEGIN
 IF octet_length(p)<>32 OR i IS NULL THEN RAISE EXCEPTION 'live recovery locator invalid' USING ERRCODE='22023'; END IF;
 SELECT * INTO w FROM public.live_watch_control WHERE root_id=r AND principal_key=p AND id=i;
 IF NOT FOUND THEN RAISE EXCEPTION 'live recovery unavailable' USING ERRCODE='55000'; END IF;
 RETURN public.live_watch_value(w);
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION live_watch_close_control(r uuid,p bytea,i uuid,expected bigint,f uuid) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE w public.live_watch_control;
BEGIN
 IF octet_length(p)<>32 OR i IS NULL OR f IS NULL OR expected IS NULL OR expected<1 THEN RAISE EXCEPTION 'live recovery close invalid' USING ERRCODE='22023'; END IF;
 SELECT * INTO w FROM public.live_watch_control WHERE root_id=r AND principal_key=p AND id=i FOR UPDATE;
 IF NOT FOUND OR w.revision<>expected OR w.fence<>f THEN RAISE EXCEPTION 'live recovery control conflict' USING ERRCODE='23505'; END IF;
 IF w.state IN ('Active','Paused','Disconnected') THEN
  UPDATE public.live_watch_control SET state='Closed' WHERE root_id=r AND id=i RETURNING * INTO w;
 END IF;
 RETURN public.live_watch_value(w);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_read_control(uuid,bytea,uuid),live_watch_close_control(uuid,bytea,uuid,bigint,uuid) FROM PUBLIC;

-- +goose Down
DROP FUNCTION live_watch_read_control(uuid,bytea,uuid),live_watch_close_control(uuid,bytea,uuid,bigint,uuid);
