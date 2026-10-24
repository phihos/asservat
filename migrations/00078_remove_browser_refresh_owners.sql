-- +goose Up
-- ADR-224 removes ADR-114's browser download refresh owners (2026-10-24).
-- A cookie-authenticated content GET now reads the current session like every
-- other read; when the session needs refreshing it fails closed and the
-- console resumes with Range after its own explicit POST refresh. Session
-- capacity keeps its SQL cap, now over browser sessions alone.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_browser_session_owner_capacity() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.browser_session_root;n bigint;
BEGIN
 SELECT * INTO STRICT r FROM public.browser_session_root WHERE id=NEW.root_id FOR UPDATE;
 SELECT count(*) INTO n FROM public.browser_session WHERE root_id=NEW.root_id;
 IF n>=r.max_sessions THEN RAISE EXCEPTION 'browser session capacity unavailable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_browser_session_owner_capacity() FROM PUBLIC;
DROP FUNCTION browser_owned_refresh_busy(uuid,bytea);
DROP TABLE browser_refresh_consumer;
DROP TABLE browser_refresh_owner;
DROP FUNCTION guard_browser_refresh_consumer();
DROP FUNCTION guard_browser_refresh_owner();
-- Forward-only: no down migration restores refresh-owner state.
