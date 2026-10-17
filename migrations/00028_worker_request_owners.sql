-- +goose Up
-- One minimized current locator per admitted worker. Credentials and addresses
-- never enter this table. The owning process still has to authorize every effect.
CREATE TABLE download_worker_owner (
 worker_id uuid PRIMARY KEY REFERENCES download_worker(id),
 request_id uuid NOT NULL,
 pod_uid uuid NOT NULL,
 process_epoch uuid NOT NULL,
 fence bigint NOT NULL CHECK(fence BETWEEN 1 AND 9007199254740991),
 started_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 released_at timestamptz,
 CHECK(expires_at > started_at AND expires_at <= started_at + interval '30 seconds'),
 CHECK(released_at IS NULL OR released_at >= started_at)
);
CREATE UNIQUE INDEX download_worker_owner_request ON download_worker_owner(request_id);
-- +goose StatementBegin
CREATE FUNCTION guard_download_worker_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' OR NEW.fence<>OLD.fence THEN
  IF NEW.started_at>clock_timestamp() OR NEW.expires_at<=clock_timestamp() THEN
   RAISE EXCEPTION 'worker owner starts only within its original finite interval';
  END IF;
 END IF;
 IF NEW.released_at>clock_timestamp() THEN
  RAISE EXCEPTION 'worker owner release cannot be future dated';
 END IF;
 IF TG_OP='INSERT' THEN RETURN NEW; END IF;
 IF NEW.worker_id IS DISTINCT FROM OLD.worker_id THEN
  RAISE EXCEPTION 'worker owner identity is immutable';
 END IF;
 IF NEW.fence = OLD.fence THEN
  IF ROW(NEW.request_id,NEW.pod_uid,NEW.process_epoch,NEW.started_at,NEW.expires_at)
   IS DISTINCT FROM ROW(OLD.request_id,OLD.pod_uid,OLD.process_epoch,OLD.started_at,OLD.expires_at)
   OR (OLD.released_at IS NOT NULL AND NEW.released_at IS DISTINCT FROM OLD.released_at) THEN
   RAISE EXCEPTION 'worker owner lease cannot be renewed or revived';
  END IF;
 ELSE
  IF NEW.fence <> OLD.fence+1 OR NEW.request_id=OLD.request_id
   OR (OLD.released_at IS NULL AND clock_timestamp()<OLD.expires_at)
   OR NEW.started_at<OLD.started_at OR NEW.released_at IS NOT NULL THEN
   RAISE EXCEPTION 'worker owner replacement requires a finished fence and fresh request';
  END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER download_worker_owner_guard BEFORE INSERT OR UPDATE ON download_worker_owner FOR EACH ROW EXECUTE FUNCTION guard_download_worker_owner();
-- No expiry-based worker capacity refund or destructive down migration.
