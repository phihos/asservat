-- +goose Up
ALTER TABLE retention_source ADD COLUMN watch_cursor text NOT NULL DEFAULT '' CHECK(octet_length(watch_cursor)<=128);
UPDATE retention_source s SET watch_cursor=c.transition_json#>>'{List,ResourceVersion}'
FROM retention_checkpoint c WHERE c.root_id=s.root_id AND c.cluster_id=s.cluster_id AND c.namespace_uid=s.namespace_uid AND c.sequence=s.sequence;
CREATE TABLE retention_catchup (
 checkpoint_id uuid PRIMARY KEY REFERENCES retention_checkpoint(id),
 after_attempt uuid, visited bigint NOT NULL DEFAULT 0 CHECK(visited>=0),
 shortened bigint NOT NULL DEFAULT 0 CHECK(shortened>=0 AND shortened<=visited),
 completed_at timestamptz,
 CHECK(after_attempt IS NOT NULL OR visited=0)
);
INSERT INTO retention_catchup(checkpoint_id) SELECT id FROM retention_checkpoint;
-- +goose StatementBegin
CREATE FUNCTION initialize_retention_catchup() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO retention_catchup(checkpoint_id) VALUES(NEW.id);
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER initialize_retention_catchup AFTER INSERT ON retention_checkpoint FOR EACH ROW EXECUTE FUNCTION initialize_retention_catchup();
CREATE TABLE retention_catchup_effect (
 checkpoint_id uuid NOT NULL REFERENCES retention_catchup(checkpoint_id),
 attempt_id uuid NOT NULL REFERENCES custody_attempt(id),
 decision_id uuid NOT NULL UNIQUE REFERENCES retention_decision(id),
 PRIMARY KEY(checkpoint_id,attempt_id)
);
-- +goose StatementBegin
CREATE FUNCTION protect_retention_catchup() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.checkpoint_id<>OLD.checkpoint_id OR NEW.visited<OLD.visited OR NEW.shortened<OLD.shortened
 OR (OLD.after_attempt IS NOT NULL AND (NEW.after_attempt IS NULL OR NEW.after_attempt<OLD.after_attempt))
 OR (OLD.completed_at IS NOT NULL AND NEW IS DISTINCT FROM OLD) THEN
 RAISE EXCEPTION 'retention catch-up cannot rewind';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER protect_retention_catchup BEFORE UPDATE ON retention_catchup FOR EACH ROW EXECUTE FUNCTION protect_retention_catchup();
CREATE INDEX retention_context_scan ON context_capture(root_id,attempt_id,created_at);
-- No destructive down: deleting work would erase unapplied shortening duties.
