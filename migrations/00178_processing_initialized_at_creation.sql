-- +goose Up
-- ADR-335 D1: processing is initialized when its root is created, so no
-- manual initialize_processing call is needed. A new root has no catalog
-- rows (catalog publication requires an initialized root), which is what
-- the manual decision asserted. Initialization spends the same root
-- transition unit and sequence step as the decision did. The trigger name
-- sorts after processing_root_guard, which still checks the initial row.
-- No Down; every statement tolerates a re-Up after a downgrade probe.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION initialize_processing_root() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 NEW.initialized_at:=clock_timestamp(); NEW.initialization_id:=NEW.epoch;
 NEW.root_transitions:=NEW.root_transitions+1; NEW.sequence:=NEW.sequence+1;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION initialize_processing_root() FROM PUBLIC;
DROP TRIGGER IF EXISTS processing_root_initialize ON processing_root;
CREATE TRIGGER processing_root_initialize BEFORE INSERT ON processing_root FOR EACH ROW EXECUTE FUNCTION initialize_processing_root();
