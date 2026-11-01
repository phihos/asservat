-- +goose Up
-- ADR-275: an incident of a policy with several recorders admits one capture
-- per further recorder. The occurrence keeps its one execution spend and its
-- first recorder's capture/reservation (00082, 00102); each further capture
-- is one immutable row here, charged to the same acceptance output pool.
CREATE TABLE policy_occurrence_capture (
 root_id uuid NOT NULL,
 occurrence_id uuid NOT NULL REFERENCES policy_occurrence(id),
 action_id text NOT NULL CHECK (octet_length(action_id) BETWEEN 1 AND 64),
 capture_id uuid NOT NULL UNIQUE REFERENCES context_capture(id),
 grant_id uuid,
 reserved_bytes bigint NOT NULL CHECK (reserved_bytes BETWEEN 1 AND 1099511627776),
 PRIMARY KEY(occurrence_id,action_id)
);
-- +goose StatementBegin
CREATE FUNCTION protect_policy_occurrence_capture() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'policy occurrence captures never change or refund' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_policy_occurrence_capture() FROM PUBLIC;
CREATE TRIGGER policy_occurrence_capture_immutable BEFORE UPDATE OR DELETE ON policy_occurrence_capture
 FOR EACH ROW EXECUTE FUNCTION protect_policy_occurrence_capture();

-- +goose Down
-- Refuse to drop spent reservations; an empty table drops.
-- +goose StatementBegin
DO $$ BEGIN IF EXISTS(SELECT 1 FROM policy_occurrence_capture) THEN RAISE EXCEPTION 'policy occurrence captures must be retired before downgrade'; END IF; END $$;
-- +goose StatementEnd
DROP TABLE policy_occurrence_capture;
DROP FUNCTION protect_policy_occurrence_capture();
