-- +goose Up
-- ADR-311: an API start uses one authority check for the 30 s recheck
-- interval instead of chained five-second windows, which lapsed installed
-- manual starts. The binding interval may now reach 30 s; every original
-- request, grant, retention and source deadline still bounds it, and the
-- start/acquisition instants stay inside [not_before, not_after).
-- context_execution_check is the not_after bound (it also names not_before).
ALTER TABLE context_execution DROP CONSTRAINT context_execution_check,
 ADD CONSTRAINT context_execution_check CHECK(isfinite(not_after) AND not_after>not_before AND not_after<=not_before+interval '30 seconds');

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN IF EXISTS(SELECT 1 FROM context_execution WHERE not_after>not_before+interval '5 seconds') THEN RAISE EXCEPTION 'API start bindings beyond five seconds prevent downgrade' USING ERRCODE='23514'; END IF; END $$;
-- +goose StatementEnd
ALTER TABLE context_execution DROP CONSTRAINT context_execution_check,
 ADD CONSTRAINT context_execution_check CHECK(isfinite(not_after) AND not_after>not_before AND not_after<=not_before+interval '5 seconds');
