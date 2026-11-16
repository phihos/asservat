-- +goose Up
-- PR #263 removed RecoveryIssuerEpoch and RecoveryRevision from the stored
-- context query (no component carries a recovery proof). guard_context_query
-- still required both keys, so every query admission failed. Remove the two
-- keys from its required-object list and the epoch comparison. The query row
-- keeps its issuer_epoch column, checked by context_query_intent_current.
-- Also drop context_query_qualification_valid: 00172 removed its callers and
-- the capacity_revision_valid it calls.
-- No Down: the recovery fields are not restored. Rerunning finds no body to
-- change.
-- +goose StatementBegin
DO $$
DECLARE def text; next text;
BEGIN
 def:=pg_catalog.pg_get_functiondef('public.guard_context_query()'::regprocedure);
 next:=replace(def,'''Plan'',''RecoveryIssuerEpoch'',''RecoveryRevision'',','''Plan'',');
 next:=regexp_replace(next,'NEW\.query->>''RecoveryIssuerEpoch'' IS DISTINCT FROM NEW\.issuer_epoch::text OR\s+','','g');
 IF next ~ 'Recovery(IssuerEpoch|Revision)' THEN
  RAISE EXCEPTION 'unhandled recovery reference in guard_context_query';
 END IF;
 IF next<>def THEN
  EXECUTE next;
 END IF;
END $$;
-- +goose StatementEnd

DROP FUNCTION IF EXISTS public.context_query_qualification_valid(jsonb,jsonb);
