-- +goose Up
-- Deferred retirement checks run after the fixed writer/view has returned. They
-- must read their own exact rows without giving capture cleanup roles access to
-- the shared lifecycle/history tables. The original read-only trigger bodies,
-- exception conditions, owner identities and deferred timing remain unchanged.
ALTER FUNCTION public.require_operation_audit_retirement() SECURITY DEFINER;
ALTER FUNCTION public.require_operation_audit_history_retirement() SECURITY DEFINER;
-- Keep relation resolution fixed and direct invocation unavailable to runtime.
ALTER FUNCTION public.require_operation_audit_retirement() SET search_path=pg_catalog,pg_temp;
ALTER FUNCTION public.require_operation_audit_history_retirement() SET search_path=pg_catalog,pg_temp;
REVOKE ALL ON FUNCTION public.require_operation_audit_retirement(),public.require_operation_audit_history_retirement() FROM PUBLIC;

-- No destructive Down or runtime base-table grants.
