-- +goose Up
-- A revision is the immutable effect. Its primary key deduplicates observation
-- and the indexed head row still serializes changes for this installation.
DROP TRIGGER owner_configuration_revision_guard ON public.hub_owner_configuration_revision;
DROP FUNCTION public.guard_owner_configuration_revision();
ALTER TABLE public.hub_owner_configuration_revision DROP COLUMN audit_receipt_json;

-- Append one digest-only audit row per revision, including revisions retained
-- across a development upgrade. Backfilled events record their migration time.
-- The source UID groups the immutable generation numbers for this source.
-- +goose StatementBegin
CREATE FUNCTION public.audit_owner_configuration_revision(r public.hub_owner_configuration_revision)
RETURNS void LANGUAGE sql SET search_path TO pg_catalog, pg_temp AS $$
 INSERT INTO public.audit_event(event_id,operation_id,kind,operation,issuer,subject,client_id,identity_type,input_digest,status,reason,effect)
 VALUES(gen_random_uuid(), r.source_uid, 'configuration', 'observe_owner_configuration', r.installation_id::text,
        r.cluster_id::text, 'hub-worker', 'workload', sha256(r.snapshot_json), 'success', r.generation::text, 'accepted');
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.audit_owner_configuration_revision(public.hub_owner_configuration_revision) FROM PUBLIC;
SELECT public.audit_owner_configuration_revision(r) FROM public.hub_owner_configuration_revision r;

-- The source role can insert revisions only. The trigger records the event
-- without giving it a general audit-table writer. See PostgreSQL CREATE FUNCTION,
-- “Writing SECURITY DEFINER Functions Safely”.
-- +goose StatementBegin
CREATE FUNCTION public.record_owner_configuration_revision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, pg_temp AS $$
BEGIN
 IF TG_OP <> 'INSERT' THEN
  RAISE EXCEPTION 'owner configuration revision is immutable' USING ERRCODE='23514';
 END IF;
 PERFORM public.audit_owner_configuration_revision(NEW);
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.record_owner_configuration_revision() FROM PUBLIC;
CREATE TRIGGER owner_configuration_revision_audit AFTER INSERT OR UPDATE OR DELETE ON public.hub_owner_configuration_revision
 FOR EACH ROW EXECUTE FUNCTION public.record_owner_configuration_revision();
