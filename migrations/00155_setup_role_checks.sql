-- +goose Up
-- Helm-native installation: runtime roles are created and reconciled by
-- `asservat setup` from the compiled grant plan, without role comments,
-- installer claims or a first-installation activation record. The paired
-- capacity setup and the audit-profile reader therefore check the role
-- name, attributes and OID only.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_audit_reader_pin_valid(s public.capacity_source) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p pg_catalog.pg_roles;
BEGIN
 SELECT * INTO STRICT p FROM pg_roles WHERE oid=s.audit_reader_role AND rolname='as_'||replace(s.installation_id::text,'-','')||'_pub_34';
 RETURN p.oid<>10 AND p.rolcanlogin AND NOT p.rolinherit AND NOT p.rolsuper AND NOT p.rolcreatedb AND NOT p.rolcreaterole AND NOT p.rolreplication AND NOT p.rolbypassrls;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_setup_original_valid(s public.capacity_source) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE x jsonb;receipt jsonb;
 purposes text[]:=ARRAY['capacity','capacity-capture','capacity-profile-read','capture-admit','capture-journal','capture-ack','capture-cleanup','capture-verifier','capture-finalizer','capture-intent-read'];
 ordinals integer[]:=ARRAY[70,71,34,40,41,42,43,44,45,16];
 a public.capture_audit_root;u pg_catalog.pg_roles;actual oid[]:='{}';at integer:=0;
BEGIN
 IF jsonb_typeof(s.setup_roles) IS DISTINCT FROM 'array' OR jsonb_array_length(s.setup_roles)<>10 THEN RETURN false;END IF;
 SELECT * INTO STRICT a FROM public.capture_audit_root WHERE root_id=s.root_id;
 IF a.installation_id<>s.installation_id THEN RETURN false;END IF;
 FOR x IN SELECT value FROM jsonb_array_elements(s.setup_roles) LOOP
  at:=at+1;receipt:=x->'Receipt';
  IF x->>'Purpose' IS DISTINCT FROM purposes[at] OR NOT public.capacity_json_integer(receipt->'roleOID',1,4294967295) OR
   receipt->>'roleName' IS DISTINCT FROM 'as_'||replace(s.installation_id::text,'-','')||'_pub_'||lpad(ordinals[at]::text,2,'0') THEN RETURN false;END IF;
  SELECT * INTO STRICT u FROM pg_roles WHERE oid=(receipt->>'roleOID')::oid AND rolname=receipt->>'roleName';
  IF u.oid=ANY(actual) OR u.oid=10 OR NOT u.rolcanlogin OR u.rolinherit OR u.rolsuper OR u.rolcreatedb OR u.rolcreaterole OR u.rolreplication OR u.rolbypassrls THEN RETURN false;END IF;
  actual:=array_append(actual,u.oid);
 END LOOP;
 RETURN actual=ARRAY[s.writer_role,s.capture_role,s.audit_reader_role,a.admission_role,a.journal_role,a.acknowledge_role,a.cleanup_role,a.verifier_role,a.finalizer_role,a.reader_role] AND a.source_role=s.capture_role;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd
