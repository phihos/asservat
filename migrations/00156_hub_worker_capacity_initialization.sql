-- +goose Up
-- Helm-native installation (decision 6): the hub-worker initializes the
-- capacity root after its first permission acceptance with its own capacity
-- login, instead of an installer holding the SQL administrator credential.
-- The function inserts the existing capture-audit/capacity-source pair once;
-- the existing row guards still check every role, qualification and pin. A
-- present pair is never changed: the stored qualification stays in effect.
-- read_capacity_qualification returns the stored qualification (a J value
-- that runtime processes read by permission root at startup).

-- +goose StatementBegin
CREATE FUNCTION initialize_capacity_source(r uuid,cluster uuid,namespace_uid text,guard bytea,account_version text,q jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;installation uuid;prefix text;until_at timestamptz;valid boolean;o oid;i integer;
 purposes text[]:=ARRAY['capacity','capacity-capture','capacity-profile-read','capture-admit','capture-journal','capture-ack','capture-cleanup','capture-verifier','capture-finalizer','capture-intent-read'];
 ordinals integer[]:=ARRAY[70,71,34,40,41,42,43,44,45,16];
 oids oid[]:='{}';roles jsonb:='[]'::jsonb;
BEGIN
 installation:=(q->'RootBacking'->>'InstallationID')::uuid;
 prefix:='as_'||replace(installation::text,'-','')||'_pub_';
 IF r IS NULL OR cluster IS NULL OR q IS NULL OR session_user<>prefix||'70' OR (q->'RootBacking'->>'RootID')::uuid IS DISTINCT FROM r OR
  octet_length(q::text)>131072 THEN RAISE EXCEPTION 'capacity initialization input invalid' USING ERRCODE='23514';END IF;
 PERFORM 1 FROM public.fleet_current_trust WHERE installation_id=installation FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 PERFORM pg_advisory_xact_lock(1095979854,hashtext(installation::text));
 SELECT * INTO s FROM public.capacity_source WHERE root_id=r;
 IF FOUND THEN
  RETURN CASE WHEN s.installation_id=installation AND s.control_cluster_id=cluster AND s.control_namespace_uid=namespace_uid AND s.source_guard_digest=guard AND
   s.account_version=account_version AND s.qualification=q THEN 'present' ELSE 'different' END;
 END IF;
 -- The same ordering as the former installer: the permission stream is
 -- current and its initial and epoch audits are acknowledged.
 SELECT LEAST(t.fresh_until,p.fresh_until,p.lease_until),
  NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=clock_timestamp() AND NOT p.suspended AND p.observed_at<=clock_timestamp()
  AND EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=p.initial_audit_id AND a.stream_id=p.id AND a.acknowledged_at IS NOT NULL)
  AND EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=p.epoch AND a.stream_id=p.id AND a.acknowledged_at IS NOT NULL)
  INTO until_at,valid FROM public.fleet_current_trust t CROSS JOIN public.permission_stream p WHERE t.installation_id=installation AND p.id=r;
 IF NOT COALESCE(valid,false) OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity initialization waits for a current permission stream' USING ERRCODE='55000';END IF;
 FOR i IN 1..10 LOOP
  SELECT oid INTO o FROM pg_catalog.pg_roles WHERE rolname=prefix||lpad(ordinals[i]::text,2,'0');
  IF o IS NULL THEN RAISE EXCEPTION 'capacity initialization role missing' USING ERRCODE='55000';END IF;
  oids:=array_append(oids,o);
  roles:=roles||jsonb_build_array(jsonb_build_object('Purpose',purposes[i],'Receipt',jsonb_build_object('roleName',prefix||lpad(ordinals[i]::text,2,'0'),'roleOID',o)));
 END LOOP;
 INSERT INTO public.capture_audit_root(root_id,installation_id,source_role,admission_role,journal_role,acknowledge_role,cleanup_role,verifier_role,finalizer_role,reader_role,revision,paused,valid_until)
  VALUES(r,installation,oids[2],oids[4],oids[5],oids[6],oids[7],oids[8],oids[9],oids[10],1,false,(q->'RootBacking'->'Capture'->'Policy'->>'ValidUntil')::timestamptz);
 INSERT INTO public.capacity_source(root_id,installation_id,control_cluster_id,control_namespace_uid,source_guard_digest,writer_role,capture_role,audit_reader_role,audit_reader_provenance,account_version,process_limit,qualification,qualification_digest,setup_receipt,setup_input,setup_roles)
  VALUES(r,installation,cluster,namespace_uid,guard,oids[1],oids[2],oids[3],'{}'::jsonb,account_version,2,q,public.connector_digest(q->'Digest'),
   jsonb_build_object('inputDigest',encode(sha256(convert_to('asservat-capacity-initialization/v1'||q::text,'UTF8')),'hex')),
   jsonb_build_object('format','asservat-capacity-initialization/v1'),roles);
 RETURN 'created';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION initialize_capacity_source(uuid,uuid,text,bytea,text,jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION read_capacity_qualification(r uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT qualification FROM public.capacity_source WHERE root_id=r
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_capacity_qualification(uuid) FROM PUBLIC;
