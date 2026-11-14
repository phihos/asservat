-- +goose Up
-- Helm-native installation: the hub-api writes the hub-local download
-- workers' control document, which names the evidence store the workers read.
-- The capacity qualification pin also returns that store's ID (the one
-- qualified backend). Read-only, like the rest of the pin.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION read_capacity_qualification_pin(r uuid,i uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object('qualificationID',s.qualification->>'ID','qualificationDigest',encode(s.qualification_digest,'hex'),
  'accountVersion',s.account_version,'capturePolicy',s.qualification->'RootBacking'->'Capture'->'Policy',
  'operationRetentionSeconds',LEAST((s.qualification->'RootBacking'->'Normal'->>'RetainedSeconds')::bigint,(s.qualification->'RootBacking'->'Resolution'->>'RetainedSeconds')::bigint),
  'evidenceStoreID',CASE WHEN jsonb_array_length(s.qualification->'Backends')=1 THEN s.qualification->'Backends'->0->>'EvidenceStoreID' END)
 FROM public.capacity_source s WHERE s.root_id=r AND s.installation_id=i
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_capacity_qualification_pin(uuid,uuid) FROM PUBLIC;

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION read_capacity_qualification_pin(r uuid,i uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object('qualificationID',s.qualification->>'ID','qualificationDigest',encode(s.qualification_digest,'hex'),
  'accountVersion',s.account_version,'capturePolicy',s.qualification->'RootBacking'->'Capture'->'Policy',
  'operationRetentionSeconds',LEAST((s.qualification->'RootBacking'->'Normal'->>'RetainedSeconds')::bigint,(s.qualification->'RootBacking'->'Resolution'->>'RetainedSeconds')::bigint))
 FROM public.capacity_source s WHERE s.root_id=r AND s.installation_id=i
$$;
-- +goose StatementEnd
