-- +goose Up
-- Helm-native installation: the hub-api reads the current capacity
-- qualification pin and capture audit policy at startup instead of receiving
-- them in an installer-produced input. One operation-audit retention covers
-- both audited lanes: the shorter never exceeds what either lane prepaid. Read-only; the existing profile reader
-- keeps all current-state checks.
-- +goose StatementBegin
CREATE FUNCTION read_capacity_qualification_pin(r uuid,i uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object('qualificationID',s.qualification->>'ID','qualificationDigest',encode(s.qualification_digest,'hex'),
  'accountVersion',s.account_version,'capturePolicy',s.qualification->'RootBacking'->'Capture'->'Policy',
  'operationRetentionSeconds',LEAST((s.qualification->'RootBacking'->'Normal'->>'RetainedSeconds')::bigint,(s.qualification->'RootBacking'->'Resolution'->>'RetainedSeconds')::bigint))
 FROM public.capacity_source s WHERE s.root_id=r AND s.installation_id=i
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_capacity_qualification_pin(uuid,uuid) FROM PUBLIC;

-- +goose Down
DROP FUNCTION read_capacity_qualification_pin(uuid,uuid);
