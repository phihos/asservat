-- +goose Up
-- Required immutable versions for CURRENT retention readiness. Old rows and
-- restrictive catch-up obligations are preserved byte-for-byte. Indexes classify
-- their own receipt only; neither function reads relations or grants authority.
-- New immutable-function semantics require rebuilding these indexes in a later
-- migration, never CREATE OR REPLACE alone.

-- +goose StatementBegin
CREATE FUNCTION public.retention_checkpoint_receipt_current(input_root uuid,input_event uuid,input_receipt jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE CALLED ON NULL INPUT SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $receipt$
DECLARE receipt_value jsonb; text_value text; text_bytes bytea; field_name text;
 maximum integer; byte_index integer; octet integer; digest_value jsonb; nonzero boolean:=false;
BEGIN
 IF input_receipt IS NULL THEN RETURN false; END IF;
 receipt_value:=input_receipt;

 IF input_root IS NULL OR input_event IS NULL
 OR input_root='00000000-0000-0000-0000-000000000000'::uuid
 OR input_event='00000000-0000-0000-0000-000000000000'::uuid THEN RETURN false; END IF;
 IF jsonb_typeof(receipt_value) IS DISTINCT FROM 'object'
 OR octet_length(convert_to(receipt_value::text,'UTF8'))>4096
 OR NOT receipt_value ?& ARRAY['Key','Version','ETag','Bytes','SHA256']
 OR (receipt_value-ARRAY['Key','Version','ETag','Bytes','SHA256'])<>'{}'::jsonb THEN RETURN false; END IF;
 IF jsonb_typeof(receipt_value->'Key') IS DISTINCT FROM 'string'
 OR (receipt_value->>'Key') COLLATE "C" IS DISTINCT FROM
    ('retention-acceptance/v1/'||input_root::text||'/'||input_event::text||'/record') COLLATE "C" THEN RETURN false; END IF;
 FOREACH field_name IN ARRAY ARRAY['Version','ETag'] LOOP
  IF jsonb_typeof(receipt_value->field_name) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
  text_value:=receipt_value->>field_name;
  IF field_name='Version' AND text_value COLLATE "C"='null' COLLATE "C" THEN RETURN false; END IF;
  text_bytes:=convert_to(text_value,'UTF8');
  maximum:=CASE WHEN field_name='Version' THEN 1024 ELSE 256 END;
  IF octet_length(text_bytes)<1 OR octet_length(text_bytes)>maximum THEN RETURN false; END IF;
  -- Go identity.Text rejects Unicode Cc: U+0000..001F and U+007F..009F.
  -- Inspect fixed UTF-8 octets, independently of database/session collation.
  FOR byte_index IN 0..octet_length(text_bytes)-1 LOOP
   octet:=get_byte(text_bytes,byte_index);
   IF octet<=31 OR octet=127 THEN RETURN false; END IF;
   IF octet=194 AND byte_index+1<octet_length(text_bytes) THEN
    IF get_byte(text_bytes,byte_index+1) BETWEEN 128 AND 159 THEN RETURN false; END IF;
   END IF;
  END LOOP;
 END LOOP;
 IF jsonb_typeof(receipt_value->'Bytes') IS DISTINCT FROM 'number' THEN RETURN false; END IF;
 text_value:=receipt_value->>'Bytes';
 IF text_value COLLATE "C" !~ '^[1-9][0-9]*$' COLLATE "C"
 OR length(text_value)>6 THEN RETURN false; END IF;
 IF text_value::bigint>524288 THEN RETURN false; END IF;
 IF jsonb_typeof(receipt_value->'SHA256') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 IF jsonb_array_length(receipt_value->'SHA256')<>32 THEN RETURN false; END IF;
 FOR digest_value IN SELECT element.value FROM jsonb_array_elements(receipt_value->'SHA256') AS element(value) LOOP
  IF jsonb_typeof(digest_value) IS DISTINCT FROM 'number' THEN RETURN false; END IF;
  text_value:=digest_value#>>'{}';
  IF text_value COLLATE "C" !~ '^(0|[1-9][0-9]*)$' COLLATE "C"
  OR length(text_value)>3 THEN RETURN false; END IF;
  octet:=text_value::integer;
  IF octet>255 THEN RETURN false; END IF;
  nonzero:=nonzero OR octet>0;
 END LOOP;
 RETURN nonzero;
EXCEPTION WHEN data_exception THEN
 -- Malformed/oversized numeric, JSON, UTF-8 or NUL input denies. Do not catch
 -- cancellation, lock/I/O failure or resource exhaustion as successful input.
 RETURN false;
END;
$receipt$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.retention_lifecycle_receipt_current(input_root uuid,input_event uuid,input_receipt bytea) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE CALLED ON NULL INPUT SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $receipt$
DECLARE receipt_value jsonb; text_value text; text_bytes bytea; field_name text;
 maximum integer; byte_index integer; octet integer; digest_value jsonb; nonzero boolean:=false;
 raw_value json; raw_digest json; member_count bigint; distinct_members bigint;
BEGIN
 IF input_receipt IS NULL OR octet_length(input_receipt) NOT BETWEEN 1 AND 4096 THEN RETURN false; END IF;
 raw_value:=convert_from(input_receipt,'UTF8')::json;
 IF json_typeof(raw_value) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 SELECT count(*),count(DISTINCT member.key COLLATE "C") INTO member_count,distinct_members
 FROM json_each(raw_value) AS member;
 IF member_count<>5 OR distinct_members<>5 THEN RETURN false; END IF;
 -- bytea retains lexical JSON spelling. Reject numeric exponents/fractions
 -- before JSONB normalization; Go's integer decoder rejects these spellings.
 IF json_typeof(raw_value->'Bytes') IS DISTINCT FROM 'number'
 OR (raw_value->>'Bytes') COLLATE "C" !~ '^[1-9][0-9]*$' COLLATE "C"
 OR json_typeof(raw_value->'SHA256') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 FOR raw_digest IN SELECT element.value FROM json_array_elements(raw_value->'SHA256') AS element(value) LOOP
  IF json_typeof(raw_digest) IS DISTINCT FROM 'number'
  OR (raw_digest#>>'{}') COLLATE "C" !~ '^(0|[1-9][0-9]*)$' COLLATE "C" THEN RETURN false; END IF;
 END LOOP;
 receipt_value:=raw_value::jsonb;

 IF input_root IS NULL OR input_event IS NULL
 OR input_root='00000000-0000-0000-0000-000000000000'::uuid
 OR input_event='00000000-0000-0000-0000-000000000000'::uuid THEN RETURN false; END IF;
 IF jsonb_typeof(receipt_value) IS DISTINCT FROM 'object'
 OR octet_length(convert_to(receipt_value::text,'UTF8'))>4096
 OR NOT receipt_value ?& ARRAY['Key','Version','ETag','Bytes','SHA256']
 OR (receipt_value-ARRAY['Key','Version','ETag','Bytes','SHA256'])<>'{}'::jsonb THEN RETURN false; END IF;
 IF jsonb_typeof(receipt_value->'Key') IS DISTINCT FROM 'string'
 OR (receipt_value->>'Key') COLLATE "C" IS DISTINCT FROM
    ('lifecycle/v1/'||input_root::text||'/'||input_event::text||'/record') COLLATE "C" THEN RETURN false; END IF;
 FOREACH field_name IN ARRAY ARRAY['Version','ETag'] LOOP
  IF jsonb_typeof(receipt_value->field_name) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
  text_value:=receipt_value->>field_name;
  IF field_name='Version' AND text_value COLLATE "C"='null' COLLATE "C" THEN RETURN false; END IF;
  text_bytes:=convert_to(text_value,'UTF8');
  maximum:=CASE WHEN field_name='Version' THEN 1024 ELSE 256 END;
  IF octet_length(text_bytes)<1 OR octet_length(text_bytes)>maximum THEN RETURN false; END IF;
  -- Go identity.Text rejects Unicode Cc: U+0000..001F and U+007F..009F.
  -- Inspect fixed UTF-8 octets, independently of database/session collation.
  FOR byte_index IN 0..octet_length(text_bytes)-1 LOOP
   octet:=get_byte(text_bytes,byte_index);
   IF octet<=31 OR octet=127 THEN RETURN false; END IF;
   IF octet=194 AND byte_index+1<octet_length(text_bytes) THEN
    IF get_byte(text_bytes,byte_index+1) BETWEEN 128 AND 159 THEN RETURN false; END IF;
   END IF;
  END LOOP;
 END LOOP;
 IF jsonb_typeof(receipt_value->'Bytes') IS DISTINCT FROM 'number' THEN RETURN false; END IF;
 text_value:=receipt_value->>'Bytes';
 IF text_value COLLATE "C" !~ '^[1-9][0-9]*$' COLLATE "C"
 OR length(text_value)>6 THEN RETURN false; END IF;
 IF text_value::bigint>131072 THEN RETURN false; END IF;
 IF jsonb_typeof(receipt_value->'SHA256') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 IF jsonb_array_length(receipt_value->'SHA256')<>32 THEN RETURN false; END IF;
 FOR digest_value IN SELECT element.value FROM jsonb_array_elements(receipt_value->'SHA256') AS element(value) LOOP
  IF jsonb_typeof(digest_value) IS DISTINCT FROM 'number' THEN RETURN false; END IF;
  text_value:=digest_value#>>'{}';
  IF text_value COLLATE "C" !~ '^(0|[1-9][0-9]*)$' COLLATE "C"
  OR length(text_value)>3 THEN RETURN false; END IF;
  octet:=text_value::integer;
  IF octet>255 THEN RETURN false; END IF;
  nonzero:=nonzero OR octet>0;
 END LOOP;
 RETURN nonzero;
EXCEPTION WHEN data_exception THEN
 -- Malformed/oversized numeric, JSON, UTF-8 or NUL input denies. Do not catch
 -- cancellation, lock/I/O failure or resource exhaustion as successful input.
 RETURN false;
END;
$receipt$;
-- +goose StatementEnd

-- Explicit data-only public capability: both functions are invoker, bounded,
-- side-effect-free predicates with fixed encodings/collations and no table reads.
REVOKE ALL ON FUNCTION public.retention_checkpoint_receipt_current(uuid,uuid,jsonb),public.retention_lifecycle_receipt_current(uuid,uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.retention_checkpoint_receipt_current(uuid,uuid,jsonb),public.retention_lifecycle_receipt_current(uuid,uuid,bytea) TO PUBLIC;

CREATE INDEX retention_checkpoint_invalid_receipt
ON public.retention_checkpoint(root_id,cluster_id,namespace_uid,id)
WHERE audit_acknowledged_at IS NULL
 OR NOT public.retention_checkpoint_receipt_current(root_id,id,audit_receipt);

CREATE INDEX retention_decision_invalid_receipt
ON public.retention_decision(root_id,id)
WHERE audit_acknowledged_at IS NULL
 OR NOT public.retention_lifecycle_receipt_current(root_id,id,audit_receipt_json);

-- No destructive Down, receipt repair, replayed acknowledgement or Ready setter.
