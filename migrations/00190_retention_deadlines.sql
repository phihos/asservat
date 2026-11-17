-- +goose Up
-- ADR-330 D12: retention is stored deadlines. A retention policy event
-- shortens the stored deadlines of the matching artifacts with one set-based
-- update and writes one audit row in the same transaction. Source epochs,
-- checkpoints, watch cursors and catch-up pages are dropped. Unreleased
-- product: their rows are deleted without migration. There is no Down: a
-- downgrade probe keeps the dropped tables, and rerunning this file changes
-- nothing.
DROP TABLE IF EXISTS retention_catchup_effect;
DROP TABLE IF EXISTS retention_catchup;
DROP TABLE IF EXISTS retention_checkpoint;
DROP TABLE IF EXISTS retention_source_epoch;
DROP TABLE IF EXISTS retention_source;
DROP FUNCTION IF EXISTS initialize_retention_catchup();
DROP FUNCTION IF EXISTS protect_retention_catchup();
DROP FUNCTION IF EXISTS retention_checkpoint_immutable();
DROP FUNCTION IF EXISTS retention_source_monotonic();
DROP FUNCTION IF EXISTS retain_list_watermark();
DROP FUNCTION IF EXISTS public.retention_checkpoint_receipt_current(uuid,uuid,bytea);
DROP INDEX IF EXISTS retention_context_scan;

-- The current policy set of the hub control namespace, written by the hub
-- worker from the EvidenceRetentionPolicy watch and read by collection.
CREATE TABLE IF NOT EXISTS retention_policy (
 uid text PRIMARY KEY CHECK(octet_length(uid) BETWEEN 1 AND 64),
 name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 253),
 generation bigint NOT NULL CHECK(generation>0),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 policy jsonb NOT NULL,
 effect jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- One append-only audit row per applied policy event.
CREATE TABLE IF NOT EXISTS retention_policy_event (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 uid text NOT NULL, name text NOT NULL, generation bigint NOT NULL,
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 change text NOT NULL CHECK(change IN ('applied','removed')),
 shortened bigint NOT NULL CHECK(shortened>=0),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- retention_policy_effect returns the shortened deadlines one policy implies
-- for the retained artifacts it matches: evidence by cluster and native
-- type, capture-history parameters by cluster as case metadata. p is
-- {"clusters":[uuid...] or [] for all, "maxima":{nativeType:seconds},
--  "caseMaximum":seconds, "budget":seconds}. It returns every matched row
-- with its current and its shortened deadlines; a row changes when either
-- is earlier; one_attempt limits it to one attempt. Apply, preview and the
-- admission trigger below share it.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retention_policy_effect(p jsonb, one_attempt uuid DEFAULT NULL)
RETURNS TABLE(attempt_id uuid, cluster_id uuid, native_type text, case_metadata boolean, old_expires_at timestamptz, old_delete_by timestamptz, expires_at timestamptz, delete_by timestamptz)
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
 WITH scoped AS (
  SELECT a.id, a.cluster_id, a.anchor_at, a.effective_expires_at, a.effective_delete_by,
   coalesce(convert_from(c.expectation_json,'UTF8')::jsonb->>'NativeType','') AS native_type, false AS case_metadata
  FROM public.custody_attempt a JOIN public.context_capture c ON c.attempt_id=a.id
  WHERE a.state<>'deleted' AND (one_attempt IS NULL OR a.id=one_attempt)
  UNION ALL
  SELECT a.id, a.cluster_id, a.anchor_at, a.effective_expires_at, a.effective_delete_by, NULL, true
  FROM public.custody_attempt a JOIN public.capture_history_parameter h ON h.attempt_id=a.id
  WHERE a.state<>'deleted' AND (one_attempt IS NULL OR a.id=one_attempt)
 ), limited AS (
  SELECT s.*, (CASE WHEN s.case_metadata THEN (p->>'caseMaximum')::bigint ELSE (p->'maxima'->>s.native_type)::bigint END) AS maximum
  FROM scoped s
  WHERE jsonb_array_length(p->'clusters')=0 OR p->'clusters' ? s.cluster_id::text
 ), next AS (
  SELECT l.id, l.cluster_id, l.native_type, l.case_metadata,
   least(l.effective_delete_by, l.anchor_at+make_interval(secs=>l.maximum)) AS delete_by,
   least(l.effective_expires_at, greatest(l.anchor_at, l.anchor_at+make_interval(secs=>l.maximum-(p->>'budget')::bigint))) AS expires_at,
   l.effective_expires_at AS old_expires, l.effective_delete_by AS old_delete
  FROM limited l WHERE l.maximum IS NOT NULL
 )
 SELECT n.id, n.cluster_id, n.native_type, n.case_metadata, n.old_expires, n.old_delete,
  least(n.expires_at, n.delete_by-interval '1 microsecond'), n.delete_by
 FROM next n
$$;
-- +goose StatementEnd

-- retention_preview aggregates the effects of proposed policies (ADR-240)
-- as a JSON array of groups: each matched artifact takes the earliest
-- deadlines of all effects. It writes nothing.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retention_preview(effects jsonb) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
 WITH e AS (
  SELECT r.attempt_id, r.cluster_id, r.native_type, r.case_metadata,
   min(r.old_expires_at) AS old_expires_at, min(r.old_delete_by) AS old_delete_by,
   min(r.expires_at) AS expires_at, min(r.delete_by) AS delete_by
  FROM jsonb_array_elements(effects) p, LATERAL public.retention_policy_effect(p.value) r
  GROUP BY 1,2,3,4
 ), c AS (
  SELECT e.*, (e.expires_at<e.old_expires_at OR e.delete_by<e.old_delete_by) AS changed FROM e
 ), g AS (
  SELECT c.cluster_id, coalesce(c.native_type,'') AS native_type, c.case_metadata, count(*) AS scanned,
   count(*) FILTER (WHERE c.changed) AS affected,
   count(*) FILTER (WHERE c.expires_at<=clock_timestamp() AND c.old_expires_at>clock_timestamp()) AS read_closed,
   count(*) FILTER (WHERE c.changed AND c.delete_by<=clock_timestamp()) AS deletion_due,
   min(c.expires_at) FILTER (WHERE c.changed) AS earliest_expires_at,
   min(c.delete_by) FILTER (WHERE c.changed) AS earliest_delete_by
  FROM c GROUP BY 1,2,3
 )
 SELECT coalesce(jsonb_agg(to_jsonb(g)),'[]'::jsonb) FROM g
$$;
-- +goose StatementEnd

-- A new artifact is never longer than any stored policy allows. The hub
-- worker locks retention_policy while it changes policies and applies them;
-- admissions take a share lock here, so a policy committed during an
-- admission either reaches this trigger or sees the admitted row.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.apply_retention_policies() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p jsonb;
BEGIN
 LOCK TABLE public.retention_policy IN SHARE MODE;
 FOR p IN SELECT r.effect FROM public.retention_policy r LOOP
  UPDATE public.custody_attempt a SET effective_expires_at=e.expires_at, effective_delete_by=e.delete_by
  FROM public.retention_policy_effect(p, NEW.attempt_id) e
  WHERE a.id=e.attempt_id AND (e.expires_at<a.effective_expires_at OR e.delete_by<a.effective_delete_by);
 END LOOP;
 RETURN NULL;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS zz_apply_retention_policies ON context_capture;
CREATE TRIGGER zz_apply_retention_policies AFTER INSERT ON context_capture FOR EACH ROW EXECUTE FUNCTION apply_retention_policies();
DROP TRIGGER IF EXISTS zz_apply_retention_policies ON capture_history_parameter;
CREATE TRIGGER zz_apply_retention_policies AFTER INSERT ON capture_history_parameter FOR EACH ROW EXECUTE FUNCTION apply_retention_policies();

-- Effective deadlines only shorten. A policy shortening keeps the sequence;
-- an early-erasure decision still advances it with its exact decision row.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.protect_custody_retention() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.retention_sequence<>0 OR (NEW.effective_expires_at IS NOT NULL AND NEW.effective_expires_at<>NEW.expires_at) OR (NEW.effective_delete_by IS NOT NULL AND NEW.effective_delete_by<>NEW.delete_by) THEN RAISE EXCEPTION 'initial retention must match registration'; END IF;
  NEW.effective_expires_at:=NEW.expires_at;NEW.effective_delete_by:=NEW.delete_by;RETURN NEW;
 END IF;
 IF (NEW.id,NEW.cluster_id,NEW.artifact_id,NEW.allocation_id,NEW.request_digest,NEW.pool_revision,NEW.allocation_revision,NEW.native_limit,NEW.reserved_bytes,NEW.anchor_at,NEW.write_until,NEW.expires_at,NEW.delete_by) IS DISTINCT FROM
 (OLD.id,OLD.cluster_id,OLD.artifact_id,OLD.allocation_id,OLD.request_digest,OLD.pool_revision,OLD.allocation_revision,OLD.native_limit,OLD.reserved_bytes,OLD.anchor_at,OLD.write_until,OLD.expires_at,OLD.delete_by) THEN RAISE EXCEPTION 'immutable custody registration'; END IF;
 IF NEW.effective_expires_at>OLD.effective_expires_at OR NEW.effective_delete_by>OLD.effective_delete_by THEN RAISE EXCEPTION 'retention deadlines only shorten'; END IF;
 IF NEW.retention_sequence<>OLD.retention_sequence AND (NEW.retention_sequence<>OLD.retention_sequence+1 OR NOT EXISTS(SELECT 1 FROM public.retention_decision d WHERE d.attempt_id=OLD.id AND d.sequence=NEW.retention_sequence AND d.previous_expires_at=OLD.effective_expires_at AND d.previous_delete_by=OLD.effective_delete_by AND d.expires_at=NEW.effective_expires_at AND d.delete_by=NEW.effective_delete_by)) THEN RAISE EXCEPTION 'retention decision mismatch'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
