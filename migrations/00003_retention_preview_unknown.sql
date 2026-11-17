-- +goose Up
-- The retention preview (ADR-240) reports Unknown instead of assuming a
-- label match. retention_policy_effect lets a row without recorded labels
-- take a label-scoped policy, so reconciliation errs towards earlier
-- deletion. The preview does not count that as
-- affected: a row whose earliest deadlines come only from label-scoped
-- effects it has no labels for is Unknown. Affected, read_closed,
-- deletion_due and the earliest dates use only the effects that need no
-- missing labels.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retention_preview(effects jsonb) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
 WITH r AS (
  SELECT x.*, (coalesce(p.value->'namespaceLabels','{}')<>'{}' OR coalesce(p.value->'workloadLabels','{}')<>'{}')
   AND (CASE WHEN x.case_metadata THEN hc.target_labels ELSE c.target_labels END) IS NULL AS guessed
  FROM jsonb_array_elements(effects) p
  CROSS JOIN LATERAL public.retention_policy_effect(p.value) x
  LEFT JOIN public.context_capture c ON NOT x.case_metadata AND c.attempt_id=x.attempt_id
  LEFT JOIN public.capture_history_parameter h ON x.case_metadata AND h.attempt_id=x.attempt_id
  LEFT JOIN public.context_capture hc ON hc.id=h.capture_id
 ), e AS (
  SELECT r.attempt_id, r.cluster_id, r.native_type, r.case_metadata,
   min(r.old_expires_at) AS old_expires_at, min(r.old_delete_by) AS old_delete_by,
   min(r.expires_at) FILTER (WHERE NOT r.guessed) AS expires_at, min(r.delete_by) FILTER (WHERE NOT r.guessed) AS delete_by,
   bool_or(r.guessed AND (r.expires_at<r.old_expires_at OR r.delete_by<r.old_delete_by)) AS guessed_change
  FROM r GROUP BY 1,2,3,4
 ), c AS (
  SELECT e.*, coalesce(e.expires_at<e.old_expires_at OR e.delete_by<e.old_delete_by, false) AS changed FROM e
 ), g AS (
  SELECT c.cluster_id, coalesce(c.native_type,'') AS native_type, c.case_metadata, count(*) AS scanned,
   count(*) FILTER (WHERE c.changed) AS affected,
   count(*) FILTER (WHERE NOT c.changed AND c.guessed_change) AS unknown,
   count(*) FILTER (WHERE c.expires_at<=clock_timestamp() AND c.old_expires_at>clock_timestamp()) AS read_closed,
   count(*) FILTER (WHERE c.changed AND c.delete_by<=clock_timestamp()) AS deletion_due,
   min(c.expires_at) FILTER (WHERE c.changed) AS earliest_expires_at,
   min(c.delete_by) FILTER (WHERE c.changed) AS earliest_delete_by
  FROM c GROUP BY 1,2,3
 )
 SELECT coalesce(jsonb_agg(to_jsonb(g)),'[]'::jsonb) FROM g
$$;
-- +goose StatementEnd
