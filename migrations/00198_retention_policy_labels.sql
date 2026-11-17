-- +goose Up
-- Label-scoped retention policies (namespaceSelector, workloadSelector)
-- match the namespace and workload labels read with the target at
-- admission. context_capture records them in target_labels as
-- {"namespace":{...},"workload":{...}}. All labels are kept, not only the
-- keys current selectors name: a policy created later may select any key.
-- Kubernetes bounds their size with the object. A capture-history parameter
-- takes the labels of its capture's row. retention_policy_effect matches a
-- policy's matchLabels (namespaceLabels, workloadLabels in the effect) by
-- jsonb containment. A row without recorded labels (admitted before this
-- migration, or saved from a source armed before it) takes every
-- policy of its cluster scope: a privacy maximum errs towards earlier
-- deletion. The admission trigger of 00190 calls this function, so it
-- applies label-scoped policies to the new row without change.
ALTER TABLE context_capture ADD COLUMN IF NOT EXISTS target_labels jsonb;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retention_policy_effect(p jsonb, one_attempt uuid DEFAULT NULL)
RETURNS TABLE(attempt_id uuid, cluster_id uuid, native_type text, case_metadata boolean, old_expires_at timestamptz, old_delete_by timestamptz, expires_at timestamptz, delete_by timestamptz)
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
 WITH scoped AS (
  SELECT a.id, a.cluster_id, a.anchor_at, a.effective_expires_at, a.effective_delete_by,
   coalesce(convert_from(c.expectation_json,'UTF8')::jsonb->>'NativeType','') AS native_type, false AS case_metadata, c.target_labels AS labels
  FROM public.custody_attempt a JOIN public.context_capture c ON c.attempt_id=a.id
  WHERE a.state<>'deleted' AND (one_attempt IS NULL OR a.id=one_attempt)
  UNION ALL
  SELECT a.id, a.cluster_id, a.anchor_at, a.effective_expires_at, a.effective_delete_by, NULL, true, c.target_labels
  FROM public.custody_attempt a JOIN public.capture_history_parameter h ON h.attempt_id=a.id
  LEFT JOIN public.context_capture c ON c.id=h.capture_id
  WHERE a.state<>'deleted' AND (one_attempt IS NULL OR a.id=one_attempt)
 ), limited AS (
  SELECT s.*, (CASE WHEN s.case_metadata THEN (p->>'caseMaximum')::bigint ELSE (p->'maxima'->>s.native_type)::bigint END) AS maximum
  FROM scoped s
  WHERE (jsonb_array_length(p->'clusters')=0 OR p->'clusters' ? s.cluster_id::text)
   AND (s.labels IS NULL OR (coalesce(s.labels->'namespace','{}') @> coalesce(p->'namespaceLabels','{}')
    AND coalesce(s.labels->'workload','{}') @> coalesce(p->'workloadLabels','{}')))
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

-- +goose Down
-- Restore the 00190 function; the column goes with it. Rerunning either
-- section changes nothing.
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
ALTER TABLE context_capture DROP COLUMN IF EXISTS target_labels;
