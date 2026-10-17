-- name: ListContextStartOwnerCandidates :many
-- Candidate discovery only; the actual owner route, native workload proof,
-- complete certificate audit and actual TLS are independently checked later.
-- Seventeen detects an incomplete result under the fixed sixteen-owner bound.
SELECT e.pod_uid,e.process_epoch
FROM hub_owner_enrollment e
WHERE e.installation_id=$1 AND e.cluster_id=$2 AND e.issuer_epoch=$3
  AND e.usage='server' AND e.retired_at IS NULL
  AND e.audit_receipt_json IS NOT NULL AND e.hold_until>clock_timestamp()
  AND EXISTS (SELECT 1 FROM hub_owner_certificate c
    WHERE c.enrollment_id=e.id AND c.activated_at IS NOT NULL
      AND c.certificate_json IS NOT NULL AND c.audit_receipt_json IS NOT NULL
      AND c.not_after>clock_timestamp())
ORDER BY e.pod_uid,e.process_epoch LIMIT 17;
