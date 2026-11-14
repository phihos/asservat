package integration

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Operator-only content-free failure observations. No stored authority,
// credential, evidence or SQL body is returned, and no state is changed.
func installedProfileComparisonProgress(ctx context.Context, admin *pgxpool.Pool, root, operation string) (string, error) {
	var state string
	err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
    'worker_audited',w.audit_receipt_json IS NOT NULL,
    'worker_claimed',w.claimed_at IS NOT NULL,
    'job_recorded',w.job_json IS NOT NULL,
    'pod_bound',w.binding_json IS NOT NULL,
    'enrollment_audited',EXISTS(SELECT 1 FROM download_worker_enrollment e WHERE e.worker_id=w.id AND e.audit_receipt_json IS NOT NULL),
    'certificate_activated',EXISTS(SELECT 1 FROM download_worker_certificate c WHERE c.worker_id=w.id AND c.activated_at IS NOT NULL),
    'batch_claimed',EXISTS(SELECT 1 FROM context_query_batch b WHERE b.query_id=q.id AND b.claim_id IS NOT NULL),
    'native_operation_recorded',EXISTS(SELECT 1 FROM context_query_batch b WHERE b.query_id=q.id AND b.native_operation IS NOT NULL),
    'native_authority_recorded',EXISTS(SELECT 1 FROM context_query_batch b WHERE b.query_id=q.id AND b.native_authority IS NOT NULL),
    'native_closed',EXISTS(SELECT 1 FROM context_query_batch b WHERE b.query_id=q.id AND b.native_closed),
    'key_children',(SELECT count(*) FROM context_query_key_binding k WHERE k.query_id=q.id))::text
    FROM context_query q LEFT JOIN download_worker w ON w.root_id=q.root_id AND w.id=q.worker_id
    WHERE q.root_id=$1 AND q.operation_id=$2`, root, operation).Scan(&state)
	return state, err
}
