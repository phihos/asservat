package integration

import (
	"context"
	"errors"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Call only after installedProjectionWaitTerminal has positively observed the
// original Job/Pod or their absence. That shared helper cannot by itself prove
// retirement when both disappeared; require the exact stored SQL proof here.
// A surviving original Job already supplied terminal proof and stays charged.
func installedProfileComparisonRetirementAfterTerminal(ctx context.Context, api kubernetes.Interface, observed value.AcquisitionWorker, retired func(context.Context) error) error {
	read, end := context.WithDeadline(ctx, observed.Intent.RunUntil.Add(30*time.Second))
	defer end()
	job, err := api.BatchV1().Jobs(observed.Binding.Namespace).Get(read, observed.Binding.Job, meta.GetOptions{})
	if apierrors.IsNotFound(err) {
		return retired(read)
	}
	if err != nil {
		return err
	}
	if string(job.UID) != observed.Binding.JobUID {
		return errors.New("comparison terminal Job identity changed")
	}
	return nil
}

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
