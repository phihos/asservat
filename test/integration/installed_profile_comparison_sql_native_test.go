package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Operator-only observations, never a runtime grant or source substitution.
// The returned live check captures exact SQL/key/source/Pod evidence immediately;
// its result defers only terminal inspection and later-demand retirement.
func installedProfileComparisonSQLCheck(t *testing.T, ctx context.Context, admin *pgxpool.Pool, api kubernetes.Interface, root string) installedProfileComparisonCheck {
	workerPods := installedRecordWorkerPods(t, ctx, api)
	return func(sources [2]installedProfileComparisonSource) func(string, string) func() func() {
		t.Helper()
		snapshot := func() string {
			t.Helper()
			var out string
			err := admin.QueryRow(ctx, `SELECT jsonb_build_array(
    (SELECT count(*) FROM artifact_download WHERE root_id=$1),
    (SELECT count(*) FROM access_grant WHERE root_id=$1),
    (SELECT count(*) FROM access_grant_use WHERE root_id=$1),
    (SELECT coalesce(sum(bytes),0) FROM access_grant_use WHERE root_id=$1),
    (SELECT coalesce(sum(operations),0) FROM access_grant_use WHERE root_id=$1))::text`, root).Scan(&out)
			if err != nil {
				t.Fatal("comparison native/grant snapshot", err)
			}
			return out
		}
		before := snapshot()
		return func(handle, operation string) func() func() {
			t.Helper()
			if snapshot() != before {
				t.Fatal("approved comparison created native downloads, approvals or raw grant use")
			}
			if operation == "" {
				return nil
			}
			wait, stop := context.WithTimeout(ctx, 10*time.Second)
			defer stop()
			last := "no joined observation"
			for wait.Err() == nil {
				var id, worker string
				var rawQuery, rawIntent, rawJob, rawBinding []byte
				var polls, generation, workers, keyChildren, ordinals, closed, units, queries, principalQueries int
				var rootSpent, principalSpent, workloadSpent int64
				var active, uncertain, sameAllocation bool
				err := admin.QueryRow(wait, `SELECT q.id::text,q.worker_id::text,q.query,q.polls,q.generation,q.active_batch IS NOT NULL,q.uncertain,
     q.baseline_allocation_id=q.allocation_id,context_query_units(q.query->'Scope'),
     (SELECT count(*) FROM download_worker w WHERE w.root_id=q.root_id AND w.query_id=q.id AND w.id=q.worker_id AND w.session_id IS NULL AND w.binding_json IS NOT NULL),
     (SELECT count(*) FROM context_query_key_binding k WHERE k.query_id=q.id AND k.used_roles=7),
     (SELECT count(DISTINCT source_ordinal) FROM context_query_key_binding k WHERE k.query_id=q.id AND k.used_roles=7 AND source_ordinal IN(0,1)),
     (SELECT count(*) FROM context_query_batch b WHERE b.query_id=q.id AND b.closed AND b.native_closed),
     (SELECT allocated FROM context_query_backing WHERE root_id=q.root_id),
     (SELECT allocated FROM context_query_principal WHERE root_id=q.root_id AND id=q.account_id),
     (SELECT allocated FROM context_query_allocation WHERE root_id=q.root_id AND id=q.allocation_id),
     (SELECT count(*) FROM context_query allq WHERE allq.root_id=q.root_id AND allq.baseline_allocation_id IS NOT NULL),
     (SELECT count(*) FROM context_query ownq WHERE ownq.root_id=q.root_id AND ownq.account_id=q.account_id AND ownq.baseline_allocation_id IS NOT NULL)
     FROM context_query q WHERE q.root_id=$1 AND q.operation_id=$2`, root, operation).Scan(&id, &worker, &rawQuery, &polls, &generation, &active, &uncertain, &sameAllocation, &units, &workers, &keyChildren, &ordinals, &closed, &rootSpent, &principalSpent, &workloadSpent, &queries, &principalQueries)
				last = fmt.Sprintf("query=%s handle=%s workers=%d polls=%d generation=%d keys=%d ordinals=%d closed=%d active=%t uncertain=%t units=%d err=%v", id, handle, workers, polls, generation, keyChildren, ordinals, closed, active, uncertain, units, err)
				if err == nil && (handle == "" || handle == id) && worker != "" && polls <= 4 && generation == 1 && workers == 1 && keyChildren == 2 && ordinals == 2 && closed == 1 && !active && !uncertain {
					if !sameAllocation || units != int(query.ProfileComparisonQueryUnits) || queries < 1 || queries > installedProfileComparisonQueries || rootSpent != int64(queries)*query.ProfileComparisonQueryUnits || principalSpent != int64(principalQueries)*query.ProfileComparisonQueryUnits || workloadSpent != rootSpent {
						t.Fatal("comparison atomic same-workload/principal/root20-unit charges", sameAllocation, units, rootSpent, principalSpent, workloadSpent, queries)
					}
					var q query.ContextQuery
					var intent query.ContextProjectionWorkerIntent
					var observed value.AcquisitionWorker
					if json.Unmarshal(rawQuery, &q) != nil || !q.Valid() || q.ID != id || q.WorkerID != worker || q.Scope.CaseID != sources[1].CaseID || q.Scope.ArtifactID != sources[1].ArtifactID || hex.EncodeToString(q.Scope.Version[:]) != sources[1].Version || q.Scope.Comparison.Baseline.CaseID != sources[0].CaseID || q.Scope.Comparison.Baseline.ArtifactID != sources[0].ArtifactID || hex.EncodeToString(q.Scope.Comparison.Baseline.Version[:]) != sources[0].Version {
						t.Fatal("comparison exact immutable source/plan readback")
					}
					err = admin.QueryRow(wait, `SELECT intent_json,job_json,binding_json FROM download_worker WHERE root_id=$1 AND query_id=$2 AND id=$3 AND session_id IS NULL`, root, id, worker).Scan(&rawIntent, &rawJob, &rawBinding)
					if err != nil || json.Unmarshal(rawIntent, &intent) != nil || !intent.Valid() || !intent.Query.Equal(q) || json.Unmarshal(rawJob, &observed.Job) != nil || json.Unmarshal(rawBinding, &observed.Binding) != nil {
						t.Fatal("comparison worker parent binding", err)
					}
					observed.Intent = intent.Worker
					if !observed.Valid() || q.Plan.Profile.Worker.MemoryBytes != query.ProfileComparisonWorkerBytes || q.Plan.Profile.Worker.WorkerTransientBytes != query.ProfileComparisonWorkerBytes || q.BaselinePlan.Profile.Worker.MemoryBytes != query.ProfileComparisonWorkerBytes || q.BaselinePlan.Profile.Worker.WorkerTransientBytes != query.ProfileComparisonWorkerBytes {
						t.Fatal("comparison lacks exact installed384MiB physical/transient reservation")
					}
					memory, _, err := workerPods.limits(observed.Binding)
					if err != nil || memory != query.ProfileComparisonWorkerBytes {
						t.Fatal("comparison actual exact384MiB Pod", memory, err)
					}
					rows, err := admin.Query(wait, `SELECT child_id::text,batch_id::text,source_ordinal,binding FROM context_query_key_binding WHERE query_id=$1 AND used_roles=7 ORDER BY source_ordinal`, id)
					if err != nil {
						t.Fatal(err)
					}
					children := 0
					for rows.Next() {
						var child, batch string
						var ordinal int
						var raw []byte
						var binding query.ContextProjectionComparisonKeyChild
						if rows.Scan(&child, &batch, &ordinal, &raw) != nil || json.Unmarshal(raw, &binding) != nil {
							rows.Close()
							t.Fatal("comparison compact key child readback")
						}
						ids, err := query.ProfileComparisonKeyChildIDs(batch)
						if err != nil || ordinal != children || ordinal > 1 || child != ids[ordinal] || binding.ID != child || binding.BatchID != batch || binding.QueryID != id || binding.WorkerID != worker || binding.SourceOrdinal != ordinal || hex.EncodeToString(binding.SourceVersion[:]) != sources[ordinal].Version {
							rows.Close()
							t.Fatal("comparison child/source ordinal or immutable version changed")
						}
						children++
					}
					err = rows.Err()
					rows.Close()
					if err != nil || children != 2 {
						t.Fatal("comparison independent3-role children", children, err)
					}
					retired := func(read context.Context) error {
						var complete bool
						if err := admin.QueryRow(read, `SELECT termination_json IS NOT NULL AND retired_proof_json IS NOT NULL AND abandoned_at IS NULL FROM download_worker WHERE root_id=$1 AND query_id=$2 AND id=$3`, root, id, worker).Scan(&complete); err != nil {
							return err
						}
						if !complete {
							return errors.New("comparison worker lacks positive stored retirement")
						}
						return nil
					}
					return func() func() {
						if err := installedProjectionWaitTerminal(ctx, api, observed); err != nil {
							t.Fatal("comparison exact worker failed terminal observation", err)
						}
						if err := installedProfileComparisonRetirementAfterTerminal(ctx, api, observed, retired); err != nil {
							t.Fatal("comparison missing worker lacks exact positive retirement", err)
						}
						if snapshot() != before {
							t.Fatal("comparison terminal inspection changed native/grant state")
						}
						t.Logf("installed comparison: query=%s source ordinals0/1, one joined batch, two independent3-role children, exact384MiB Pod/transient,20units, retained totals root=%d principal=%d workload=%d", id, rootSpent, principalSpent, workloadSpent)
						return func() {
							t.Helper()
							if err := retired(ctx); err != nil {
								t.Fatal("later real demand did not positively retire comparison worker", err)
							}
						}
					}
				}
				if installedJourneyPause(wait, 100*time.Millisecond) != nil {
					break
				}
			}
			diagnostic, endDiagnostic := context.WithTimeout(ctx, 3*time.Second)
			defer endDiagnostic()
			if state, err := installedProfileComparisonProgress(diagnostic, admin, root, operation); err == nil {
				t.Log("comparison worker/batch progress:", state)
			} else {
				t.Log("comparison worker/batch progress unavailable:", err)
			}
			t.Fatal("comparison lacks exact joined query/key/worker evidence:", last)
			return nil
		}
	}
}

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
