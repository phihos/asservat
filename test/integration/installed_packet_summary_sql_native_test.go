package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Keep the existing download/grant snapshot, exact worker/key/batch join and
// original terminal wait. This read-only wrapper adds the new closed packet
// scope/resource/charge proof BEFORE that wait, while its exact Pod is live.
func installedPacketSummarySQLCheck(t *testing.T, ctx context.Context, admin *pgxpool.Pool, api kubernetes.Interface, root string) installedProjectionCheck {
	shared := installedProjectionSQLCheck(t, ctx, admin, api, root)
	return func(artifactID string) func(string, string) func() {
		verify := shared(artifactID)
		return func(handle, operation string) func() {
			t.Helper()
			var observed value.AcquisitionWorker
			if operation != "" {
				call, stop := context.WithTimeout(ctx, 5*time.Second)
				var raw []byte
				var units, rows, rootSpent, workloadSpent, principalSpent, queries int
				var job, binding []byte
				err := admin.QueryRow(call, `SELECT w.intent_json,w.job_json,w.binding_json,context_query_units(q.query->'Scope'),(SELECT count(*) FROM context_query_key_binding k WHERE k.query_id=q.id),b.allocated,a.allocated,p.allocated,(SELECT count(*) FROM context_query x WHERE x.root_id=q.root_id)
FROM context_query q JOIN context_query_backing b ON b.root_id=q.root_id JOIN context_query_allocation a ON a.id=q.allocation_id JOIN context_query_principal p ON p.id=q.account_id JOIN download_worker w ON w.id=q.worker_id AND w.query_id=q.id AND w.session_id IS NULL
WHERE q.root_id=$1 AND q.operation_id=$2 AND q.query->'Scope'->>'ArtifactID'=$3`, root, operation, artifactID).Scan(&raw, &job, &binding, &units, &rows, &rootSpent, &workloadSpent, &principalSpent, &queries)
				var intent query.ContextProjectionWorkerIntent
				if err != nil || json.Unmarshal(raw, &intent) != nil || !intent.Valid() || json.Unmarshal(job, &observed.Job) != nil || json.Unmarshal(binding, &observed.Binding) != nil {
					stop()
					t.Fatal("packet exact worker/query SQL readback", err)
				}
				scope := intent.Query.Scope
				if scope.NativeType != artifact.PCAPNGArtifact || scope.SourceFormat != artifact.PCAPNGFormat || scope.DisplayVersion != query.PacketSummaryDisplayVersion || scope.Selection != (query.LineSelection{}) || scope.Headers != (query.HTTPHeaderWindow{}) || scope.Profile != (query.ProfileSummarySelection{}) || scope.Syscalls != (query.SyscallWindow{}) || scope.Comparison != (query.ProfileComparisonWindow{}) || scope.SourceProjectionDigest != (artifact.Digest{}) || scope.ArtifactID != artifactID || handle != "" && intent.Query.ID != handle || units != query.PacketSummaryQueryUnits || rows != 1 || queries < 1 || queries > 2 || rootSpent != queries*query.PacketSummaryQueryUnits || workloadSpent != rootSpent || principalSpent != query.PacketSummaryQueryUnits || intent.Query.Plan.Profile.Worker.MemoryBytes != query.ProfileComparisonWorkerBytes || intent.Query.Plan.Profile.Worker.WorkerTransientBytes != query.ProfileComparisonWorkerBytes {
					stop()
					t.Fatal("packet source/selection/paid resource reservation changed")
				}
				observed.Intent = intent.Worker
				pod, err := api.CoreV1().Pods(observed.Binding.Namespace).Get(call, observed.Binding.Pod, meta.GetOptions{})
				if !observed.Valid() || err != nil || string(pod.UID) != observed.Binding.PodUID || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Resources.Limits.Memory().Value() != intent.Query.Plan.Profile.Worker.MemoryBytes || pod.Spec.Containers[0].Resources.Limits.Cpu().MilliValue() != 500 {
					stop()
					t.Fatal("packet original worker actual384MiB/500m Pod", err)
				}
				stop()
				t.Log("installed packet summary SQL: exact metadataPCAPNG scope/allselectionzero, two read units/one three-key child, original384MiB+500m Pod and transient declaration")
			}
			retirement := verify(handle, operation)
			if operation != "" {
				err := installedProfileComparisonRetirementAfterTerminal(ctx, api, observed, func(read context.Context) error {
					var retired bool
					err := admin.QueryRow(read, `SELECT termination_json IS NOT NULL AND retired_proof_json IS NOT NULL AND abandoned_at IS NULL FROM download_worker WHERE root_id=$1 AND id=$2 AND query_id=$3`, root, observed.Intent.ID, observed.Intent.Parent.ID).Scan(&retired)
					if err != nil {
						return err
					}
					if !retired {
						return errors.New("packet worker missing positive original retirement")
					}
					return nil
				})
				if err != nil {
					t.Fatal("packet terminal/retirement exact proof", err)
				}
			}
			return retirement
		}
	}
}
