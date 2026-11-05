package integration

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"testing"
	"time"
)

// This is operator-only readback. It permits ONLY the explicitly reviewed page
// disclosure deltas; accepted collection/observation state stays byte-exact.
func installedLogsQuerySQLCheck(t *testing.T, ctx context.Context, admin *pgxpool.Pool, api kubernetes.Interface, root string, terminalSink func(func()), requireReplay ...bool) installedProjectionCheck {
	return func(artifactID string) func(string, string) func() {
		t.Helper()
		snapshot := func() string {
			t.Helper()
			var s string
			err := admin.QueryRow(ctx, `SELECT jsonb_build_object('grants',(SELECT jsonb_agg(to_jsonb(g)-'bytes_spent'-'operations_spent'-'artifacts_spent' ORDER BY id) FROM access_grant g WHERE root_id=$1),'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM policy_observation_session s WHERE root_id=$1),'spend',(SELECT jsonb_agg(to_jsonb(s) ORDER BY grant_id) FROM adhoc_observation_spend s WHERE root_id=$1),'captures',(SELECT count(*) FROM context_capture WHERE root_id=$1),'downloads',(SELECT count(*) FROM artifact_download WHERE root_id=$1))::text`, root).Scan(&s)
			if err != nil {
				t.Fatal("raw logs query acquisition snapshot", err)
			}
			return s
		}
		before := snapshot()
		disclosureState := func() string {
			var state string
			if err := admin.QueryRow(ctx, `SELECT jsonb_build_array((SELECT count(*) FROM access_grant_use WHERE root_id=$1),(SELECT count(*) FROM access_grant_child WHERE root_id=$1),(SELECT coalesce(sum(artifacts_spent),0) FROM access_grant WHERE root_id=$1),(SELECT coalesce(sum(bytes_spent),0) FROM access_grant WHERE root_id=$1),(SELECT coalesce(sum(operations_spent),0) FROM access_grant WHERE root_id=$1),(SELECT count(*) FROM context_query WHERE root_id=$1),(SELECT allocated FROM context_query_backing WHERE root_id=$1),(SELECT count(*) FROM context_query_call c JOIN context_query q ON q.id=c.query_id WHERE q.root_id=$1))::text`, root).Scan(&state); err != nil {
				t.Fatal("logs disclosure state", err)
			}
			return state
		}
		beforeDisclosure := disclosureState()
		return func(handle, operation string) func() {
			t.Helper()
			if snapshot() != before {
				t.Fatal("raw logs query changed acquisition/originalreview/observation or native session")
			}
			if operation == "" {
				if disclosureState() != beforeDisclosure {
					t.Fatal("denied read+raw native preparation changed children/disclosure pool")
				}
				return nil
			}
			call, stop := context.WithTimeout(ctx, 5*time.Second)
			var raw, job, binding, expectation []byte
			var units, rootUnits, workUnits, principalUnits, expectedPrincipal, expectedRoot, queries, summaries, children, uses int
			var bytes, ops int64
			err := admin.QueryRow(call, `SELECT w.intent_json,w.job_json,w.binding_json,c.expectation_json,context_query_units(q.query->'Scope'),b.allocated,a.allocated,p.allocated,
(SELECT coalesce(sum(context_query_units(x.query->'Scope')),0) FROM context_query x WHERE x.root_id=q.root_id AND x.account_id=p.id),
(SELECT coalesce(sum(context_query_units(x.query->'Scope')),0) FROM context_query x WHERE x.root_id=q.root_id),
(SELECT count(*) FROM context_query x WHERE x.root_id=q.root_id AND x.query->'Scope'->>'DisplayVersion'='approved-logs/v1'),
(SELECT count(*) FROM context_query x WHERE x.root_id=q.root_id AND x.query->'Scope'->>'DisplayVersion' IS DISTINCT FROM 'approved-logs/v1'),
(SELECT count(*) FROM context_query_key_binding k WHERE k.query_id=q.id),
(SELECT count(*) FROM access_grant_use u WHERE u.root_id=q.root_id AND u.operation='get_logs'),
(SELECT coalesce(sum(u.bytes),0) FROM access_grant_use u WHERE u.root_id=q.root_id AND u.operation='get_logs'),
(SELECT coalesce(sum(u.operations),0) FROM access_grant_use u WHERE u.root_id=q.root_id AND u.operation='get_logs')
FROM context_query q JOIN context_capture c ON c.root_id=q.root_id AND c.id::text=q.query#>>'{Scope,CaptureID}' JOIN context_query_backing b ON b.root_id=q.root_id JOIN context_query_allocation a ON a.id=q.allocation_id JOIN context_query_principal p ON p.id=q.account_id JOIN download_worker w ON w.id=q.worker_id AND w.query_id=q.id AND w.session_id IS NULL
WHERE q.root_id=$1 AND q.operation_id=$2 AND q.query->'Scope'->>'ArtifactID'=$3`, root, operation, artifactID).Scan(&raw, &job, &binding, &expectation, &units, &rootUnits, &workUnits, &principalUnits, &expectedPrincipal, &expectedRoot, &queries, &summaries, &children, &uses, &bytes, &ops)
			var intent query.ContextProjectionWorkerIntent
			var observed value.AcquisitionWorker
			var original artifact.ContextExpectation
			if err != nil || json.Unmarshal(expectation, &original) != nil || original.Validate() != nil || json.Unmarshal(raw, &intent) != nil || !intent.Valid() || json.Unmarshal(job, &observed.Job) != nil || json.Unmarshal(binding, &observed.Binding) != nil {
				stop()
				t.Fatal("raw logs query exact SQL worker", err)
			}
			q, s := intent.Query, intent.Query.Scope
			if original.NativeType != artifact.LogsArtifact || original.DataClass != "raw" || original.Logs == nil || !original.Logs.Valid() || original.Registration.Location.ArtifactID != artifactID || s.CaptureID != original.CaptureUID || s.CaseID != original.CaseID || s.PodUID != original.PodUID || s.NamespaceUID != original.NamespaceUID || s.WorkloadUID != original.WorkloadUID || s.NativeType != artifact.LogsArtifact || s.SourceFormat != artifact.LogFormat || s.DisplayVersion != query.LogQueryDisplayVersion || s.RawGrantID == "" || q.Grant.ParentID != s.RawGrantID || !q.Grant.Valid() || !q.InvocationKey.Valid() || s.ArtifactID != artifactID || handle != "" && q.ID != handle || s.Logs != (query.LogWindow{Limit: 100}) || q.Scope.ReadBatches() != 2 || q.Plan.Profile.Worker.MemoryBytes < query.LogQueryWorkerBytes || q.Plan.Profile.Worker.WorkerTransientBytes < query.LogQueryWorkerBytes {
				stop()
				t.Fatal("raw logs query lost original raw scope/grant/selection/worker reservation")
			}
			if units != query.LogQueryUnits || summaries != 0 || queries < 1 || queries > 2 || rootUnits != expectedRoot || expectedRoot != query.LogQueryUnits*queries || workUnits != rootUnits || principalUnits != expectedPrincipal || expectedPrincipal <= 0 || children != 1 || uses != queries || bytes != int64(queries)*query.ContextResultBytes || ops != int64(queries) {
				stop()
				t.Fatalf("raw logs query accounting units=%d summaries=%d queries=%d root=%d expectedRoot=%d workload=%d principal=%d exactPrincipal=%d children=%d uses=%d bytes=%d ops=%d", units, summaries, queries, rootUnits, expectedRoot, workUnits, principalUnits, expectedPrincipal, children, uses, bytes, ops)
			}
			var validUses bool
			err = admin.QueryRow(call, `SELECT count(*)=1 AND bool_and(u.id=b.id AND u.parent_id=(q.query->'Grant'->>'ParentID')::uuid AND u.child_id=(q.query->'Grant'->>'ChildID')::uuid AND u.operation='get_logs' AND u.bytes=24576 AND u.operations=1 AND g.max_artifacts=1 AND g.artifacts_spent=1 AND g.kind='adHocCapture' AND g.max_bytes=16777216 AND g.max_operations=16 AND g.result_access->'operations'='["download_artifact","get_logs"]'::jsonb AND g.result_access->'clientIDs'='["console","mcp"]'::jsonb AND g.result_access->'clientIDs' ? (q.actor->>'ClientID') AND g.bytes_spent=(SELECT sum(x.bytes) FROM access_grant_use x WHERE x.parent_id=g.id) AND g.operations_spent=(SELECT sum(x.operations) FROM access_grant_use x WHERE x.parent_id=g.id)) FROM context_query q JOIN context_query_batch b ON b.query_id=q.id JOIN access_grant_use u ON u.id=b.id JOIN access_grant g ON g.id=u.parent_id WHERE q.root_id=$1 AND q.id=$2`, root, q.ID).Scan(&validUses)
			if err != nil || !validUses {
				stop()
				t.Fatal("raw logs query exact per-batch use/parent pool", err)
			}
			wantBegins := 1
			if len(requireReplay) == 1 && requireReplay[0] {
				wantBegins = 2
			}
			var begins int
			var validCalls bool
			err = admin.QueryRow(call, `SELECT count(*),bool_and(
 c.request#>>'{Call,Tool}'='get_logs' AND c.request#>'{Call,InputFormat}'=q.initial_request#>'{Call,InputFormat}' AND
 c.request#>'{Call,MACVersion}'=q.initial_request#>'{Call,MACVersion}' AND c.request#>'{Call,InputDigest}'=q.initial_request#>'{Call,InputDigest}' AND
 c.request#>'{Call,Principal}'=q.initial_request#>'{Call,Principal}' AND
 (c.operation_id=q.operation_id OR NOT EXISTS(SELECT 1 FROM context_query_batch b WHERE b.query_id=q.id AND b.operation_id=c.operation_id))) AND bool_or(c.operation_id=q.operation_id)
 FROM context_query q JOIN context_query_call c ON c.query_id=q.id AND NOT c.is_poll WHERE q.root_id=$1 AND q.id=$2`, root, q.ID).Scan(&begins, &validCalls)
			if err != nil || !validCalls || begins != wantBegins {
				stop()
				t.Fatalf("raw logs query exact Begin/replay journal calls=%d/%d valid=%t err=%v", begins, wantBegins, validCalls, err)
			}
			observed.Intent = intent.Worker
			pod, e := api.CoreV1().Pods(observed.Binding.Namespace).Get(call, observed.Binding.Pod, meta.GetOptions{})
			if err != nil || !validUses || !observed.Valid() || e != nil || string(pod.UID) != observed.Binding.PodUID || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Resources.Limits.Memory().Value() != q.Plan.Profile.Worker.MemoryBytes || pod.Spec.Containers[0].Resources.Limits.Cpu().MilliValue() != 500 {
				stop()
				t.Fatal("raw logs query exact batch/use or original worker Pod", err, e)
			}
			stop()
			// Start the existing no-further-effect snapshot AFTER the explicitly
			// accounted page debit, then reuse its exact joined-batch/key/terminal proof.
			var waitTerminal func()
			shared := installedProjectionSQLCheck(t, ctx, admin, api, root, func(wait func()) { waitTerminal = wait })
			retirement := shared(artifactID)(handle, operation)
			finishTerminal := func() {
				if waitTerminal == nil {
					t.Fatal("missing original query terminal wait")
				}
				waitTerminal()
				err = installedProfileComparisonRetirementAfterTerminal(ctx, api, observed, func(read context.Context) error {
					var retired bool
					err := admin.QueryRow(read, `SELECT termination_json IS NOT NULL AND retired_proof_json IS NOT NULL AND abandoned_at IS NULL FROM download_worker WHERE root_id=$1 AND id=$2 AND query_id=$3`, root, observed.Intent.ID, q.ID).Scan(&retired)
					if err != nil {
						return err
					}
					if !retired {
						return errors.New("raw logs query missing positive original retirement")
					}
					return nil
				})
				if err != nil {
					t.Fatal("raw logs query exact terminal/retirement", err)
				}
				t.Logf("installed raw logs query SQL: priorqueries%d queries%d/%dunits; exact account%d=root%d/workload%d; each page one24KiB/one-op original parent+child use, one three-role native/public joined batch; original Pod limit%d/500m; collection/observation unchanged", 0, queries, queries*query.LogQueryUnits, principalUnits, rootUnits, workUnits, q.Plan.Profile.Worker.MemoryBytes)
			}
			if terminalSink != nil {
				terminalSink(finishTerminal)
			} else {
				finishTerminal()
			}

			return retirement
		}
	}
}
