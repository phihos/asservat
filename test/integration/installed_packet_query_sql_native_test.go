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
func installedPacketQuerySQLCheck(t *testing.T, ctx context.Context, admin *pgxpool.Pool, api kubernetes.Interface, root string, retained *[]func(), terminalSink func(func())) installedProjectionCheck {
	return func(artifactID string) func(string, string) func() {
		t.Helper()
		snapshot := func() string {
			t.Helper()
			var s string
			err := admin.QueryRow(ctx, `SELECT jsonb_build_object('grants',(SELECT jsonb_agg(to_jsonb(g)-'bytes_spent'-'operations_spent'-'artifacts_spent' ORDER BY id) FROM access_grant g WHERE root_id=$1),'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM policy_observation_session s WHERE root_id=$1),'spend',(SELECT jsonb_agg(to_jsonb(s) ORDER BY grant_id) FROM adhoc_observation_spend s WHERE root_id=$1),'captures',(SELECT count(*) FROM context_capture WHERE root_id=$1),'downloads',(SELECT count(*) FROM artifact_download WHERE root_id=$1))::text`, root).Scan(&s)
			if err != nil {
				t.Fatal("packet query acquisition snapshot", err)
			}
			return s
		}
		before := snapshot()
		disclosureState := func() string {
			var state string
			if err := admin.QueryRow(ctx, `SELECT jsonb_build_array((SELECT count(*) FROM access_grant_use WHERE root_id=$1),(SELECT count(*) FROM access_grant_child WHERE root_id=$1),(SELECT coalesce(sum(artifacts_spent),0) FROM access_grant WHERE root_id=$1),(SELECT coalesce(sum(bytes_spent),0) FROM access_grant WHERE root_id=$1),(SELECT coalesce(sum(operations_spent),0) FROM access_grant WHERE root_id=$1))::text`, root).Scan(&state); err != nil {
				t.Fatal("packet disclosure state", err)
			}
			return state
		}
		beforeDisclosure := disclosureState()
		return func(handle, operation string) func() {
			t.Helper()
			if snapshot() != before {
				t.Fatal("packet query changed acquisition/originalreview/observation or native session")
			}
			if operation == "" {
				if disclosureState() != beforeDisclosure {
					t.Fatal("denied read+raw native preparation changed children/disclosure pool")
				}
				return nil
			}
			call, stop := context.WithTimeout(ctx, 5*time.Second)
			var raw, job, binding []byte
			var units, rootUnits, workUnits, principalUnits, expectedPrincipal, expectedRoot, queries, summaries, children, uses int
			var bytes, ops int64
			err := admin.QueryRow(call, `SELECT w.intent_json,w.job_json,w.binding_json,context_query_units(q.query->'Scope'),b.allocated,a.allocated,p.allocated,
(SELECT coalesce(sum(context_query_units(x.query->'Scope')),0) FROM context_query x WHERE x.root_id=q.root_id AND x.account_id=p.id),
(SELECT coalesce(sum(context_query_units(x.query->'Scope')),0) FROM context_query x WHERE x.root_id=q.root_id),
(SELECT count(*) FROM context_query x WHERE x.root_id=q.root_id AND x.query->'Scope'->>'DisplayVersion'='approved-pcap-query/v1'),
(SELECT count(*) FROM context_query x WHERE x.root_id=q.root_id AND x.query->'Scope'->>'DisplayVersion'='approved-raw-pcap-summary/v1'),
(SELECT count(*) FROM context_query_key_binding k WHERE k.query_id=q.id),
(SELECT count(*) FROM access_grant_use u WHERE u.root_id=q.root_id AND u.operation='pcap_query'),
(SELECT coalesce(sum(u.bytes),0) FROM access_grant_use u WHERE u.root_id=q.root_id AND u.operation='pcap_query'),
(SELECT coalesce(sum(u.operations),0) FROM access_grant_use u WHERE u.root_id=q.root_id AND u.operation='pcap_query')
FROM context_query q JOIN context_query_backing b ON b.root_id=q.root_id JOIN context_query_allocation a ON a.id=q.allocation_id JOIN context_query_principal p ON p.id=q.account_id JOIN download_worker w ON w.id=q.worker_id AND w.query_id=q.id AND w.session_id IS NULL
WHERE q.root_id=$1 AND q.operation_id=$2 AND q.query->'Scope'->>'ArtifactID'=$3`, root, operation, artifactID).Scan(&raw, &job, &binding, &units, &rootUnits, &workUnits, &principalUnits, &expectedPrincipal, &expectedRoot, &queries, &summaries, &children, &uses, &bytes, &ops)
			var intent query.ContextProjectionWorkerIntent
			var observed value.AcquisitionWorker
			if err != nil || json.Unmarshal(raw, &intent) != nil || !intent.Valid() || json.Unmarshal(job, &observed.Job) != nil || json.Unmarshal(binding, &observed.Binding) != nil {
				stop()
				t.Fatal("packet query exact SQL worker", err)
			}
			q, s := intent.Query, intent.Query.Scope
			if s.NativeType != artifact.RawPCAPNGArtifact || s.SourceFormat != artifact.RawPCAPNGFormat || s.DisplayVersion != query.PacketQueryDisplayVersion || s.RawGrantID == "" || q.Grant.ParentID != s.RawGrantID || !q.Grant.Valid() || !q.InvocationKey.Valid() || s.ArtifactID != artifactID || handle != "" && q.ID != handle || s.PacketQuery.Selection().MaxPackets != 20 || s.PacketQuery.PrefixOffset != 0 || s.PacketQuery.PrefixLength != 64 || q.Scope.ReadBatches() != 2 || q.Plan.Profile.Worker.MemoryBytes < query.PacketQueryWorkerBytes || q.Plan.Profile.Worker.WorkerTransientBytes < query.PacketQueryWorkerBytes {
				stop()
				t.Fatal("packet query lost original raw scope/grant/selection/worker reservation")
			}
			if units != 4 || summaries != 2 || queries < 1 || queries > 2 || rootUnits != expectedRoot || expectedRoot != 4+4*queries || workUnits != rootUnits || principalUnits != expectedPrincipal || expectedPrincipal <= 0 || children != 1 || uses != queries || bytes != int64(queries)*query.ContextResultBytes || ops != int64(queries) {
				stop()
				t.Fatalf("packet query accounting units=%d summaries=%d queries=%d root=%d expectedRoot=%d workload=%d principal=%d exactPrincipal=%d children=%d uses=%d bytes=%d ops=%d", units, summaries, queries, rootUnits, expectedRoot, workUnits, principalUnits, expectedPrincipal, children, uses, bytes, ops)
			}
			var validUses bool
			err = admin.QueryRow(call, `SELECT count(*)=1 AND bool_and(u.id=b.id AND u.parent_id=(q.query->'Grant'->>'ParentID')::uuid AND u.child_id=(q.query->'Grant'->>'ChildID')::uuid AND u.operation='pcap_query' AND u.bytes=24576 AND u.operations=1 AND g.bytes_spent=(SELECT sum(x.bytes) FROM access_grant_use x WHERE x.parent_id=g.id) AND g.operations_spent=(SELECT sum(x.operations) FROM access_grant_use x WHERE x.parent_id=g.id)) FROM context_query q JOIN context_query_batch b ON b.query_id=q.id JOIN access_grant_use u ON u.id=b.id JOIN access_grant g ON g.id=u.parent_id WHERE q.root_id=$1 AND q.id=$2`, root, q.ID).Scan(&validUses)
			observed.Intent = intent.Worker
			pod, e := api.CoreV1().Pods(observed.Binding.Namespace).Get(call, observed.Binding.Pod, meta.GetOptions{})
			if err != nil || !validUses || !observed.Valid() || e != nil || string(pod.UID) != observed.Binding.PodUID || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Resources.Limits.Memory().Value() != q.Plan.Profile.Worker.MemoryBytes || pod.Spec.Containers[0].Resources.Limits.Cpu().MilliValue() != 500 {
				stop()
				t.Fatal("packet query exact batch/use or original worker Pod", err, e)
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
						return errors.New("packet query missing positive original retirement")
					}
					return nil
				})
				if err != nil {
					t.Fatal("packet query exact terminal/retirement", err)
				}
				t.Logf("installed packet query SQL: summaries2/%dunits queries%d/%dunits; exact account%d=root%d/workload%d; each page one24KiB/one-op original parent+child use, one three-role native/public joined batch; original Pod limit%d/500m; collection/observation unchanged", 4, queries, queries*4, principalUnits, rootUnits, workUnits, q.Plan.Profile.Worker.MemoryBytes)
			}
			if terminalSink != nil {
				terminalSink(finishTerminal)
			} else {
				finishTerminal()
			}

			if retained != nil {
				*retained = append(*retained, retirement)
			}
			return retirement
		}
	}
}
