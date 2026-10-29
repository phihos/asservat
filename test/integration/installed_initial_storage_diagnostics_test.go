package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Fixture administrator only. One exact preview lookup, bounded by three
// seconds, projects fixed booleans and dates; no blueprint, identity, target,
// filter, credentials or object locations leave SQL. These facts confer no
// collection authority and cannot refresh the binding or demand. Permission
// flags describe stored/current state only: no recovery, source or trust proof
// is fabricated, and postmortem state does not establish a request-time cause.
const installedInitialStorageQuery = `WITH p AS MATERIALIZED (
 SELECT cp.root_id,convert_from(cp.blueprint_json,'UTF8')::jsonb AS blueprint
 FROM context_preview cp WHERE cp.root_id=$1 AND cp.id=$2
), n AS MATERIALIZED (SELECT clock_timestamp() AS at)
SELECT p.root_id IS NOT NULL,b.root_id IS NOT NULL,w.id IS NOT NULL,w.ready_at IS NOT NULL,
 coalesce(b.allocation_id=(p.blueprint#>>'{Storage,AllocationID}')::uuid,false),
 coalesce(w.allocation_id=(p.blueprint#>>'{Storage,AllocationID}')::uuid,false),
 coalesce(b.fresh_until-b.observed_at<=interval '5 seconds',false),
 coalesce(b.fresh_until-b.observed_at=interval '30 seconds',false),
 coalesce(b.observed_at=(w.ready_completion->>'ObservedAt')::timestamptz AND
          b.fresh_until=(w.ready_completion->>'Until')::timestamptz,false),
 d.root_id IS NOT NULL,coalesce(n.at<d.not_after,false),
 b.observed_at,b.fresh_until,n.at,d.requested_at,d.not_after,
 ps.id IS NOT NULL,coalesce(NOT ps.suspended AND ps.observed_at<=n.at AND
 ps.fresh_until<=ps.observed_at+interval '5 seconds' AND n.at<ps.fresh_until AND n.at<ps.lease_until,false),
 ia.acknowledged_at IS NOT NULL,ea.acknowledged_at IS NOT NULL,
 coalesce(q.within_limit,false),coalesce(q.basis,false),coalesce(q.current_sequence,false),coalesce(q.live_lifetime,false),
 coalesce(q.maintainer,false),coalesce(q.activation_ack,false)
 FROM n LEFT JOIN p ON true
 LEFT JOIN context_storage_binding b ON b.root_id=p.root_id AND
 b.cluster_id=(p.blueprint#>>'{Target,ClusterID}')::uuid AND
 b.namespace_uid=p.blueprint#>>'{Target,Namespace,UID}' AND
 b.workload_uid=p.blueprint#>>'{Target,Workload,UID}'
 LEFT JOIN capacity_workload w ON w.root_id=p.root_id AND
 w.cluster_id=(p.blueprint#>>'{Target,ClusterID}')::uuid AND
 w.namespace_uid=p.blueprint#>>'{Target,Namespace,UID}' AND
 w.workload_uid=p.blueprint#>>'{Target,Workload,UID}'
 LEFT JOIN capacity_refresh_demand d ON d.root_id=p.root_id AND
 d.cluster_id=(p.blueprint#>>'{Target,ClusterID}')::uuid AND
 d.namespace_uid=p.blueprint#>>'{Target,Namespace,UID}' AND
 d.workload_uid=p.blueprint#>>'{Target,Workload,UID}'
 LEFT JOIN permission_stream ps ON ps.id=p.root_id
 LEFT JOIN authority_audit ia ON ia.id=ps.initial_audit_id AND ia.stream_id=ps.id
 LEFT JOIN authority_audit ea ON ea.id=ps.epoch AND ea.stream_id=ps.id
 LEFT JOIN LATERAL (
 SELECT count(*)<=1024 AS within_limit,bool_or(true) AS basis,
 bool_or(x.seen_sequence=ps.sequence) AS current_sequence,
 bool_or(x.seen_sequence=ps.sequence AND (x.not_after IS NULL OR n.at<x.not_after)) AS live_lifetime,
 bool_or(x.seen_sequence=ps.sequence AND (x.not_after IS NULL OR n.at<x.not_after) AND x.maintainer) AS maintainer,
 bool_or(x.seen_sequence=ps.sequence AND (x.not_after IS NULL OR n.at<x.not_after) AND x.activation_ack) AS activation_ack
 FROM (
 SELECT pb.seen_sequence,pb.not_after,
 EXISTS(SELECT 1 FROM permission_assignment a WHERE a.stream_id=pb.stream_id AND a.basis_key=pb.basis_key
 AND a.role='workload-maintainer' AND a.retired_at IS NULL) AS maintainer,
 EXISTS(SELECT 1 FROM permission_assignment a JOIN authority_audit proof ON proof.id=a.activation_audit_id
 WHERE a.stream_id=pb.stream_id AND a.basis_key=pb.basis_key AND a.role='workload-maintainer'
 AND a.retired_at IS NULL AND proof.stream_id=pb.stream_id AND proof.acknowledged_at IS NOT NULL) AS activation_ack
 FROM permission_basis pb WHERE pb.stream_id=p.root_id AND pb.effect='Allow'
 AND pb.cluster_id=(p.blueprint#>>'{Target,ClusterID}')::uuid
 AND pb.namespace_uid=p.blueprint#>>'{Target,Namespace,UID}'
 AND (cardinality(pb.workload_uids)=0 OR (p.blueprint#>>'{Target,Workload,UID}')=ANY(pb.workload_uids))
 ORDER BY pb.basis_key LIMIT 1025
 ) x
 ) q ON true`

// Target flags are successive stored-basis predicates, using the production
// namespace-wide (empty workload list) semantics and bounded basis scan. They
// deliberately do not claim the complete ReadCapacityPermissions contract.
type installedInitialStorageFacts struct {
	PermissionStream, PermissionCurrent, InitialACK, EpochACK                            bool
	TargetBasisWithinLimit                                                               bool
	TargetBasis, TargetSequence, TargetLifetime, TargetMaintainer, TargetActivationACK   bool
	Preview, Binding, Enrolled, Ready, SelectedAllocation, EnrolledAllocation            bool
	ShortInterval, ThirtySecondInterval, ReadyPublication, DemandRecorded, DemandCurrent bool
	ObservedAt, FreshUntil, Now, DemandRequested, DemandNotAfter                         pgtype.Timestamptz
}

func readInstalledInitialStorage(ctx context.Context, pool *pgxpool.Pool, root, preview string) (installedInitialStorageFacts, error) {
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var f installedInitialStorageFacts
	err := pool.QueryRow(call, installedInitialStorageQuery, root, preview).Scan(
		&f.Preview, &f.Binding, &f.Enrolled, &f.Ready, &f.SelectedAllocation, &f.EnrolledAllocation,
		&f.ShortInterval, &f.ThirtySecondInterval, &f.ReadyPublication, &f.DemandRecorded, &f.DemandCurrent,
		&f.ObservedAt, &f.FreshUntil, &f.Now, &f.DemandRequested, &f.DemandNotAfter,
		&f.PermissionStream, &f.PermissionCurrent, &f.InitialACK, &f.EpochACK,
		&f.TargetBasisWithinLimit, &f.TargetBasis, &f.TargetSequence, &f.TargetLifetime, &f.TargetMaintainer, &f.TargetActivationACK)
	return f, err
}

func installedInitialStorageDiagnostics(t *testing.T, ctx context.Context, pool *pgxpool.Pool, root, preview string) {
	t.Helper()
	f, err := readInstalledInitialStorage(ctx, pool, root, preview)
	if err != nil {
		t.Log("installed initial storage diagnostic unavailable")
		return
	}
	date := func(v pgtype.Timestamptz) string {
		if !v.Valid || v.InfinityModifier != pgtype.Finite {
			return "absent"
		}
		return v.Time.UTC().Format(time.RFC3339Nano)
	}
	t.Logf("installed initial storage: preview=%t binding=%t enrolled=%t ready=%t selectedAllocation=%t enrolledAllocation=%t shortInterval=%t thirtySecondInterval=%t readyPublication=%t demandRecorded=%t demandCurrent=%t observedAt=%s freshUntil=%s now=%s demandRequested=%s demandNotAfter=%s",
		f.Preview, f.Binding, f.Enrolled, f.Ready, f.SelectedAllocation, f.EnrolledAllocation,
		f.ShortInterval, f.ThirtySecondInterval, f.ReadyPublication, f.DemandRecorded, f.DemandCurrent,
		date(f.ObservedAt), date(f.FreshUntil), date(f.Now), date(f.DemandRequested), date(f.DemandNotAfter))
	t.Logf("installed stored/current permission state: stream=%t current=%t initialACK=%t epochACK=%t targetBasisWithinLimit=%t targetBasis=%t targetSequence=%t targetLifetime=%t targetMaintainer=%t targetActivationACK=%t",
		f.PermissionStream, f.PermissionCurrent, f.InitialACK, f.EpochACK,
		f.TargetBasisWithinLimit, f.TargetBasis, f.TargetSequence, f.TargetLifetime, f.TargetMaintainer, f.TargetActivationACK)
}
