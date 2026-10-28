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
// collection authority and cannot refresh the binding or demand.
const installedInitialStorageQuery = `WITH p AS MATERIALIZED (
 SELECT root_id,convert_from(blueprint_json,'UTF8')::jsonb AS blueprint
 FROM context_preview WHERE root_id=$1 AND id=$2
), n AS MATERIALIZED (SELECT clock_timestamp() AS at)
SELECT p.root_id IS NOT NULL,b.root_id IS NOT NULL,w.id IS NOT NULL,w.ready_at IS NOT NULL,
 coalesce(b.allocation_id=(p.blueprint#>>'{Storage,AllocationID}')::uuid,false),
 coalesce(w.allocation_id=(p.blueprint#>>'{Storage,AllocationID}')::uuid,false),
 coalesce(b.fresh_until-b.observed_at<=interval '5 seconds',false),
 coalesce(b.fresh_until-b.observed_at=interval '30 seconds',false),
 coalesce(b.observed_at=(w.ready_completion->>'ObservedAt')::timestamptz AND
          b.fresh_until=(w.ready_completion->>'Until')::timestamptz,false),
 d.root_id IS NOT NULL,coalesce(n.at<d.not_after,false),
 b.observed_at,b.fresh_until,n.at,d.requested_at,d.not_after
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
 d.workload_uid=p.blueprint#>>'{Target,Workload,UID}'`

type installedInitialStorageFacts struct {
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
		&f.ObservedAt, &f.FreshUntil, &f.Now, &f.DemandRequested, &f.DemandNotAfter)
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
}
