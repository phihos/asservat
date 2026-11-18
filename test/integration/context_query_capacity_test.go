package integration

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	app "asservat.local/asservat/internal/application/capacity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SQL qualification of one original shared logical reservation: one installed
// anchor and one exact workload allocation. Deployment observations are fixture
// input; this does not measure physical resource use.
func TestContextQueryCapacityWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, qualifyContextQueryCapacitySQL)
}

func syntheticQueryCapacityQualification(t *testing.T, f *capacitySQLFixture) {
	t.Helper()
	rev := identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{41}}
	p := value.ContextQueryResourceProfile{ID: custodyID(), Source: rev, Qualification: rev, Path: value.ContextProjectionPath{Purpose: value.ContextProjectionPurpose}, Lifetime: 60 * time.Second, PollLimit: 4, ControlTransitionLimit: 32,
		Worker: value.ContextQueryWorkerLimits{CPUMilli: 100, MemoryBytes: 64 << 20, EphemeralStorageBytes: 4 << 20, WorkerTransientBytes: 8 << 20, HubTransientBytes: 128 << 10, ProviderConcurrency: 1, AuthenticationConcurrency: 1, Runtime: time.Minute, CredentialLifetime: 2 * time.Minute, ProviderEffectLifetime: time.Minute, Cleanup: time.Minute},
		Cost:   value.ContextQueryCost{Workers: 1, ReadBatches: 2, ReadBytes: 8 << 20, StructuredBytes: 48 << 10, WireBytes: 128 << 10, UnwrapAttempts: 6, ProviderRequests: 100, AuthenticationRequests: 100, SigningAttempts: 2, AuditObjects: 14, SQLRows: 47, SQLBytes: 4 << 20, WALBytes: 64 << 20, BackupBytes: 8 << 20}}
	q := app.ContextQueryQualification{Format: app.ContextQueryQualificationFormat, CapacityID: custodyID(), Profile: p, RootQueries: 2, PrincipalQueries: 1, PrincipalAccounts: 2, WorkloadAccounts: 1, WorkloadQueries: 2, Admission: 60 * time.Second,
		History: app.QueryHistoryQualification{Layout: app.ContextQueryHistoryLayout, Revision: rev, FixedBytes: 1 << 20, PrincipalBytes: 4096, AllocationBytes: 4096, RowBytes: 4096, FixedQueryRows: 10, InvocationRows: 1, ControlRows: 1, TransitionWALBytes: 64 << 10, BackupCopies: 2, WALCopies: 2, AuditCipherBytes: 64 << 10, BackupHorizon: time.Hour, RetirementCleanup: time.Minute}}
	var err error
	q.Envelope, err = q.Required()
	if err != nil {
		t.Fatal(err)
	}
	f.qualification.ContextQuery = &q
	if !f.qualification.Valid() {
		t.Fatal("synthetic shared query qualification invalid")
	}
}

func qualifyContextQueryCapacitySQL(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, objects *objectstore.Store) {
	f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, objects, func(f *capacitySQLFixture) { syntheticQueryCapacityQualification(t, f) })
	f.setup(t)
	var err error
	var acceptance, hard string
	var observations int64
	if err = admin.QueryRow(ctx, "SELECT acceptance_id::text,plan->>'HardUntil',observations FROM context_query_capacity WHERE root_id=$1", f.input.PermissionRootID).Scan(&acceptance, &hard, &observations); err != nil || acceptance != f.qualification.ContextQuery.CapacityID || observations != 0 {
		t.Fatal("one installed anchor without query observer", err)
	}
	var allocation string
	var valid bool
	if err = admin.QueryRow(ctx, "SELECT id::text,context_query_capacity_allocation_current(root_id,id) FROM context_query_allocation WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3 AND workload_uid=$4", f.input.PermissionRootID, scope.ClusterID, f.namespace.UID, f.workloads[0].UID).Scan(&allocation, &valid); err != nil || !valid {
		t.Fatal("exact workload allocation", err)
	}
	var again, againHard, againAllocation string
	if err = admin.QueryRow(ctx, "SELECT c.acceptance_id::text,c.plan->>'HardUntil',a.id::text FROM context_query_capacity c JOIN context_query_allocation a USING(root_id) WHERE c.root_id=$1", f.input.PermissionRootID).Scan(&again, &againHard, &againAllocation); err != nil || again != acceptance || againHard != hard || againAllocation != allocation {
		t.Fatal("source refresh replaced original charge or deadline", err)
	}
	var count int
	if err = admin.QueryRow(ctx, "SELECT count(*) FROM context_query_allocation WHERE root_id=$1", f.input.PermissionRootID).Scan(&count); err != nil || count != 1 {
		t.Fatal("allocation charge changed", count, err)
	}
}
