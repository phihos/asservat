package integration

import (
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func TestPacketQueryOriginalManagedFunding(t *testing.T) {
	q, source := capacityNativeQualification(t, custodyID(), custodyID(), custodyID(), custodyID(), "fixture-accounts-v1")
	f := &capacitySQLFixture{qualification: q, template: source}
	queryLedgerQualification(t, f)
	accepted := f.qualification.ContextQuery
	accepted.Profile.Worker.MemoryBytes, accepted.Profile.Worker.WorkerTransientBytes = query.PacketQueryWorkerBytes, query.PacketQueryWorkerBytes
	accepted.RootQueries, accepted.PrincipalQueries, accepted.WorkloadQueries = 20, 20, 20
	var err error
	accepted.Envelope, err = accepted.Required()
	if err != nil {
		t.Fatal(err)
	}
	packetLedgerFunding(t, f)
	pool, err := app.CompileProtectedPoolPlan(source, source.Pools[0].Resource.Name)
	if err != nil {
		t.Fatal(err)
	}
	base, err := app.CompileQualifiedRootBacking(f.qualification, pool)
	if err != nil {
		t.Fatal("original query root backing", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, digest := base.Canonical()
	root := app.RootConfiguration{Format: app.RootConfigurationFormat, RootID: q.RootBacking.RootID, AttemptID: custodyID(), PlanDigest: digest, Revision: 1, InitialObservedAt: now, InitialUntil: now.Add(5 * time.Second), RevisionObservedAt: now, RevisionUntil: now.Add(5 * time.Second), PlannedUntil: now.Add(time.Duration(q.RootBacking.AdmissionSeconds) * time.Second), ReservedAt: now, CaptureBackedAt: &now, ReadyAt: &now}
	backing, err := app.CompileQueryBacking(f.qualification, root, base, pool, artifact.Digest{1}, custodyID())
	if err != nil {
		t.Fatal("compiled query backing", err)
	}
	// The new service qualifier retains one two-unit summary then one four-unit
	// two-page query per pristine source root. The planned installed journey
	// retains two summaries plus two queries:12units, separately funded at16.
	if query.PacketSummaryQueryUnits != 2 || query.PacketQueryQueryUnits != 4 || query.PacketQueryReadBatches != 2 || 2*query.PacketSummaryQueryUnits+2*query.PacketQueryQueryUnits != 12 || accepted.RootQueries < 12 || accepted.PrincipalQueries < 12 || accepted.WorkloadQueries < 12 {
		t.Fatal("original query funding lost old/new coverage")
	}
	t.Logf("service original20units/account: oldsummary2 + newquery4 =6/root; installed planned2old+2new=12/16; compiled SQL=%d WAL=%d backup=%d, no later topup/refund", backing.Reservation.SQLBytes, backing.Reservation.WALBytes, backing.Reservation.BackupBytes)
}
