package integration

import (
	"testing"

	capacity "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
)

// Only this focus reallocates existing synthetic pool objects. Total objects,
// every byte limit and production defaults remain unchanged.
func installedCapacityObjectPartitions() (system, burst int64) {
	if installedJourneyFocus() == "profile-comparison" {
		return 20000, 30000
	}
	return 10000, 40000
}

// Protect the actual native account/record and pool-object coupling using the
// existing synthetic qualification. Other footprint/authority dimensions stay
// with those existing fixtures; this is not a second installer implementation.
func installedProfileComparisonCapacityFixture(t *testing.T, p contracts.InstallerCapacitySettings) (capacity.CapacityQualification, capacity.CapacitySnapshot) {
	t.Helper()
	q, source := capacityNativeQualification(t, custodyID(), custodyID(), custodyID(), custodyID(), "profile-object-preflight")
	in := &q.RootBacking
	in.Accounts, in.RecordsPerAccount = p.Accounts, p.Records
	in.ContextHistory.ProfileProtocol = capacity.ProfileProtocolVersion
	resize := func(lane *capacity.RootAuditBacking, accounts, records int64) {
		lane.Accounts, lane.RecordsPerAccount = accounts, records
		lane.Policy.MetadataSlots = accounts * records
		backup, wal := lane.Policy.History.SlotBacking(lane.Policy.MaxPurgeLeases)
		lane.Policy.BackupReservedBytes, lane.Policy.WALReservedBytes = accounts*records*backup, accounts*records*wal
	}
	resize(&in.Capture, p.Accounts, p.Records)
	resize(&in.Normal, p.Lanes.Normal.Accounts, p.Lanes.Normal.Records)
	resize(&in.Resolution, p.Lanes.Resolution.Accounts, p.Lanes.Resolution.Records)
	resize(&in.Processing, p.Lanes.Processing.Accounts, p.Lanes.Processing.Records)
	in.ProcessingState.MaxCaptures = p.Accounts * p.Records
	in.ProcessingState.BackupBytes, in.ProcessingState.WALBytes, _ = in.ProcessingState.RequiredBytes()
	f := &capacitySQLFixture{qualification: q}
	syntheticQueryCapacityQualification(t, f)
	q = f.qualification
	x := q.ContextQuery
	x.RootQueries, x.PrincipalQueries, x.PrincipalAccounts, x.WorkloadAccounts, x.WorkloadQueries = p.Accounts*p.Records, p.Records, p.Accounts*p.Records, p.Accounts, p.Records
	x.Profile.Worker.MemoryBytes, x.Profile.Worker.WorkerTransientBytes = query.ProfileComparisonWorkerBytes, query.ProfileComparisonWorkerBytes
	var err error
	x.Envelope, err = x.Required()
	if err != nil || !q.Valid() {
		t.Fatal("shared query object qualification", err)
	}
	// Match the native pool's fully partitioned object vector. Byte and other
	// source dimensions deliberately retain the existing synthetic defaults.
	pool, policy := source.Pools[0].Budget, source.Policies[0].Budget
	pool.Capacity.Objects, pool.Safety.Objects = 100000, 10000
	pool.System.Objects, pool.Burst.Objects = installedCapacityObjectPartitions()
	pool.Slots[0].Workloads, pool.Slots[0].Protected.Objects = 4, 10000
	policy.Protected.Objects, policy.Hard.Objects, policy.Context.Objects = 10000, 20000, 1000
	policy.NamespaceAccounts, policy.NamespaceMaximum.Objects = 4, 80000
	return q, source
}
