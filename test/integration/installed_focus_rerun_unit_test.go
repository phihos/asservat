package integration

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
)

// A development-only keep run funds installedKeptRuns() logs focus runs; its
// synthetic operator capacity must still compile, and ordinary runs keep the
// original exact single-run funding.
func TestInstalledKeepModeFundsLogsReruns(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-logs")
	if installedKeptRuns() != 1 || nativeCapacityProfile().Records != installedLogsQueryUnits || installedRunSuffix() != "" {
		t.Fatal("ordinary run changed by keep/rerun support")
	}
	t.Setenv("ASSERVAT_INSTALLED_KEEP", "1")
	runs := installedKeptRuns()
	p := *nativeCapacityProfile()
	if runs != 4 || p.Records != runs*installedLogsQueryUnits {
		t.Fatal("keep run funding", runs, p.Records)
	}
	q, source := installedProfileComparisonCapacityFixture(t, p)
	system, _ := installedCapacityObjectPartitions()
	if source.Pools[0].Budget.Capacity.Objects += system - 20000; source.Pools[0].Budget.Capacity.Objects != installedPoolCapacityObjects() {
		t.Fatal("keep run pool partition", installedPoolCapacityObjects())
	}
	pool, err := capacity.CompileProtectedPoolPlan(source, "capacity")
	if err != nil {
		t.Fatal(err)
	}
	backing, err := capacity.CompileQualifiedRootBacking(q, pool)
	if err != nil {
		t.Fatal("keep run root backing", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, digest := backing.Canonical()
	root := capacity.RootConfiguration{Format: capacity.RootConfigurationFormat, RootID: q.RootBacking.RootID, AttemptID: custodyID(), PlanDigest: digest, Revision: 1, InitialObservedAt: now, InitialUntil: now.Add(5 * time.Second), RevisionObservedAt: now, RevisionUntil: now.Add(5 * time.Second), PlannedUntil: now.Add(time.Duration(q.RootBacking.AdmissionSeconds) * time.Second), ReservedAt: now, CaptureBackedAt: &now, ReadyAt: &now}
	if _, err = capacity.CompileQueryBacking(q, root, backing, pool, artifact.Digest{1}, custodyID()); err != nil {
		t.Fatal("keep run query backing", err)
	}
}
