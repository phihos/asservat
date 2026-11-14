package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	capacity "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"

	query "asservat.local/asservat/internal/domain/analysis"
	"github.com/google/pprof/profile"
)

func TestInstalledProfileComparisonFocusPreflight(t *testing.T) {
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "")
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "profile-comparison")
	if got := installedClusterCount(); got != 2 {
		t.Fatalf("bootstrap consumer expects %d clusters; Python focus descriptor provides 2", got)
	}
	if !installedProfileFocus() || !installedRecordingFocus() || !installedFastFixture() || nativeCapacityProfile().Records != installedProfileComparisonQueries*query.ProfileComparisonQueryUnits || nativeCapacityProfile().Records != 40 {
		t.Fatal("comparison focus not wired to exact two-query40-unit fixture")
	}
	checkManualProfilePlan(t, "00000000-0000-4000-8000-000000000001", approvedRecordingArguments("00000000-0000-4000-8000-000000000001", "payments", "api"))
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	if !installedProfileFocus() || nativeCapacityProfile().Records != 12 || query.ProfileSummaryQueryUnits != 10 {
		t.Fatal("manual four-capture funding or ten-unit summary charge changed")
	}
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "approved-recording")
	if installedProfileFocus() || nativeCapacityProfile().Records != 8 {
		t.Fatal("non-profile fixture changed")
	}
}

func TestInstalledProfileComparisonIndependentNativeCalculation(t *testing.T) {
	leaf, root := &profile.Function{ID: 1, Name: "leaf"}, &profile.Function{ID: 2, Name: "root"}
	inline := &profile.Location{ID: 1, Line: []profile.Line{{Function: leaf}, {Function: root}}}
	recursive := &profile.Location{ID: 2, Line: []profile.Line{{Function: root}}}
	native := func(value, duration int64) []byte {
		p := &profile.Profile{SampleType: []*profile.ValueType{{Type: "cpu", Unit: "nanoseconds"}}, Sample: []*profile.Sample{{Location: []*profile.Location{inline, recursive, inline}, Value: []int64{value}}}, Location: []*profile.Location{inline, recursive}, Function: []*profile.Function{leaf, root}, DurationNanos: duration}
		var out bytes.Buffer
		if err := p.Write(&out); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	rows, totals, durations, err := independentInstalledProfileComparison(native(10, 2e9), native(14, 1e9), 20)
	if err != nil || totals != [2]int64{10, 14} || durations != [2]float64{2, 1} || len(rows) != 2 || rows[0].Function == nil || *rows[0].Function != "leaf" || rows[1].Function == nil || *rows[1].Function != "root" {
		t.Fatal("independent recursion/inline/rate facts", rows, totals, durations, err)
	}
	for _, row := range rows {
		if row.Baseline != 5 || row.Incident != 14 || row.Delta != 9 {
			t.Fatal("native rate or recursive multiplicity changed", row)
		}
	}
	limited, _, _, err := independentInstalledProfileComparison(native(10, 2e9), native(14, 1e9), 1)
	if err != nil || !reflect.DeepEqual(limited, rows[:1]) {
		t.Fatal("limit was applied before complete native aggregation", err)
	}
	if _, _, _, err := independentInstalledProfileComparison([]byte("invalid"), native(14, 1e9), 20); err == nil {
		t.Fatal("malformed downloaded native profile accepted")
	}
}

func TestInstalledProfileComparisonBrowserReplyRetainsBothSourceProvenance(t *testing.T) {
	raw, err := os.ReadFile("../../examples/mcp-profile-comparison-result.json")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil || wire.ValidateOutput("compare_profiles", raw) != nil {
		t.Fatal("canonical comparison/browser fixture", err)
	}
	var reply installedJourneyEnvelope
	if json.Unmarshal(raw, &reply) != nil || reply.Status != "ok" || reply.DataClass != "extract" || len(reply.Provenance) != 2 || reply.Provenance[0].ArtifactID == "" || reply.Provenance[1].Digest == "" {
		t.Fatal("browser transport dropped comparison source fields")
	}
}

func TestInstalledProfileComparisonActualPoolCapacity(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "profile-comparison")
	q, source := installedProfileComparisonCapacityFixture(t, *nativeCapacityProfile())
	// The original fully partitioned pool was structurally valid but could
	// not fund even the profile-protocol capture root. Preserve that failure.
	old := source
	old.Pools = append([]capacity.PoolObservation(nil), source.Pools...)
	oldBudget := *source.Pools[0].Budget
	oldBudget.System.Objects, oldBudget.Burst.Objects = 10000, 40000
	old.Pools[0].Budget = &oldBudget
	oldPool, err := capacity.CompileProtectedPoolPlan(old, "capacity")
	if err != nil {
		t.Fatal("original native pool shape", err)
	}
	if _, err := capacity.CompileQualifiedRootBacking(q, oldPool); !errors.Is(err, capacity.ErrBudgetFull) {
		t.Fatal("original10000-object partition unexpectedly funds comparison", err)
	}
	pool, err := capacity.CompileProtectedPoolPlan(source, "capacity")
	if err != nil {
		t.Fatal("native complete pool input", err)
	}
	plan, err := capacity.CompileQualifiedRootBacking(q, pool)
	if err != nil {
		t.Fatal("actual native comparison root does not fit its source pool", err)
	}
	total := plan.Totals()
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, digest := plan.Canonical()
	root := capacity.RootConfiguration{Format: capacity.RootConfigurationFormat, RootID: q.RootBacking.RootID, AttemptID: custodyID(), PlanDigest: digest, Revision: 1, InitialObservedAt: now, InitialUntil: now.Add(5 * time.Second), RevisionObservedAt: now, RevisionUntil: now.Add(5 * time.Second), PlannedUntil: now.Add(time.Duration(q.RootBacking.AdmissionSeconds) * time.Second), ReservedAt: now, CaptureBackedAt: &now, ReadyAt: &now}
	paired, err := capacity.CompileQueryBacking(q, root, plan, pool, artifact.Digest{1}, custodyID())
	if err != nil {
		t.Fatal("combined actual native root/query backing", err)
	}
	objects, bytes := total.SystemObjects.Objects+paired.Reservation.SystemObjects.Objects, total.SystemObjects.Bytes+paired.Reservation.SystemObjects.Bytes
	if total.Records != 640 || total.SystemObjects.Objects != 10752 || paired.Reservation.SystemObjects.Objects != 8960 || objects != 19712 || objects > pool.System.Objects || pool.System.Objects != 20000 || pool.Burst.Objects != 30000 || pool.Capacity.Objects != 100000 {
		t.Fatal("native object reservation or fixed partition changed", total, paired.Reservation, pool)
	}
	t.Logf("native object preflight (other costs synthetic): accounts=%d records=%d root_units=%d base_objects=%d query_objects=%d combined_objects=%d combined_bytes=%d system_objects=%d shared_burst_objects=%d total_objects=%d", q.RootBacking.Accounts, q.RootBacking.RecordsPerAccount, total.Records, total.SystemObjects.Objects, paired.Reservation.SystemObjects.Objects, objects, bytes, pool.System.Objects, pool.Burst.Objects, pool.Capacity.Objects)
	for _, focus := range []string{"manual-profile", "manual-syscall", "approved-recording"} {
		t.Setenv("ASSERVAT_JOURNEY_FOCUS", focus)
		system, burst := installedCapacityObjectPartitions()
		if system != 10000 || burst != 40000 {
			t.Fatal("unrelated native pool partition changed", focus, system, burst)
		}
	}
}
