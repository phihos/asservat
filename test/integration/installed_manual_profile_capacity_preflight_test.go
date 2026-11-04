package integration

import (
	"testing"
	"time"

	capacity "asservat.local/asservat/internal/application/capacity"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	capture "asservat.local/asservat/internal/domain/capture"
)

func TestInstalledManualProfileActualPoolCapacity(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	const cluster = "00000000-0000-4000-8000-000000000001"
	const captures = int64(4) // CPU10, busy10, unavailable10, independently reviewed Stop30.
	arguments := manualProfileArguments(cluster, "payments", "api")
	composition := arguments["profile_composition"].(map[string]any)
	native := int64(composition["maxTotalBytes"].(int))
	stop := manualProfileStopArguments(cluster, "payments", "api")["profile_composition"].(map[string]any)
	if native != 16<<20 || int64(stop["maxTotalBytes"].(int)) != native {
		t.Fatal("reviewed per-action native limit changed")
	}
	profile := artifact.Registration{NativeLimit: native}
	stream := artifact.StreamingPlan{Registration: profile}
	history := artifact.Registration{NativeLimit: capture.MaxHistoryParameters}
	// Production admission reserves final ciphertext plus multipart backing;
	// history separately reserves four copies in the same allocation. Neither
	// success nor a known refusal returns these charges during this journey.
	perCapture := capacity.BudgetAmount{Bytes: profile.ReservedBytes() + stream.TemporaryBytes() + history.ReservedBytes(), Objects: 4 + 1 + int64(stream.PartLimit()) + 4}
	needed := capacity.BudgetAmount{Bytes: captures * perCapture.Bytes, Objects: captures * perCapture.Objects}
	if perCapture.Bytes != 36962304 || perCapture.Objects != 12 || needed.Bytes != 147849216 || needed.Objects != 48 {
		t.Fatal("profile/history backing changed; reassess fixture funding", perCapture, needed)
	}
	old := capacity.BudgetAmount{Bytes: 8 * (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes(), Objects: 32}
	// The observed failure is already inevitable without counting history:
	// two full reservations leave less than a third base registration.
	remaining := old.Bytes - 2*(profile.ReservedBytes()+stream.TemporaryBytes())
	if old.Bytes != 79429632 || remaining >= profile.ReservedBytes() || old.Bytes >= needed.Bytes || old.Objects >= needed.Objects {
		t.Fatal("original fixture no longer reproduces third-admission exhaustion", old, remaining)
	}
	bytes, objects := installedRegionalContextReserve()
	t.Run("four-captures-and-history", func(t *testing.T) {
		if bytes != needed.Bytes || objects != needed.Objects {
			t.Fatalf("initial regional funding = %d bytes/%d objects; four retained captures+history require exactly %d/%d", bytes, objects, needed.Bytes, needed.Objects)
		}
	})
	p := *nativeCapacityProfile()
	q, source := installedProfileComparisonCapacityFixture(t, p)
	work, err := capacity.CompileContextProtocolBacking(needed, q.RootBacking.ContextHistory)
	if err != nil || work.Records != 12 || work.Evidence != needed {
		t.Fatal("actual regional evidence funding/protocol", work, err)
	}
	// Existing SQL enrollment rejects a regional protocol above the root's
	// RecordsPerAccount. Its previous 10-record root cannot accept this 12-record
	// reserve; summary admission still charges its unchanged ten query units.
	if work.Records <= 10 || query.ProfileSummaryQueryUnits != 10 {
		t.Fatal("historical root/summary accounting changed")
	}
	t.Run("qualified-root-ceiling", func(t *testing.T) {
		if p.Records != work.Records || q.ContextQuery.WorkloadQueries < query.ProfileSummaryQueryUnits {
			t.Fatal("root must fund regional12-record protocol and one ten-unit summary", p.Records, work.Records, q.ContextQuery.WorkloadQueries)
		}
	})
	pool, err := capacity.CompileProtectedPoolPlan(source, "capacity")
	if err != nil {
		t.Fatal("actual pool object vector", err)
	}
	plan, err := capacity.CompileQualifiedRootBacking(q, pool)
	if err != nil {
		t.Fatal("qualified profile root", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, digest := plan.Canonical()
	root := capacity.RootConfiguration{Format: capacity.RootConfigurationFormat, RootID: q.RootBacking.RootID, AttemptID: custodyID(), PlanDigest: digest, Revision: 1, InitialObservedAt: now, InitialUntil: now.Add(5 * time.Second), RevisionObservedAt: now, RevisionUntil: now.Add(5 * time.Second), PlannedUntil: now.Add(time.Duration(q.RootBacking.AdmissionSeconds) * time.Second), ReservedAt: now, CaptureBackedAt: &now, ReadyAt: &now}
	queries, err := capacity.CompileQueryBacking(q, root, plan, pool, artifact.Digest{1}, custodyID())
	if err != nil {
		t.Fatal("combined root/query backing", err)
	}
	total := plan.Totals()
	combined := total.SystemObjects.Objects + queries.Reservation.SystemObjects.Objects
	if pool.System.Objects != 10000 || pool.Burst.Objects != 40000 || pool.Capacity.Objects != 100000 || combined > pool.System.Objects {
		t.Fatal("manual profile changed/exhausted fixed pool partition", total, queries.Reservation, pool)
	}
	if total.Records != 192 || total.SystemObjects.Objects != 4032 || queries.Reservation.SystemObjects.Objects != 2688 || combined != 6720 {
		t.Fatal("composed object arithmetic changed", total, queries.Reservation)
	}
	t.Logf("manual profile preflight: four captures+history=%d bytes/%d objects; old=%d/%d; root=%d accounts*%d records; summary_units=%d; system_objects=%d+%d=%d/10000; shared_burst=40000 (other footprint costs synthetic)", needed.Bytes, needed.Objects, old.Bytes, old.Objects, p.Accounts, p.Records, query.ProfileSummaryQueryUnits, total.SystemObjects.Objects, queries.Reservation.SystemObjects.Objects, combined)
}

func TestInstalledManualProfileFundingLeavesOtherFociUnchanged(t *testing.T) {
	for _, tc := range []struct {
		focus   string
		records int64
	}{{"profile-comparison", 40}, {"approved-recording", 8}, {"manual-syscall", 10}, {"", 8}} {
		t.Run(tc.focus, func(t *testing.T) {
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", tc.focus)
			wantBytes := int64(8 * 1544192)
			if installedRecordingFocus() {
				wantBytes = 8 * (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes()
			}
			bytes, objects := installedRegionalContextReserve()
			if bytes != wantBytes || objects != 32 || nativeCapacityProfile().Records != tc.records {
				t.Fatal("unrelated fixture funding changed", bytes, objects, nativeCapacityProfile().Records)
			}
		})
	}
}
