package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativePacingProviderDeltaRejectsMissingOrResetCounters(t *testing.T) {
	before, after := map[string]nativeProviderCounters{}, map[string]nativeProviderCounters{}
	for _, name := range nativeProviderCategories {
		before[name] = nativeProviderCounters{}
		after[name] = nativeProviderCounters{}
	}
	before["s3_get"] = nativeProviderCounters{Dispatches: 2, Active: 1, Status2xx: 1, HeaderNanoseconds: 10}
	after["s3_get"] = nativeProviderCounters{Dispatches: 3, Active: 0, Status2xx: 3, HeaderNanoseconds: 30}
	d, err := nativeProviderDelta(before, after)
	if err != nil || d["s3_get"].Dispatches != 1 || d["s3_get"].Active != -1 || d["s3_get"].HeaderNanoseconds != 20 {
		t.Fatal("in-flight gauge decrease discarded valid monotonic work", err, d)
	}
	after["s3_get"] = nativeProviderCounters{Dispatches: 1}
	if _, err := nativeProviderDelta(before, after); err == nil {
		t.Fatal("counter reset reported as a valid cost delta")
	}
	delete(after, "kms_other")
	if _, err := nativeProviderDelta(before, after); err == nil {
		t.Fatal("missing counter category reported as zero")
	}
}

func TestNativePacingReportRetainsIncomparableNumericEdges(t *testing.T) {
	now := time.Now().UTC()
	before := nativeSQLSnapshot{StartedAt: now, FinishedAt: now.Add(time.Millisecond), ResetAt: now.Add(-time.Hour), Deallocations: 1, Roles: map[uint32]nativeSQLCounters{42: {Calls: 3, Rows: 4, Statements: 2, ExecutionMilliseconds: 1}}}
	after := nativeSQLSnapshot{StartedAt: now.Add(time.Second), FinishedAt: now.Add(time.Second + time.Millisecond), ResetAt: before.ResetAt, Deallocations: 2, Roles: map[uint32]nativeSQLCounters{42: {Calls: 5, Rows: 6, Statements: 2, ExecutionMilliseconds: 2}}}
	parent := t.TempDir()
	work := filepath.Join(parent, "integration")
	if err := os.MkdirAll(work, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, "results"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	measurement := nativePacingMeasurement{Complete: true, Phases: []nativePacingPhase{{Name: "setup", Before: nativePacingSnapshot{SQL: before}, After: nativePacingSnapshot{SQL: after}}}}
	if err := measurement.writeReport(); err == nil {
		t.Fatal("lost coverage was qualified")
	}
	raw, err := os.ReadFile(filepath.Join(parent, "results", "native-paced-report.json"))
	if err != nil {
		t.Fatal("lost coverage discarded numeric evidence", err)
	}
	var saved nativePacingMeasurement
	if err = json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.MeasurementFailure != "SQL snapshot entries evicted" || saved.Complete || len(saved.Phases) != 1 || saved.Phases[0].Before.SQL.Deallocations != 1 || saved.Phases[0].After.SQL.Deallocations != 2 || saved.ObservedSQLDelta != nil {
		t.Fatal("incomplete report hid numeric edges or invented deltas", string(raw))
	}
}
