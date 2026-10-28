package integration

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capacity"
	"github.com/jackc/pgx/v5/pgtype"
)

// Runs immediately after the actual first Ready publication, before creating
// another independent workload observation. No stored timestamps are edited.
func qualifyInitialBindingProjection(t *testing.T, f *capacitySQLFixture, o app.EnrollmentObservation, enrollment app.Enrollment) func(*testing.T) {
	t.Helper()
	type state struct {
		observed, until time.Time
		spent           int64
	}
	read := func(t *testing.T) state {
		t.Helper()
		var s state
		if err := f.admin.QueryRow(f.ctx, `SELECT b.observed_at,b.fresh_until,s.configuration_spent FROM context_storage_binding b JOIN capacity_source s USING(root_id) WHERE b.root_id=$1 AND b.allocation_id=$2`, o.Key.RootID, enrollment.AllocationID).Scan(&s.observed, &s.until, &s.spent); err != nil {
			t.Fatal(err)
		}
		return s
	}
	initial := read(t)
	if !initial.observed.Equal(o.ObservedAt) || initial.until.After(o.FreshUntil) || !initial.until.After(initial.observed) {
		t.Fatal("first Ready did not retain original short publication interval")
	}
	if err := f.enrollments.RefreshCapacityEnrollment(f.ctx, o, enrollment); err != nil {
		t.Fatal("same observation first binding projection", err)
	}
	projected := read(t)
	if !projected.observed.Equal(initial.observed) || !projected.until.Equal(o.ObservedAt.Add(30*time.Second)) || projected.spent != initial.spent+1 {
		t.Fatal("same observation did not project once from original time", initial, projected)
	}
	// The actual generated SQL RPC returns its original short proof interval,
	// even though the persisted mapping now has its reviewed 30-second lifetime.
	plan, pool, source, err := o.Plan.CanonicalValues()
	if err != nil {
		t.Fatal(err)
	}
	observation, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	var root pgtype.UUID
	if err = root.Scan(o.Key.RootID); err != nil {
		t.Fatal(err)
	}
	params := custodydb.RefreshCapacityEnrollmentParams{RootID: root, ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool, SourceCanonical: source, ExpectedValue: expected}
	raw, err := custodydb.New(f.roles["capacity"]).RefreshCapacityEnrollment(f.ctx, params)
	if err != nil {
		t.Fatal("duplicate original SQL refresh", err)
	}
	var receipt struct {
		Enrollment *app.Enrollment
		FreshUntil time.Time
	}
	if err = json.Unmarshal(raw, &receipt); err != nil || receipt.Enrollment == nil || !reflect.DeepEqual(*receipt.Enrollment, enrollment) || receipt.FreshUntil.After(o.FreshUntil) || !time.Now().Before(receipt.FreshUntil) {
		t.Fatal("projection extended or changed original receipt", err)
	}
	duplicate := read(t)
	if !duplicate.observed.Equal(projected.observed) || !duplicate.until.Equal(projected.until) || duplicate.spent != projected.spent {
		t.Fatal("duplicate observation recharged or changed binding", projected, duplicate)
	}
	newer := f.workloadObservation(t, 0)
	if !newer.ObservedAt.After(o.ObservedAt) {
		t.Fatal("new independent observation did not advance")
	}
	if err = f.enrollments.RefreshCapacityEnrollment(f.ctx, newer, enrollment); err != nil {
		t.Fatal("newer observation", err)
	}
	advanced := read(t)
	if !advanced.observed.Equal(newer.ObservedAt) || !advanced.until.Equal(newer.ObservedAt.Add(30*time.Second)) {
		t.Fatal("new observation projection changed original timestamp")
	}
	if err = f.enrollments.RefreshCapacityEnrollment(f.ctx, o, enrollment); err != nil {
		t.Fatal("older still-current observation", err)
	}
	retained := read(t)
	if !retained.observed.Equal(advanced.observed) || !retained.until.Equal(advanced.until) || retained.spent != advanced.spent {
		t.Fatal("older caller replaced or recharged newer observation")
	}
	t.Logf("initial_binding_seconds=%.6f projected_seconds=30 initial_projection_configuration_debit=%d duplicate_debit=%d receipt_within_original=true newer_retained=true", initial.until.Sub(initial.observed).Seconds(), projected.spent-initial.spent, duplicate.spent-projected.spent)
	return func(t *testing.T) {
		t.Helper()
		if time.Now().Before(o.FreshUntil) {
			t.Fatal("original proof did not actually expire")
		}
		before := read(t)
		if err := f.enrollments.RefreshCapacityEnrollment(f.ctx, o, enrollment); err == nil {
			t.Fatal("adapter accepted expired original observation")
		}
		if _, err := custodydb.New(f.roles["capacity"]).RefreshCapacityEnrollment(f.ctx, params); err == nil {
			t.Fatal("SQL projected from expired original proof")
		}
		after := read(t)
		if !after.observed.Equal(before.observed) || !after.until.Equal(before.until) || after.spent != before.spent {
			t.Fatal("expired original observation changed binding or configuration debit")
		}
		t.Log("expired_original_adapter_and_sql_denied=true configuration_debit=0")
	}
}
