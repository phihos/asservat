package postgres

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/authorization"
)

func storageObservationFixture() (custodydb.ObserveContextStorageRow, string, authorization.Target, time.Time) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	root := "00000000-0000-4000-8000-000000000001"
	target := authorization.Target{ClusterID: "00000000-0000-4000-8000-000000000002", NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod"}
	row := custodydb.ObserveContextStorageRow{RootID: id(root), ClusterID: id(target.ClusterID), NamespaceUid: target.NamespaceUID, WorkloadUid: target.WorkloadUID, AllocationID: id("00000000-0000-4000-8000-000000000003"), SourceUid: "source", SourceGeneration: 1, SourceDigest: make([]byte, 32), ObservedAt: ts(now.Add(-time.Second)), FreshUntil: ts(now.Add(4 * time.Second)), AllocationRevision: 1, AllocationValidUntil: ts(now.Add(time.Hour)), ServiceClass: "context", StoreID: id("00000000-0000-4000-8000-000000000004"), PoolRevision: 2, PoolValidUntil: ts(now.Add(time.Hour))}
	row.CapacityUntil = row.FreshUntil
	row.ControlPoolConfigured, row.ControlAccountConfigured = true, true
	row.ControlPoolRevision, row.ControlAccountRevision = 1, 1
	row.ControlPoolUntil, row.ControlAccountUntil = ts(now.Add(time.Hour)), ts(now.Add(time.Hour))
	row.ControlPoolFull, row.ControlPoolReplay, row.BackedFull, row.BackedReplay = 10, 10, 10, 10
	row.ControlAccountFull, row.ControlAccountReplay = 10, 10
	row.SourceDigest[0] = 1
	return row, root, target, now
}

func TestContextStorageObservationRetainsOriginalBounds(t *testing.T) {
	row, root, target, now := storageObservationFixture()
	v, err := contextStorageObservation(row, root, target, now)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Binding.ObservedAt.Equal(row.ObservedAt.Time) || !v.Binding.FreshUntil.Equal(row.FreshUntil.Time) || v.Selection.PoolRevision != 2 || v.Selection.AllocationRevision != 1 || v.Selection.BindingRevision != v.Binding.Revision {
		t.Fatal("read renewed source observation or lost current revisions")
	}
	row.AllocationValidUntil = ts(now.Add(time.Second))
	v, err = contextStorageObservation(row, root, target, now)
	if err != nil || !v.Binding.FreshUntil.Equal(row.AllocationValidUntil.Time) {
		t.Fatal("allocation expiry did not shorten observation", err)
	}
	if _, err = contextStorageObservation(row, root, target, row.AllocationValidUntil.Time); err == nil {
		t.Fatal("expired allocation remained available")
	}
}

func TestContextStorageObservationRejectsChangedOrInvalidSources(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*custodydb.ObserveContextStorageRow)
	}{
		{"control-pool-unconfigured", func(r *custodydb.ObserveContextStorageRow) { r.ControlPoolConfigured = false }},
		{"control-account-unconfigured", func(r *custodydb.ObserveContextStorageRow) { r.ControlAccountConfigured = false }},
		{"control-full-exhausted", func(r *custodydb.ObserveContextStorageRow) { r.ChargedFull = r.ControlAccountFull }},
		{"control-replay-exhausted", func(r *custodydb.ObserveContextStorageRow) { r.ChargedReplay = r.ControlAccountReplay }},
		{"control-original-deadline", func(r *custodydb.ObserveContextStorageRow) { r.ControlAccountUntil = r.ObservedAt }},
		{"pool-paused", func(r *custodydb.ObserveContextStorageRow) { r.PoolPaused = true }},
		{"allocation-paused", func(r *custodydb.ObserveContextStorageRow) { r.AllocationPaused = true }},
		{"wrong-class", func(r *custodydb.ObserveContextStorageRow) { r.ServiceClass = "evidence" }},
		{"wrong-root", func(r *custodydb.ObserveContextStorageRow) { r.RootID = id("00000000-0000-4000-8000-000000000006") }},
		{"wrong-workload", func(r *custodydb.ObserveContextStorageRow) { r.WorkloadUid = "other" }},
		{"bad-digest", func(r *custodydb.ObserveContextStorageRow) { r.SourceDigest = []byte{1} }},
		{"future-source", func(r *custodydb.ObserveContextStorageRow) { r.ObservedAt = ts(r.ObservedAt.Time.Add(2 * time.Second)) }},
		{"expired-source", func(r *custodydb.ObserveContextStorageRow) { r.FreshUntil = r.ObservedAt }},
		{"overlong-source-even-if-clamped", func(r *custodydb.ObserveContextStorageRow) {
			r.FreshUntil = ts(r.ObservedAt.Time.Add(time.Hour))
			r.PoolValidUntil = ts(r.ObservedAt.Time.Add(3 * time.Second))
		}},
		{"missing-time", func(r *custodydb.ObserveContextStorageRow) { r.FreshUntil.Valid = false }},
		{"zero-revision", func(r *custodydb.ObserveContextStorageRow) { r.PoolRevision = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, root, target, now := storageObservationFixture()
			test.change(&r)
			if _, err := contextStorageObservation(r, root, target, now); err == nil {
				t.Fatal("invalid storage observation accepted")
			}
		})
	}
}

// A physical binding and fully funded legacy children do not imply that the
// three managed enrollment phases have reached Ready. The database supplies
// this exact earliest bound; the read may not silently omit or renew it.
func TestCapacityManagedStorageFenceRetainsEarliestOriginalDeadline(t *testing.T) {
	row, root, target, now := storageObservationFixture()
	row.CapacityUntil = ts(now.Add(250 * time.Millisecond))
	got, e := contextStorageObservation(row, root, target, now)
	if e != nil || !got.Binding.FreshUntil.Equal(row.CapacityUntil.Time) || !got.Binding.ObservedAt.Equal(row.ObservedAt.Time) {
		t.Fatal("managed capacity bound was dropped or source was renewed", e)
	}
	if _, e = contextStorageObservation(row, root, target, row.CapacityUntil.Time); e == nil {
		t.Fatal("read crossing its original managed fence remained available")
	}
	for _, mode := range []string{"missing", "incomplete", "later-than-source"} {
		t.Run(mode, func(t *testing.T) {
			r, root, target, now := storageObservationFixture()
			switch mode {
			case "missing":
				r.CapacityUntil.Valid = false
			case "incomplete":
				r.CapacityUntil = ts(now)
			case "later-than-source":
				r.CapacityUntil = ts(r.FreshUntil.Time.Add(time.Microsecond))
			}
			if _, e := contextStorageObservation(r, root, target, now); e == nil {
				t.Fatal("unqualified managed readiness was accepted")
			}
		})
	}
}
