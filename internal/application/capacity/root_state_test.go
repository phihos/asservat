package capacity

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func capacityRootStateFixture() RootConfiguration {
	n := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	return RootConfiguration{Format: RootConfigurationFormat, RootID: "30000000-0000-4000-8000-000000000001", AttemptID: "30000000-0000-4000-8000-000000000002", PlanDigest: artifact.Digest{1}, Revision: 1, InitialObservedAt: n, InitialUntil: n.Add(5 * time.Second), RevisionObservedAt: n, RevisionUntil: n.Add(5 * time.Second), PlannedUntil: n.Add(time.Hour), ReservedAt: n.Add(time.Second)}
}

func TestCapacityRootContinuationKeepsOriginalIntervalsAndOnceFacts(t *testing.T) {
	v := capacityRootStateFixture()
	if !v.Valid() || v.AdmissionReady(v.ReservedAt) {
		t.Fatal("partial root became admission ready")
	}
	// Completing pure SQL under a new independently current observation may
	// happen after the initial five seconds, without editing that interval.
	c := v.ReservedAt.Add(time.Minute)
	next := v
	next.CaptureBackedAt = &c
	if !v.CompatibleContinuation(next) || next.AdmissionReady(c) {
		t.Fatal("exact late SQL phase did not remain incomplete")
	}
	r := c.Add(time.Second)
	ready := next
	ready.ReadyAt = &r
	if !next.CompatibleContinuation(ready) || !ready.AdmissionReady(r) || ready.AdmissionReady(ready.PlannedUntil) {
		t.Fatal("ready must preserve planned admission end")
	}
	for _, name := range []string{"phase-end", "planned-end", "attempt", "erase-capture", "move-ready", "initial-time", "revision"} {
		t.Run(name, func(t *testing.T) {
			changed := ready
			switch name {
			case "phase-end":
				changed.RevisionUntil = changed.RevisionUntil.Add(time.Microsecond)
			case "planned-end":
				changed.PlannedUntil = changed.PlannedUntil.Add(time.Microsecond)
			case "attempt":
				changed.AttemptID = "30000000-0000-4000-8000-000000000003"
			case "erase-capture":
				changed.CaptureBackedAt = nil
			case "move-ready":
				d := r.Add(time.Microsecond)
				changed.ReadyAt = &d
			case "initial-time":
				changed.InitialObservedAt = changed.InitialObservedAt.Add(-time.Microsecond)
			case "revision":
				changed.Revision++
			}
			if ready.CompatibleContinuation(changed) {
				t.Fatal("old configuration rewritten")
			}
		})
	}
}

func TestCapacityRootExpiredPartialRequiresPositiveSQLDisposition(t *testing.T) {
	v := capacityRootStateFixture()
	at := v.PlannedUntil.Add(time.Second)
	if v.AdmissionReady(at) {
		t.Fatal("expired incomplete root became ready")
	}
	closed := v
	closed.ReconciledAt = &at
	if closed.Valid() {
		t.Fatal("elapsed time manufactured a disposition")
	}
	closed.ReconciledDigest = artifact.Digest{2}
	if !closed.Valid() || !v.CompatibleContinuation(closed) || closed.AdmissionReady(at) {
		t.Fatal("closed predecessor granted new admission")
	}
	bad := closed
	bad.ReconciledDigest = artifact.Digest{3}
	if closed.CompatibleContinuation(bad) {
		t.Fatal("original disposition changed")
	}
	late := v
	late.CaptureBackedAt = &at
	if late.Valid() {
		t.Fatal("late missing child can no longer be presented as backed under old planned end")
	}
}
