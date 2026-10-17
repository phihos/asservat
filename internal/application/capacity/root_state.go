package capacity

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

const RootConfigurationFormat = "protected-capacity-configuration/v1"

// RootConfiguration is a receipt of transactional configuration only. It never
// authorizes a capture, disclosure, key effect or recovery transition. The
// original root attempt and its first interval survive every configuration
// revision; each revision separately retains its original planning interval.
// A fresh observation can finish missing compatible SQL effects, not edit any
// of these dates or replenish the prepaid transaction budget.
type RootConfiguration struct {
	Format, RootID, AttemptID                       string
	PlanDigest                                      artifact.Digest
	Revision                                        int64
	InitialObservedAt, InitialUntil                 time.Time
	RevisionObservedAt, RevisionUntil, PlannedUntil time.Time
	ReservedAt                                      time.Time
	CaptureBackedAt, ReadyAt, ReconciledAt          *time.Time
	PreviousDigest, ReconciledDigest                artifact.Digest
}

func capacityMicro(t time.Time) bool { return !t.IsZero() && t.Nanosecond()%1000 == 0 }

func (v RootConfiguration) Valid() bool {
	if v.Format != RootConfigurationFormat || !authorization.UUID(v.RootID) || !authorization.UUID(v.AttemptID) || v.RootID == v.AttemptID || v.PlanDigest == (artifact.Digest{}) || v.Revision < 1 || v.Revision >= 1<<60 {
		return false
	}
	for _, d := range []time.Time{v.InitialObservedAt, v.InitialUntil, v.RevisionObservedAt, v.RevisionUntil, v.PlannedUntil, v.ReservedAt} {
		if !capacityMicro(d) {
			return false
		}
	}
	if !v.InitialUntil.After(v.InitialObservedAt) || v.InitialUntil.After(v.InitialObservedAt.Add(CapacitySourceInterval)) || v.RevisionObservedAt.Before(v.InitialObservedAt) || !v.RevisionUntil.After(v.RevisionObservedAt) || v.RevisionUntil.After(v.RevisionObservedAt.Add(CapacitySourceInterval)) || v.ReservedAt.Before(v.RevisionObservedAt) || !v.ReservedAt.Before(v.RevisionUntil) || !v.PlannedUntil.After(v.ReservedAt) {
		return false
	}
	if v.Revision == 1 {
		if !v.InitialObservedAt.Equal(v.RevisionObservedAt) || !v.InitialUntil.Equal(v.RevisionUntil) || v.PreviousDigest != (artifact.Digest{}) {
			return false
		}
	} else if v.PreviousDigest == (artifact.Digest{}) {
		return false
	}
	last := v.ReservedAt
	if v.CaptureBackedAt != nil {
		if !capacityMicro(*v.CaptureBackedAt) || v.CaptureBackedAt.Before(last) || !v.CaptureBackedAt.Before(v.PlannedUntil) {
			return false
		}
		last = *v.CaptureBackedAt
	}
	if v.ReadyAt != nil {
		if v.CaptureBackedAt == nil || !capacityMicro(*v.ReadyAt) || v.ReadyAt.Before(last) || !v.ReadyAt.Before(v.PlannedUntil) {
			return false
		}
		last = *v.ReadyAt
	}
	if (v.ReconciledAt == nil) != (v.ReconciledDigest == (artifact.Digest{})) {
		return false
	}
	if v.ReconciledAt != nil && (!capacityMicro(*v.ReconciledAt) || v.ReconciledAt.Before(last)) {
		return false
	}
	return true
}

// CompatibleContinuation compares retained values, not elapsed time or an
// error string. Only SQL's exact current all-child reconciliation can issue a
// ReconciledDigest. An absent receipt is never inferred from an expired lease.
func (v RootConfiguration) CompatibleContinuation(next RootConfiguration) bool {
	if !v.Valid() || !next.Valid() || v.RootID != next.RootID || v.AttemptID != next.AttemptID || v.PlanDigest != next.PlanDigest || !v.InitialObservedAt.Equal(next.InitialObservedAt) || !v.InitialUntil.Equal(next.InitialUntil) {
		return false
	}
	if next.Revision != v.Revision {
		return false
	}
	if !v.RevisionObservedAt.Equal(next.RevisionObservedAt) || !v.RevisionUntil.Equal(next.RevisionUntil) || !v.PlannedUntil.Equal(next.PlannedUntil) || !v.ReservedAt.Equal(next.ReservedAt) || v.PreviousDigest != next.PreviousDigest {
		return false
	}
	for _, p := range [][2]*time.Time{{v.CaptureBackedAt, next.CaptureBackedAt}, {v.ReadyAt, next.ReadyAt}, {v.ReconciledAt, next.ReconciledAt}} {
		if v.ReconciledAt != nil && (p[0] == nil) != (p[1] == nil) {
			return false
		}
		if p[0] != nil && (p[1] == nil || !p[0].Equal(*p[1])) {
			return false
		}
	}
	return v.ReconciledAt == nil || v.ReconciledDigest == next.ReconciledDigest
}

func (v RootConfiguration) AdmissionReady(now time.Time) bool {
	return v.Valid() && v.ReadyAt != nil && v.ReconciledAt == nil && !now.Before(*v.ReadyAt) && now.Before(v.PlannedUntil)
}

// CompatibleRenewal accepts only one newly selected SQL configuration. It never
// treats a changed interval as continuation of the old phase; the immutable
// first attempt survives, and SQL supplies a positive predecessor digest.
func (v RootConfiguration) CompatibleRenewal(next RootConfiguration, o RootBackingObservation) bool {
	planned, ok := o.ConfigurationUntil()
	return ok && v.Valid() && next.Valid() && v.RootID == next.RootID && v.AttemptID == next.AttemptID && v.PlanDigest == next.PlanDigest &&
		v.InitialObservedAt.Equal(next.InitialObservedAt) && v.InitialUntil.Equal(next.InitialUntil) && next.Revision == v.Revision+1 &&
		next.RevisionObservedAt.Equal(o.ObservedAt) && !next.RevisionUntil.After(o.FreshUntil) && next.PlannedUntil.Equal(planned) && next.PlannedUntil.After(v.PlannedUntil) &&
		next.PreviousDigest != (artifact.Digest{}) && next.CaptureBackedAt == nil && next.ReadyAt == nil && next.ReconciledAt == nil
}
