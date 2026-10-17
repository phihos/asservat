package capacity

import (
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// The processing proof retains only the already validated source identity and
// original interval. Privacy operators, client settings and human groups do not
// enter the capacity configuration record. It cannot initialize processing.
type RootProcessingObservation struct {
	Revision               identity.Revision
	ProtectionDigest       artifact.Digest
	ObservedAt, FreshUntil time.Time
}

type RootBackingObservation struct {
	RootID, InstallationID, QualificationID       string
	QualificationDigest, PlanDigest, SourceDigest artifact.Digest
	SourceRevision                                int64
	Recovery                                      artifact.RecoveryProof
	Processing                                    RootProcessingObservation
	ObservedAt, FreshUntil                        time.Time
	Plan                                          RootBackingPlan `json:"-"`
	poolCanonical                                 string
}

func NewRootBackingObservation(q CapacityQualification, source AcceptedCapacitySource, processing privacy.DownloadPolicy, recovery artifact.RecoveryProof, now time.Time) (RootBackingObservation, error) {
	var zero RootBackingObservation
	if !q.Valid() || !source.Valid(now) || !processing.Valid(now) || processing.Suspended || !recovery.Valid(now) || source.RootID != q.RootBacking.RootID || source.InstallationID != q.RootBacking.InstallationID || source.QualificationID != q.ID || source.QualificationDigest != q.Digest || processing.RootID != source.RootID || processing.InstallationID != source.InstallationID || processing.RecoveryEpoch != recovery.IssuerEpoch || recovery.InstallationID != source.InstallationID || processing.Revision.UID != q.RootBacking.ProcessingSourceUID || processing.ProtectionDigest != q.RootBacking.ProcessingProtectionDigest {
		return zero, cfg.ErrUnavailable
	}
	name := ""
	for _, p := range source.Observation.Snapshot.Pools {
		if p.Resource.UID == q.RootBacking.SystemPoolUID {
			name = p.Resource.Name
		}
	}
	if name == "" {
		return zero, cfg.ErrUnavailable
	}
	p, e := CompileProtectedPoolPlan(source.Observation.Snapshot, name)
	if e != nil {
		return zero, e
	}
	plan, e := CompileQualifiedRootBacking(q, p)
	if e != nil {
		return zero, e
	}
	pool, _, e := CanonicalProtectedPoolPlan(source.Observation.Snapshot, name)
	if e != nil {
		return zero, e
	}
	_, digest := plan.Canonical()
	start := now.UTC().Truncate(time.Microsecond)
	until := identity.Earlier(source.FreshUntil, identity.Earlier(processing.FreshUntil, recovery.FreshUntil)).Truncate(time.Microsecond)
	out := RootBackingObservation{RootID: source.RootID, InstallationID: source.InstallationID, QualificationID: q.ID, QualificationDigest: q.Digest, PlanDigest: digest, SourceDigest: source.Observation.Digest, SourceRevision: source.Revision, Recovery: recovery, Processing: RootProcessingObservation{processing.Revision, processing.ProtectionDigest, processing.ObservedAt, processing.FreshUntil}, ObservedAt: start, FreshUntil: until, Plan: plan, poolCanonical: string(pool)}
	if !out.Valid(now) {
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}

func (o RootBackingObservation) Valid(now time.Time) bool {
	if o.Plan.canonical == "" || o.poolCanonical == "" || o.SourceDigest == (artifact.Digest{}) || o.SourceRevision < 1 || o.SourceRevision >= 1<<60 || !o.Recovery.Valid(now) || o.Recovery.InstallationID != o.InstallationID || !o.Processing.Revision.Valid() || o.Processing.ProtectionDigest == (artifact.Digest{}) || !identity.Fresh(o.Processing.ObservedAt, o.Processing.FreshUntil, now, CapacitySourceInterval) || !identity.Fresh(o.ObservedAt, o.FreshUntil, now, CapacitySourceInterval) || !capacityMicro(o.ObservedAt) || !capacityMicro(o.FreshUntil) || o.FreshUntil.After(o.Processing.FreshUntil) || o.FreshUntil.After(o.Recovery.FreshUntil) || o.Plan.digest != o.PlanDigest {
		return false
	}
	var wire struct {
		Input  RootBackingInput
		Totals RootBackingTotals
	}
	if json.Unmarshal([]byte(o.Plan.canonical), &wire) != nil {
		return false
	}
	in := wire.Input
	return in.RootID == o.RootID && in.InstallationID == o.InstallationID && in.QualificationID == o.QualificationID && in.QualificationDigest == o.QualificationDigest && in.ProcessingSourceUID == o.Processing.Revision.UID && in.ProcessingProtectionDigest == o.Processing.ProtectionDigest
}

func (o RootBackingObservation) CanonicalValues() (plan, pool []byte) {
	return []byte(o.Plan.canonical), []byte(o.poolCanonical)
}

// ConfigurationUntil derives a new configuration cutoff from the fixed plan
// and THIS original protected observation. It grants no effect and must not be
// used to replace a persisted revision's dates during ordinary replay.
func (o RootBackingObservation) ConfigurationUntil() (time.Time, bool) {
	var wire struct {
		Input  RootBackingInput
		Totals RootBackingTotals
	}
	if o.Plan.canonical == "" || o.Plan.digest != o.PlanDigest || !capacityMicro(o.ObservedAt) || json.Unmarshal([]byte(o.Plan.canonical), &wire) != nil || wire.Input.AdmissionSeconds < 60 || wire.Input.AdmissionSeconds > 86400 {
		return time.Time{}, false
	}
	return o.ObservedAt.Add(time.Duration(wire.Input.AdmissionSeconds) * time.Second), true
}
