package fleet

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestOwnerAuditEpochAccountingChargesUnknownClaims(t *testing.T) {
	p := ownerEpochFacts(t).Reserve.Policy
	capacity, ok := p.RequiredCapacity()
	if !ok || capacity.Epochs != 64 || capacity.Dependencies != 2048 || capacity.Objects != (OwnerAuditEpochBudget{CiphertextBytes: 64 << 20, DataVersions: 256, DeleteMarkers: 256, MultipartUploads: 128, MultipartParts: 256, MetadataBytes: 64 << 16}) {
		t.Fatal("aggregate capacity omitted a dimension", capacity, ok)
	}
	// A lost writer response may leave no listed bytes. The fully charged slot
	// still prevents a claim once the original maximum is reached.
	unknown := OwnerAuditEpochSpend{ChargedEpochs: p.MaxOpenEpochs}
	if unknown.FitsAnotherEpoch(p) {
		t.Fatal("empty known inventory refunded unknown claims")
	}
	one := OwnerAuditEpochSpend{ChargedEpochs: 1, Dependencies: p.MaxDependenciesPerEpoch, Known: p.PerEpoch}
	if !one.FitsAnotherEpoch(p) {
		t.Fatal("full original charge rejected despite independent room")
	}
	for name, change := range map[string]func(*OwnerAuditEpochSpend){
		"pending":               func(s *OwnerAuditEpochSpend) { s.PendingEpochs = 1 },
		"uncertain-exhaustion":  func(s *OwnerAuditEpochSpend) { s.ChargedEpochs = 2; s.UncertainEpochs = 2 },
		"unowned-uncertainty":   func(s *OwnerAuditEpochSpend) { s.UncertainEpochs = 2 },
		"negative-uncertainty":  func(s *OwnerAuditEpochSpend) { s.UncertainEpochs = -1 },
		"negative-pending":      func(s *OwnerAuditEpochSpend) { s.PendingEpochs = -1 },
		"negative-count":        func(s *OwnerAuditEpochSpend) { s.ChargedEpochs = -1 },
		"oversized-count":       func(s *OwnerAuditEpochSpend) { s.ChargedEpochs = math.MaxInt64 },
		"negative-dependencies": func(s *OwnerAuditEpochSpend) { s.Dependencies = -1 },
		"excess-dependencies":   func(s *OwnerAuditEpochSpend) { s.Dependencies++ },
		"unowned-obligation":    func(s *OwnerAuditEpochSpend) { s.ChargedEpochs = 0 },
		"excess-bytes":          func(s *OwnerAuditEpochSpend) { s.Known.CiphertextBytes++ },
		"excess-versions":       func(s *OwnerAuditEpochSpend) { s.Known.DataVersions++ },
		"excess-markers":        func(s *OwnerAuditEpochSpend) { s.Known.DeleteMarkers++ },
		"excess-uploads":        func(s *OwnerAuditEpochSpend) { s.Known.MultipartUploads++ },
		"excess-parts":          func(s *OwnerAuditEpochSpend) { s.Known.MultipartParts++ },
		"excess-metadata":       func(s *OwnerAuditEpochSpend) { s.Known.MetadataBytes++ },
		"negative-bytes":        func(s *OwnerAuditEpochSpend) { s.Known.CiphertextBytes = -1 },
		"negative-versions":     func(s *OwnerAuditEpochSpend) { s.Known.DataVersions = -1 },
		"negative-markers":      func(s *OwnerAuditEpochSpend) { s.Known.DeleteMarkers = -1 },
		"negative-uploads":      func(s *OwnerAuditEpochSpend) { s.Known.MultipartUploads = -1 },
		"negative-parts":        func(s *OwnerAuditEpochSpend) { s.Known.MultipartParts = -1 },
		"negative-metadata":     func(s *OwnerAuditEpochSpend) { s.Known.MetadataBytes = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			s := one
			change(&s)
			if s.FitsAnotherEpoch(p) {
				t.Fatal("new claim allowed with pending/invalid/out-of-contract spend")
			}
		})
	}
	for _, n := range []int64{0, -1, math.MaxInt64} {
		bad := p
		bad.PerEpoch.CiphertextBytes = n
		if c, ok := bad.RequiredCapacity(); ok || c != (OwnerAuditEpochCapacity{}) {
			t.Fatal("invalid/overflow arithmetic returned capacity", n, c)
		}
	}
}

func TestOwnerAuditEpochAdmissionRequiresWholeRetainedLifecycle(t *testing.T) {
	e := ownerEpochFacts(t)
	now := e.ClaimedAt.Add(time.Minute)
	source := OwnerConfigurationObservation{Configuration: e.Configuration.Clone(), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	o := AcceptedOwnerAuditEpochObservation{Source: source, Epoch: e.Clone(), ObservedAt: now, FreshUntil: source.FreshUntil, CurrentRetainUntil: e.Deadlines.RetainUntil}
	d := OwnerAuditEpochDependency{ID: "44444444-4444-4444-8444-444444444444", EffectID: "77777777-7777-4777-8777-777777777777", Purpose: OwnerAuditCertificateDependency, Epoch: e.Clone(), AdmittedAt: now, EndsAt: now.Add(20 * time.Minute)}
	if !d.MatchesAdmission(o, now) {
		t.Fatal("valid synthetic original admission failed")
	}
	shortened := o.Clone()
	shortened.CurrentRetainUntil = now.Add(time.Minute)
	if !shortened.Valid(now) || d.MatchesAdmission(shortened, now) {
		t.Fatal("fresh source allowed lifecycle beyond current retained receipt")
	}
	// An independently admitted original operation may still continue until the
	// shortened cutoff. This is not admission of its entire lifecycle again.
	retained := AdmittedOwnerAuditEpochObservation{Source: source, Dependency: d.Clone(), ObservedAt: now, FreshUntil: source.FreshUntil, CurrentRetainUntil: shortened.CurrentRetainUntil}
	if !retained.Valid(now) {
		t.Fatal("current shortening lost valid bounded continuation")
	}
	for name, change := range map[string]func(*OwnerAuditEpochDependency){
		"missing-effect":     func(d *OwnerAuditEpochDependency) { d.EffectID = "" },
		"malformed-effect":   func(d *OwnerAuditEpochDependency) { d.EffectID = "not-an-effect-UUID" },
		"future-admission":   func(d *OwnerAuditEpochDependency) { d.AdmittedAt = now.Add(time.Microsecond) },
		"before-observation": func(d *OwnerAuditEpochDependency) { d.AdmittedAt = now.Add(-time.Microsecond) },
		"changed-epoch":      func(d *OwnerAuditEpochDependency) { d.Epoch.Ordinal++ },
		"changed-source":     func(d *OwnerAuditEpochDependency) { d.Epoch.Configuration.Revision.Generation++ },
		"changed-reserve":    func(d *OwnerAuditEpochDependency) { d.Epoch.Reserve.ID = d.ID },
	} {
		t.Run(name, func(t *testing.T) {
			copy := d.Clone()
			change(&copy)
			if copy.MatchesAdmission(o, now) {
				t.Fatal("invalid or cross-epoch admission accepted")
			}
		})
	}
	other := d.Clone()
	other.EffectID = "88888888-8888-4888-8888-888888888888"
	if !other.WellFormed() || other.Equal(d) {
		t.Fatal("concrete effect identity lost from exact admission equality")
	}
	// Shape cannot verify which effect is stored; this deliberately still fits
	// the policy. Concrete SQL must compare the actual purpose-owned attempt.
	if !other.MatchesAdmission(o, now) {
		t.Fatal("shape check purported to invent stored effect authority")
	}
}

func TestOwnerAuditEpochScheduleReportsUnfundedRollover(t *testing.T) {
	p := ownerEpochFacts(t).Reserve.Policy
	schedule, err := p.Schedule()
	// Synthetic, newly selected test policy: 280 minutes total residual horizon
	// divided by a five-minute interval, plus pending one and uncertain two.
	if err != nil || schedule.MinimumOpenEpochs != 59 || schedule.AdmissionOverlap != 5*time.Minute || schedule.EpochInterval != 5*time.Minute {
		t.Fatal("incorrect fixed-cadence lower bound", schedule, err)
	}
	p.MaxOpenEpochs = 8 // The earlier unshipped fixture could not sustain rollover.
	schedule, err = p.Schedule()
	if !errors.Is(err, ErrOwnerAuditEpochSlotsInsufficient) || schedule.MinimumOpenEpochs != 59 || p.MaxOpenEpochs != 8 || p.WellFormed() {
		t.Fatal("unsustainable limit silently raised or accepted", schedule, err)
	}
	p.MaxOpenEpochs = 59
	p.ResidualAfterMetadata += time.Microsecond
	schedule, err = p.Schedule()
	if !errors.Is(err, ErrOwnerAuditEpochSlotsInsufficient) || schedule.MinimumOpenEpochs != 60 {
		t.Fatal("partial residual interval truncated", schedule, err)
	}
	p.MaxOpenEpochs = 60
	if _, err := p.Schedule(); err != nil {
		t.Fatal("explicit sufficient lower bound rejected", err)
	}
	p.MaxUncertainEpochs = math.MaxInt64
	if _, err := p.Schedule(); !errors.Is(err, ErrOwnerAuditEpochPolicyInvalid) {
		t.Fatal("uncertain-slot arithmetic overflow accepted", err)
	}
}

func TestOwnerAuditEpochAdmissionRejectsElapsedOriginalDependency(t *testing.T) {
	e := ownerEpochFacts(t)
	observed := e.ClaimedAt.Add(time.Minute)
	source := OwnerConfigurationObservation{Configuration: e.Configuration.Clone(), ObservedAt: observed, FreshUntil: observed.Add(5 * time.Second)}
	o := AcceptedOwnerAuditEpochObservation{Source: source, Epoch: e.Clone(), ObservedAt: observed, FreshUntil: source.FreshUntil, CurrentRetainUntil: e.Deadlines.RetainUntil}
	d := OwnerAuditEpochDependency{ID: "44444444-4444-4444-8444-444444444444", EffectID: "77777777-7777-4777-8777-777777777777", Purpose: OwnerAuditRequestDependency, Epoch: e.Clone(), AdmittedAt: observed, EndsAt: observed.Add(time.Second)}
	original := d.Clone()
	for _, tc := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{name: "immediately-before", now: d.EndsAt.Add(-time.Microsecond), want: true},
		{name: "exact-original-end", now: d.EndsAt, want: false},
		{name: "after-original-end", now: d.EndsAt.Add(time.Microsecond), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !o.Valid(tc.now) || !d.WellFormed() {
				t.Fatal("regression fixture lost fresh source and well-formed original dependency")
			}
			if got := d.MatchesAdmission(o, tc.now); got != tc.want {
				t.Fatalf("original dependency end was not enforced: admission=%v want=%v", got, tc.want)
			}
			if !d.Equal(original) || !o.Epoch.Equal(original.Epoch) {
				t.Fatal("expiry check rewrote the original record or deadlines")
			}
		})
	}
}
