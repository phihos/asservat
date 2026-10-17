package fleet

import (
	"math"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func ownerEpochFacts(t *testing.T) OwnerAuditEpoch {
	t.Helper()
	const id = "11111111-1111-4111-8111-111111111111"
	anchor := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	policy := OwnerAuditEpochPolicy{EpochInterval: 5 * time.Minute, AdmissionWindow: 10 * time.Minute, MaxDependencyLifetime: 30 * time.Minute, RetainAfterDependencies: time.Hour, DeleteBudget: time.Hour, MetadataAfterDeletion: time.Hour, ResidualAfterMetadata: time.Hour, MaxOpenEpochs: 64, MaxUncertainEpochs: 2, MaxDependenciesPerEpoch: 32, PerEpoch: OwnerAuditEpochBudget{CiphertextBytes: 1 << 20, DataVersions: 4, DeleteMarkers: 4, MultipartUploads: 2, MultipartParts: 4, MetadataBytes: 1 << 16}}
	reserve := OwnerControlAuditReserveReference{ID: id, InstallationRootID: id, InstallationID: id, ClusterID: id, SourceUID: id, StoreID: id, CapacityID: id, PoolID: id, AllocationID: id, QualificationID: id, RootDigest: artifact.Digest{1}, QualificationDigest: artifact.Digest{2}, PolicyDigest: artifact.Digest{3}, ProvisionedAt: anchor.Add(-time.Minute), Policy: policy}
	config := OwnerConfiguration{Pool: OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "owner", ServiceUID: id, Deployment: "owner", DeploymentUID: id, ServiceAccount: "owner", AccountUID: id, Port: 8443}, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{4}}, ProtectionDigest: artifact.Digest{5}, IssuerRoots: [][]byte{{6}}}
	dates, ok := OwnerAuditEpochDates(anchor, policy)
	e := OwnerAuditEpoch{ID: "22222222-2222-4222-8222-222222222222", AttemptID: "33333333-3333-4333-8333-333333333333", Ordinal: 1, Reserve: reserve, Configuration: config, ClaimedAt: anchor, Deadlines: dates}
	if !ok || !e.WellFormed() {
		t.Fatal("invalid synthetic epoch")
	}
	return e
}

func TestOwnerAuditEpochRejectsInvalidBoundsAndOriginalPins(t *testing.T) {
	for name, change := range map[string]func(*OwnerAuditEpoch){
		"missing-policy":         func(e *OwnerAuditEpoch) { e.Reserve.Policy = OwnerAuditEpochPolicy{} },
		"zero-cadence":           func(e *OwnerAuditEpoch) { e.Reserve.Policy.EpochInterval = 0 },
		"cadence-past-admission": func(e *OwnerAuditEpoch) { e.Reserve.Policy.EpochInterval = e.Reserve.Policy.AdmissionWindow },
		"negative-duration":      func(e *OwnerAuditEpoch) { e.Reserve.Policy.DeleteBudget = -time.Hour },
		"fractional-sql-time":    func(e *OwnerAuditEpoch) { e.Reserve.Policy.DeleteBudget += time.Nanosecond },
		"duration-sum-overflow": func(e *OwnerAuditEpoch) {
			e.Reserve.Policy.ResidualAfterMetadata = time.Duration(math.MaxInt64 / 1000 * 1000)
		},
		"byte-product-overflow":         func(e *OwnerAuditEpoch) { e.Reserve.Policy.PerEpoch.CiphertextBytes = math.MaxInt64 },
		"count-product-overflow":        func(e *OwnerAuditEpoch) { e.Reserve.Policy.MaxDependenciesPerEpoch = math.MaxInt64 },
		"no-pending-room":               func(e *OwnerAuditEpoch) { e.Reserve.Policy.MaxOpenEpochs = 1 },
		"missing-unknown-upload-budget": func(e *OwnerAuditEpoch) { e.Reserve.Policy.PerEpoch.MultipartUploads = 0 },
		"missing-marker-budget":         func(e *OwnerAuditEpoch) { e.Reserve.Policy.PerEpoch.DeleteMarkers = 0 },
		"parts-less-than-uploads":       func(e *OwnerAuditEpoch) { e.Reserve.Policy.PerEpoch.MultipartParts = 1 },
		"later-reserve":                 func(e *OwnerAuditEpoch) { e.Reserve.ProvisionedAt = e.ClaimedAt.Add(time.Second) },
		"missing-allocation":            func(e *OwnerAuditEpoch) { e.Reserve.AllocationID = "" },
		"missing-qualification":         func(e *OwnerAuditEpoch) { e.Reserve.QualificationDigest = artifact.Digest{} },
		"foreign-source":                func(e *OwnerAuditEpoch) { e.Reserve.SourceUID = e.ID },
		"foreign-cluster":               func(e *OwnerAuditEpoch) { e.Reserve.ClusterID = e.ID },
		"foreign-installation":          func(e *OwnerAuditEpoch) { e.Reserve.InstallationID = e.ID },
		"zero-ordinal":                  func(e *OwnerAuditEpoch) { e.Ordinal = 0 },
		"missing-attempt":               func(e *OwnerAuditEpoch) { e.AttemptID = "" },
		"aliased-attempt":               func(e *OwnerAuditEpoch) { e.AttemptID = e.ID },
		"suspended":                     func(e *OwnerAuditEpoch) { e.Configuration.Suspended = true },
		"moved-admission":               func(e *OwnerAuditEpoch) { e.Deadlines.AdmitUntil = e.Deadlines.AdmitUntil.Add(time.Microsecond) },
		"moved-residual":                func(e *OwnerAuditEpoch) { e.Deadlines.ResidualUntil = e.Deadlines.ResidualUntil.Add(time.Microsecond) },
		"changed-anchor":                func(e *OwnerAuditEpoch) { e.ClaimedAt = e.ClaimedAt.Add(time.Microsecond) },
		"non-UTC":                       func(e *OwnerAuditEpoch) { e.ClaimedAt = e.ClaimedAt.In(time.FixedZone("other", 3600)) },
	} {
		t.Run(name, func(t *testing.T) {
			e := ownerEpochFacts(t)
			change(&e)
			if e.WellFormed() {
				t.Fatal("invalid epoch accepted")
			}
		})
	}
	e := ownerEpochFacts(t)
	if _, ok := OwnerAuditEpochDates(time.Date(9999, 12, 31, 23, 59, 0, 0, time.UTC), e.Reserve.Policy); ok {
		t.Fatal("out-of-wire-range absolute date accepted")
	}
	if _, ok := OwnerAuditEpochDates(time.Time{}, e.Reserve.Policy); ok {
		t.Fatal("zero anchor accepted")
	}
}

func TestOwnerAuditEpochCloneAndInstantEquality(t *testing.T) {
	e := ownerEpochFacts(t)
	copy := e.Clone()
	copy.ClaimedAt = copy.ClaimedAt.In(time.FixedZone("same-instant", 0))
	if !copy.WellFormed() || !copy.Equal(e) {
		t.Fatal("same UTC instant changed equality")
	}
	copy.Configuration.IssuerRoots[0][0]++
	if copy.Equal(e) || e.Configuration.IssuerRoots[0][0] != 6 {
		t.Fatal("clone changed original roots or equality lost them")
	}
	copy = e.Clone()
	copy.Reserve.StoreID = e.ID
	if copy.Equal(e) {
		t.Fatal("store identity omitted from equality")
	}
	copy = e.Clone()
	copy.Deadlines.DeleteBy = copy.Deadlines.DeleteBy.Add(time.Microsecond)
	if copy.Equal(e) {
		t.Fatal("original dates omitted from equality")
	}
}

func TestOwnerAuditEpochRolloverDoesNotMoveAdmittedDependency(t *testing.T) {
	old := ownerEpochFacts(t)
	dependency := OwnerAuditEpochDependency{ID: "44444444-4444-4444-8444-444444444444", EffectID: "77777777-7777-4777-8777-777777777777", Purpose: OwnerAuditCertificateDependency, Epoch: old.Clone(), AdmittedAt: old.ClaimedAt.Add(time.Minute), EndsAt: old.ClaimedAt.Add(25 * time.Minute)}
	if !dependency.WellFormed() {
		t.Fatal("invalid synthetic admitted dependency")
	}
	next := old.Clone()
	next.ID = "55555555-5555-4555-8555-555555555555"
	next.AttemptID = "66666666-6666-4666-8666-666666666666"
	next.Ordinal = 2
	next.ClaimedAt = old.ClaimedAt.Add(5 * time.Minute)
	next.Deadlines, _ = OwnerAuditEpochDates(next.ClaimedAt, next.Reserve.Policy)
	now := old.ClaimedAt.Add(11 * time.Minute)
	source := OwnerConfigurationObservation{Configuration: old.Configuration.Clone(), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	current := AcceptedOwnerAuditEpochObservation{Source: source, Epoch: next, ObservedAt: now, FreshUntil: source.FreshUntil, CurrentRetainUntil: next.Deadlines.RetainUntil}
	retained := AdmittedOwnerAuditEpochObservation{Source: source, Dependency: dependency.Clone(), ObservedAt: now, FreshUntil: source.FreshUntil, CurrentRetainUntil: old.Deadlines.RetainUntil}
	if !current.Valid(now) || !retained.Valid(now) {
		t.Fatal("successor or original admitted interval lost")
	}
	// This only checks values. Actual selected-head/non-revocation and stored
	// receipt/dependency comparison remain mandatory concrete SQL work.
	wrong := current.Clone()
	wrong.Epoch = old.Clone()
	if wrong.Valid(now) {
		t.Fatal("old epoch admitted new work after fixed cutoff")
	}
	swapped := dependency.Clone()
	swapped.Epoch = next.Clone()
	if swapped.Equal(dependency) {
		t.Fatal("successor substituted for original dependency")
	}
	changed := retained.Clone()
	changed.Source.Configuration.Revision.Generation++
	if changed.Valid(now) {
		t.Fatal("semantic source change accepted")
	}
	shortened := retained.Clone()
	shortened.CurrentRetainUntil = now
	if shortened.Valid(now) {
		t.Fatal("current retention shortening ignored")
	}
	extended := retained.Clone()
	extended.CurrentRetainUntil = old.Deadlines.RetainUntil.Add(time.Microsecond)
	if extended.Valid(now) {
		t.Fatal("current read extended original retained epoch")
	}
	ended := dependency.EndsAt
	expired := retained.Clone()
	expired.Source.ObservedAt = ended
	expired.Source.FreshUntil = ended.Add(time.Second)
	expired.ObservedAt = ended
	expired.FreshUntil = expired.Source.FreshUntil
	if expired.Valid(ended) {
		t.Fatal("original dependency expiry renewed")
	}
	moved := dependency.Clone()
	moved.EndsAt = moved.AdmittedAt.Add(old.Reserve.Policy.MaxDependencyLifetime + time.Microsecond)
	if moved.WellFormed() {
		t.Fatal("dependency outlived its original policy bound")
	}
	if !retained.Dependency.Equal(dependency) {
		t.Fatal("head rollover mutated original dependency")
	}
	retained.Dependency.Epoch.Configuration.IssuerRoots[0][0]++
	if dependency.Epoch.Configuration.IssuerRoots[0][0] != 6 {
		t.Fatal("observation clone aliased original dependency")
	}
}
