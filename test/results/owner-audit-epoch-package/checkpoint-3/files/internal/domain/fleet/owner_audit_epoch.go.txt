package fleet

import (
	"errors"
	"math"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

// OwnerAuditEpochPolicy is an unselected installer policy value. Every bound is
// explicit; arithmetic validity does not qualify storage, latency or capacity.
// The fixed chain is admission -> dependencies -> retention -> deletion ->
// metadata -> residual copies. All horizons start at the original claim anchor.
type OwnerAuditEpochPolicy struct {
	EpochInterval, AdmissionWindow, MaxDependencyLifetime time.Duration
	RetainAfterDependencies, DeleteBudget                 time.Duration
	MetadataAfterDeletion, ResidualAfterMetadata          time.Duration
	// MaxDependenciesPerEpoch counts all unresolved dependency rows, including
	// completed work whose original retirement obligations are still charged.
	MaxOpenEpochs, MaxUncertainEpochs, MaxDependenciesPerEpoch int64
	PerEpoch                                                   OwnerAuditEpochBudget
}

// Markers and unknown uploads are separate charged obligations, including when
// measured ciphertext size is zero. CiphertextBytes is the total byte ceiling
// across all data versions and unfinished uploads for one epoch, not a separate
// allowance per version. MetadataBytes covers its live dependency/obligation rows;
// backing must additionally qualify bounded provider and residual overhead.
// These are ceilings, not measurements.
type OwnerAuditEpochBudget struct {
	CiphertextBytes, DataVersions, DeleteMarkers, MultipartUploads, MultipartParts, MetadataBytes int64
}

func (b OwnerAuditEpochBudget) WellFormed() bool {
	return b.CiphertextBytes > 0 && b.DataVersions > 0 && b.DeleteMarkers > 0 && b.MultipartUploads > 0 && b.MultipartParts >= b.MultipartUploads && b.MetadataBytes > 0
}

var (
	ErrOwnerAuditEpochPolicyInvalid     = errors.New("invalid finite owner audit epoch policy")
	ErrOwnerAuditEpochSlotsInsufficient = errors.New("owner audit epoch schedule exceeds configured open slots")
)

// OwnerAuditEpochSchedule is only a mathematical lower bound. Positive closure,
// cleanup latency, source availability and backing remain separate qualification.
// No method silently increases the administrator's configured allocation.
type OwnerAuditEpochSchedule struct {
	EpochInterval, AdmissionOverlap time.Duration
	MinimumOpenEpochs               int64
}

// Schedule reports the exact minimum even when the configured slot limit is too
// small. Normal epochs remain charged through their full original residual end;
// the lower bound adds one pending claim plus an explicit uncertain allowance.
// Fixed automatic rollover uses EpochInterval without changing semantic source
// generation or requiring a person to approve every routine epoch.
func (p OwnerAuditEpochPolicy) Schedule() (OwnerAuditEpochSchedule, error) {
	var out OwnerAuditEpochSchedule
	if !p.PerEpoch.WellFormed() || p.MaxOpenEpochs < 1 || p.MaxUncertainEpochs < 1 || p.MaxDependenciesPerEpoch < 1 || p.EpochInterval <= 0 || p.EpochInterval%time.Microsecond != 0 || p.EpochInterval >= p.AdmissionWindow {
		return out, ErrOwnerAuditEpochPolicyInvalid
	}
	total := time.Duration(0)
	for _, d := range []time.Duration{p.AdmissionWindow, p.MaxDependencyLifetime, p.RetainAfterDependencies, p.DeleteBudget, p.MetadataAfterDeletion, p.ResidualAfterMetadata} {
		if d <= 0 || d%time.Microsecond != 0 || d > time.Duration(math.MaxInt64)-total {
			return out, ErrOwnerAuditEpochPolicyInvalid
		}
		total += d
	}
	normal := int64((total-1)/p.EpochInterval) + 1
	if p.MaxUncertainEpochs > math.MaxInt64-1-normal {
		return out, ErrOwnerAuditEpochPolicyInvalid
	}
	out = OwnerAuditEpochSchedule{EpochInterval: p.EpochInterval, AdmissionOverlap: p.AdmissionWindow - p.EpochInterval, MinimumOpenEpochs: normal + 1 + p.MaxUncertainEpochs}
	if p.MaxOpenEpochs < out.MinimumOpenEpochs {
		return out, ErrOwnerAuditEpochSlotsInsufficient
	}
	for _, n := range []int64{p.PerEpoch.CiphertextBytes, p.PerEpoch.DataVersions, p.PerEpoch.DeleteMarkers, p.PerEpoch.MultipartUploads, p.PerEpoch.MultipartParts, p.PerEpoch.MetadataBytes, p.MaxDependenciesPerEpoch} {
		if n > math.MaxInt64/p.MaxOpenEpochs {
			return out, ErrOwnerAuditEpochPolicyInvalid
		}
	}
	return out, nil
}
func (p OwnerAuditEpochPolicy) WellFormed() bool { _, err := p.Schedule(); return err == nil }

// This is provenance, not reservation authority. Concrete protected provisioning
// and current SQL must verify the same positive allocation/qualification/policy.
// Qualified physical accounting and future SQL facets remain unimplemented.
type OwnerControlAuditReserveReference struct {
	ID, InstallationRootID, InstallationID, ClusterID, SourceUID, StoreID string
	CapacityID, PoolID, AllocationID, QualificationID                     string
	RootDigest, QualificationDigest, PolicyDigest                         artifact.Digest
	ProvisionedAt                                                         time.Time
	Policy                                                                OwnerAuditEpochPolicy
}

func (r OwnerControlAuditReserveReference) WellFormed() bool {
	for _, id := range []string{r.ID, r.InstallationRootID, r.InstallationID, r.ClusterID, r.SourceUID, r.StoreID, r.CapacityID, r.PoolID, r.AllocationID, r.QualificationID} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return r.RootDigest != (artifact.Digest{}) && r.QualificationDigest != (artifact.Digest{}) && r.PolicyDigest != (artifact.Digest{}) && ownerEpochTime(r.ProvisionedAt) && r.Policy.WellFormed()
}
func (r OwnerControlAuditReserveReference) Equal(other OwnerControlAuditReserveReference) bool {
	a, b := r, other
	a.ProvisionedAt = time.Time{}
	b.ProvisionedAt = time.Time{}
	return a == b && r.ProvisionedAt.Equal(other.ProvisionedAt)
}

type OwnerAuditEpochDeadlines struct {
	AdmitUntil, DependenciesUntil, RetainUntil, DeleteBy, MetadataUntil, ResidualUntil time.Time
}

func OwnerAuditEpochDates(anchor time.Time, p OwnerAuditEpochPolicy) (OwnerAuditEpochDeadlines, bool) {
	var out OwnerAuditEpochDeadlines
	if !ownerEpochTime(anchor) || !p.WellFormed() {
		return out, false
	}
	at := anchor
	fields := []*time.Time{&out.AdmitUntil, &out.DependenciesUntil, &out.RetainUntil, &out.DeleteBy, &out.MetadataUntil, &out.ResidualUntil}
	durations := []time.Duration{p.AdmissionWindow, p.MaxDependencyLifetime, p.RetainAfterDependencies, p.DeleteBudget, p.MetadataAfterDeletion, p.ResidualAfterMetadata}
	for i, d := range durations {
		next := at.Add(d)
		if !ownerEpochTime(next) || !next.After(at) {
			return OwnerAuditEpochDeadlines{}, false
		}
		*fields[i] = next
		at = next
	}
	return out, true
}
func (d OwnerAuditEpochDeadlines) Equal(other OwnerAuditEpochDeadlines) bool {
	return d.AdmitUntil.Equal(other.AdmitUntil) && d.DependenciesUntil.Equal(other.DependenciesUntil) && d.RetainUntil.Equal(other.RetainUntil) && d.DeleteBy.Equal(other.DeleteBy) && d.MetadataUntil.Equal(other.MetadataUntil) && d.ResidualUntil.Equal(other.ResidualUntil)
}

// OwnerAuditEpoch is historical immutable intent, never current acceptance.
// Its ID/ordinal/attempt are allocated and checked for nonreuse by the future
// protected SQL producer; a caller-created well-formed value grants no effect.
type OwnerAuditEpoch struct {
	ID, AttemptID string
	Ordinal       int64
	Reserve       OwnerControlAuditReserveReference
	Configuration OwnerConfiguration
	ClaimedAt     time.Time
	Deadlines     OwnerAuditEpochDeadlines
}

func (e OwnerAuditEpoch) WellFormed() bool {
	if !authorization.UUID(e.ID) || !authorization.UUID(e.AttemptID) || e.ID == e.AttemptID || e.Ordinal < 1 || !e.Reserve.WellFormed() || !e.Configuration.Valid() || e.Configuration.Suspended || e.ClaimedAt.Before(e.Reserve.ProvisionedAt) {
		return false
	}
	c := e.Configuration
	if c.Pool.InstallationID != e.Reserve.InstallationID || c.Pool.ClusterID != e.Reserve.ClusterID || c.Revision.UID != e.Reserve.SourceUID {
		return false
	}
	dates, ok := OwnerAuditEpochDates(e.ClaimedAt, e.Reserve.Policy)
	return ok && e.Deadlines.Equal(dates)
}
func (e OwnerAuditEpoch) Equal(other OwnerAuditEpoch) bool {
	return e.ID == other.ID && e.AttemptID == other.AttemptID && e.Ordinal == other.Ordinal && e.Reserve.Equal(other.Reserve) && e.Configuration.Equal(other.Configuration) && e.ClaimedAt.Equal(other.ClaimedAt) && e.Deadlines.Equal(other.Deadlines)
}
func (e OwnerAuditEpoch) Clone() OwnerAuditEpoch { e.Configuration = e.Configuration.Clone(); return e }

// Restrict new absolute dates to the timestamp representation shared with SQL
// and JSON. Historical semantic configuration dates/formats are not rewritten.
func ownerEpochTime(t time.Time) bool {
	_, offset := t.Zone()
	return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && offset == 0 && t.Nanosecond()%1000 == 0
}
