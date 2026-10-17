package configuration

import (
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

var ErrRetentionHistoryBehind = errors.New("retention watch has not reached the complete policy list")
var ErrRetentionObservationObsolete = errors.New("retention observation predates the accepted or changed source")

// RetentionBootstrapReview accepts pre-existing values once. The independently
// pinned installation object binds the complete policy set AND current write
// protection. Reviewer is audit provenance, never a credential or grant.
type RetentionBootstrapReview struct {
	Resource                         Resource
	Reviewer                         string
	PoliciesDigest, ProtectionDigest artifact.Digest
	ReviewedAt, ExpiresAt            time.Time
	ObservedAt, FreshUntil           time.Time
}

func (r RetentionBootstrapReview) Valid(now time.Time) bool {
	return r.Resource.Kind == "ConfigMap" && authorization.UUID(r.Resource.ClusterID) && identity.Text(r.Resource.Namespace, 63) && identity.Text(r.Resource.NamespaceUID, 64) && identity.Text(r.Resource.Name, 253) && identity.Text(r.Resource.UID, 64) && identity.Text(r.Resource.ResourceVersion, 128) && r.Resource.SpecDigest != (artifact.Digest{}) && !r.Resource.Deleting && identity.Text(r.Reviewer, 256) && r.PoliciesDigest != (artifact.Digest{}) && r.ProtectionDigest != (artifact.Digest{}) && identity.Fresh(r.ReviewedAt, r.ExpiresAt, now, time.Hour) && identity.Fresh(r.ObservedAt, r.FreshUntil, now, 5*time.Second)
}
