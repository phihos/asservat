package configuration

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// BootstrapReview is an attestation read from protected installation
// configuration, never from an AccessBinding/PermissionSource's own metadata.
// Reviewer is recorded provenance, not a role or a substitute for source trust.
type BootstrapReview struct {
	Resource               Resource
	Reviewer               string
	BindingsDigest         artifact.Digest
	ReviewedAt, ExpiresAt  time.Time
	ObservedAt, FreshUntil time.Time
}

// PermissionInitialization binds the first accepted snapshot to either a
// guarded empty installation or a protected, exact review of existing values.
type PermissionInitialization struct {
	ClusterID      string
	Control        NamespaceRef
	BindingsDigest artifact.Digest
	BindingCount   int
	Review         *BootstrapReview
}

func (p PermissionInitialization) Valid(now time.Time) bool {
	if p.BindingsDigest == (artifact.Digest{}) || p.BindingCount < 0 || p.BindingCount > 1024 || !identity.Text(p.ClusterID, 64) || !identity.Text(p.Control.Name, 63) || !identity.Text(p.Control.UID, 64) {
		return false
	}
	if p.BindingCount == 0 {
		return p.Review == nil
	}
	r := p.Review
	return r != nil && r.Valid(now) && r.Resource.ClusterID == p.ClusterID && r.Resource.Namespace == p.Control.Name && r.Resource.NamespaceUID == p.Control.UID && r.BindingsDigest == p.BindingsDigest
}

func (r BootstrapReview) Valid(now time.Time) bool {
	return r.Resource.Kind == "ConfigMap" && identity.Text(r.Resource.UID, 64) && identity.Text(r.Resource.ResourceVersion, 128) && identity.Text(r.Resource.NamespaceUID, 64) && r.Resource.SpecDigest != (artifact.Digest{}) && !r.Resource.Deleting && identity.Text(r.Reviewer, 256) && r.BindingsDigest != (artifact.Digest{}) && identity.Fresh(r.ReviewedAt, r.ExpiresAt, now, time.Hour) && identity.Fresh(r.ObservedAt, r.FreshUntil, now, 5*time.Second)
}
