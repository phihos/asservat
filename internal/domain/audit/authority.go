// Package audit defines bounded, content-minimized durable audit records.
package audit

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

type AuthorityRecord struct {
	ID, RootID, Epoch, Kind string
	Sequence                int64
	InputDigest             artifact.Digest
	CreatedAt               time.Time
	// Namespaces is the minimized namespace observation that the accepted
	// PermissionSource assignments were derived from (ADR-242): keys, names,
	// UIDs and value digests only.
	Namespaces *configuration.NamespaceObservation `json:",omitempty"`
	// RemoteNamespaces are other joined clusters' observations (ADR-247).
	RemoteNamespaces []configuration.NamespaceObservation `json:",omitempty"`
	// Workloads are the workload observations of the batch (ADR-247).
	Workloads []configuration.WorkloadObservation `json:",omitempty"`
	// ReviewSources are the accepted decision-time sources of a
	// permission-change (ADR-245); ReviewRetirements name the sources whose
	// per-principal assignments this event retired, and how many.
	ReviewSources     []configuration.ReviewSource `json:",omitempty"`
	ReviewRetirements []ReviewRetirement           `json:",omitempty"`
	// Review is the one decision change of a permission-review event
	// (ADR-245, REQ-PER-006).
	Review *ReviewDecisionChange `json:",omitempty"`
}

// Decision-time review changes (ADR-245). A review that confirms the current
// state of its (source, principal, Pod) records no event; its SQL row is
// updated in place.
const (
	ReviewGranted  = "granted"  // first allowed review of the Pod
	ReviewRevoked  = "revoked"  // an allowed decision ended by a refusal
	ReviewRestored = "restored" // an allowed review after a refusal
)

// ReviewDecisionChange is the minimized record of one decision-time review
// whose outcome changed: source UID/revision, the principal and its mapping
// reference, the persistent assignment, the target UIDs, decision time and
// lifetime, and the closed outcome as reason. No token, Kubernetes user name,
// group or namespace/Pod name is recorded.
type ReviewDecisionChange struct {
	Change, Outcome                              string
	SourceUID                                    string
	SourceGeneration                             int64
	SourceDigest                                 artifact.Digest
	IdentityMapping                              string
	Issuer, Subject                              string
	AssignmentID                                 string
	ClusterID, NamespaceUID, WorkloadUID, PodUID string
	DecidedAt, FreshUntil                        time.Time
}

func (c ReviewDecisionChange) valid() bool {
	switch c.Change {
	case ReviewGranted, ReviewRestored:
		if c.Outcome != "Allowed" || !c.FreshUntil.After(c.DecidedAt) || c.FreshUntil.After(c.DecidedAt.Add(configuration.ReviewDecisionAge)) {
			return false
		}
	case ReviewRevoked:
		if c.Outcome == "Allowed" || !identity.Text(c.Outcome, 32) || !c.FreshUntil.Equal(c.DecidedAt) {
			return false
		}
	default:
		return false
	}
	return identity.Text(c.SourceUID, 64) && c.SourceGeneration >= 1 && c.SourceDigest != (artifact.Digest{}) && identity.Text(c.IdentityMapping, 63) && identity.Text(c.Issuer, 2048) && identity.Text(c.Subject, 256) &&
		authorization.UUID(c.AssignmentID) && authorization.UUID(c.ClusterID) && identity.Text(c.NamespaceUID, 64) && identity.Text(c.WorkloadUID, 64) && identity.Text(c.PodUID, 64) && !c.DecidedAt.IsZero()
}

// ReviewRetirement records that one event retired every current
// per-principal assignment of one decision-time source. Principals are not
// listed: they are the source's recorded audiences, not configuration.
type ReviewRetirement struct {
	SourceUID string
	Retired   int64
}

func (r AuthorityRecord) Valid() bool {
	if !authorization.UUID(r.ID) || !authorization.UUID(r.RootID) || !authorization.UUID(r.Epoch) || r.Sequence < 0 || r.CreatedAt.IsZero() || r.InputDigest == (artifact.Digest{}) {
		return false
	}
	if r.Kind != "permission-reset" && r.Kind != "permission-change" && r.Kind != "permission-suspend" && r.Kind != "permission-review" {
		return false
	}
	if (r.Kind == "permission-review") != (r.Review != nil) || r.Review != nil && (!r.Review.valid() || len(r.ReviewRetirements) > 0) {
		return false
	}
	if (r.Namespaces != nil || len(r.RemoteNamespaces) > 0 || len(r.Workloads) > 0 || len(r.ReviewSources) > 0) && r.Kind != "permission-change" || r.Namespaces != nil && !r.Namespaces.Valid() || !configuration.RemoteNamespacesValid(r.Namespaces, r.RemoteNamespaces) || !configuration.WorkloadObservationsValid(r.Workloads) {
		return false
	}
	for _, s := range r.ReviewSources {
		if !s.Valid() {
			return false
		}
	}
	for _, x := range r.ReviewRetirements {
		if !identity.Text(x.SourceUID, 64) || x.Retired < 0 {
			return false
		}
	}
	return true
}

type Receipt struct {
	Key, Version, ETag string
	Bytes              int64
	SHA256             artifact.Digest
}
