// Package audit defines bounded, content-minimized durable audit records.
package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// Permission changes record assignment identities, never group membership lists,
// Kubernetes free text, tokens or collected evidence. Source digests link config.
type AssignmentChange struct {
	ID, Change  string
	Audience    artifact.AudienceAssignment
	ScopeDigest artifact.Digest
}
type AuthorityRecord struct {
	ID, RootID, Epoch, Kind string
	Sequence                int64
	InputDigest             artifact.Digest
	CreatedAt               time.Time
	Changes                 []AssignmentChange
	Bootstrap               *PermissionBootstrap
	Automation              []AutomationDelegation `json:",omitempty"`
	// Namespaces is the minimized namespace observation that the accepted
	// PermissionSource assignments were derived from (ADR-242): keys, names,
	// UIDs and value digests only.
	Namespaces *configuration.NamespaceObservation `json:",omitempty"`
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
		if c.Outcome != "Allowed" || !c.FreshUntil.After(c.DecidedAt) || c.FreshUntil.After(c.DecidedAt.Add(configuration.MaxDecisionAge)) {
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

// Complete minimized delegation snapshot for this accepted configuration. It
// records envelopes, not personal group membership or authored free text.
type AutomationDelegation struct {
	BasisKey    string
	Revision    identity.Revision
	ScopeDigest artifact.Digest
	Envelope    authorization.AutomationEnvelope
}

// Minimized first-acceptance provenance. Reviewer is an attested actor label,
// never an authorization decision. Empty installations have no review fields.
type PermissionBootstrap struct {
	ClusterID, NamespaceUID            string
	BindingsDigest                     artifact.Digest
	BindingCount                       int
	ReviewUID, ReviewVersion, Reviewer string
	ReviewDigest                       artifact.Digest
	ReviewedAt, ExpiresAt              time.Time
}

func (r AuthorityRecord) Valid() bool {
	if !authorization.UUID(r.ID) || !authorization.UUID(r.RootID) || !authorization.UUID(r.Epoch) || r.Sequence < 0 || r.CreatedAt.IsZero() || r.InputDigest == (artifact.Digest{}) || len(r.Changes) > 8192 {
		return false
	}
	if r.Kind != "permission-reset" && r.Kind != "permission-change" && r.Kind != "permission-suspend" && r.Kind != "permission-review" {
		return false
	}
	if (r.Kind == "permission-review") != (r.Review != nil) || r.Review != nil && (!r.Review.valid() || len(r.Changes) > 0 || r.Bootstrap != nil || len(r.ReviewRetirements) > 0) {
		return false
	}
	if len(r.Automation) > 1024 || (len(r.Automation) > 0 || r.Namespaces != nil || len(r.ReviewSources) > 0) && r.Kind != "permission-change" || r.Namespaces != nil && !r.Namespaces.Valid() {
		return false
	}
	if len(r.ReviewSources) > 64 || len(r.ReviewRetirements) > 128 {
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
	delegations := map[string]bool{}
	for _, a := range r.Automation {
		if !identity.Text(a.BasisKey, 256) || delegations[a.BasisKey] || !a.Revision.Valid() || a.ScopeDigest == (artifact.Digest{}) || !a.Envelope.Valid() {
			return false
		}
		delegations[a.BasisKey] = true
	}
	if p := r.Bootstrap; p != nil {
		if r.Kind != "permission-change" || !authorization.UUID(p.ClusterID) || !identity.Text(p.NamespaceUID, 64) || p.BindingsDigest == (artifact.Digest{}) || p.BindingCount < 0 || p.BindingCount > 1024 {
			return false
		}
		if p.BindingCount == 0 {
			if p.ReviewUID != "" || p.ReviewVersion != "" || p.Reviewer != "" || p.ReviewDigest != (artifact.Digest{}) || !p.ReviewedAt.IsZero() || !p.ExpiresAt.IsZero() {
				return false
			}
		} else if !identity.Text(p.ReviewUID, 64) || !identity.Text(p.ReviewVersion, 128) || !identity.Text(p.Reviewer, 256) || p.ReviewDigest == (artifact.Digest{}) || !identity.Fresh(p.ReviewedAt, p.ExpiresAt, r.CreatedAt, time.Hour) {
			return false
		}
	}
	seen := map[string]bool{}
	for _, c := range r.Changes {
		a := c.Audience
		if !authorization.UUID(c.ID) || seen[c.ID] || c.ID != a.AssignmentID || (c.Change != "added" && c.Change != "retired") || c.ScopeDigest == (artifact.Digest{}) {
			return false
		}
		if (a.Kind != "User" && a.Kind != "Group" && a.Kind != "Workload") || !identity.Text(a.Issuer, 2048) || !identity.Text(a.SubjectID, 256) || (a.BasisKind != "AccessBinding" && a.BasisKind != "PermissionSource") || !identity.Text(a.BasisUID, 64) || a.BasisDigest == (artifact.Digest{}) {
			return false
		}
		if a.Role != "workload-maintainer" && a.Role != "evidence-reader" && a.Role != "evidence-owner" && a.Role != "action-approver" {
			return false
		}
		seen[c.ID] = true
	}
	return true
}

type Receipt struct {
	Key, Version, ETag string
	Bytes              int64
	SHA256             artifact.Digest
}

func AuthorityKey(root, event string) string {
	return "authority/v1/" + root + "/" + event + "/record"
}
func (r Receipt) Valid(root, event string) bool {
	return authorization.UUID(root) && authorization.UUID(event) && r.Key == AuthorityKey(root, event) && r.Version != "null" && identity.Text(r.Version, 1024) && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= 16<<20 && r.SHA256 != (artifact.Digest{})
}
