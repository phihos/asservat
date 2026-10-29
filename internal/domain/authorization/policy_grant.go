package authorization

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

const (
	GrantPolicy                = "policy"
	PolicyGrantDefaultLifetime = 7 * 24 * time.Hour
	PolicyGrantMaximumLifetime = 365 * 24 * time.Hour
)

// WorkloadTarget deliberately has no Pod incarnation. It cannot be supplied to
// a concrete capture/disclosure evaluator that requires Target.Valid().
type WorkloadTarget struct{ ClusterID, NamespaceUID, WorkloadUID string }

func (t WorkloadTarget) Valid() bool {
	return UUID(t.ClusterID) && identity.Text(t.NamespaceUID, 64) && identity.Text(t.WorkloadUID, 64)
}

// PolicyApprovalSettings is an accepted protected setting. Persistence must
// apply every accepted lower maximum to all earlier-issued grants, including
// unused grants. It is not a historical raw ConfigMap journal.
type PolicyApprovalSettings identity.PolicyGrantApproval

func (p PolicyApprovalSettings) Valid() bool { return identity.PolicyGrantApproval(p).Valid() }

func DefaultPolicyApprovalSettings() PolicyApprovalSettings {
	return PolicyApprovalSettings(identity.DefaultPolicyGrantApproval())
}

// Clamp only shortens the existing expiry, from the original issuedAt. Raising
// a maximum cannot renew a previously clamped grant. The caller supplies a
// previously accepted setting and persists the result under the grant lock.
func (p PolicyApprovalSettings) Clamp(issuedAt, current time.Time) time.Time {
	if !p.Valid() || issuedAt.IsZero() || current.IsZero() {
		return time.Time{}
	}
	return identity.Earlier(current, issuedAt.Add(p.MaxAge))
}

// PolicyGrantScope binds accepted team execution, never the requester's token
// lifetime. The immutable scope and review digest include this exact authority,
// finite requested budgets and accepted approval settings reference.
type PolicyGrantScope struct {
	Authority         AcceptedPolicyAuthority
	RecipeDigest      artifact.Digest
	Limits            AutomationLimits
	ApprovalPolicyRef identity.Revision
	// ApprovalMaxAge is the original reviewed ceiling, separate from later
	// monotonic PolicyNotAfter overlays. It needs no settings history lookup.
	ApprovalMaxAge time.Duration
	Observation    *ObservationLimits
}

func (p PolicyGrantScope) Clone() PolicyGrantScope {
	p.Authority.Owners = slices.Clone(p.Authority.Owners)
	p.Authority.Actions = slices.Clone(p.Authority.Actions)
	if p.Observation != nil {
		o := *p.Observation
		p.Observation = &o
	}
	return p
}

func (p PolicyGrantScope) Workload() WorkloadTarget {
	return WorkloadTarget{p.Authority.ClusterID, p.Authority.NamespaceUID, p.Authority.WorkloadUID}
}

func (p PolicyGrantScope) valid(issuedAt time.Time) bool {
	a := p.Authority
	if p.Observation == nil && p.Limits.MaxObservedBytes != 0 || p.Observation != nil && (!p.Observation.Valid() || p.Observation.MaxObservedBytes != p.Limits.MaxObservedBytes) {
		return false
	}
	return p.RecipeDigest != (artifact.Digest{}) && p.ApprovalMaxAge >= time.Second && p.ApprovalMaxAge <= PolicyGrantMaximumLifetime && p.ApprovalMaxAge%time.Second == 0 && a.Valid(issuedAt) && p.Workload().Valid() && p.ApprovalPolicyRef.Valid() && p.Limits.MaxExecutions > 0 && p.Limits.MaxExecutions <= a.Limits.MaxExecutions && p.Limits.MaxBytes > 0 && p.Limits.MaxBytes <= a.Limits.MaxBytes && p.Limits.MaxObservedBytes >= 0 && p.Limits.MaxObservedBytes <= a.Limits.MaxObservedBytes
}
