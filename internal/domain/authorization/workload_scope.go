package authorization

import (
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

// WorkloadProjection contains only accepted whole-workload assignments and the
// complete deny snapshot. Per-Pod decision-time reviews cannot sponsor future
// replicas. This value cannot be passed to an artifact/capture evaluator.
type WorkloadProjection struct {
	Target                             WorkloadTarget
	Revision                           identity.Revision
	ObservedAt, FreshUntil             time.Time
	DeniesComplete                     bool
	DeniesObservedAt, DeniesFreshUntil time.Time
	Allows, Denies                     []CurrentAssignment
}

// WorkloadScopeEligibility shares ordinary assignment/deny rules without
// inventing a Pod. It is management/review eligibility, never evidence access
// or an executable concrete-Pod permit.
func WorkloadScopeEligibility(i identity.Identity, p WorkloadProjection, op Operation, t WorkloadTarget, now time.Time) Result {
	if !t.Valid() || p.Target != t || op != CollectContext && op != ReadApproved && op != ApproveAction {
		return Result{Reason: "InvalidRequest"}
	}
	for _, a := range p.Allows {
		if a.Reviewed {
			return Result{Reason: "PermissionUnavailable"}
		}
	}
	for _, a := range p.Denies {
		if a.Reviewed {
			return Result{Reason: "PermissionUnavailable"}
		}
	}
	ordinary := p.projection()
	target := ordinary.Target
	r, _ := evaluateDetailScope(i, ordinary, op, target, nil, now, false, true)
	return r
}

// PolicyGrantManagementEligibility requires a current sponsoring maintainer
// team assignment. The historical requester/creator principal is insufficient.
// This is restrictive management only, never collection or evidence authority.
func PolicyGrantManagementEligibility(i identity.Identity, p WorkloadProjection, a AcceptedPolicyAuthority, now time.Time) Result {
	if i.Principal.Kind != identity.Human || p.Target != (WorkloadTarget{a.ClusterID, a.NamespaceUID, a.WorkloadUID}) {
		return Result{Reason: "InvalidRequest"}
	}
	r := WorkloadScopeEligibility(i, p, ReadApproved, p.Target, now)
	if !r.Eligible {
		return r
	}
	for _, current := range r.ContributingAssignments {
		if current.Kind != "Group" || current.Role != "workload-maintainer" || current.BasisKind != "AccessBinding" || current.BasisUID != a.Delegation.UID {
			continue
		}
		for _, owner := range a.Owners {
			if current == owner {
				return r
			}
		}
	}
	return Result{Reason: "DelegationRequired"}
}

func (p WorkloadProjection) projection() Projection {
	target := Target{ClusterID: p.Target.ClusterID, NamespaceUID: p.Target.NamespaceUID, WorkloadUID: p.Target.WorkloadUID}
	ordinary := Projection{Target: target, Revision: p.Revision, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil, DeniesComplete: p.DeniesComplete, DeniesObservedAt: p.DeniesObservedAt, DeniesFreshUntil: p.DeniesFreshUntil, Allows: p.Allows, Denies: p.Denies}
	return ordinary
}
