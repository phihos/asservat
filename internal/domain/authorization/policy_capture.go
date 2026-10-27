package authorization

import (
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

// PolicyContextAction is the delegated action kind of the pod-status context
// diagnostic (ADR-228): a bounded Kubernetes metadata snapshot.
const PolicyContextAction = "kubernetesSnapshot"

const policyIssuerPrefix = "urn:asservat:installation:"

// PolicyExecutor reports whether p is exactly the deterministic executor
// principal of one policy (ADR-059). The string form confers no authority:
// callers still need the accepted policy and current delegation.
func PolicyExecutor(p identity.Principal) (installation, policy string, ok bool) {
	installation, found := strings.CutPrefix(p.Issuer, policyIssuerPrefix)
	if !found {
		return "", "", false
	}
	policy, found = strings.CutPrefix(p.Subject, "policy:")
	if !found || p != PolicyPrincipal(installation, policy) || p == (identity.Principal{}) {
		return "", "", false
	}
	return installation, policy, true
}

// CaptureActor accepts the two actors of a context capture: an authenticated
// human, or an accepted policy's executor (ADR-228). Neither is authority.
func CaptureActor(p identity.Principal) bool {
	if !p.Valid() {
		return false
	}
	if p.Kind == identity.Human {
		return true
	}
	_, _, ok := PolicyExecutor(p)
	return ok
}

// PolicyIdentityRevision binds an executor identity to one accepted scope.
// A replaced or re-accepted scope therefore changes the identity revision.
func PolicyIdentityRevision(a AcceptedPolicyAuthority) identity.Revision {
	return identity.Revision{UID: a.PolicyUID, Generation: 1, Digest: a.ScopeDigest}
}

// PolicyExecutorIdentity is the bounded identity value an accepted policy
// executes under. It is derived from protected acceptance, never a token.
func PolicyExecutorIdentity(a AcceptedPolicyAuthority, observed, until time.Time) identity.Identity {
	return identity.Identity{Principal: a.Executor, Policy: PolicyIdentityRevision(a), Scopes: []string{"evidence:capture"}, VerifiedAt: observed, ValidUntil: until}
}

// PolicyContextEligibility is the context-collection eligibility of an
// accepted policy's executor for one triggering Pod (ADR-228). Team authority
// comes from EvaluatePolicy; the default evidence audience is computed exactly
// as for a human capture, so neither the creator nor the executor is added.
func PolicyContextEligibility(i identity.Identity, a AcceptedPolicyAuthority, p AutomationProjection, target Target, now time.Time) CaptureEligibility {
	deny := func(reason string) CaptureEligibility { return CaptureEligibility{Result: Result{Reason: reason}} }
	if !i.Valid(now) || i.Principal != a.Executor || i.Policy != PolicyIdentityRevision(a) {
		return deny("IdentityUnavailable")
	}
	if !slices.Contains(a.Actions, PolicyContextAction) {
		return deny("OutsideDelegation")
	}
	r := EvaluatePolicy(a, p, PolicyUse{PolicyUID: a.PolicyUID, ScopeDigest: a.ScopeDigest, Target: target, Purpose: PolicyIncident}, now)
	if !r.Eligible {
		return deny(r.Reason)
	}
	audience, until, reason := defaultAudience(p.Permissions, nil, now)
	if reason != "" {
		return deny(reason)
	}
	owners := slices.Clone(a.Owners)
	sortAssignments(owners)
	until = identity.Earlier(until, identity.Earlier(r.ValidUntil, i.ValidUntil))
	return CaptureEligibility{Result: Result{Eligible: true, Reason: "Eligible", Principal: a.Executor, IdentityRevision: i.Policy, PermissionRevision: p.Permissions.Revision, ValidUntil: until, ContributingAssignments: owners}, Target: target, VerifiedIdentity: i, DefaultAudience: audience}
}

// PolicyScope is the whole-workload target of policy-level checks
// (acceptance and status): the projection is workload-scoped, so the Pod
// field names the workload itself. Capture checks use the triggering Pod.
func PolicyScope(a AcceptedPolicyAuthority) Target {
	return WorkloadScope(a.ClusterID, a.NamespaceUID, a.WorkloadUID)
}

// WorkloadScope is the whole-workload target of a check that needs no Pod
// (policy acceptance, capture history): permission projections are
// workload-scoped, so the Pod field names the workload itself.
func WorkloadScope(cluster, namespaceUID, workloadUID string) Target {
	return Target{ClusterID: cluster, NamespaceUID: namespaceUID, WorkloadUID: workloadUID, PodUID: workloadUID}
}

// PolicyStopEligibility is the right to deactivate an accepted policy
// (ADR-229): the current human holds a current, undenied workload-maintainer
// group assignment of the policy's delegating AccessBinding, the same team
// authority that sponsors activation. Stopping collects and discloses nothing.
func PolicyStopEligibility(i identity.Identity, p Projection, a AcceptedPolicyAuthority, now time.Time) Result {
	if i.Principal.Kind != identity.Human {
		return Result{Reason: "IdentityUnavailable"}
	}
	r := ScopeEligibility(i, p, ReadApproved, PolicyScope(a), now)
	if !r.Eligible {
		return r
	}
	for _, o := range r.ContributingAssignments {
		if o.Kind == "Group" && o.Role == "workload-maintainer" && o.BasisKind == "AccessBinding" && o.BasisUID == a.Delegation.UID {
			return r
		}
	}
	return Result{Reason: "DelegationRequired"}
}
