package authorization

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// AutomationEnvelope is an operator's per-policy ceiling, not an executable
// grant. Workload/global capacity still bounds the aggregate of all policies.
type AutomationEnvelope struct {
	AllowedActions                                                []string
	MaxLifetimeSeconds, MaxExecutions, MaxBytes, MaxObservedBytes int64
}

func (e AutomationEnvelope) Valid() bool {
	if len(e.AllowedActions) == 0 || !identity.Strings(e.AllowedActions, 14, 32) || e.MaxLifetimeSeconds < 1 || e.MaxLifetimeSeconds > 31536000 || e.MaxExecutions < 1 || e.MaxExecutions > 10000 || e.MaxBytes < 1 || e.MaxBytes > 1<<40 || e.MaxObservedBytes < 0 || e.MaxObservedBytes > 1<<40 {
		return false
	}
	for _, a := range e.AllowedActions {
		switch a {
		case "kubernetesSnapshot", "logs", "processSnapshot", "fileRead", "packetCapture", "networkSnapshot", "runtimeDiagnostic", "kernelCore", "liveCore", "command", "httpDiagnostic", "artifactCollect", "profile", "syscallTrace":
		default:
			return false
		}
	}
	return true
}

// PolicyPrincipal is installation-local. It is never accepted by the public
// OIDC verifier or allowed to impersonate a person. The authenticated worker and
// the policy on whose behalf it executes have separate audit identities.
func PolicyPrincipal(installationID, policyUID string) identity.Principal {
	if !UUID(installationID) || !identity.Text(policyUID, 64) {
		return identity.Principal{}
	}
	return identity.Principal{Issuer: "urn:asservat:installation:" + installationID, Subject: "policy:" + policyUID, ClientID: "policy-executor", Kind: identity.Workload}
}

// PolicySourceInterval bounds one protected policy source observation and
// the accepted-policy snapshot read from it. ADR-228 relaxed the
// agent-authored five seconds: a policy-triggered capture's preview, admission
// and regional start run on one observation and take longer than five seconds
// end to end; the 15-second trigger poll refreshes it.
const PolicySourceInterval = 30 * time.Second

type AutomationLimits struct{ MaxExecutions, MaxBytes, MaxObservedBytes int64 }

// AcceptedPolicyAuthority is loaded from protected accepted execution, never
// authored fields or a CRD status. Creator is historical provenance only.
// Owners pins the collection assignments supporting delegation, not a list of
// their members or a replacement for evidence-owner management assignments.
type AcceptedPolicyAuthority struct {
	InstallationID, PolicyUID            string
	Creator, Executor                    identity.Principal
	ScopeDigest                          artifact.Digest
	ClusterID, NamespaceUID, WorkloadUID string
	Delegation                           identity.Revision
	Owners                               []artifact.AudienceAssignment
	Actions                              []string
	Limits                               AutomationLimits
	IssuedAt, NotAfter                   time.Time
}

// AcceptedPolicySnapshot carries the original source/recovery read deadline;
// a delayed preflight must not turn an old source observation into fresh proof.
type AcceptedPolicySnapshot struct {
	Authority              AcceptedPolicyAuthority
	ObservedAt, FreshUntil time.Time
	// SourceUntil is the policy's own bound (source observation and expiry)
	// without the recovery read's interval, which every effect transaction
	// checks independently (ADR-228). FreshUntil is never later.
	SourceUntil time.Time
}

type AutomationProjection struct {
	InstallationID         string
	Delegation             identity.Revision
	Envelope               AutomationEnvelope
	ObservedAt, FreshUntil time.Time
	NotAfter               time.Time // Optional AccessBinding expiry, never extended by a read.
	Disabled               bool
	Permissions            Projection // Exact pod, complete current denies and assignments.
}

type PolicyPurpose string

const (
	PolicyArm      PolicyPurpose = "arm"
	PolicyRenew    PolicyPurpose = "renew"
	PolicyIncident PolicyPurpose = "incident"
	PolicySave     PolicyPurpose = "recordingSave"
)

type PolicyUse struct {
	PolicyUID   string
	ScopeDigest artifact.Digest
	Target      Target
	Purpose     PolicyPurpose
}

// PolicyEligibility is deliberately not a human Result/Identity. It cannot be
// supplied to ordinary evidence evaluation or substitute for an atomic permit.
type PolicyEligibility struct {
	Eligible                       bool
	Reason                         string
	Executor                       identity.Principal
	ValidUntil                     time.Time
	Delegation, PermissionRevision identity.Revision
}

func (p AcceptedPolicyAuthority) Valid(now time.Time) bool {
	if !UUID(p.InstallationID) || !identity.Text(p.PolicyUID, 64) || !p.Creator.Valid() || p.Executor != PolicyPrincipal(p.InstallationID, p.PolicyUID) || p.ScopeDigest == (artifact.Digest{}) || !UUID(p.ClusterID) || !identity.Text(p.NamespaceUID, 64) || !identity.Text(p.WorkloadUID, 64) || !p.Delegation.Valid() || !identity.Fresh(p.IssuedAt, p.NotAfter, now, 365*24*time.Hour) || len(p.Owners) < 1 || len(p.Owners) > 8 {
		return false
	}
	e := AutomationEnvelope{p.Actions, int64(p.NotAfter.Sub(p.IssuedAt) / time.Second), p.Limits.MaxExecutions, p.Limits.MaxBytes, p.Limits.MaxObservedBytes}
	if !e.Valid() || p.NotAfter.Sub(p.IssuedAt)%time.Second != 0 {
		return false
	}
	seen := map[string]bool{}
	for _, o := range p.Owners {
		if !validAudience(o) || o.Kind != "Group" || o.Role != "workload-maintainer" || o.BasisKind != "AccessBinding" || o.BasisUID != p.Delegation.UID || seen[o.AssignmentID] {
			return false
		}
		seen[o.AssignmentID] = true
	}
	return true
}

// EvaluatePolicy uses current team delegation, not the creator's last login.
// Caller still needs protected acceptance, authenticated purpose-specific worker
// dispatch, current action grants, atomic quota/audit/recovery/privacy admission
// and a signed short permit before any observation, collection or saved output.
func EvaluatePolicy(a AcceptedPolicyAuthority, p AutomationProjection, use PolicyUse, now time.Time) PolicyEligibility {
	deny := func(reason string) PolicyEligibility { return PolicyEligibility{Reason: reason} }
	if !use.Target.Valid() || use.PolicyUID != a.PolicyUID || use.ScopeDigest != a.ScopeDigest {
		return deny("InvalidPolicyUse")
	}
	switch use.Purpose {
	case PolicyArm, PolicyRenew, PolicyIncident, PolicySave:
	default:
		return deny("InvalidPolicyPurpose")
	}
	if !a.Valid(now) {
		return deny("PolicyAuthorityExpiredOrInvalid")
	}
	if (use.Purpose == PolicyArm || use.Purpose == PolicyRenew) && a.Limits.MaxObservedBytes == 0 {
		return deny("ObservationNotDelegated")
	}
	if use.Target.ClusterID != a.ClusterID || use.Target.NamespaceUID != a.NamespaceUID || use.Target.WorkloadUID != a.WorkloadUID {
		return deny("OutsidePolicyScope")
	}
	if p.InstallationID != a.InstallationID || p.Delegation != a.Delegation || p.Disabled || !p.Envelope.Valid() || !identity.Fresh(p.ObservedAt, p.FreshUntil, now, 60*time.Second) {
		return deny("AutomationUnavailable")
	}
	if (!p.NotAfter.IsZero() && !now.Before(p.NotAfter)) || a.NotAfter.After(a.IssuedAt.Add(time.Duration(p.Envelope.MaxLifetimeSeconds)*time.Second)) || a.Limits.MaxExecutions > p.Envelope.MaxExecutions || a.Limits.MaxBytes > p.Envelope.MaxBytes || a.Limits.MaxObservedBytes > p.Envelope.MaxObservedBytes {
		return deny("OutsideDelegation")
	}
	for _, action := range a.Actions {
		if !slices.Contains(p.Envelope.AllowedActions, action) {
			return deny("OutsideDelegation")
		}
	}
	q := p.Permissions
	if !q.Revision.Valid() || q.Target != use.Target || !q.DeniesComplete || !identity.Fresh(q.ObservedAt, q.FreshUntil, now, 60*time.Second) || !identity.Fresh(q.DeniesObservedAt, q.DeniesFreshUntil, now, PermissionObservationInterval) || !rowsValid(q.Allows) || !rowsValid(q.Denies) {
		return deny("PermissionUnavailable")
	}
	until := identity.Earlier(a.NotAfter, identity.Earlier(p.FreshUntil, identity.Earlier(q.FreshUntil, q.DeniesFreshUntil)))
	if !p.NotAfter.IsZero() {
		until = identity.Earlier(until, p.NotAfter)
	}
	// A deny affecting any pinned sponsoring team or this executor blocks the
	// policy. An unrelated personal deny does not revoke team delegation.
	for _, d := range q.Denies {
		if !identity.Fresh(d.ObservedAt, d.FreshUntil, now, PermissionObservationInterval) {
			return deny("PermissionUnavailable")
		}
		until = identity.Earlier(until, d.FreshUntil)
		if d.Audience.Role != "workload-maintainer" {
			continue
		}
		if d.Audience.Kind == "Workload" && d.Audience.Issuer == a.Executor.Issuer && d.Audience.SubjectID == a.Executor.Subject {
			return deny("ExplicitDeny")
		}
		for _, o := range a.Owners {
			if d.Audience.Kind == o.Kind && d.Audience.Issuer == o.Issuer && d.Audience.SubjectID == o.SubjectID {
				return deny("ExplicitDeny")
			}
		}
	}
	for _, o := range a.Owners {
		found := false
		for _, current := range q.Allows {
			if current.Audience == o && identity.Fresh(current.ObservedAt, current.FreshUntil, now, 60*time.Second) {
				found = true
				until = identity.Earlier(until, current.FreshUntil)
				break
			}
		}
		if !found {
			return deny("OwnerAssignmentChanged")
		}
	}
	return PolicyEligibility{true, "Eligible", a.Executor, until, p.Delegation, q.Revision}
}

// ValidatePolicyAcceptance checks the current authenticated author as well as
// the candidate's team delegation. It is preflight only: acceptance must freeze
// and persist the reviewed scope with audit, freshness fences and a consumed
// submission nonce. It does not refresh an existing policy's expiry/budgets.
func ValidatePolicyAcceptance(author identity.Identity, a AcceptedPolicyAuthority, p AutomationProjection, use PolicyUse, now time.Time) PolicyEligibility {
	if author.Principal.Kind != identity.Human {
		return PolicyEligibility{Reason: "HumanSubmitterRequired"}
	}
	// An editor may differ from the immutable creator. Protected acceptance
	// verifies the submission's actor and preserves the original creator itself.
	rights := ScopeEligibility(author, p.Permissions, CollectContext, use.Target, now)
	if !rights.Eligible {
		return PolicyEligibility{Reason: rights.Reason}
	}
	member := false
	for _, owner := range a.Owners {
		if matches(owner, author) {
			member = true
		}
	}
	if !member {
		return PolicyEligibility{Reason: "NoDelegationMembership"}
	}
	result := EvaluatePolicy(a, p, use, now)
	if result.Eligible {
		result.ValidUntil = identity.Earlier(result.ValidUntil, rights.ValidUntil)
	}
	return result
}
