package authorization

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// These ports return protected acceptance and current configuration projections,
// never user-authored executor fields, CRD status or a stored login snapshot.
type AcceptedPolicyReader interface {
	AcceptedPolicyAuthority(context.Context, string) (value.AcceptedPolicySnapshot, error)
}
type AutomationAuthorityReader interface {
	PolicyAutomationAuthority(context.Context, value.AcceptedPolicyAuthority, value.Target) (value.AutomationProjection, error)
}

// AutomationEvaluator is a private worker preflight, not a public API, an OIDC
// identity resolver, a reservation transaction or an execution permit. Runtime
// composition must authenticate the worker and fence/spend atomically afterward.
type AutomationEvaluator struct {
	Accepted AcceptedPolicyReader
	Current  AutomationAuthorityReader
	Now      func() time.Time
}

func (e AutomationEvaluator) Eligibility(ctx context.Context, use value.PolicyUse) value.PolicyEligibility {
	deny := func() value.PolicyEligibility { return value.PolicyEligibility{Reason: "AutomationUnavailable"} }
	if e.Accepted == nil || e.Current == nil || e.Now == nil || ctx.Err() != nil {
		return deny()
	}
	started := e.Now()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	accepted, err := e.Accepted.AcceptedPolicyAuthority(ctx, use.PolicyUID)
	a := accepted.Authority
	if err != nil || !a.Valid(e.Now()) || a.PolicyUID != use.PolicyUID || a.ScopeDigest != use.ScopeDigest || !use.Target.Valid() || a.ClusterID != use.Target.ClusterID || a.NamespaceUID != use.Target.NamespaceUID || a.WorkloadUID != use.Target.WorkloadUID {
		return deny()
	}
	p, err := e.Current.PolicyAutomationAuthority(ctx, a, use.Target)
	now := e.Now()
	if err != nil || ctx.Err() != nil || now.Before(started) || !now.Before(started.Add(5*time.Second)) || !identity.Fresh(accepted.ObservedAt, accepted.FreshUntil, now, 5*time.Second) {
		return deny()
	}
	result := value.EvaluatePolicy(a, p, use, now)
	if result.Eligible {
		result.ValidUntil = identity.Earlier(result.ValidUntil, accepted.FreshUntil)
	}
	return result
}
