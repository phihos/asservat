package capture

import (
	"context"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// recordingSaveIdentity is request-owned hub composition, never a public token
// or wire identity. Policy execution remains attached to the original caller.
type recordingSaveIdentity struct {
	policy    policyIdentity
	initiator identities.CurrentIdentity
	original  identity.Identity
	until     time.Time
}

func (s recordingSaveIdentity) InitiatingIdentity(ctx context.Context) (identity.Identity, error) {
	i, err := s.initiator.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.policy.now()) || i.Principal != s.original.Principal || i.Policy != s.original.Policy || !slices.Contains(i.Scopes, "evidence:capture") {
		return identity.Identity{}, value.ErrDenied
	}
	i.ValidUntil = identity.Earlier(i.ValidUntil, identity.Earlier(s.original.ValidUntil, s.until))
	if !i.Valid(s.policy.now()) {
		return identity.Identity{}, value.ErrDenied
	}
	return i, nil
}
func (s recordingSaveIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	i, err := s.InitiatingIdentity(ctx)
	if err != nil {
		return identity.Identity{}, err
	}
	p, err := s.policy.ResolveIdentity(ctx)
	if err != nil {
		return identity.Identity{}, err
	}
	p.ValidUntil = identity.Earlier(p.ValidUntil, i.ValidUntil)
	if !p.Valid(s.policy.now()) {
		return identity.Identity{}, value.ErrDenied
	}
	return p, nil
}

func (s ContextInvestigation) manualSaveRequest(ctx context.Context, current identities.CurrentIdentity, p value.ContextPreview) (identities.CurrentIdentity, *value.RecordingSaveAdmission, error) {
	saved := p.Intent.Snapshot
	if saved == nil || saved.TriggerKind != "recordingSave" {
		return current, nil, nil
	}
	if s.RecordingPolicies == nil || s.PolicyAccepted == nil {
		return nil, nil, value.ErrUnavailable
	}
	scope, err := compiler.ReadContextScopeIdentity(p.CanonicalScope, p.ScopeDigest)
	if err != nil || scope.Requester == nil || *scope.Requester != p.Actor || scope.Actor != p.Executor() || scope.Target != (authorization.Target{ClusterID: p.Target.ClusterID, NamespaceUID: p.Target.Namespace.UID, WorkloadUID: p.Target.Workload.UID, PodUID: p.Target.PodUID}) {
		return nil, nil, value.ErrDenied
	}
	policy, err := s.RecordingPolicies.RecordingPolicy(ctx, saved.PolicyName, saved.PolicyUID)
	if err != nil {
		return nil, nil, err
	}
	if !policy.Policy.RecordingSaves || policy.Accepted.Authority.ScopeDigest != saved.ExecutionDigest || policy.Accepted.Authority.Executor != p.Executor() {
		return nil, nil, value.ErrDenied
	}
	initiator := s.Eligibility.ContextEligibilityCurrent(ctx, current, scope.Target)
	if !initiator.Eligible || initiator.Principal != p.Actor || !initiator.VerifiedIdentity.Valid(s.Now()) {
		return nil, nil, value.ErrDenied
	}
	until := identity.Earlier(initiator.ValidUntil, identity.Earlier(initiator.VerifiedIdentity.ValidUntil, policy.Accepted.SourceUntil))
	combined := recordingSaveIdentity{policy: newPolicyIdentity(ctx, s.PolicyAccepted, policy.Accepted.Authority, until, s.Now), initiator: current, original: initiator.VerifiedIdentity, until: until}
	return combined, &value.RecordingSaveAdmission{Policy: policy.Policy, Authority: policy.Accepted.Authority, Initiator: initiator}, nil
}

func manualSaveProcessingBound(authority time.Time, lineage *value.HistoryLineage) time.Time {
	if lineage != nil {
		return identity.Earlier(authority, lineage.ExpiresAt)
	}
	return authority
}
