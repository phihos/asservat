package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// PolicyGrantPlanReader resolves the currently accepted exact team scope. It is
// server-owned; public callers submit a policy UID, never authority or a scope.
type PolicyGrantPlanReader interface {
	PolicyGrantPlan(context.Context, string) (PolicyGrantPlan, error)
}

type PolicyGrantPlan struct {
	Authority    value.AcceptedPolicyAuthority
	RecipeDigest artifact.Digest
	Scope        []byte
	Review       GrantReview
	DataClass    string
	Reasons      []value.SensitiveReason
	FreshUntil   time.Time
}

type AcceptedPolicyApprovalSettings struct {
	Values                 value.PolicyApprovalSettings
	Revision               identity.Revision
	ObservedAt, FreshUntil time.Time
}

type PolicyApprovalSettingsReader interface {
	PolicyApprovalSettings(context.Context) (AcceptedPolicyApprovalSettings, error)
}

// PolicyGrantRequestLookup identifies the existing immutable request journal,
// independently from current defaults or a newly interpreted collection plan.
type PolicyGrantRequestLookup struct {
	Requester                 identity.Principal
	PolicyUID, IdempotencyKey string
	InputDigest               artifact.Digest
}
type PolicyGrantRequestReader interface {
	LookupPolicyGrantRequest(context.Context, PolicyGrantRequestLookup) (value.Grant, bool, error)
}

// PolicyGrantRequestDigest binds caller choices (including zero = use defaults)
// and full authenticated actor/client. It excludes refreshed settings/proofs.
func PolicyGrantRequestDigest(actor identity.Principal, in PolicyGrantRequestInput) artifact.Digest {
	b, _ := json.Marshal(struct {
		Format      string
		Actor       identity.Principal
		PolicyUID   string
		Lifetime    time.Duration
		Limits      value.AutomationLimits
		Observation *value.ObservationLimits
	}{"policy-grant-request/v1", actor, in.PolicyUID, in.Lifetime, in.Limits, in.Observation})
	return sha256.Sum256(b)
}

// PolicyGrantRequestInput selects finite budgets inside the currently accepted
// authority. The requester is resolved from the live authenticated request.
type PolicyGrantRequestInput struct {
	PolicyUID, IdempotencyKey string
	Lifetime                  time.Duration
	Limits                    value.AutomationLimits
	Observation               *value.ObservationLimits
}

func (s GrantService) workload(ctx context.Context, i identity.Identity, t value.WorkloadTarget, op value.Operation) (value.Result, error) {
	if s.WorkloadPermissions == nil {
		return value.Result{}, ErrGrantUnavailable
	}
	p, err := s.WorkloadPermissions.WorkloadPermissions(ctx, t)
	if err != nil {
		return value.Result{}, ErrGrantUnavailable
	}
	return value.WorkloadScopeEligibility(i, p, op, t, s.Now()), nil
}

// grantEligibility dispatches on the stored scope kind, preserving strict
// concrete-Pod checks for ad hoc grants and avoiding dummy Pod identifiers.
func (s GrantService) grantEligibility(ctx context.Context, i identity.Identity, g value.Grant, op value.Operation) (value.Result, error) {
	if g.Kind == value.GrantPolicy {
		if g.Policy == nil {
			return value.Result{}, value.ErrGrantInvalid
		}
		return s.workload(ctx, i, g.Policy.Workload(), op)
	}
	return s.collector(ctx, i, g.Target, op)
}

func (s GrantService) policySettings(ctx context.Context) (AcceptedPolicyApprovalSettings, error) {
	if s.ApprovalSettings == nil {
		return AcceptedPolicyApprovalSettings{}, ErrGrantUnavailable
	}
	p, err := s.ApprovalSettings.PolicyApprovalSettings(ctx)
	if err != nil || !p.Values.Valid() || !p.Revision.Valid() || !identity.Fresh(p.ObservedAt, p.FreshUntil, s.Now(), 30*time.Second) {
		return AcceptedPolicyApprovalSettings{}, ErrGrantUnavailable
	}
	return p, nil
}

// RequestPolicy opens one independent review, without coupling future execution
// to the human/service requester's credentials or personal result access.
func (s GrantService) RequestPolicy(ctx context.Context, current identities.CurrentIdentity, in PolicyGrantRequestInput) (value.Grant, bool, error) {
	var zero value.Grant
	if ctx == nil || ctx.Err() != nil || !s.ready() || s.PolicyRequests == nil || current == nil {
		return zero, false, ErrGrantUnavailable
	}
	if !identity.Text(in.PolicyUID, 64) || !identity.Text(in.IdempotencyKey, 128) {
		return zero, false, value.ErrGrantInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) || !slices.Contains(i.Scopes, "evidence:capture") {
		return zero, false, identity.ErrDenied
	}
	if _, _, policyExecutor := value.PolicyExecutor(i.Principal); policyExecutor {
		return zero, false, identity.ErrDenied
	}
	if in.Observation != nil {
		o := *in.Observation
		in.Observation = &o
	}
	inputDigest := PolicyGrantRequestDigest(i.Principal, in)
	previous, found, err := s.PolicyRequests.LookupPolicyGrantRequest(ctx, PolicyGrantRequestLookup{Requester: i.Principal, PolicyUID: in.PolicyUID, IdempotencyKey: in.IdempotencyKey, InputDigest: inputDigest})
	if err != nil {
		return zero, false, err
	}
	if found {
		return s.policyRequestReplay(ctx, current, i, in.PolicyUID, previous)
	}
	if s.PolicyPlans == nil {
		return zero, false, ErrGrantUnavailable
	}
	plan, err := s.PolicyPlans.PolicyGrantPlan(ctx, in.PolicyUID)
	if err != nil || plan.RecipeDigest == (artifact.Digest{}) || plan.Authority.PolicyUID != in.PolicyUID || plan.Authority.InstallationID != s.InstallationID || !plan.Authority.Valid(s.Now()) || !s.Now().Before(plan.FreshUntil) || sha256.Sum256(plan.Scope) != plan.Authority.ScopeDigest {
		return zero, false, ErrGrantUnavailable
	}
	settings, err := s.policySettings(ctx)
	if err != nil {
		return zero, false, err
	}
	lifetime := in.Lifetime
	if lifetime == 0 {
		lifetime = settings.Values.DefaultAge
	}
	if lifetime < time.Second || lifetime > settings.Values.MaxAge || lifetime%time.Second != 0 {
		return zero, false, value.ErrGrantInvalid
	}
	scopeValue := (value.PolicyGrantScope{Authority: plan.Authority, RecipeDigest: plan.RecipeDigest, Limits: in.Limits, ApprovalPolicyRef: settings.Revision, ApprovalMaxAge: settings.Values.MaxAge, Observation: in.Observation}).Clone()
	scope := &scopeValue
	eligible, err := s.workload(ctx, i, scope.Workload(), value.CollectContext)
	if err != nil {
		return zero, false, err
	}
	if !eligible.Eligible {
		return zero, false, identity.ErrDenied
	}
	if ceiling := plan.Review.ObservationLimits; ceiling != nil {
		if in.Observation == nil || !in.Observation.Within(*ceiling) {
			return zero, false, value.ErrGrantScope
		}
	} else if in.Observation != nil {
		return zero, false, value.ErrGrantScope
	}
	plan.Review.ObservationLimits = in.Observation
	review, err := json.Marshal(plan.Review)
	if err != nil {
		return zero, false, value.ErrGrantInvalid
	}
	g := value.Grant{ID: s.NewID(), RootID: s.RootID, Kind: value.GrantPolicy, ExecutionDigest: plan.Authority.ScopeDigest, DataClass: plan.DataClass, Reasons: slices.Clone(plan.Reasons), Scope: slices.Clone(plan.Scope), Review: review, Requester: i.Principal, Lifetime: lifetime, Policy: scope, Revision: 1}
	g.ReviewDigest = ReviewDigest(g, review)
	probe := g
	probe.RequestedAt = s.Now()
	probe.ReviewUntil = probe.RequestedAt.Add(value.GrantReviewWindow)
	probe.PolicyNotAfter = identity.Earlier(probe.RequestedAt.Add(lifetime), plan.Authority.NotAfter)
	if !probe.Valid() {
		return zero, false, value.ErrGrantInvalid
	}
	recovery, err := s.recovery(ctx)
	if err != nil {
		return zero, false, err
	}
	out, replay, err := s.Store.RequestGrant(ctx, StoredGrantRequest{Grant: g, IdempotencyKey: in.IdempotencyKey, RequestDigest: inputDigest}, recovery)
	if err != nil {
		return zero, false, err
	}
	if replay {
		return s.policyRequestReplay(ctx, current, i, in.PolicyUID, out)
	}
	if out.Kind != value.GrantPolicy || out.Policy == nil || out.Policy.Authority.PolicyUID != in.PolicyUID || out.Requester != i.Principal || out.ReviewDigest != g.ReviewDigest {
		return zero, false, ErrGrantConflict
	}
	if !s.Now().Before(plan.FreshUntil) || !s.Now().Before(settings.FreshUntil) || !s.Now().Before(eligible.ValidUntil) {
		return zero, false, ErrGrantUnavailable
	}
	if err = s.final(ctx, current, i); err != nil {
		return zero, false, err
	}
	if !s.Now().Before(i.ValidUntil) || !s.Now().Before(plan.FreshUntil) || !s.Now().Before(settings.FreshUntil) || !s.Now().Before(eligible.ValidUntil) {
		return zero, false, ErrGrantUnavailable
	}
	return out, replay, nil
}

func (s GrantService) policyRequestReplay(ctx context.Context, current identities.CurrentIdentity, i identity.Identity, policy string, g value.Grant) (value.Grant, bool, error) {
	var zero value.Grant
	if !g.Valid() || g.RootID != s.RootID || g.Kind != value.GrantPolicy || g.Policy == nil || g.Policy.Authority.InstallationID != s.InstallationID || g.Policy.Authority.PolicyUID != policy || g.Requester != i.Principal || ReviewDigest(g, g.Review) != g.ReviewDigest {
		return zero, false, ErrGrantConflict
	}
	eligible, err := s.workload(ctx, i, g.Policy.Workload(), value.CollectContext)
	if err != nil {
		return zero, false, err
	}
	if !eligible.Eligible {
		return zero, false, identity.ErrDenied
	}
	if err = s.final(ctx, current, i); err != nil {
		return zero, false, err
	}
	now := s.Now()
	if ctx.Err() != nil || !now.Before(i.ValidUntil) || !now.Before(eligible.ValidUntil) {
		return zero, false, ErrGrantUnavailable
	}
	return g, true, nil // original result only; never authority or a new issuance
}

// revocationEligibility permits a current team manager or independent current
// approver for policy grants, using one cached workload projection read.
func (s GrantService) revocationEligibility(ctx context.Context, i identity.Identity, g value.Grant) (value.Result, error) {
	if g.Kind != value.GrantPolicy {
		return s.grantEligibility(ctx, i, g, value.ApproveAction)
	}
	if g.Policy == nil || s.WorkloadPermissions == nil {
		return value.Result{}, ErrGrantUnavailable
	}
	p, err := s.WorkloadPermissions.WorkloadPermissions(ctx, g.Policy.Workload())
	if err != nil {
		return value.Result{}, ErrGrantUnavailable
	}
	r := value.WorkloadScopeEligibility(i, p, value.ApproveAction, g.Policy.Workload(), s.Now())
	if r.Eligible {
		return r, nil
	}
	return value.PolicyGrantManagementEligibility(i, p, g.Policy.Authority, s.Now()), nil
}

// A service principal has no cross-client same-human identity. Its original
// actor/client must match exactly before requester metadata paths apply.
func grantRequesterMatches(g value.Grant, p identity.Principal) bool {
	if g.Kind == value.GrantPolicy && (g.Requester.Kind != identity.Human || p.Kind != identity.Human) {
		return g.Requester == p
	}
	return sameHuman(g.Requester, p)
}

// finalGrantMetadata reuses C03's existing current-identity comparison after
// blocking metadata reads. It performs the same final identity read as before;
// no second workload read or historical requester authority is introduced.
func (s GrantService) finalGrantMetadata(ctx context.Context, current identities.CurrentIdentity, i identity.Identity, policy bool) error {
	if !policy {
		return s.final(ctx, current, i)
	}
	last, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !sameProjectionIdentity(cloneProjectionIdentity(i), last, s.Now()) {
		return identity.ErrDenied
	}
	return nil
}
