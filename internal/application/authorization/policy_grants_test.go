package authorization

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type policyPlanFunc func(context.Context, string) (PolicyGrantPlan, error)

func (f policyPlanFunc) PolicyGrantPlan(c context.Context, id string) (PolicyGrantPlan, error) {
	return f(c, id)
}

type approvalSettingsFunc func(context.Context) (AcceptedPolicyApprovalSettings, error)

func (f approvalSettingsFunc) PolicyApprovalSettings(c context.Context) (AcceptedPolicyApprovalSettings, error) {
	return f(c)
}

type workloadProjectionFunc func(context.Context, value.WorkloadTarget) (value.WorkloadProjection, error)

func (f workloadProjectionFunc) WorkloadPermissions(c context.Context, t value.WorkloadTarget) (value.WorkloadProjection, error) {
	return f(c, t)
}

func newPolicyGrantFixture(t *testing.T) (*grantFixture, PolicyGrantRequestInput) {
	t.Helper()
	f := newGrantFixture(t)
	f.svc.PolicyRequests = f.store
	// This is test-only accepted authority; product composition must resolve the
	// current audited policy and original execution scope through PolicyPlans.
	scope := []byte(`{"schemaVersion":"policy-test/v1"}`)
	rev := identity.Revision{UID: "binding", Generation: 1, Digest: [32]byte{1}}
	p := f.projection(f.target)
	owner := p.Allows[0].Audience
	owner.Kind = "Group"
	owner.SubjectID = f.requester.Groups[0]
	authority := value.AcceptedPolicyAuthority{InstallationID: grantRoot, PolicyUID: "policy-uid", Creator: f.outside.Principal, Executor: value.PolicyPrincipal(grantRoot, "policy-uid"), ScopeDigest: sha256.Sum256(scope), ClusterID: f.target.ClusterID, NamespaceUID: f.target.NamespaceUID, WorkloadUID: f.target.WorkloadUID, Delegation: rev, Owners: []artifact.AudienceAssignment{owner}, Actions: []string{"packetCapture"}, Limits: value.AutomationLimits{MaxExecutions: 10, MaxBytes: 1 << 20, MaxObservedBytes: 1 << 20}, IssuedAt: f.now.Add(-time.Hour), NotAfter: f.now.Add(30 * 24 * time.Hour)}
	f.svc.PolicyPlans = policyPlanFunc(func(_ context.Context, id string) (PolicyGrantPlan, error) {
		return PolicyGrantPlan{Authority: authority, RecipeDigest: artifact.Digest{5}, Scope: scope, DataClass: "extract", Reasons: []value.SensitiveReason{{ActionID: "packets", Code: "rawBytePredicate"}}, Review: GrantReview{ObservationLimits: &GrantObservationLimits{MaxSessionSeconds: 10, MaxObservedBytes: 1 << 20, MaxBytesPerSecond: 16 << 20, MaxConcurrentSessions: 1}, Namespace: "payments", WorkloadKind: "Deployment", WorkloadName: "api", Actions: []GrantReviewAction{{ActionID: "packets", Kind: "packetCapture", Filter: "tcp[13] & 2 != 0"}}, Deadline: authority.NotAfter}, FreshUntil: f.now.Add(30 * time.Second)}, nil
	})
	f.svc.ApprovalSettings = approvalSettingsFunc(func(context.Context) (AcceptedPolicyApprovalSettings, error) {
		return AcceptedPolicyApprovalSettings{Values: value.PolicyApprovalSettings{DefaultAge: 7 * 24 * time.Hour, MaxAge: 30 * 24 * time.Hour, RenewalNotice: 24 * time.Hour}, Revision: rev, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second)}, nil
	})
	f.svc.WorkloadPermissions = workloadProjectionFunc(func(_ context.Context, target value.WorkloadTarget) (value.WorkloadProjection, error) {
		p := f.projection(f.target)
		p.Allows[0].Audience = owner
		return value.WorkloadProjection{Target: target, Revision: p.Revision, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil, DeniesComplete: p.DeniesComplete, DeniesObservedAt: p.DeniesObservedAt, DeniesFreshUntil: p.DeniesFreshUntil, Allows: p.Allows, Denies: p.Denies}, nil
	})
	return f, PolicyGrantRequestInput{PolicyUID: authority.PolicyUID, IdempotencyKey: "policy-first-review", Limits: value.AutomationLimits{MaxExecutions: 2, MaxBytes: 65536, MaxObservedBytes: 1000}, Observation: &value.ObservationLimits{MaxSessionSeconds: 10, MaxObservedBytes: 1000, MaxBytesPerSecond: 10000, MaxConcurrentSessions: 1}}

}

func TestPolicyGrantRequestReviewAndCurrentTeamControl(t *testing.T) {
	ctx := context.Background()
	f, in := newPolicyGrantFixture(t)
	current := grantIdentity{f.requester, &f.now}
	g, replay, err := f.svc.RequestPolicy(ctx, current, in)
	if err != nil || replay {
		t.Fatal(g, replay, err)
	}
	if !g.Valid() || g.Kind != value.GrantPolicy || g.Policy.Authority.Executor == g.Requester || g.Policy.Authority.Creator == g.Requester || g.CaptureID != "" || g.PreviewID != "" || g.Target != (value.Target{}) || g.ResultAccess != nil {
		t.Fatal("actor/authority scopes conflated", g)
	}
	again, replay, err := f.svc.RequestPolicy(ctx, current, in)
	if err != nil || !replay || again.ID != g.ID {
		t.Fatal("lost request reply", again, replay, err)
	}
	// A policy's empty personal capture fields do not impose a global uniqueness
	// constraint: a new reviewed renewal has its own immutable grant identity.
	in.IdempotencyKey = "policy-renewal"
	renewed, _, err := f.svc.RequestPolicy(ctx, current, in)
	if err != nil || renewed.ID == g.ID {
		t.Fatal("explicit new review unavailable", err)
	}
	self := f.requester
	self.Principal.ClientID = "another-original-client"
	if _, _, err = f.svc.Decide(ctx, grantIdentity{self, &f.now}, g.ID, true, "self", "self-key"); !errors.Is(err, value.ErrSelfApproval) {
		t.Fatal("cross-client self-review", err)
	}
	f.now = f.now.Add(5 * time.Second)
	approved, _, err := f.svc.Decide(ctx, grantIdentity{f.approver, &f.now}, g.ID, true, "bounded policy", "independent-review")
	if err != nil || !approved.ExpiresAt.Equal(g.RequestedAt.Add(7*24*time.Hour)) {
		t.Fatal("approval renewed from decision", approved.ExpiresAt, err)
	}
	if _, _, err = f.svc.Revoke(ctx, current, g.ID, approved.Revision, "manager-revoke"); err != nil {
		t.Fatal("current sponsoring team manager cannot revoke", err)
	}
}

func TestPolicyGrantRefusesDepartedRequesterControlAndStaleScope(t *testing.T) {
	ctx := context.Background()
	f, in := newPolicyGrantFixture(t)
	g, _, err := f.svc.RequestPolicy(ctx, grantIdentity{f.requester, &f.now}, in)
	if err != nil {
		t.Fatal(err)
	}
	departed := f.requester
	departed.Groups = nil
	if _, _, err = f.svc.Revoke(ctx, grantIdentity{departed, &f.now}, g.ID, g.Revision, "departed"); !errors.Is(err, value.ErrNotApprover) {
		t.Fatal("requester provenance became perpetual control", err)
	}
	old := f.svc.PolicyPlans
	f.svc.PolicyPlans = policyPlanFunc(func(c context.Context, id string) (PolicyGrantPlan, error) {
		p, e := old.PolicyGrantPlan(c, id)
		p.FreshUntil = f.now
		return p, e
	})
	in.IdempotencyKey = "stale-source"
	if _, _, err = f.svc.RequestPolicy(ctx, grantIdentity{f.requester, &f.now}, in); !errors.Is(err, ErrGrantUnavailable) {
		t.Fatal("stale policy accepted", err)
	}
}

func TestPolicyGrantReviewDigestBindsBudgetsAuthorityAndApprovalSettings(t *testing.T) {
	f, in := newPolicyGrantFixture(t)
	g, _, err := f.svc.RequestPolicy(context.Background(), grantIdentity{f.requester, &f.now}, in)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*value.PolicyGrantScope){
		"bytes":                     func(p *value.PolicyGrantScope) { p.Limits.MaxBytes-- },
		"observed":                  func(p *value.PolicyGrantScope) { o := *p.Observation; o.MaxObservedBytes--; p.Observation = &o },
		"executor":                  func(p *value.PolicyGrantScope) { p.Authority.Executor.Subject = "other" },
		"original authority":        func(p *value.PolicyGrantScope) { p.Authority.IssuedAt = p.Authority.IssuedAt.Add(time.Second) },
		"recipe":                    func(p *value.PolicyGrantScope) { p.RecipeDigest[0]++ },
		"original approval maximum": func(p *value.PolicyGrantScope) { p.ApprovalMaxAge -= time.Second },
		"settings":                  func(p *value.PolicyGrantScope) { p.ApprovalPolicyRef.Generation++ },
	} {
		t.Run(name, func(t *testing.T) {
			x := g
			p := *g.Policy
			x.Policy = &p
			mutate(&p)
			if ReviewDigest(x, x.Review) == g.ReviewDigest {
				t.Fatal("unreviewed scope change")
			}
		})
	}
}

func TestPolicyGrantCannotInflateResolvedObservationLimits(t *testing.T) {
	for name, change := range map[string]func(*value.ObservationLimits){"session": func(o *value.ObservationLimits) { o.MaxSessionSeconds = 11 }, "rate": func(o *value.ObservationLimits) { o.MaxBytesPerSecond = 32 << 20 }, "concurrent replicas": func(o *value.ObservationLimits) { o.MaxConcurrentSessions = 2 }, "events not implemented": func(o *value.ObservationLimits) { o.MaxObservedEvents = 1 }} {
		t.Run(name, func(t *testing.T) {
			f, in := newPolicyGrantFixture(t)
			change(in.Observation)
			if _, _, err := f.svc.RequestPolicy(context.Background(), grantIdentity{f.requester, &f.now}, in); !errors.Is(err, value.ErrGrantScope) {
				t.Fatal("unreviewed observation capability granted", err)
			}
		})
	}
}

// A receipt belongs to one caller-authored intent, including the choice to use
// installation defaults. New protected observations do not rewrite that intent.
func TestPolicyGrantLostRequestReplySurvivesDefaultAndSourceChanges(t *testing.T) {
	for _, change := range []string{"default-age", "benign-settings-revision", "unavailable-current-plan", "missing-current-plan"} {
		t.Run(change, func(t *testing.T) {
			f, in := newPolicyGrantFixture(t)
			current := grantIdentity{f.requester, &f.now}
			first, _, err := f.svc.RequestPolicy(context.Background(), current, in)
			if err != nil {
				t.Fatal(err)
			}
			settings := f.svc.ApprovalSettings
			switch change {
			case "default-age", "benign-settings-revision":
				f.svc.ApprovalSettings = approvalSettingsFunc(func(ctx context.Context) (AcceptedPolicyApprovalSettings, error) {
					s, e := settings.PolicyApprovalSettings(ctx)
					s.Revision.Generation++
					s.Revision.Digest[0]++
					if change == "default-age" {
						s.Values.DefaultAge = 24 * time.Hour
					}
					return s, e
				})
			case "missing-current-plan":
				f.svc.PolicyPlans = nil
			case "unavailable-current-plan":
				f.svc.PolicyPlans = policyPlanFunc(func(context.Context, string) (PolicyGrantPlan, error) { return PolicyGrantPlan{}, ErrGrantUnavailable })
			}
			again, replay, err := f.svc.RequestPolicy(context.Background(), current, in)
			if err != nil || !replay || again.ID != first.ID || again.Lifetime != first.Lifetime || again.PolicyNotAfter != first.PolicyNotAfter || again.ReviewDigest != first.ReviewDigest || again.Policy.ApprovalMaxAge != first.Policy.ApprovalMaxAge {
				t.Fatal("lost reply replaced or stranded original request", again.ID, replay, err)
			}
		})
	}
}

func policyRequestTestKey(actor identity.Principal, key string) string {
	return actor.Issuer + "\n" + actor.Subject + "\n" + actor.ClientID + "\n" + string(actor.Kind) + "\n" + key
}
func (m *memoryGrants) LookupPolicyGrantRequest(_ context.Context, q PolicyGrantRequestLookup) (value.Grant, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := "policy:" + policyRequestTestKey(q.Requester, q.IdempotencyKey)
	id, ok := m.keys[key]
	if !ok {
		return value.Grant{}, false, nil
	}
	if m.policyInputs[key] != q.InputDigest {
		return value.Grant{}, false, ErrGrantConflict
	}
	g := m.rows[id]
	if g.Kind != value.GrantPolicy || g.Policy == nil || g.Policy.Authority.PolicyUID != q.PolicyUID || g.Requester != q.Requester {
		return value.Grant{}, false, ErrGrantConflict
	}
	return g, true, nil
}

func TestPolicyGrantRequestReplayRejectsChangedInputAndNeverTransfersCaller(t *testing.T) {
	for _, change := range []string{"policy", "budget", "observation", "default-choice"} {
		t.Run(change, func(t *testing.T) {
			f, in := newPolicyGrantFixture(t)
			current := grantIdentity{f.requester, &f.now}
			first, _, err := f.svc.RequestPolicy(context.Background(), current, in)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "policy":
				in.PolicyUID = "other-policy"
			case "budget":
				in.Limits.MaxBytes++
			case "observation":
				o := *in.Observation
				o.MaxBytesPerSecond++
				in.Observation = &o
			case "default-choice":
				in.Lifetime = first.Lifetime
			}
			if _, _, err = f.svc.RequestPolicy(context.Background(), current, in); !errors.Is(err, ErrGrantConflict) || f.ids != 1 {
				t.Fatal("changed intent reused key or created grant", change, err, f.ids)
			}
		})
	}
	f, in := newPolicyGrantFixture(t)
	first, _, err := f.svc.RequestPolicy(context.Background(), grantIdentity{f.requester, &f.now}, in)
	if err != nil {
		t.Fatal(err)
	}
	other := f.requester
	other.Principal.ClientID = "another-managed-client"
	g, replay, err := f.svc.RequestPolicy(context.Background(), grantIdentity{other, &f.now}, in)
	if err != nil || replay || g.ID == first.ID || g.Requester != other.Principal {
		t.Fatal("client inherited original receipt", g.ID, replay, err)
	}
}

type policyReplayIdentityFunc func(context.Context) (identity.Identity, error)

func (f policyReplayIdentityFunc) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	return f(ctx)
}

func TestPolicyGrantRequestReplayKeepsCurrentRightsAndAcceptedLowerDeadline(t *testing.T) {
	for _, change := range []string{"departed", "final-identity-delay", "lower-then-raise"} {
		t.Run(change, func(t *testing.T) {
			f, in := newPolicyGrantFixture(t)
			first, _, err := f.svc.RequestPolicy(context.Background(), grantIdentity{f.requester, &f.now}, in)
			if err != nil {
				t.Fatal(err)
			}
			current := policyReplayIdentityFunc(func(context.Context) (identity.Identity, error) {
				return (grantIdentity{f.requester, &f.now}).ResolveIdentity(context.Background())
			})
			switch change {
			case "departed":
				f.requester.Groups = nil
			case "final-identity-delay":
				calls := 0
				current = policyReplayIdentityFunc(func(ctx context.Context) (identity.Identity, error) {
					calls++
					if calls == 2 {
						f.now = f.now.Add(31 * time.Second)
					}
					return (grantIdentity{f.requester, &f.now}).ResolveIdentity(ctx)
				})
			case "lower-then-raise":
				// Model the planned SQL projection's accepted monotonic overlay. This
				// unit test does not qualify SQL clamping; it tests receipt recovery.
				row := f.store.rows[first.ID]
				row.PolicyNotAfter = row.RequestedAt.Add(time.Second)
				f.store.rows[first.ID] = row
				f.now = f.now.Add(2 * time.Second)
				f.svc.PolicyPlans = policyPlanFunc(func(context.Context, string) (PolicyGrantPlan, error) { return PolicyGrantPlan{}, ErrGrantUnavailable })
			}
			g, replay, err := f.svc.RequestPolicy(context.Background(), current, in)
			if change == "lower-then-raise" {
				if err != nil || !replay || g.ID != first.ID || !g.PolicyNotAfter.Equal(first.RequestedAt.Add(time.Second)) || g.Phase(f.now) != value.GrantExpired {
					t.Fatal("request replay revived accepted lower deadline", g.ID, replay, err)
				}
			} else if err == nil || g.ID != "" {
				t.Fatal("replay disclosed after rights/original identity expiry", change, err)
			}
			if f.ids != 1 {
				t.Fatal("replay created a new request", f.ids)
			}
		})
	}
}
