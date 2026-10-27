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

func TestPolicyGrantRevocationRejectsWrongWorkloadProjection(t *testing.T) {
	f, in := newPolicyGrantFixture(t)
	g, _, err := f.svc.RequestPolicy(t.Context(), grantIdentity{f.requester, &f.now}, in)
	if err != nil {
		t.Fatal(err)
	}
	original := f.svc.WorkloadPermissions
	f.svc.WorkloadPermissions = workloadProjectionFunc(func(ctx context.Context, target value.WorkloadTarget) (value.WorkloadProjection, error) {
		p, e := original.WorkloadPermissions(ctx, target)
		p.Target.WorkloadUID = "unrelated-workload"
		return p, e
	})
	if _, _, err = f.svc.Revoke(t.Context(), grantIdentity{f.approver, &f.now}, g.ID, g.Revision, "wrong-workload"); !errors.Is(err, value.ErrNotApprover) {
		t.Fatal("unrelated projection revoked grant", err)
	}
	if !f.store.rows[g.ID].RevokedAt.IsZero() || f.store.rows[g.ID].Revision != g.Revision {
		t.Fatal("refused revocation changed grant")
	}
}

func TestPolicyGrantRequesterMetadataRequiresCurrentWorkloadRights(t *testing.T) {
	f, in := newPolicyGrantFixture(t)
	current := grantIdentity{f.requester, &f.now}
	g, _, err := f.svc.RequestPolicy(t.Context(), current, in)
	if err != nil {
		t.Fatal(err)
	}
	if view, _, err := f.svc.Get(t.Context(), current, g.ID); err != nil || view.Grant.ID != g.ID {
		t.Fatal("current requester cannot inspect", err)
	}
	if rows, _, err := f.svc.List(t.Context(), current, "requested", 10); err != nil || len(rows) != 1 {
		t.Fatal("current requests missing", rows, err)
	}
	f.requester.Groups = nil
	current = grantIdentity{f.requester, &f.now}
	if view, _, err := f.svc.Get(t.Context(), current, g.ID); !errors.Is(err, ErrGrantNotFound) || view.Grant.ID != "" {
		t.Fatal("departed requester read frozen team metadata", view.Grant.ID, err)
	}
	if rows, _, err := f.svc.List(t.Context(), current, "requested", 10); err != nil || len(rows) != 0 {
		t.Fatal("departed requester listed team metadata", len(rows), err)
	}
}

func TestPolicyGrantMetadataRechecksIdentityAndOriginalRightsDeadline(t *testing.T) {
	for _, view := range []string{"get", "requested"} {
		for _, change := range []string{"groups-withdrawn", "projection-expired"} {
			t.Run(view+"/"+change, func(t *testing.T) {
				f, in := newPolicyGrantFixture(t)
				g, _, err := f.svc.RequestPolicy(t.Context(), grantIdentity{f.requester, &f.now}, in)
				if err != nil {
					t.Fatal(err)
				}
				original := f.svc.WorkloadPermissions
				f.svc.WorkloadPermissions = workloadProjectionFunc(func(ctx context.Context, target value.WorkloadTarget) (value.WorkloadProjection, error) {
					p, e := original.WorkloadPermissions(ctx, target)
					p.FreshUntil = f.now.Add(time.Second)
					return p, e
				})
				calls := 0
				current := policyReplayIdentityFunc(func(ctx context.Context) (identity.Identity, error) {
					calls++
					i, e := (grantIdentity{f.requester, &f.now}).ResolveIdentity(ctx)
					if calls > 1 {
						if change == "groups-withdrawn" {
							i.Groups = nil
						} else {
							f.now = f.now.Add(2 * time.Second)
							i, e = (grantIdentity{f.requester, &f.now}).ResolveIdentity(ctx)
						}
					}
					return i, e
				})
				if view == "get" {
					v, _, e := f.svc.Get(t.Context(), current, g.ID)
					if e == nil || v.Grant.ID != "" {
						t.Fatal("metadata disclosed after blocking identity/rights check", v.Grant.ID, e)
					}
				} else {
					rows, _, e := f.svc.List(t.Context(), current, "requested", 10)
					if e == nil || len(rows) != 0 {
						t.Fatal("list disclosed after blocking identity/rights check", len(rows), e)
					}
				}
			})
		}
	}
}

func TestPolicyGrantServiceRequesterMetadataDoesNotTransferClient(t *testing.T) {
	f, in := newPolicyGrantFixture(t)
	f.requester.Principal.Kind = identity.Workload
	f.requester.Principal.Subject = "service-requester"
	f.requester.Principal.ClientID = "service-a"
	original := grantIdentity{f.requester, &f.now}
	a, _, err := f.svc.RequestPolicy(t.Context(), original, in)
	if err != nil {
		t.Fatal(err)
	}
	caller := f.requester
	caller.Principal.ClientID = "service-b"
	other := grantIdentity{caller, &f.now}
	if v, _, e := f.svc.Get(t.Context(), other, a.ID); !errors.Is(e, ErrGrantNotFound) || v.Grant.ID != "" {
		t.Fatal("other service client inherited metadata", v.Grant.ID, e)
	}
	if rows, _, e := f.svc.List(t.Context(), other, "requested", 10); e != nil || len(rows) != 0 {
		t.Fatal("other service client inherited request", len(rows), e)
	}
	b, replay, err := f.svc.RequestPolicy(t.Context(), other, in)
	if err != nil || replay || b.ID == a.ID {
		t.Fatal("other client reused original journal", b.ID, replay, err)
	}
	for _, tc := range []struct {
		source grantIdentity
		id     string
	}{{original, a.ID}, {other, b.ID}} {
		if rows, _, e := f.svc.List(t.Context(), tc.source, "requested", 10); e != nil || len(rows) != 1 || rows[0].Grant.ID != tc.id {
			t.Fatal("full service actor/client filter lost", rows, e)
		}
	}
}
func TestPolicyGrantRequesterListReadsEachWorkloadOnce(t *testing.T) {
	f, in := newPolicyGrantFixture(t)
	current := grantIdentity{f.requester, &f.now}
	if _, _, e := f.svc.RequestPolicy(t.Context(), current, in); e != nil {
		t.Fatal(e)
	}
	in.IdempotencyKey = "next-review"
	if _, _, e := f.svc.RequestPolicy(t.Context(), current, in); e != nil {
		t.Fatal(e)
	}
	original := f.svc.WorkloadPermissions
	reads := 0
	f.svc.WorkloadPermissions = workloadProjectionFunc(func(ctx context.Context, target value.WorkloadTarget) (value.WorkloadProjection, error) {
		reads++
		return original.WorkloadPermissions(ctx, target)
	})
	if rows, _, e := f.svc.List(t.Context(), current, "requested", 10); e != nil || len(rows) != 2 || reads != 1 {
		t.Fatal("policy requester metadata repeated workload read", len(rows), reads, e)
	}
}
func TestPolicyGrantRequesterMetadataRefusesWrongUnavailableOrDeniedProjection(t *testing.T) {
	for _, mode := range []string{"wrong-target", "unavailable", "denied"} {
		t.Run(mode, func(t *testing.T) {
			f, in := newPolicyGrantFixture(t)
			current := grantIdentity{f.requester, &f.now}
			g, _, e := f.svc.RequestPolicy(t.Context(), current, in)
			if e != nil {
				t.Fatal(e)
			}
			original := f.svc.WorkloadPermissions
			f.svc.WorkloadPermissions = workloadProjectionFunc(func(ctx context.Context, target value.WorkloadTarget) (value.WorkloadProjection, error) {
				p, e := original.WorkloadPermissions(ctx, target)
				switch mode {
				case "wrong-target":
					p.Target.WorkloadUID = "other-workload"
				case "unavailable":
					e = ErrGrantUnavailable
				case "denied":
					p.Denies = append(p.Denies, p.Allows[0])
				}
				return p, e
			})
			if v, _, err := f.svc.Get(t.Context(), current, g.ID); !errors.Is(err, ErrGrantNotFound) || v.Grant.ID != "" {
				t.Fatal("unavailable current rights exposed metadata", v.Grant.ID, err)
			}
			if rows, _, err := f.svc.List(t.Context(), current, "requested", 10); err != nil || len(rows) != 0 {
				t.Fatal("unavailable current rights exposed request list", len(rows), err)
			}
		})
	}
}
func TestPolicyGrantMetadataKeepsCurrentApproverAndLegacyAdHocPaths(t *testing.T) {
	f, in := newPolicyGrantFixture(t)
	g, _, e := f.svc.RequestPolicy(t.Context(), grantIdentity{f.requester, &f.now}, in)
	if e != nil {
		t.Fatal(e)
	}
	approver := grantIdentity{f.approver, &f.now}
	if v, _, err := f.svc.Get(t.Context(), approver, g.ID); err != nil || !v.Approver {
		t.Fatal("current independent approver lost metadata", err)
	}
	if rows, _, err := f.svc.List(t.Context(), approver, "pending", 10); err != nil || len(rows) != 1 || !rows[0].Approver {
		t.Fatal("current approver inbox changed", rows, err)
	}
	legacy := newGrantFixture(t)
	old := legacy.request(t, 1, nil)
	legacy.requester.Groups = nil
	legacy.svc.Permissions = projectionFunc(func(value.Target) value.Projection { panic("legacy requester metadata acquired a new permission read") })
	requester := grantIdentity{legacy.requester, &legacy.now}
	if v, _, err := legacy.svc.Get(t.Context(), requester, old.ID); err != nil || v.Grant.ID != old.ID {
		t.Fatal("legacy requester metadata changed", err)
	}
	if rows, _, err := legacy.svc.List(t.Context(), requester, "requested", 10); err != nil || len(rows) != 1 {
		t.Fatal("legacy requester list changed", len(rows), err)
	}
}

func TestPolicyGrantMetadataNeverOffersPersonalCaptureContinuation(t *testing.T) {
	f, in := newPolicyGrantFixture(t)
	g, _, err := f.svc.RequestPolicy(t.Context(), grantIdentity{f.requester, &f.now}, in)
	if err != nil {
		t.Fatal(err)
	}
	g = f.approve(t, g)
	for _, client := range []string{f.requester.Principal.ClientID, "another-human-client"} {
		actor := f.requester
		actor.Principal.ClientID = client
		v, _, err := f.svc.Get(t.Context(), grantIdentity{actor, &f.now}, g.ID)
		if err != nil || v.CanResume || v.CanResolve || v.ResumeRequiresOriginalClient {
			t.Fatal("team grant became personal capture continuation", client, v.CanResume, v.CanResolve, v.ResumeRequiresOriginalClient, err)
		}
	}
}

func TestPolicyGrantCurrentSponsorCanInspectAfterRequesterDepartureWithoutDecisionAuthority(t *testing.T) {
	f, in := newPolicyGrantFixture(t)
	g, _, err := f.svc.RequestPolicy(t.Context(), grantIdentity{f.requester, &f.now}, in)
	if err != nil {
		t.Fatal(err)
	}
	bob := f.requester
	bob.Principal.Subject = "current-team-manager"
	bob.Assurance = f.approver.Assurance
	f.requester.Groups = nil
	old := f.svc.WorkloadPermissions
	reads := 0
	f.svc.WorkloadPermissions = workloadProjectionFunc(func(ctx context.Context, target value.WorkloadTarget) (value.WorkloadProjection, error) {
		reads++
		return old.WorkloadPermissions(ctx, target)
	})
	v, until, err := f.svc.Get(t.Context(), grantIdentity{bob, &f.now}, g.ID)
	if err != nil || v.Grant.ID != g.ID || !v.CanRevoke || v.Approver || v.CanResume || v.CanResolve || v.ResumeRequiresOriginalClient || !until.After(f.now) || reads != 1 {
		t.Fatal("current sponsor cannot manage original team grant without becoming approver", v, until, reads, err)
	}
	if _, _, err = f.svc.Decide(t.Context(), grantIdentity{bob, &f.now}, g.ID, true, "current sponsor cannot review", "no-review"); !errors.Is(err, value.ErrNotApprover) {
		t.Fatal("management implied decision authority", err)
	}
}

func TestPolicyGrantManagerMetadataRefusesUnrelatedOrStaleAuthority(t *testing.T) {
	for _, name := range []string{"wrong-workload", "stale-denies", "unavailable", "reader-only", "other-basis", "replaced-assignment", "changed-basis-digest", "lost-group"} {
		t.Run(name, func(t *testing.T) {
			f, in := newPolicyGrantFixture(t)
			g, _, err := f.svc.RequestPolicy(t.Context(), grantIdentity{f.requester, &f.now}, in)
			if err != nil {
				t.Fatal(err)
			}
			bob := f.requester
			bob.Principal.Subject = "current-team-manager"
			old := f.svc.WorkloadPermissions
			reads := 0
			f.svc.WorkloadPermissions = workloadProjectionFunc(func(ctx context.Context, target value.WorkloadTarget) (value.WorkloadProjection, error) {
				reads++
				p, err := old.WorkloadPermissions(ctx, target)
				switch name {
				case "wrong-workload":
					p.Target.WorkloadUID = "another-workload"
				case "stale-denies":
					p.DeniesFreshUntil = f.now
				case "unavailable":
					return value.WorkloadProjection{}, errors.New("synthetic unavailable")
				case "reader-only":
					p.Allows[0].Audience.Role = "evidence-reader"
				case "other-basis":
					p.Allows[0].Audience.BasisUID = "different-binding"
				case "replaced-assignment":
					p.Allows[0].Audience.AssignmentID = grantID(999)
				case "changed-basis-digest":
					p.Allows[0].Audience.BasisDigest[0]++
				}
				return p, err
			})
			if name == "lost-group" {
				bob.Groups = nil
			}
			if v, _, err := f.svc.Get(t.Context(), grantIdentity{bob, &f.now}, g.ID); !errors.Is(err, ErrGrantNotFound) || v.Grant.ID != "" || reads != 1 {
				t.Fatal("historical/other team obtained policy configuration", name, v.Grant.ID, reads, err)
			}
		})
	}
}

func TestPolicyGrantRequesterWithoutPinnedManagementGetsNoRevocationHint(t *testing.T) {
	f, in := newPolicyGrantFixture(t)
	current := grantIdentity{f.requester, &f.now}
	g, _, err := f.svc.RequestPolicy(t.Context(), current, in)
	if err != nil {
		t.Fatal(err)
	}
	old := f.svc.WorkloadPermissions
	reads := 0
	f.svc.WorkloadPermissions = workloadProjectionFunc(func(ctx context.Context, target value.WorkloadTarget) (value.WorkloadProjection, error) {
		reads++
		p, err := old.WorkloadPermissions(ctx, target)
		p.Allows[0].Audience.AssignmentID = grantID(999)
		return p, err
	})
	v, _, err := f.svc.Get(t.Context(), current, g.ID)
	if err != nil || v.Grant.ID != g.ID || v.CanRevoke || v.Approver || reads != 1 {
		t.Fatal("collection provenance implied current pinned team management", v.CanRevoke, v.Approver, reads, err)
	}
	reads = 0
	rows, _, err := f.svc.List(t.Context(), current, "requested", 10)
	if err != nil || len(rows) != 1 || rows[0].CanRevoke || reads != 1 {
		t.Fatal("requested list offered unavailable revocation", len(rows), reads, err)
	}
}

// A replay can block on the SQL row lock just like a fresh revocation. Its
// historical success must not return protected grant metadata to a stale caller.
type blockedPolicyRevokeStore struct {
	GrantStore
	entered chan struct{}
	release chan struct{}
}

func (s blockedPolicyRevokeStore) RevokeGrant(ctx context.Context, in GrantRevocationInput, r artifact.RecoveryProof) (value.Grant, bool, error) {
	close(s.entered)
	select {
	case <-s.release:
	case <-ctx.Done():
		return value.Grant{}, false, ctx.Err()
	}
	return s.GrantStore.RevokeGrant(ctx, in, r)
}

type policyReplayIdentity struct{ i identity.Identity }

func (s *policyReplayIdentity) ResolveIdentity(context.Context) (identity.Identity, error) {
	return s.i, nil
}
func TestPolicyGrantRevokeReplayRechecksCurrentIdentityAndOriginalDeadline(t *testing.T) {
	for _, change := range []string{"groups", "identity-expiry", "eligibility-expiry"} {
		t.Run(change, func(t *testing.T) {
			f, in := newPolicyGrantFixture(t)
			current := &policyReplayIdentity{i: f.requester}
			g, _, err := f.svc.RequestPolicy(context.Background(), current, in)
			if err != nil {
				t.Fatal(err)
			}
			g, _, err = f.svc.Revoke(context.Background(), current, g.ID, g.Revision, "withdraw-policy")
			if err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			f.svc.Store = blockedPolicyRevokeStore{GrantStore: f.store, entered: entered, release: release}
			type result struct {
				g   value.Grant
				err error
			}
			done := make(chan result, 1)
			go func() {
				out, _, err := f.svc.Revoke(context.Background(), current, g.ID, g.Revision-1, "withdraw-policy")
				done <- result{out, err}
			}()
			<-entered
			switch change {
			case "groups":
				current.i.Groups = []string{"unrelated"}
			case "identity-expiry":
				current.i.ValidUntil = f.now
			case "eligibility-expiry":
				f.now = f.now.Add(31 * time.Second)
				current.i.VerifiedAt = f.now
				current.i.ValidUntil = f.now.Add(30 * time.Second)
			}
			close(release)
			got := <-done
			if got.err == nil || got.g.ID != "" {
				t.Fatal("blocked replay disclosed historical grant metadata", got.err, got.g.ID)
			}
			after, _ := f.store.Grant(context.Background(), g.ID)
			if after.Revision != g.Revision || after.PolicySpend != g.PolicySpend || after.RevokedAt != g.RevokedAt {
				t.Fatal("refused replay mutated immutable outcome/spend")
			}
		})
	}
}
