package authorization

import (
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func policyGrantFixture() (Grant, time.Time) {
	a, _, _, now := automationFixture()
	a.NotAfter = now.Add(30 * 24 * time.Hour)
	g := grantFixture(now)
	g.Kind, g.PreviewID, g.CaptureID, g.Target = GrantPolicy, "", "", Target{}
	g.ExecutionDigest = a.ScopeDigest
	g.Lifetime = PolicyGrantDefaultLifetime
	g.PolicyNotAfter = now.Add(g.Lifetime)
	limits := a.Limits
	limits.MaxObservedBytes = 0
	g.Policy = &PolicyGrantScope{Authority: a, RecipeDigest: artifact.Digest{5}, Limits: limits, ApprovalMaxAge: 30 * 24 * time.Hour, ApprovalPolicyRef: identity.Revision{UID: "approval-policy", Generation: 1, Digest: artifact.Digest{9}}}
	return g, now
}

func TestPolicyGrantTargetAndIdentitySeparation(t *testing.T) {
	g, now := policyGrantFixture()
	if !g.Valid() {
		t.Fatal("workload-scoped pending policy grant invalid")
	}
	if got := g.Policy.Workload(); !got.Valid() || got.WorkloadUID != g.Policy.Authority.WorkloadUID {
		t.Fatal("real workload target missing", got)
	}
	for name, change := range map[string]func(*Grant){
		"executor substituted for requester": func(g *Grant) { g.Requester = g.Policy.Authority.Executor },
		"fake preview":                       func(g *Grant) { g.PreviewID = grantFixture(now).PreviewID },
		"fake capture":                       func(g *Grant) { g.CaptureID = grantFixture(now).CaptureID },
		"fake pod":                           func(g *Grant) { g.Target = grantFixture(now).Target },
		"personal result access":             func(g *Grant) { g.ResultAccess = &ResultAccess{} },
		"scope mismatch":                     func(g *Grant) { g.ExecutionDigest = artifact.Digest{99} },
		"missing recipe":                     func(g *Grant) { p := *g.Policy; p.RecipeDigest = artifact.Digest{}; g.Policy = &p },
		"missing original maximum":           func(g *Grant) { p := *g.Policy; p.ApprovalMaxAge = 0; g.Policy = &p },
		"original maximum below lifetime":    func(g *Grant) { p := *g.Policy; p.ApprovalMaxAge = time.Second; g.Policy = &p },
		"inflated budget":                    func(g *Grant) { p := *g.Policy; p.Limits.MaxExecutions++; g.Policy = &p },
	} {
		t.Run(name, func(t *testing.T) {
			x := g
			change(&x)
			if x.Valid() {
				t.Fatal("invalid policy scope accepted")
			}
		})
	}
	service := g
	service.Requester.Kind = identity.Workload
	if !service.Valid() {
		t.Fatal("authenticated service requester refused")
	}
	i := reviewer(now, "dev", "another-client", true)
	if err := CheckDecision(g, i, eligibleFor(i, now), true, now); !errors.Is(err, ErrSelfApproval) {
		t.Fatal("same requester through another client", err)
	}
	// The policy executor is not the requesting human; comparing against it would
	// silently let the original person approve their own request.
	if g.Requester == g.Policy.Authority.Executor {
		t.Fatal("fixture conflates actors")
	}
}

func TestPolicyGrantOriginalIssuanceAndClamp(t *testing.T) {
	g, now := policyGrantFixture()
	lead := reviewer(now, "lead", "console", true)
	decided := now.Add(20 * time.Minute)
	g.Decision = &GrantDecision{Approved: true, Approver: lead.Principal, Reason: "reviewed", ACR: "1", AuthenticatedAt: decided, DecidedAt: decided}
	g.Revision = 2
	g.ExpiresAt = now.Add(PolicyGrantDefaultLifetime)
	if !g.Valid() {
		t.Fatal("expiry must anchor original issue, not delayed review")
	}
	p := PolicyApprovalSettings{DefaultAge: 7 * 24 * time.Hour, MaxAge: 30 * 24 * time.Hour, RenewalNotice: 24 * time.Hour}
	if !p.Valid() {
		t.Fatal("defaults")
	}
	p.MaxAge = 2 * 24 * time.Hour
	p.DefaultAge = 24 * time.Hour
	g.PolicyNotAfter = p.Clamp(g.RequestedAt, g.PolicyNotAfter)
	g.ExpiresAt = g.PolicyNotAfter
	if !g.Valid() || !g.ExpiresAt.Equal(now.Add(48*time.Hour)) {
		t.Fatal("lower setting did not clamp original issue")
	}
	p.MaxAge = 30 * 24 * time.Hour
	if p.Clamp(g.RequestedAt, g.ExpiresAt) != g.ExpiresAt {
		t.Fatal("raising maximum renewed grant")
	}
	if err := CheckCaptureUse(g, reviewer(now, "dev", "console", false), "", g.ExecutionDigest, g.ReviewDigest, now); !errors.Is(err, ErrGrantScope) {
		t.Fatal("policy grant became personal capture authority", err)
	}
	self := reviewer(now, "dev", "console", false)
	if CanRevoke(g, self, Result{}, now) {
		t.Fatal("historical requester has perpetual team control")
	}
}

func TestAcceptedLowerMaximumClampsUnusedPendingRequest(t *testing.T) {
	g, now := policyGrantFixture()
	originalLifetime := g.Lifetime
	lower := PolicyApprovalSettings{DefaultAge: time.Second, MaxAge: time.Second, RenewalNotice: time.Second}
	g.PolicyNotAfter = lower.Clamp(g.RequestedAt, g.PolicyNotAfter)
	if !g.Valid() || g.Phase(now.Add(2*time.Second)) != GrantExpired {
		t.Fatal("unused pending request escaped accepted lower maximum")
	}
	raised := PolicyApprovalSettings{DefaultAge: 7 * 24 * time.Hour, MaxAge: 30 * 24 * time.Hour, RenewalNotice: 24 * time.Hour}
	g.PolicyNotAfter = raised.Clamp(g.RequestedAt, g.PolicyNotAfter)
	if g.Lifetime != originalLifetime || !g.PolicyNotAfter.Equal(now.Add(time.Second)) {
		t.Fatal("raising maximum silently renewed pending grant")
	}
}
