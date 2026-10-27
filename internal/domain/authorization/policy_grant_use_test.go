package authorization

import (
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func approvedPolicyUseFixture(t *testing.T) (Grant, AcceptedPolicyAuthority, Target, time.Time) {
	t.Helper()
	g, now := policyGrantFixture()
	lead := reviewer(now, "lead", "console", true)
	g.Decision = &GrantDecision{Approved: true, Approver: lead.Principal, Reason: "independent team approval", ACR: "1", AuthenticatedAt: now, DecidedAt: now}
	g.ExpiresAt, g.Revision = g.PolicyNotAfter, 2
	target := Target{ClusterID: g.Policy.Authority.ClusterID, NamespaceUID: g.Policy.Authority.NamespaceUID, WorkloadUID: g.Policy.Authority.WorkloadUID, PodUID: "actual-pod"}
	if !g.Valid() || !target.Valid() {
		t.Fatal("invalid policy use fixture")
	}
	return g, g.Policy.Authority, target, now
}
func TestPolicyGrantCaptureIsTeamScopedAndUsesFiniteSeparatePools(t *testing.T) {
	g, a, target, now := approvedPolicyUseFixture(t)
	if g.Requester == a.Executor {
		t.Fatal("requester is executor")
	}
	if err := CheckPolicyCapture(g, a, target, 100, now); err != nil {
		t.Fatal("team authority", err)
	}
	for _, name := range []string{"wrong-pod-scope", "fake-pod", "changed-authority-period", "changed-executor", "changed-scope", "no-approval", "collected-bytes", "executions", "personal-counter"} {
		t.Run(name, func(t *testing.T) {
			x, b, p := g, a, target
			switch name {
			case "wrong-pod-scope":
				p.WorkloadUID = "other-workload"
			case "fake-pod":
				p.PodUID = ""
			case "changed-authority-period":
				b.IssuedAt = b.IssuedAt.Add(time.Second)
			case "changed-executor":
				b.Executor.Subject = "other-policy"
			case "changed-scope":
				b.ScopeDigest = artifact.Digest{99}
			case "no-approval":
				x.Decision = nil
				x.ExpiresAt = time.Time{}
			case "collected-bytes":
				x.PolicySpend.CollectedBytes = x.Policy.Limits.MaxBytes
			case "executions":
				x.PolicySpend.Executions = x.Policy.Limits.MaxExecutions
			case "personal-counter":
				x.Spent.Bytes = 1
			}
			if err := CheckPolicyCapture(x, b, p, 100, now); err == nil {
				t.Fatal("invalid authority or exhausted pool admitted")
			}
		})
	}
	// Replacing a concrete Pod within the approved workload is a fresh admission,
	// not a fabricated policy target; each new Pod still needs current SQL rights.
	target.PodUID = "next-real-replica"
	if err := CheckPolicyCapture(g, a, target, 100, now); err != nil {
		t.Fatal("future replica scope missing", err)
	}
}
func TestPolicyGrantExhaustionKeepsExistingCreditButStopsNewSpend(t *testing.T) {
	g, a, target, now := approvedPolicyUseFixture(t)
	p := g.Policy.Clone()
	p.Limits.MaxObservedBytes = 2000
	p.Observation = &ObservationLimits{MaxSessionSeconds: 10, MaxObservedBytes: 2000, MaxBytesPerSecond: 100, MaxConcurrentSessions: 1}
	g.Policy = &p
	if err := CheckPolicyObservationStart(g, a, target, 2*time.Second, 500, 0, now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rate-session-ceiling", "duration", "remaining-pool"} {
		t.Run(name, func(t *testing.T) {
			credit, active, duration := int64(500), int64(0), 2*time.Second
			switch name {
			case "rate-session-ceiling":
				active = 1
			case "duration":
				duration = 11 * time.Second
			case "remaining-pool":
				credit = 2001
			}
			want := ErrPolicyGrantBudgetExhausted
			if name == "duration" {
				want = ErrGrantScope
			}
			if err := CheckPolicyObservationStart(g, a, target, duration, credit, active, now); !errors.Is(err, want) {
				t.Fatal("unbounded observation admitted", err)
			}
		})
	}
	g.PolicySpend.ObservedBytes = 2000 // all credit conservatively reserved, not all consumed at node
	if !g.Valid() || g.Phase(now) != GrantExhausted {
		t.Fatal("exhausted pool state", g.Phase(now))
	}
	if err := CheckPolicyGrantCurrent(g, a, g.Policy.Workload(), now); err != nil {
		t.Fatal("parent pool zero invalidated already prepaid session", err)
	}
	if err := CheckPolicyObservationStart(g, a, target, time.Second, 1, 0, now); !errors.Is(err, ErrPolicyGrantBudgetExhausted) {
		t.Fatal("new session refilled observed pool", err)
	}
	g.RevokedAt, g.Revoker = now, g.Decision.Approver
	if err := CheckPolicyGrantCurrent(g, a, g.Policy.Workload(), now); !errors.Is(err, ErrGrantRevoked) {
		t.Fatal("exhaustion hid revocation", err)
	}
	g.RevokedAt = time.Time{}
	if err := CheckPolicyGrantCurrent(g, a, g.Policy.Workload(), g.ExpiresAt); !errors.Is(err, ErrGrantExpired) {
		t.Fatal("exhaustion hid original expiry", err)
	}
}

func TestPolicyGrantCurrentExpiryWinsAtTheOriginalAuthorityEnd(t *testing.T) {
	g, a, _, now := approvedPolicyUseFixture(t)
	a.NotAfter = now.Add(5 * time.Second)
	p := g.Policy.Clone()
	p.Authority = a
	g.Policy = &p
	g.PolicyNotAfter, g.ExpiresAt = a.NotAfter, a.NotAfter
	if !g.Valid() {
		t.Fatal("clipped finite grant invalid")
	}
	if err := CheckPolicyGrantCurrent(g, a, g.Policy.Workload(), a.NotAfter); !errors.Is(err, ErrGrantExpired) {
		t.Fatal("authority end hid grant expiry", err)
	}
}
