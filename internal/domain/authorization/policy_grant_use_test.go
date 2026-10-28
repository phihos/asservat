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

func finitePolicyObservationFixture(t *testing.T) (Grant, AcceptedPolicyAuthority, Target, time.Time) {
	t.Helper()
	g, a, target, now := approvedPolicyUseFixture(t)
	a.Limits.MaxObservedBytes = 1 << 30
	p := g.Policy.Clone()
	p.Authority = a
	p.Limits.MaxObservedBytes = 1 << 30
	p.Observation = &ObservationLimits{MaxSessionSeconds: 30, MaxObservedBytes: 1 << 30, MaxBytesPerSecond: 16 << 20, MaxConcurrentSessions: 2}
	g.Policy = &p
	if !g.Valid() {
		t.Fatal("invalid finite observation fixture")
	}
	return g, a, target, now
}

func TestFinitePolicyObservationPreservesOriginalBoundsAndConservativeCredit(t *testing.T) {
	for _, mode := range []string{"fifteen-seconds", "fractional-duration", "reviewed-session", "capture-end", "grant-end", "policy-pool", "grant-pool", "original-start"} {
		t.Run(mode, func(t *testing.T) {
			g, a, target, now := finitePolicyObservationFixture(t)
			duration, remaining := 15*time.Second, int64(1<<30)
			start, hard := now.Add(10*time.Second), now.Add(time.Minute)
			wantUntil, wantStart, wantCredit := now.Add(20*time.Second), now.Add(5*time.Second), int64(256<<20)
			switch mode {
			case "fractional-duration":
				duration = 12500 * time.Millisecond
				wantStart = now.Add(7500 * time.Millisecond)
				wantCredit = 224 << 20
			case "reviewed-session":
				g.Policy.Observation.MaxSessionSeconds = 18
				wantUntil = now.Add(18 * time.Second)
				wantStart = now.Add(3 * time.Second)
			case "capture-end":
				hard = now.Add(17 * time.Second)
				wantUntil = hard
				wantStart = now.Add(2 * time.Second)
			case "grant-end":
				g.PolicyNotAfter = now.Add(16 * time.Second)
				g.ExpiresAt = g.PolicyNotAfter
				wantUntil = g.PolicyNotAfter
				wantStart = now.Add(time.Second)
			case "policy-pool":
				remaining = 123
				wantCredit = 123
			case "grant-pool":
				g.PolicySpend.ObservedBytes = (1 << 30) - 456
				wantCredit = 456
			case "original-start":
				start = now.Add(2 * time.Second)
				wantStart = start
			}
			p, err := PlanFinitePolicyObservation(g, a, target, duration, remaining, 0, start, hard, now)
			if err != nil || !p.StartedAt.Equal(now) || !p.Until.Equal(wantUntil) || !p.LatestStart.Equal(wantStart) || p.Credit != wantCredit || p.Duration != duration || p.BytesPerSecond != 16<<20 {
				t.Fatalf("unexpected reservation: %+v %v", p, err)
			}
			if !g.Valid() {
				t.Fatal("planner mutated grant")
			}
		})
	}
}

func TestFinitePolicyObservationDeclinesUnusableOrUnauthorizedWindow(t *testing.T) {
	for _, mode := range []string{"session-cannot-fit", "capture-cannot-fit", "zero-duration", "longer-action", "expired-start", "wrong-pod", "revoked", "concurrency", "grant-empty", "policy-empty", "policy-inflated"} {
		t.Run(mode, func(t *testing.T) {
			g, a, target, now := finitePolicyObservationFixture(t)
			duration, remaining := 15*time.Second, int64(1<<30)
			start, hard := now.Add(10*time.Second), now.Add(time.Minute)
			switch mode {
			case "session-cannot-fit":
				g.Policy.Observation.MaxSessionSeconds = 15
			case "capture-cannot-fit":
				hard = now.Add(duration)
			case "zero-duration":
				duration = 0
			case "longer-action":
				duration = 16 * time.Second
			case "expired-start":
				start = now
			case "wrong-pod":
				target.PodUID = ""
			case "revoked":
				g.RevokedAt = now
				g.Revoker = g.Decision.Approver
			case "concurrency":
			case "grant-empty":
				g.PolicySpend.ObservedBytes = 1 << 30
			case "policy-empty":
				remaining = 0
			case "policy-inflated":
				remaining++
			}
			active := int64(0)
			if mode == "concurrency" {
				active = 2
			}
			p, err := PlanFinitePolicyObservation(g, a, target, duration, remaining, active, start, hard, now)
			if err == nil || p != (FinitePolicyObservation{}) {
				t.Fatalf("invalid finite authority admitted: %+v %v", p, err)
			}
		})
	}
}
