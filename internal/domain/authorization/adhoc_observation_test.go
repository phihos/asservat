package authorization

import (
	"testing"
	"time"
)

// ADR-279: a manual raw session is planned only under an approved, current
// grant with reviewed limits, within its concurrency, with a credit of the
// reviewed rate for the rounded duration plus one burst second.
func TestPlanFiniteAdHocObservation(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	g := Grant{Kind: GrantAdHocCapture, Decision: &GrantDecision{Approved: true}, ExpiresAt: now.Add(time.Hour)}
	limits := ObservationLimits{MaxSessionSeconds: 60, MaxObservedBytes: 1 << 30, MaxBytesPerSecond: 16 << 20, MaxConcurrentSessions: 1}
	p, err := PlanFiniteAdHocObservation(g, limits, 10*time.Second, 0, now.Add(10*time.Second), now.Add(time.Minute), now)
	if err != nil || p.Credit != 16<<20*11 || !p.Until.Equal(now.Add(20*time.Second)) || !p.LatestStart.Equal(now.Add(10*time.Second)) || p.BytesPerSecond != 16<<20 {
		t.Fatalf("%+v %v", p, err)
	}
	for name, edit := range map[string]func(*Grant, *ObservationLimits, *int64){
		"pending":     func(g *Grant, _ *ObservationLimits, _ *int64) { g.Decision = nil },
		"denied":      func(g *Grant, _ *ObservationLimits, _ *int64) { g.Decision = &GrantDecision{} },
		"revoked":     func(g *Grant, _ *ObservationLimits, _ *int64) { g.RevokedAt = now },
		"expired":     func(g *Grant, _ *ObservationLimits, _ *int64) { g.ExpiresAt = now },
		"no limits":   func(_ *Grant, l *ObservationLimits, _ *int64) { *l = ObservationLimits{} },
		"policy kind": func(g *Grant, _ *ObservationLimits, _ *int64) { g.Kind = GrantPolicy },
		"busy":        func(_ *Grant, _ *ObservationLimits, active *int64) { *active = 1 },
	} {
		c, l, active := g, limits, int64(0)
		edit(&c, &l, &active)
		if _, err := PlanFiniteAdHocObservation(c, l, 10*time.Second, active, now.Add(10*time.Second), now.Add(time.Minute), now); err == nil {
			t.Fatal(name, "planned")
		}
	}
	if _, err := PlanFiniteAdHocObservation(g, limits, 16*time.Second, 0, now.Add(10*time.Second), now.Add(time.Minute), now); err == nil {
		t.Fatal("over 15 seconds planned")
	}
}
