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
	g := Grant{Kind: GrantAdHocCapture, Scope: []byte(`{"approval":{"dataClass":"raw","observationLimits":{"maxSessionSeconds":60,"maxObservedBytes":1073741824,"maxBytesPerSecond":16777216,"maxConcurrentSessions":1}}}`),
		Decision: &GrantDecision{Approved: true}, ExpiresAt: now.Add(time.Hour)}
	p, err := PlanFiniteAdHocObservation(g, 10*time.Second, 0, now.Add(10*time.Second), now.Add(time.Minute), now)
	if err != nil || p.Credit != 16<<20*11 || !p.Until.Equal(now.Add(20*time.Second)) || !p.LatestStart.Equal(now.Add(10*time.Second)) || p.BytesPerSecond != 16<<20 {
		t.Fatalf("%+v %v", p, err)
	}
	for name, edit := range map[string]func(*Grant, *int64){
		"pending":     func(g *Grant, _ *int64) { g.Decision = nil },
		"denied":      func(g *Grant, _ *int64) { g.Decision = &GrantDecision{} },
		"revoked":     func(g *Grant, _ *int64) { g.RevokedAt = now },
		"expired":     func(g *Grant, _ *int64) { g.ExpiresAt = now },
		"no limits":   func(g *Grant, _ *int64) { g.Scope = []byte(`{"approval":{"dataClass":"raw"}}`) },
		"policy kind": func(g *Grant, _ *int64) { g.Kind = GrantPolicy },
		"busy":        func(_ *Grant, active *int64) { *active = 1 },
	} {
		c, active := g, int64(0)
		edit(&c, &active)
		if _, err := PlanFiniteAdHocObservation(c, 10*time.Second, active, now.Add(10*time.Second), now.Add(time.Minute), now); err == nil {
			t.Fatal(name, "planned")
		}
	}
	if _, err := PlanFiniteAdHocObservation(g, 16*time.Second, 0, now.Add(10*time.Second), now.Add(time.Minute), now); err == nil {
		t.Fatal("over 15 seconds planned")
	}
}
