package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
	"time"
)

func TestLiveSourceReadScopeMaintainerAndOriginalAudience(t *testing.T) {
	i, p, e, now := fixture()
	i.Scopes = []string{"evidence:read"}
	r := LiveSourceEligibility(i, p, p.Target, e.Audience, now.Add(time.Second), now)
	if !r.Eligible || !r.ValidUntil.Equal(now.Add(time.Second)) {
		t.Fatal("read-only token of entitled maintainer refused", r)
	}
	for _, role := range []string{"evidence-reader", "evidence-owner", "action-approver"} {
		q := p
		q.Allows = append([]CurrentAssignment(nil), p.Allows...)
		q.Allows[0].Audience.Role = role
		audience := []artifact.AudienceAssignment{q.Allows[0].Audience}
		if LiveSourceEligibility(i, q, p.Target, audience, now.Add(time.Second), now).Eligible {
			t.Fatal("non-maintainer live access", role)
		}
	}
	old := append([]artifact.AudienceAssignment(nil), e.Audience...)
	old[0].AssignmentID = "44444444-4444-4444-4444-444444444444"
	if LiveSourceEligibility(i, p, p.Target, old, now.Add(time.Second), now).Eligible {
		t.Fatal("new assignment borrowed old source audience")
	}
	p.Denies = p.Allows
	if LiveSourceEligibility(i, p, p.Target, e.Audience, now.Add(time.Second), now).Eligible {
		t.Fatal("deny ignored")
	}
}
