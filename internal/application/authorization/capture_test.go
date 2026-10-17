package authorization

import (
	"context"
	"testing"

	value "asservat.local/asservat/internal/domain/authorization"
)

func TestContextEligibilityResolvesCompleteAudienceWithoutArtifactLookup(t *testing.T) {
	f, s, r := newFixture()
	f.i.Scopes = append(f.i.Scopes, "evidence:capture")
	owner := f.p.Allows[0]
	owner.Audience.AssignmentID = "aaaaaaaa-aaaa-4aaa-8aaa-111111111111"
	owner.Audience.SubjectID = "other-team"
	owner.Audience.Role = "evidence-owner"
	f.p.Allows = append(f.p.Allows, owner)
	out := s.ContextEligibility(context.Background(), "synthetic-token", r.Target)
	if !out.Eligible || len(out.DefaultAudience) != 2 || f.reads != 0 || f.policyReads != 1 {
		t.Fatalf("incorrect capture eligibility: %+v", out)
	}
	f.identityError = true
	if out = s.ContextEligibility(context.Background(), "bad", r.Target); out.Eligible || f.policyReads != 1 {
		t.Fatal("unauthenticated capture enumerated assignments")
	}
	if s.ContextEligibility(context.Background(), "bad", value.Target{}).Eligible {
		t.Fatal("invalid target accepted")
	}
}
