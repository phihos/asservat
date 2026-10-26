package authorization

import (
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestCaptureHistoryRequiresRequesterOrRetainedCurrentAssignment(t *testing.T) {
	for _, name := range []string{"requester", "requester-other-client", "retained-member", "new-assignment", "no-assignment", "deny", "scope", "invalid-creator"} {
		t.Run(name, func(t *testing.T) {
			i, p, _, now := fixture()
			creator := i.Principal
			retained := []artifact.AudienceAssignment{p.Allows[0].Audience}
			want := true
			switch name {
			case "requester-other-client":
				i.Principal.ClientID = "mcp"
			case "retained-member":
				creator.Subject = "another-developer"
			case "new-assignment":
				// The same group re-granted later is another assignment.
				creator.Subject = "another-developer"
				retained[0].AssignmentID = "00000000-0000-4000-8000-0000000000aa"
				want = false
			case "no-assignment":
				p.Allows = nil
				want = false
			case "deny":
				p.Denies = p.Allows
				p.Denies[0].FreshUntil = p.DeniesFreshUntil
				want = false
			case "scope":
				i.Scopes = []string{"evidence:capture"}
				want = false
			case "invalid-creator":
				creator.Issuer = ""
				want = false
			}
			got := CaptureHistoryEligibility(i, p, p.Target, creator, retained, now)
			if got.Eligible != want {
				t.Fatalf("eligibility=%v reason=%s", got.Eligible, got.Reason)
			}
			if !want && len(got.ContributingAssignments) > 0 {
				t.Fatal("denial disclosed assignments")
			}
		})
	}
}
