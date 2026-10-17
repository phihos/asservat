package authorization

import "testing"

func TestCaptureProgressRequiresCurrentRequesterOrMaintainer(t *testing.T) {
	for _, name := range []string{"requester-reader", "same-human-other-client", "foreign-reader", "foreign-maintainer", "changed-issuer", "removed-assignment", "deny", "scope", "stale-denies"} {
		t.Run(name, func(t *testing.T) {
			i, p, _, now := fixture()
			creator := i.Principal
			p.Allows[0].Audience.Role = "evidence-reader"
			want := true
			switch name {
			case "same-human-other-client":
				i.Principal.ClientID = "mcp"
			case "foreign-reader":
				i.Principal.Subject = "another-developer"
				want = false
			case "foreign-maintainer":
				i.Principal.Subject = "another-developer"
				p.Allows[0].Audience.Role = "workload-maintainer"
			case "changed-issuer":
				creator.Issuer = "https://other.example.invalid"
				want = false
			case "removed-assignment":
				p.Allows = nil
				want = false
			case "deny":
				p.Denies = p.Allows
				p.Denies[0].FreshUntil = p.DeniesFreshUntil
				want = false
			case "scope":
				i.Scopes = []string{"evidence:capture"}
				want = false
			case "stale-denies":
				p.DeniesFreshUntil = now
				want = false
			}
			got := CaptureProgressEligibility(i, p, p.Target, creator, now)
			if got.Eligible != want {
				t.Fatalf("eligibility=%v reason=%s", got.Eligible, got.Reason)
			}
			if !want && len(got.ContributingAssignments) > 0 {
				t.Fatal("denial disclosed assignments")
			}
		})
	}
}
