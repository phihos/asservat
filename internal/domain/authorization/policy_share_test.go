package authorization

import "testing"

// ADR-239: the policy's owner teams are the automation binding's
// evidence-owner Group assignments of the sponsoring groups; a team member
// (not only the activator) manages the recurring sharing.
func TestPolicyShareManagementAndManagers(t *testing.T) {
	creator, recipient, p, _, s, now := shareFixture()
	r, owners := PolicyShareManagement(creator, p, p.Target, "binding-uid", []string{"team-a"}, now)
	if !r.Eligible || len(owners) != 1 || owners[0] != s.Management[0] {
		t.Fatal("owner team not pinned", r.Reason, owners)
	}
	if r, _ := PolicyShareManagement(creator, p, p.Target, "other-binding", []string{"team-a"}, now); r.Eligible || r.Reason != "NoOwnerAuthority" {
		t.Fatal("owner of another binding pinned", r.Reason)
	}
	if r, _ := PolicyShareManagement(creator, p, p.Target, "binding-uid", []string{"team-b"}, now); r.Eligible || r.Reason != "NoOwnerAuthority" {
		t.Fatal("owner outside the sponsoring groups pinned", r.Reason)
	}
	noScope := creator
	noScope.Scopes = []string{"evidence:read"}
	if r, _ := PolicyShareManagement(noScope, p, p.Target, "binding-uid", []string{"team-a"}, now); r.Eligible || r.Reason != "InsufficientScope" {
		t.Fatal("sharing without evidence:share", r.Reason)
	}
	mate := creator
	mate.Principal.Subject = "team-mate"
	if held, _ := PolicySharingManagedBy(creator.Principal, owners, p.Target, mate, p, now); len(held) != 1 || held[0] != owners[0] {
		t.Fatal("team member does not manage the recurring sharing", held)
	}
	if held, _ := PolicySharingManagedBy(creator.Principal, owners, p.Target, recipient, p, now); held != nil {
		t.Fatal("recipient manages the recurring sharing")
	}
}
