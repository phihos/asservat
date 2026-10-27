package authorization

import (
	"testing"
	"time"
)

// ADR-238: an explicit selection picks among the caller's own current
// owner assignments for the artifact and never adds another.
func TestSelectShareManagement(t *testing.T) {
	creator, _, p, e, s, now := shareFixture()
	team := p.Allows[1]
	team.Audience.SubjectID, team.Audience.AssignmentID = "team-b", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	foreign := p.Allows[1]
	foreign.Audience.SubjectID, foreign.Audience.AssignmentID = "team-c", "cccccccc-cccc-cccc-cccc-cccccccccccc"
	p.Allows = append(p.Allows, team, foreign)
	e.Audience = append(e.Audience, team.Audience, foreign.Audience)
	creator.Groups = append(creator.Groups, "team-b")
	if r, owners := SelectShareManagement(creator, p, p.Target, &e, ManagementRequest{Mode: "teams", Teams: []string{"team-b"}}, now); !r.Eligible || len(owners) != 1 || owners[0] != team.Audience {
		t.Fatal("held team", r.Reason, owners)
	}
	for _, m := range []ManagementRequest{{Mode: "teams", Teams: []string{"team-c"}}, {Mode: "creator"}} {
		if r, owners := SelectShareManagement(creator, p, p.Target, &e, m, now); r.Eligible || r.Reason != "ManagementNotHeld" || owners != nil {
			t.Fatal("selection of an assignment the caller does not hold", m, r.Reason)
		}
	}
	// A held team outside the artifact's retained audience is not held for it.
	e.Audience = e.Audience[:len(e.Audience)-2]
	if r, _ := SelectShareManagement(creator, p, p.Target, &e, ManagementRequest{Mode: "teams", Teams: []string{"team-b"}}, now); r.Eligible || r.Reason != "ManagementNotHeld" {
		t.Fatal("team outside the retained audience", r.Reason)
	}
	for _, m := range []ManagementRequest{{Mode: "teams"}, {Mode: "teams", Teams: []string{"x", "x"}}, {Mode: "creator", Teams: []string{"x"}}, {Mode: "other"}} {
		if r, _ := SelectShareManagement(creator, p, p.Target, &e, m, now); r.Eligible || r.Reason != "InvalidRequest" {
			t.Fatal("invalid selection", m, r.Reason)
		}
	}
	// The administrator delegation pins any current owner team inside the
	// retained audience, never one outside it or named by a current deny.
	e.Audience = append(e.Audience, team.Audience, foreign.Audience)
	issuer := creator.Principal.Issuer
	if r, owners := AdministeredShareManagement(issuer, p, p.Target, &e, []string{"team-c"}, now); !r.Eligible || len(owners) != 1 || owners[0] != foreign.Audience {
		t.Fatal("administered team", r.Reason, owners)
	}
	if r, _ := AdministeredShareManagement(issuer, p, p.Target, &e, []string{"maintainers-not-owner"}, now); r.Reason != "ManagementNotHeld" {
		t.Fatal("non-owner group administered", r.Reason)
	}
	outside := e
	outside.Audience = outside.Audience[:len(outside.Audience)-1]
	if r, _ := AdministeredShareManagement(issuer, p, p.Target, &outside, []string{"team-c"}, now); r.Reason != "ManagementNotHeld" {
		t.Fatal("team outside the retained audience administered", r.Reason)
	}
	denied := p
	d := foreign
	d.Audience.AssignmentID = "dddddddd-dddd-dddd-dddd-dddddddddddd"
	denied.Denies = []CurrentAssignment{d}
	if r, _ := AdministeredShareManagement(issuer, denied, p.Target, &e, []string{"team-c"}, now); r.Reason != "ManagementNotHeld" {
		t.Fatal("denied team administered", r.Reason)
	}
	if r, _ := AdministeredShareManagement("https://other.example.invalid", p, p.Target, &e, []string{"team-c"}, now); r.Reason != "ManagementNotHeld" {
		t.Fatal("team of another issuer administered", r.Reason)
	}
	// A transferred share (revision above 2) is valid while live and after
	// revocation.
	s.Revision = 3
	if !s.Valid() {
		t.Fatal("transferred share")
	}
	s.Revision, s.RevokedAt = 4, now.Add(-time.Second)
	if !s.Valid() {
		t.Fatal("revoked transferred share")
	}
}
