package authorization

import (
	"slices"
	"testing"
	"time"
)

func otherTeam(a CurrentAssignment, id string) CurrentAssignment {
	a.Audience.SubjectID, a.Audience.AssignmentID = "team-b", id
	return a
}

// ADR-234: the explanation is the real evaluator's decision for the caller,
// plus which of its own conditions decided it.
func TestExplainUsesEvaluatorDecision(t *testing.T) {
	type scenario struct {
		name   string
		change func(*Projection, *[]string, *time.Time)
		op     Operation
		want   Decision
		unmet  string
	}
	for _, s := range []scenario{
		{"allow", func(*Projection, *[]string, *time.Time) {}, CollectContext, Allow, ""},
		{"deny names caller", func(p *Projection, _ *[]string, _ *time.Time) {
			d := p.Allows[0]
			d.Audience.AssignmentID = "55555555-5555-5555-5555-555555555555"
			p.Denies = []CurrentAssignment{d}
		}, ReadApproved, Deny, UnmetExplicitDeny},
		{"missing capture scope", func(_ *Projection, scopes *[]string, _ *time.Time) {
			*scopes = []string{"evidence:read"}
		}, CollectContext, Deny, UnmetClientScope},
		{"role does not permit op", func(p *Projection, _ *[]string, _ *time.Time) {
			p.Allows[0].Audience.Role = "evidence-reader"
		}, CollectContext, Deny, UnmetNoMatchingAllow},
		{"stale allow", func(p *Projection, _ *[]string, now *time.Time) {
			p.Allows[0].ObservedAt, p.Allows[0].FreshUntil = now.Add(-2*time.Minute), now.Add(-time.Minute)
		}, ReadApproved, Indeterminate, UnmetPermissionStale},
		{"stale projection", func(p *Projection, _ *[]string, now *time.Time) {
			p.DeniesFreshUntil = now.Add(-time.Second)
		}, ReadApproved, Indeterminate, UnmetPermissionStale},
	} {
		t.Run(s.name, func(t *testing.T) {
			i, p, _, now := fixture()
			s.change(&p, &i.Scopes, &now)
			got := Explain(i, p, s.op, p.Target, now)
			if got.Decision != s.want || got.Unmet != s.unmet || !got.Disclosed || got.Target != p.Target {
				t.Fatalf("got %+v", got)
			}
			if eligible := ScopeEligibility(i, p, s.op, p.Target, now).Eligible; eligible != (got.Decision == Allow) {
				t.Fatalf("explanation %s disagrees with evaluator eligible=%t", got.Decision, eligible)
			}
		})
	}
}

func TestExplainReportsOwnAssignments(t *testing.T) {
	i, p, _, now := fixture()
	other := otherTeam(p.Allows[0], "66666666-6666-6666-6666-666666666666")
	p.Allows = append(p.Allows, other)
	got := Explain(i, p, ReadApproved, p.Target, now)
	if got.Decision != Allow || len(got.Assignments) != 1 || got.Assignments[0].Effect != "allow" || got.Assignments[0].Assignment != p.Allows[0].Audience {
		t.Fatalf("allow must list only the caller's contributing assignment: %+v", got)
	}
	if got.ValidUntil.IsZero() || got.ValidUntil.After(i.ValidUntil) {
		t.Fatalf("validity %v not bounded by identity", got.ValidUntil)
	}

	deny := p.Allows[0]
	deny.Audience.AssignmentID = "77777777-7777-7777-7777-777777777777"
	p.Denies = []CurrentAssignment{otherTeam(deny, "88888888-8888-8888-8888-888888888888"), deny}
	got = Explain(i, p, ReadApproved, p.Target, now)
	if got.Decision != Deny || len(got.Assignments) != 1 || got.Assignments[0].Effect != "deny" || got.Assignments[0].Assignment != deny.Audience {
		t.Fatalf("deny must name only the deny that matches the caller: %+v", got)
	}

	i.Scopes = []string{"evidence:read"}
	p.Denies = nil
	if got = Explain(i, p, DownloadApproved, p.Target, now); got.MissingScope != "evidence:download" || len(got.Assignments) != 0 {
		t.Fatalf("missing scope: %+v", got)
	}
}

// A caller with no assignment on the target gets one uniform answer, so the
// explanation reveals neither existence nor other principals' bindings.
func TestExplainUndisclosedWithoutOwnAssignment(t *testing.T) {
	for _, name := range []string{"other team only", "deny names caller", "stale projection", "missing scope", "no rows"} {
		t.Run(name, func(t *testing.T) {
			i, p, _, now := fixture()
			p.Allows[0] = otherTeam(p.Allows[0], "99999999-9999-9999-9999-999999999999")
			switch name {
			case "deny names caller":
				d := p.Allows[0]
				d.Audience.SubjectID, d.Audience.AssignmentID = "team-a", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
				p.Denies = []CurrentAssignment{d}
			case "stale projection":
				p.FreshUntil = now.Add(-time.Second)
			case "missing scope":
				i.Scopes = nil
			case "no rows":
				p.Allows = nil
			}
			got := Explain(i, p, CollectContext, p.Target, now)
			if got.Decision != Deny || got.Unmet != UnmetNoMatchingAllow || got.Disclosed || got.Target != (Target{}) || got.Assignments != nil || got.MissingScope != "" {
				t.Fatalf("not uniform: %+v", got)
			}
			if got.Decision != Undisclosed().Decision || got.Unmet != Undisclosed().Unmet {
				t.Fatal("undisclosed shape changed")
			}
		})
	}
	i, p, _, now := fixture()
	other := p.Target
	other.PodUID = "another-pod"
	if got := Explain(i, p, ReadApproved, other, now); got.Disclosed {
		t.Fatal("a projection for another target disclosed details")
	}
}

func TestRequiredRolesFollowEvaluatorTable(t *testing.T) {
	if got := RequiredRoles(CollectContext); !slices.Equal(got, []string{"workload-maintainer"}) {
		t.Fatal(got)
	}
	if got := RequiredRoles(DownloadApproved); !slices.Equal(got, []string{"evidence-reader", "workload-maintainer", "evidence-owner"}) {
		t.Fatal(got)
	}
}
