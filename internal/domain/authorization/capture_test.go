package authorization

import (
	"fmt"
	"testing"
	"time"
)

func TestCaptureAudienceIncludesOtherReadersAndMultipleOwnerTeams(t *testing.T) {
	i, p, _, now := fixture()
	for n, role := range []string{"evidence-reader", "evidence-owner", "evidence-owner", "action-approver"} {
		a := p.Allows[0]
		a.Audience.AssignmentID = fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012d", n+1)
		a.Audience.SubjectID = fmt.Sprintf("other-team-%d", n)
		a.Audience.Role = role
		p.Allows = append(p.Allows, a)
	}
	result := ContextEligibility(i, p, p.Target, now)
	if !result.Eligible || len(result.ContributingAssignments) != 1 || len(result.DefaultAudience) != 4 {
		t.Fatalf("caller audience replaced complete audience: %+v", result)
	}
	owners := 0
	for _, a := range result.DefaultAudience {
		if a.Role == "evidence-owner" {
			owners++
		}
		if a.SubjectID == i.Principal.Subject {
			t.Fatal("creator gained implicit access")
		}
	}
	if owners != 2 {
		t.Fatal("multiple independent owner assignments lost")
	}
	result.DefaultAudience[0].SubjectID = "mutated"
	if p.Allows[0].Audience.SubjectID != "team-a" {
		t.Fatal("returned mutable alias")
	}
}
func TestCaptureAudienceDenyFreshnessAndBound(t *testing.T) {
	i, p, _, now := fixture()
	reader := p.Allows[0]
	reader.Audience.AssignmentID = "aaaaaaaa-aaaa-4aaa-8aaa-111111111111"
	reader.Audience.SubjectID = "other"
	reader.Audience.Role = "evidence-owner"
	reader.FreshUntil = now.Add(time.Second)
	p.Allows = append(p.Allows, reader)
	r := ContextEligibility(i, p, p.Target, now)
	if !r.Eligible || !r.ValidUntil.Equal(reader.FreshUntil) {
		t.Fatal("audience freshness not intersected")
	}
	d := reader
	d.Audience.AssignmentID = "bbbbbbbb-bbbb-4bbb-8bbb-111111111111"
	d.Audience.Role = "evidence-reader"
	d.FreshUntil = now.Add(5 * time.Second)
	p.Denies = []CurrentAssignment{d}
	r = ContextEligibility(i, p, p.Target, now)
	if !r.Eligible || len(r.DefaultAudience) != 1 {
		t.Fatal("denied group retained")
	}
	p.DeniesComplete = false
	if ContextEligibility(i, p, p.Target, now).Eligible {
		t.Fatal("incomplete denies accepted")
	}
	p.DeniesComplete = true
	p.Denies = nil
	for n := 0; n < 31; n++ {
		a := reader
		a.Audience.AssignmentID = fmt.Sprintf("cccccccc-cccc-4ccc-8ccc-%012d", n+1)
		p.Allows = append(p.Allows, a)
	}
	r = ContextEligibility(i, p, p.Target, now)
	if r.Eligible || r.Reason != "AudienceOverflow" || r.DefaultAudience != nil {
		t.Fatal("oversized audience silently narrowed")
	}
}
