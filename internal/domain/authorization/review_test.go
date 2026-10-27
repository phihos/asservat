package authorization

import (
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// reviewed is one principal's decision-time allow (ADR-245).
func reviewed(subject, id string, now time.Time) CurrentAssignment {
	return CurrentAssignment{Audience: artifact.AudienceAssignment{Kind: "User", Issuer: "https://id.example.invalid", SubjectID: subject, Role: "workload-maintainer", BasisKind: "PermissionSource", BasisUID: "exec-source", BasisDigest: artifact.Digest{5}, AssignmentID: id},
		ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Reviewed: true}
}

func TestReviewedAllowGrantsOnlyItsPrincipalAndJoinsOnlyItsOwnCapture(t *testing.T) {
	i, p, _, now := fixture()
	p.Allows = []CurrentAssignment{reviewed(i.Principal.Subject, "44444444-4444-4444-4444-444444444444", now), reviewed("other-user", "55555555-5555-5555-5555-555555555555", now)}
	i.Groups = nil
	c := ContextEligibility(i, p, p.Target, now)
	if !c.Eligible || len(c.DefaultAudience) != 1 || c.DefaultAudience[0].SubjectID != i.Principal.Subject {
		t.Fatalf("capturing principal must be the decision-time source's only audience: %+v", c)
	}
	other := i
	other.Principal.Subject = "third-user"
	if r := Evaluate(other, p, CollectContext, p.Target, nil, now); r.Eligible {
		t.Fatal("another principal's review granted access")
	}
	// A policy executor never admits a reviewed allow into its audience.
	if audience, _, reason := defaultAudience(p, nil, now); reason != "NoEvidenceAudience" || len(audience) != 0 {
		t.Fatalf("policy audience took a principal's review: %v %q", audience, reason)
	}
	// A workload principal with the same subject is not the reviewed user.
	w := i
	w.Principal.Kind = identity.Workload
	if r := Evaluate(w, p, CollectContext, p.Target, nil, now); r.Eligible {
		t.Fatal("workload principal matched a human's review")
	}
}

func TestExplicitDenyWinsOverReviewedAllow(t *testing.T) {
	i, p, _, now := fixture()
	p.Allows = []CurrentAssignment{reviewed(i.Principal.Subject, "44444444-4444-4444-4444-444444444444", now)}
	deny := reviewed(i.Principal.Subject, "66666666-6666-6666-6666-666666666666", now)
	deny.Reviewed, deny.Audience.BasisKind, deny.Audience.BasisUID = false, "AccessBinding", "deny-binding"
	p.Denies = []CurrentAssignment{deny}
	if r := Evaluate(i, p, CollectContext, p.Target, nil, now); r.Eligible || r.Reason != "ExplicitDeny" {
		t.Fatalf("reviewed allow overrode a deny: %+v", r)
	}
}

// Reads need the exact recorded assignment, so a fresh review restores read
// access to the principal's own capture only while its assignment ID holds.
func TestReviewedAllowReadsOnlyEvidenceRecordingThatAssignment(t *testing.T) {
	i, p, e, now := fixture()
	own := reviewed(i.Principal.Subject, "44444444-4444-4444-4444-444444444444", now)
	p.Allows = []CurrentAssignment{own}
	i.Groups = nil
	e.Audience = []artifact.AudienceAssignment{own.Audience}
	if r := Evaluate(i, p, ReadApproved, p.Target, &e, now); !r.Eligible || !slices.Equal(r.ContributingAssignments, e.Audience) {
		t.Fatalf("own capture unreadable: %+v", r)
	}
	reminted := reviewed(i.Principal.Subject, "77777777-7777-7777-7777-777777777777", now)
	p.Allows = []CurrentAssignment{reminted}
	if r := Evaluate(i, p, ReadApproved, p.Target, &e, now); r.Eligible {
		t.Fatal("a later assignment read evidence recorded under a retired one")
	}
	p.Allows = []CurrentAssignment{own}
	if r := Evaluate(i, p, ReadApproved, p.Target, &e, now.Add(31*time.Second)); r.Eligible {
		t.Fatal("expired decision kept read access")
	}
}
