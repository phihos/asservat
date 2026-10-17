package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"testing"
	"time"
)

type fixture struct {
	now                                       time.Time
	i                                         identity.Identity
	p                                         value.Projection
	e                                         value.Retained
	reads, policyReads                        int
	identityError, policyError, evidenceError bool
	advance                                   time.Duration
}

func (f *fixture) Resolve(context.Context, string) (identity.Identity, error) {
	if f.identityError {
		return identity.Identity{}, errors.New("private identity failure")
	}
	return f.i, nil
}
func (f *fixture) Permissions(ctx context.Context, t value.Target) (value.Projection, error) {
	f.policyReads++
	if f.policyError {
		return value.Projection{}, errors.New("private config failure")
	}
	return f.p, nil
}
func (f *fixture) RetainedAudience(context.Context, string) (value.Retained, error) {
	f.reads++
	f.now = f.now.Add(f.advance)
	if f.evidenceError {
		return value.Retained{}, errors.New("private object failure")
	}
	return f.e, nil
}
func newFixture() (*fixture, Evaluator, Request) {
	n := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	r := identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}
	i := identity.Identity{Principal: identity.Principal{Issuer: "https://issuer.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}, Scopes: []string{"evidence:read", "evidence:download"}, Groups: []string{"team"}, Policy: r, VerifiedAt: n, ValidUntil: n.Add(30 * time.Second)}
	t := value.Target{ClusterID: "11111111-1111-1111-1111-111111111111", NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod"}
	a := artifact.AudienceAssignment{Kind: "Group", Issuer: i.Principal.Issuer, SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", BasisDigest: artifact.Digest{1}, AssignmentID: "22222222-2222-2222-2222-222222222222"}
	p := value.Projection{Target: t, Revision: r, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: n, DeniesFreshUntil: n.Add(5 * time.Second), Allows: []value.CurrentAssignment{{Audience: a, ObservedAt: n, FreshUntil: n.Add(30 * time.Second)}}}
	e := value.Retained{ArtifactID: "33333333-3333-3333-3333-333333333333", Target: t, DataClass: "metadata", ExpiresAt: n.Add(time.Hour), Audience: []artifact.AudienceAssignment{a}}
	f := &fixture{now: n, i: i, p: p, e: e}
	return f, Evaluator{Identities: f, Permissions: f, Evidence: f, Now: func() time.Time { return f.now }}, Request{value.DownloadApproved, t, e.ArtifactID}
}
func TestNoEvidenceLookupBeforeCurrentEligibility(t *testing.T) {
	for _, which := range []string{"unauthenticated", "no entitlement", "unknown denies", "missing scope", "explicit deny"} {
		t.Run(which, func(t *testing.T) {
			f, s, r := newFixture()
			switch which {
			case "unauthenticated":
				f.identityError = true
			case "no entitlement":
				f.p.Allows = nil
			case "unknown denies":
				f.p.DeniesComplete = false
			case "missing scope":
				f.i.Scopes = nil
			case "explicit deny":
				f.p.Denies = append(f.p.Denies, f.p.Allows[0])
			}
			out := s.Eligibility(context.Background(), "synthetic-token", r)
			if out.Eligible || f.reads != 0 {
				t.Fatalf("forbidden lookup: eligible=%v reads=%d", out.Eligible, f.reads)
			}
			if which == "unauthenticated" && f.policyReads != 0 {
				t.Fatal("unauthenticated configuration lookup")
			}
		})
	}
}
func TestRevalidateAfterBlockingReaders(t *testing.T) {
	f, s, r := newFixture()
	if out := s.Eligibility(context.Background(), "synthetic-token", r); !out.Eligible {
		t.Fatal(out.Reason)
	}
	f.advance = 31 * time.Second
	if out := s.Eligibility(context.Background(), "synthetic-token", r); out.Eligible {
		t.Fatal("blocking lookup extended authority")
	}
	f, s, r = newFixture()
	f.e.ArtifactID = "44444444-4444-4444-4444-444444444444"
	if out := s.Eligibility(context.Background(), "synthetic-token", r); out.Eligible {
		t.Fatal("substituted artifact")
	}
	f, s, r = newFixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out := s.Eligibility(ctx, "synthetic-token", r); out.Eligible || f.reads != 0 || f.policyReads != 0 {
		t.Fatal("cancelled eligibility performed work")
	}
	f, s, r = newFixture()
	f.evidenceError = true
	if out := s.Eligibility(context.Background(), "synthetic-token", r); out.Eligible || out.Reason != "EvidenceUnavailable" {
		t.Fatal("unsafe error projection")
	}
}
