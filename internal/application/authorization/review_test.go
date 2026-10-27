package authorization

import (
	"context"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

type reviewFake struct {
	sources   []configuration.ReviewSource
	recorded  []RecordedReview
	decisions []ReviewDecision
	requests  []targets.AccessReviewRequest
	outcome   string
	failure   error
	log       *[]string
}

func (f *reviewFake) ReviewSources(_ context.Context, cluster string) ([]configuration.ReviewSource, error) {
	var out []configuration.ReviewSource
	for _, s := range f.sources {
		if s.ClusterID == cluster {
			out = append(out, s)
		}
	}
	return out, nil
}
func (f *reviewFake) RecordedReviews(_ context.Context, p identity.Principal, t value.Target) ([]RecordedReview, error) {
	if f.log != nil {
		*f.log = append(*f.log, "recorded")
	}
	return f.recorded, nil
}
func (f *reviewFake) RecordedCaptureReviews(context.Context, identity.Principal, string) ([]RecordedReview, error) {
	return f.recorded, nil
}
func (f *reviewFake) RecordReview(_ context.Context, d ReviewDecision) error {
	f.decisions = append(f.decisions, d)
	return nil
}
func (f *reviewFake) ReviewAccess(_ context.Context, r targets.AccessReviewRequest) (targets.AccessReviewAnswer, error) {
	f.requests = append(f.requests, r)
	if f.failure != nil {
		return targets.AccessReviewAnswer{}, f.failure
	}
	return targets.AccessReviewAnswer{SourceUID: r.Source.UID, Outcome: f.outcome}, nil
}

func reviewSourceFixture(uid string) configuration.ReviewSource {
	s, _ := configuration.ReviewSourceFor(configuration.Source{Resource: configuration.Resource{Kind: "PermissionSource", UID: uid, ResourceVersion: "1", Generation: 1, SpecDigest: artifact.Digest{7}}, Enabled: true, Type: configuration.SourceKubernetesExec,
		ClusterID: "11111111-1111-1111-1111-111111111111", Role: "workload-maintainer", MaxDecisionAge: 30 * time.Second, MaxNamespaces: 10, IdentityMappingRef: "company", AdmissionParity: configuration.AdmissionParity{Mode: "noAdditionalRestrictions", ReviewRef: "review"}})
	return s
}

func reviewTargetFixture() targets.Request {
	return targets.Request{ClusterID: "11111111-1111-1111-1111-111111111111", Namespace: configuration.NamespaceRef{Name: "payments", UID: "ns"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-1", PodUID: "pod"}
}

func TestAccessReviewsRecordEveryOutcomeForHumansOnly(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	human := identity.Identity{Principal: identity.Principal{Issuer: "https://issuer.invalid", Subject: "alice", ClientID: "console", Kind: identity.Human}, Groups: []string{"team"}, Policy: identity.Revision{UID: "p", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(time.Minute)}
	for name, tc := range map[string]struct {
		outcome string
		failure error
		allowed bool
	}{
		"allowed":     {targets.AccessAllowed, nil, true},
		"denied":      {targets.AccessDenied, nil, false},
		"outside":     {targets.AccessOutsideSource, nil, false},
		"unavailable": {"", targets.ErrUnavailable, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := &reviewFake{sources: []configuration.ReviewSource{reviewSourceFixture("a"), reviewSourceFixture("b")}, outcome: tc.outcome, failure: tc.failure}
			s := AccessReviews{Store: f, Reviewer: f, Now: func() time.Time { return now }}
			_ = s.ReviewResolved(context.Background(), human, reviewTargetFixture())
			if len(f.requests) != 2 || len(f.decisions) != 2 {
				t.Fatalf("one review and one record per source: %d %d", len(f.requests), len(f.decisions))
			}
			for _, d := range f.decisions {
				// A SAR outage is recorded as a refusal: it ends an earlier decision.
				if d.Allowed != tc.allowed || d.Principal != human.Principal || d.Target != reviewTargetFixture() || !d.DecidedAt.Equal(now) {
					t.Fatalf("decision %+v", d)
				}
			}
			r := f.requests[0]
			if r.Principal.Subject != "alice" || !slices.Equal(r.Principal.Groups, []string{"team"}) || r.Source.Check != configuration.ReviewPodExec || r.Source.IdentityMapping != "company" {
				t.Fatalf("request %+v", r)
			}
		})
	}
	workload := human.Principal
	workload.Kind = identity.Workload
	for name, principal := range map[string]identity.Principal{"workload": workload, "policy": value.PolicyPrincipal("33333333-3333-3333-3333-333333333333", "policy-uid")} {
		f := &reviewFake{sources: []configuration.ReviewSource{reviewSourceFixture("a")}, outcome: targets.AccessAllowed}
		p := human
		p.Principal = principal
		_ = AccessReviews{Store: f, Reviewer: f, Now: func() time.Time { return now }}.ReviewResolved(context.Background(), p, reviewTargetFixture())
		if len(f.requests)+len(f.decisions) != 0 {
			t.Errorf("%s principal was reviewed: exec inheritance is human-only", name)
		}
	}
}

func TestAccessReviewsRepeatOnlyRecordedTargetsOfCurrentSources(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	human := identity.Identity{Principal: identity.Principal{Issuer: "https://issuer.invalid", Subject: "alice", ClientID: "console", Kind: identity.Human}, Groups: []string{"team-now"}, Policy: identity.Revision{UID: "p", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(time.Minute)}
	recorded := reviewTargetFixture()
	other := recorded
	other.PodUID, other.PodName = "other-pod", "api-2"
	f := &reviewFake{sources: []configuration.ReviewSource{reviewSourceFixture("a")}, outcome: targets.AccessAllowed,
		recorded: []RecordedReview{{SourceUID: "a", Target: recorded}, {SourceUID: "retired", Target: recorded}, {SourceUID: "a", Target: other}}}
	s := AccessReviews{Store: f, Reviewer: f, Now: func() time.Time { return now }}
	target := value.Target{ClusterID: recorded.ClusterID, NamespaceUID: recorded.Namespace.UID, WorkloadUID: recorded.Workload.UID, PodUID: recorded.PodUID}
	if err := s.ReviewRecorded(context.Background(), human, target); err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 1 || f.requests[0].Target != recorded || !slices.Equal(f.requests[0].Principal.Groups, []string{"team-now"}) {
		t.Fatalf("recorded review repeated wrongly: %+v", f.requests)
	}
}

// The read paths review before their permission read, so the fresh decision
// (or its end) is what the evaluator sees; evidence is still read only after
// current eligibility.
func TestEvaluatorReviewsBeforePermissionRead(t *testing.T) {
	f, s, r := newFixture()
	var order []string
	reviews := &reviewFake{log: &order}
	s.Reviews = AccessReviews{Store: reviews, Reviewer: reviews, Now: func() time.Time { return f.now }}
	s.Permissions = orderedProjection{f, &order}
	if got := s.Eligibility(context.Background(), "token", r); !got.Eligible {
		t.Fatalf("eligibility %+v", got)
	}
	if !slices.Equal(order, []string{"recorded", "permissions"}) {
		t.Fatalf("order %v", order)
	}
}

type orderedProjection struct {
	f   *fixture
	log *[]string
}

func (o orderedProjection) Permissions(ctx context.Context, t value.Target) (value.Projection, error) {
	*o.log = append(*o.log, "permissions")
	return o.f.Permissions(ctx, t)
}
