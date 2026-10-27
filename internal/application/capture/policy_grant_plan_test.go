package capture

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
)

type acceptedGrantPlanFixture struct {
	snapshot authorization.AcceptedPolicySnapshot
	record   value.PolicyAcceptance
}

func (f *acceptedGrantPlanFixture) AcceptedPolicyRecord(context.Context, string) (authorization.AcceptedPolicySnapshot, value.PolicyAcceptance, error) {
	return f.snapshot, f.record, nil
}

type grantPlanDocumentFunc func(context.Context, string, string) (value.PolicySource, []byte, error)

func (f grantPlanDocumentFunc) ReadPolicy(ctx context.Context, name, uid string) (value.PolicySource, []byte, error) {
	return f(ctx, name, uid)
}

func newPolicyGrantPlanFixture(t *testing.T) (*workloadActivationFixture, *acceptedGrantPlanFixture, PolicyGrantPlans) {
	t.Helper()
	f, activation := newWorkloadActivationFixture(t)
	if _, err := activation.Activate(context.Background(), f, "restarts", "first", true); err != nil {
		t.Fatal(err)
	}
	in := f.accepted[0]
	source, _, _ := f.ReadPolicy(context.Background(), "restarts", "policy-uid")
	record := value.PolicyAcceptance{ID: "99999999-9999-4999-8999-999999999999", RootID: activationRoot, Source: source, Submission: in.Submission, Authority: in.Authority, Submitter: f.author.Principal, IdentityRevision: f.author.Policy, PermissionRevision: f.projection.Revision, Recovery: in.Recovery, IntentVersion: 1, AcceptedAt: f.now}
	if !record.Valid() {
		t.Fatal("invalid accepted fixture")
	}
	accepted := &acceptedGrantPlanFixture{snapshot: authorization.AcceptedPolicySnapshot{Authority: record.Authority, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second), SourceUntil: source.FreshUntil}, record: record}
	plans := PolicyGrantPlans{Accepted: accepted, Documents: f, CompileRecorder: testPolicyRecorderCompiler, RecipeName: "builtin-pod-status-v1", RecipeDigest: testRecipe, Now: func() time.Time { return f.now }}
	return f, accepted, plans
}

func TestPolicyGrantPlanRebuildsOnlyExactAcceptedWorkloadScope(t *testing.T) {
	_, accepted, plans := newPolicyGrantPlanFixture(t)
	p, err := plans.PolicyGrantPlan(context.Background(), "policy-uid")
	if err != nil || sha256.Sum256(p.Scope) != accepted.record.Authority.ScopeDigest || p.Authority.PolicyUID != "policy-uid" || p.RecipeDigest == (artifact.Digest{}) || p.Review.PodName != "" || p.Review.WorkloadKind != "Deployment" || len(p.Review.Actions) != 1 || p.Review.Actions[0].Kind != "packetCapture" || len(p.Reasons) != 1 || p.Reasons[0].Code != "policyCollection" {
		t.Fatal("exact policy review", p, err)
	}
	if p.FreshUntil != accepted.snapshot.FreshUntil || p.Review.Deadline != accepted.record.Authority.NotAfter {
		t.Fatal("review renewed authority or freshness")
	}
}

func TestPolicyGrantPlanRefusesChangedInterpretationAndUnavailableAuthority(t *testing.T) {
	for _, name := range []string{"unknown-policy", "changed-recipe", "deleted-source", "wrong-source-name", "changed-collection", "expired-acceptance", "mismatched-authority", "lost-request"} {
		t.Run(name, func(t *testing.T) {
			f, accepted, plans := newPolicyGrantPlanFixture(t)
			policy := "policy-uid"
			ctx := context.Background()
			switch name {
			case "unknown-policy":
				policy = "other-policy"
			case "changed-recipe":
				edit := f.edit
				f.edit = func(s map[string]any) { edit(s); s["profileComposition"].(map[string]any)["maxDuration"] = "30s" }
			case "deleted-source", "wrong-source-name", "changed-collection":
				plans.Documents = grantPlanDocumentFunc(func(ctx context.Context, nameArg, uid string) (value.PolicySource, []byte, error) {
					s, b, e := f.ReadPolicy(ctx, nameArg, uid)
					if name == "deleted-source" {
						s.Deleted = true
					}
					if name == "wrong-source-name" {
						s.Name = "other"
					}
					if name == "changed-collection" {
						s.CollectionDigest[0]++
					}
					return s, b, e
				})
			case "expired-acceptance":
				accepted.snapshot.FreshUntil = f.now
			case "mismatched-authority":
				accepted.snapshot.Authority.NotAfter = accepted.snapshot.Authority.NotAfter.Add(-time.Second)
			case "lost-request":
				call, cancel := context.WithCancel(ctx)
				cancel()
				ctx = call
			}
			if _, err := plans.PolicyGrantPlan(ctx, policy); !errors.Is(err, authapp.ErrGrantUnavailable) {
				t.Fatal("changed/unavailable plan supplied", err)
			}
		})
	}
}
