package oidc

import (
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	identityapp "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
	"time"
)

// These are test-only projections, not a production configuration/catalog
// backend. The flow verifies real TLS/JWT processing plus the application chain.
type flowSources struct {
	policy                         identity.Policy
	projection                     authorization.Projection
	retained                       authorization.Retained
	permissionReads, evidenceReads int
}

func (s *flowSources) IdentityPolicy(context.Context, string) (identity.Policy, error) {
	return s.policy, nil
}
func (s *flowSources) Permissions(context.Context, authorization.Target) (authorization.Projection, error) {
	s.permissionReads++
	return s.projection, nil
}
func (s *flowSources) RetainedAudience(context.Context, string) (authorization.Retained, error) {
	s.evidenceReads++
	return s.retained, nil
}

func TestVerifiedTokenThroughCurrentEligibility(t *testing.T) {
	f := newFixture(t)
	n := f.now()
	revision := identity.Revision{UID: "protected-policy", Generation: 1, Digest: [32]byte{1}}
	target := authorization.Target{ClusterID: "11111111-1111-1111-1111-111111111111", NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod"}
	a := artifact.AudienceAssignment{Kind: "Group", Issuer: f.v.trust.Issuer, SubjectID: "team-a", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", BasisDigest: artifact.Digest{1}, AssignmentID: "22222222-2222-2222-2222-222222222222"}
	sources := &flowSources{
		policy:     identity.Policy{Revision: revision, Issuer: f.v.trust.Issuer, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), Clients: []identity.Client{{ID: "console", Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"team-a", "team-b"}, GroupsAtIssueQualified: true, GroupMaxAge: 5 * time.Minute},
		projection: authorization.Projection{Target: target, Revision: revision, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: n, DeniesFreshUntil: n.Add(5 * time.Second), Allows: []authorization.CurrentAssignment{{Audience: a, ObservedAt: n, FreshUntil: n.Add(30 * time.Second)}}},
		retained:   authorization.Retained{ArtifactID: "33333333-3333-3333-3333-333333333333", Target: target, DataClass: "metadata", ExpiresAt: n.Add(time.Hour), Audience: []artifact.AudienceAssignment{a}},
	}
	identities := identityapp.Service{Tokens: f.v, Policies: sources, Now: f.now}
	evaluator := authorizationapp.Evaluator{Identities: identities, Permissions: sources, Evidence: sources, Now: f.now}
	r := authorizationapp.Request{Operation: authorization.DownloadApproved, Target: target, ArtifactID: sources.retained.ArtifactID}
	token := sign(t, f.key, "key-1", "at+jwt", f.claims())
	if result := evaluator.Eligibility(context.Background(), token, r); !result.Eligible || result.Principal.Subject != "developer" {
		t.Fatalf("ordinary developer download eligibility: %s", result.Reason)
	}
	collect := authorizationapp.Request{Operation: authorization.CollectContext, Target: target}
	if result := evaluator.Eligibility(context.Background(), token, collect); !result.Eligible {
		t.Fatal(result.Reason)
	}
	if sources.evidenceReads != 1 {
		t.Fatal("collection preflight looked up evidence")
	}
	// Organization membership is not workload membership.
	claims := f.claims()
	claims["groups"] = []string{"team-b"}
	teamB := sign(t, f.key, "key-1", "at+jwt", claims)
	if result := evaluator.Eligibility(context.Background(), teamB, r); result.Eligible || sources.evidenceReads != 1 {
		t.Fatal("unrelated team reached evidence lookup")
	}
	// Current ownership changes do not change an old artifact's audience.
	sources.projection.Allows[0].Audience.SubjectID = "team-b"
	sources.projection.Allows[0].Audience.AssignmentID = "44444444-4444-4444-4444-444444444444"
	if result := evaluator.Eligibility(context.Background(), teamB, r); result.Eligible {
		t.Fatal("new owners inherited older evidence")
	}
	sources.projection.Allows[0].Audience.SubjectID = "team-a"
	if result := evaluator.Eligibility(context.Background(), token, r); result.Eligible {
		t.Fatal("ownership A-B-A cycle resurrected an old assignment")
	}
	// A valid key/signature never overrides current client removal.
	sources.policy.Clients = nil
	reads := sources.permissionReads
	if result := evaluator.Eligibility(context.Background(), token, collect); result.Eligible || sources.permissionReads != reads {
		t.Fatal("revoked client consulted workload permissions")
	}
	t.Log("real TLS/JWKS and signed access token -> organization eligibility -> current workload permission -> retained audience; no collection, publication or disclosure performed")
}
