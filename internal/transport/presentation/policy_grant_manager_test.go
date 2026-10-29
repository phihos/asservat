package presentation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type managerWireStore struct {
	authapp.GrantStore
	g         authorization.Grant
	mutations int
}

func (s *managerWireStore) Grant(_ context.Context, id string) (authorization.Grant, error) {
	if id != s.g.ID {
		return authorization.Grant{}, authapp.ErrGrantNotFound
	}
	return s.g, nil
}
func (s *managerWireStore) RevokeGrant(_ context.Context, in authapp.GrantRevocationInput, _ artifact.RecoveryProof) (authorization.Grant, bool, error) {
	if in.GrantID != s.g.ID || in.ExpectedRevision != s.g.Revision {
		return authorization.Grant{}, false, authapp.ErrGrantConflict
	}
	s.mutations++
	s.g.Revision++
	s.g.RevokedAt = s.g.RequestedAt.Add(time.Minute)
	s.g.Revoker = in.Revoker
	return s.g, false, nil
}

type managerWireWorkload struct {
	p     authorization.WorkloadProjection
	reads int
}

func (s *managerWireWorkload) WorkloadPermissions(context.Context, authorization.WorkloadTarget) (authorization.WorkloadProjection, error) {
	s.reads++
	return s.p, nil
}

type managerWirePermissions struct{ authapp.ProjectionReader }

func (managerWirePermissions) Permissions(context.Context, authorization.Target) (authorization.Projection, error) {
	panic("policy manager invented a Pod lookup")
}

type managerWireRecovery struct{ proof artifact.RecoveryProof }

func (s managerWireRecovery) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return s.proof, nil
}

// Real C03 -> canonical presentation route, with synthetic store/identity/source
// facts. This is not SQL, IdP, encrypted audit or execution qualification.
func TestPolicyGrantManagerRouteUsesCurrentScopeWithoutDecisionOrEvidenceAuthority(t *testing.T) {
	base, current := operationFixture(t, true)
	now := base.config.Now()
	current.i.Groups = []string{"maintainers"}
	original := grantView(now)
	g := original.Grant
	target := g.Target
	g.Kind, g.PreviewID, g.CaptureID, g.Target = authorization.GrantPolicy, "", "", authorization.Target{}
	g.Requester.Issuer, g.Requester.Subject = current.i.Principal.Issuer, "departed-requester"
	g.ResultAccess, g.ResultAccessDigest = nil, artifact.Digest{}
	g.Scope = []byte(`{"format":"synthetic-policy-manager/v1"}`)
	g.ExecutionDigest = sha256.Sum256(g.Scope)
	owner := artifact.AudienceAssignment{Kind: "Group", Issuer: current.i.Principal.Issuer, SubjectID: "maintainers", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: "00000000-0000-4000-8000-000000000901", BasisDigest: artifact.Digest{1}}
	revision := identity.Revision{UID: "binding", Generation: 1, Digest: artifact.Digest{1}}
	authority := authorization.AcceptedPolicyAuthority{InstallationID: g.RootID, PolicyUID: "team-policy", Creator: g.Requester, Executor: authorization.PolicyPrincipal(g.RootID, "team-policy"), ScopeDigest: g.ExecutionDigest, ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, Delegation: revision, Owners: []artifact.AudienceAssignment{owner}, Actions: []string{"packetCapture"}, Limits: authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 1 << 20}, IssuedAt: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	g.Policy = &authorization.PolicyGrantScope{Authority: authority, RecipeDigest: artifact.Digest{7}, Limits: authorization.AutomationLimits{MaxExecutions: 2, MaxBytes: 1 << 20}, ApprovalPolicyRef: revision, ApprovalMaxAge: 24 * time.Hour}
	g.RequestedAt = now.Add(-time.Minute)
	g.ReviewUntil = g.RequestedAt.Add(time.Hour)
	g.PolicyNotAfter = g.RequestedAt.Add(g.Lifetime)
	g.ExpiresAt = g.PolicyNotAfter
	g.Decision = &authorization.GrantDecision{Approved: true, Approver: identity.Principal{Issuer: g.Requester.Issuer, Subject: "independent-reviewer", ClientID: "review-console", Kind: identity.Human}, Reason: "finite team collection", ACR: "mfa", AuthenticatedAt: g.RequestedAt, DecidedAt: g.RequestedAt.Add(time.Second)}
	g.Revision = 2
	g.PolicySpend = authorization.PolicyGrantSpend{Executions: 1, CollectedBytes: 4096}
	original.Review.PodName = ""
	original.Review.Deadline = authority.NotAfter
	original.Review.ObservationLimits = nil
	original.Review.Actions[0].Filter = "tcp port 80"
	original.Review.Actions[0].Sensitive = []string{"recordingApprovalRequired"}
	original.Review.Actions[0].MaxBytes = 1 << 20
	g.Reasons = []authorization.SensitiveReason{{ActionID: "a1", Code: "recordingApprovalRequired"}}
	g.Review, _ = json.Marshal(original.Review)
	g.ReviewDigest = authapp.ReviewDigest(g, g.Review)
	if !g.Valid() {
		t.Fatal("invalid synthetic original grant")
	}
	store := &managerWireStore{g: g}
	projection := &managerWireWorkload{p: authorization.WorkloadProjection{Target: g.Policy.Workload(), Revision: current.i.Policy, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: now.Add(5 * time.Second), Allows: []authorization.CurrentAssignment{{Audience: owner, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}}}
	service := authapp.GrantService{RootID: g.RootID, InstallationID: g.RootID, Permissions: managerWirePermissions{}, WorkloadPermissions: projection, Store: store, Recovery: managerWireRecovery{artifact.RecoveryProof{InstallationID: g.RootID, IssuerEpoch: g.RootID, Revision: revision, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}, Now: base.config.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}
	wire, err := NewGrantOperations("https://console.invalid", base.config.Now, service.NewID, service)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]string{"grant_id": g.ID})
	reply, err := wire.Call(t.Context(), current, "get_grant", input)
	var result struct {
		Status string    `json:"status"`
		Data   grantData `json:"data"`
	}
	if err != nil || json.Unmarshal(reply.Body, &result) != nil || result.Status != "ok" || result.Data.Policy == nil || !result.Data.CanRevoke || result.Data.CanDecide || result.Data.Target.ClusterID != target.ClusterID || result.Data.Target.WorkloadUID != target.WorkloadUID || result.Data.Policy.ExecutionsUsed != 1 || result.Data.Policy.CollectedBytesUsed != 4096 || !result.Data.NotAfter.Equal(g.PolicyNotAfter) || projection.reads != 1 {
		t.Fatalf("manager metadata is not current real workload scope: %v %s reads%d", err, reply.Body, projection.reads)
	}
	for _, key := range []string{`"capture_id"`, `"preview_id"`, `"pod_name"`, `"preview_deadline"`, `"result_access"`} {
		if strings.Contains(string(reply.Body), key) {
			t.Fatal("policy response fabricated personal capture scope", key)
		}
	}
	denied, err := wire.Call(t.Context(), current, "decide_review", []byte(`{"grant_id":"`+g.ID+`","decision":"approve","reason":"manager is not reviewer","idempotency_key":"no-decision"}`))
	if err != nil || !strings.Contains(string(denied.Body), `"code":"NotAvailable"`) || store.mutations != 0 {
		t.Fatal("manager became a reviewer", err, string(denied.Body))
	}
	revoked, err := wire.Call(t.Context(), current, "revoke_grant", []byte(`{"grant_id":"`+g.ID+`","expected_revision":2,"idempotency_key":"manager-revoke"}`))
	if err != nil || !strings.Contains(string(revoked.Body), `"phase":"Revoked"`) || store.mutations != 1 || store.g.PolicySpend != g.PolicySpend {
		t.Fatal("manager control lost original budget or scope", err, string(revoked.Body))
	}
	projection.p.Allows[0].Audience.AssignmentID = "00000000-0000-4000-8000-000000000902"
	hidden, err := wire.Call(t.Context(), current, "get_grant", input)
	if err != nil || !strings.Contains(string(hidden.Body), `"code":"NotAvailable"`) || strings.Contains(string(hidden.Body), "team-policy") {
		t.Fatal("replaced assignment disclosed team metadata", err, string(hidden.Body))
	}
}
