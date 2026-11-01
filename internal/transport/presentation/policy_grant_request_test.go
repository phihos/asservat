package presentation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Synthetic use case for the canonical audit/transport boundary; C03 and SQL
// request authorization have separate component tests.
type policyRequestWire struct {
	*grantUseCase
	calls, reads int
	input        authapp.PolicyGrantRequestInput
}

func (s *policyRequestWire) RequestPolicy(_ context.Context, _ identities.CurrentIdentity, in authapp.PolicyGrantRequestInput) (authorization.Grant, bool, error) {
	s.calls++
	s.input = in
	return s.view.Grant, s.replay, s.err
}
func (s *policyRequestWire) Get(ctx context.Context, i identities.CurrentIdentity, id string) (authapp.GrantView, time.Time, error) {
	s.reads++
	return s.grantUseCase.Get(ctx, i, id)
}
func policyRequestWireView(now time.Time, actor identity.Principal) authapp.GrantView {
	v := grantView(now)
	g := v.Grant
	target := g.Target
	g.Kind, g.PreviewID, g.CaptureID, g.Target = authorization.GrantPolicy, "", "", authorization.Target{}
	g.Requester = actor
	g.ResultAccess = nil
	g.ResultAccessDigest = artifact.Digest{}
	g.Scope = []byte(`{"format":"synthetic-policy-request-wire/v1"}`)
	g.ExecutionDigest = sha256.Sum256(g.Scope)
	revision := identity.Revision{UID: "binding", Generation: 1, Digest: artifact.Digest{1}}
	owner := artifact.AudienceAssignment{Kind: "Group", Issuer: actor.Issuer, SubjectID: "maintainers", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", BasisDigest: artifact.Digest{1}, AssignmentID: "00000000-0000-4000-8000-000000000901"}
	a := authorization.AcceptedPolicyAuthority{InstallationID: g.RootID, PolicyUID: "team-policy", Creator: actor, Executor: authorization.PolicyPrincipal(g.RootID, "team-policy"), ScopeDigest: g.ExecutionDigest, ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, Delegation: revision, Owners: []artifact.AudienceAssignment{owner}, Actions: []string{"packetCapture"}, Limits: authorization.AutomationLimits{MaxExecutions: 100, MaxBytes: 1 << 30}, IssuedAt: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour)}
	g.Policy = &authorization.PolicyGrantScope{Authority: a, RecipeDigest: artifact.Digest{8}, Limits: authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 64 << 20}, ApprovalPolicyRef: revision, ApprovalMaxAge: 30 * 24 * time.Hour}
	g.Lifetime = 24 * time.Hour
	g.PolicyNotAfter = now.Add(24 * time.Hour)
	g.Reasons = []authorization.SensitiveReason{{ActionID: "a1", Code: "policyCollection"}}
	v.Grant = g
	v.Approver = false
	v.CanRevoke = true
	v.Review.PodName = ""
	v.Review.ObservationLimits = nil
	v.Review.Deadline = a.NotAfter
	v.Review.Actions[0].ExecutionMode = "onTrigger"
	v.Review.Actions[0].Before = "0s"
	v.Review.Actions[0].After = "2s"
	v.Review.Actions[0].Sensitive = []string{}
	v.Grant.Review, _ = json.Marshal(v.Review)
	v.Grant.ReviewDigest = authapp.ReviewDigest(v.Grant, v.Grant.Review)
	return v
}
func TestPublicPolicyGrantRequestUsesExistingViewAndIndependentAuditBoundary(t *testing.T) {
	raw := []byte(`{"policy_uid":"team-policy","policy_name":"restarts","idempotency_key":"original-key","limits":{"max_executions":10,"max_collected_bytes":67108864,"max_observed_bytes":0}}`)
	for _, mode := range []string{"success", "intent-unavailable", "outcome-unavailable", "service-unknown"} {
		t.Run(mode, func(t *testing.T) {
			audited, current, gate := auditedFixture(t)
			use := &policyRequestWire{grantUseCase: &grantUseCase{view: policyRequestWireView(current.i.VerifiedAt, current.i.Principal), until: current.metadataUntil}}
			if mode == "service-unknown" {
				use.err = authapp.ErrGrantUnavailable
			}
			gate.beginFail = mode == "intent-unavailable"
			gate.finishFail = mode == "outcome-unavailable"
			operations, err := NewGrantOperations(audited.inner.PublicOrigin(), audited.config.Now, audited.config.NewID, use)
			if err != nil {
				t.Fatal(err)
			}
			audited.inner, err = NewInvestigationGrantOperations(audited.inner.(*InvestigationOperations), operations)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := audited.Call(context.Background(), current, "request_policy_grant", raw)
			if mode == "intent-unavailable" {
				if err == nil || use.calls != 0 || use.reads != 0 || len(gate.outcomes) != 0 || len(reply.Body) != 0 {
					t.Fatal("request dispatched before acknowledged encrypted intent", err, use.calls)
				}
				return
			}
			if use.calls != 1 || len(gate.outcomes) != 1 || !gate.outcomes[0].Valid() {
				t.Fatal("missing bounded public request/outcome", use.calls, gate.outcomes)
			}
			if mode == "outcome-unavailable" {
				if err == nil || len(reply.Body) != 0 || use.reads != 1 {
					t.Fatal("unacknowledged outcome escaped", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "service-unknown" {
				if gate.outcomes[0].Effect != "unknown" || use.reads != 0 {
					t.Fatal("unknown request was treated as no mutation", gate.outcomes)
				}
				return
			}
			if gate.outcomes[0].Effect != "accepted" || use.reads != 1 || use.input.PolicyUID != "team-policy" || use.input.PolicyName != "restarts" || use.input.IdempotencyKey != "original-key" || use.input.Lifetime != 0 || use.input.Limits.MaxBytes != 64<<20 || use.input.Observation != nil {
				t.Fatal("typed input/default period or actual metadata lost", use.input, gate.outcomes)
			}
			var out struct{ Data map[string]any }
			if json.Unmarshal(reply.Body, &out) != nil || out.Data["kind"] != "policy" || out.Data["capture_id"] != nil || out.Data["can_decide"] != false {
				t.Fatal("policy request invented manual capture or reviewer authority", string(reply.Body))
			}
		})
	}
}
