package presentation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type grantUseCase struct {
	until   time.Time
	view    authapp.GrantView
	err     error
	decided struct {
		id, reason, key string
		approve         bool
	}
}

func (g *grantUseCase) Get(context.Context, identities.CurrentIdentity, string) (authapp.GrantView, time.Time, error) {
	return g.view, g.until, g.err
}
func (g *grantUseCase) List(context.Context, identities.CurrentIdentity, string, int) ([]authapp.GrantView, time.Time, error) {
	return []authapp.GrantView{g.view}, g.until, g.err
}
func (g *grantUseCase) Decide(_ context.Context, _ identities.CurrentIdentity, id string, approve bool, reason, key string) (authorization.Grant, bool, error) {
	g.decided.id, g.decided.approve, g.decided.reason, g.decided.key = id, approve, reason, key
	out := g.view.Grant
	out.Revision = 2
	now := out.RequestedAt
	out.Decision = &authorization.GrantDecision{Approved: approve, Approver: identity.Principal{Issuer: out.Requester.Issuer, Subject: "lead", ClientID: "console", Kind: identity.Human}, Reason: reason, ACR: "mfa", AuthenticatedAt: now, DecidedAt: now}
	if approve {
		out.ExpiresAt = now.Add(out.Lifetime)
	}
	return out, false, g.err
}
func (g *grantUseCase) Revoke(context.Context, identities.CurrentIdentity, string, int64, string) (authorization.Grant, bool, error) {
	out := g.view.Grant
	out.Revision = 3
	return out, false, g.err
}

func grantView(now time.Time) authapp.GrantView {
	g := authorization.Grant{ID: "00000000-0000-4000-8000-0000000009a1", RootID: "00000000-0000-4000-8000-000000000001", Kind: authorization.GrantAdHocCapture, PreviewID: "00000000-0000-4000-8000-000000000020", CaptureID: "00000000-0000-4000-8000-000000000045",
		Target: authorization.Target{ClusterID: "00000000-0000-4000-8000-000000000004", NamespaceUID: "ns", WorkloadUID: "w", PodUID: "pod"}, ExecutionDigest: artifact.Digest{1}, ReviewDigest: artifact.Digest{2}, DataClass: "extract",
		Reasons: []authorization.SensitiveReason{{ActionID: "a1", Code: "rawBytePredicate"}}, Scope: []byte("{}"), Review: []byte("{}"),
		Requester:   identity.Principal{Issuer: "https://id.example.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human},
		RequestedAt: now, ReviewUntil: now.Add(time.Hour), Lifetime: time.Hour, Revision: 1,
		ResultAccess: &authorization.ResultAccess{ActionIDs: []string{"a1"}, Operations: []string{"download_artifact"}, ClientIDs: []string{"console"}, MaxArtifacts: 1, MaxBytes: 100, MaxOperations: 2, NotAfter: now.Add(2 * time.Hour)}, ResultAccessDigest: artifact.Digest{3}}
	return authapp.GrantView{Grant: g, Phase: authorization.GrantPending, Approver: true, Review: authapp.GrantReview{Namespace: "payments", WorkloadKind: "Deployment", WorkloadName: "api", PodName: "api-a", Deadline: now.Add(5 * time.Minute),
		Actions:           []authapp.GrantReviewAction{{ActionID: "a1", Kind: "packetCapture", ExecutionMode: "ongoing", Before: "30s", After: "10s", Filter: "tcp[13] & 2 != 0", FilterDigest: artifact.Digest{4}, FilterInstructions: 4, MaxBytes: 16 << 20, RingMaxBytes: 16 << 20, RingMaxAge: "50s", Sensitive: []string{"rawBytePredicate"}}},
		ObservationLimits: &authapp.GrantObservationLimits{MaxSessionSeconds: 15, MaxObservedBytes: 1 << 30, MaxBytesPerSecond: 16 << 20, MaxConcurrentSessions: 1}}}
}

func TestGrantOperationsWire(t *testing.T) {
	base, f := operationFixture(t, true)
	uc := &grantUseCase{view: grantView(f.i.VerifiedAt), until: f.metadataUntil}
	s, err := NewGrantOperations("https://console.invalid", base.config.Now, func() string { return "00000000-0000-4000-8000-000000000099" }, uc)
	if err != nil {
		t.Fatal(err)
	}
	// get_grant is an MCP and browser tool; the inbox and decisions are browser-only.
	for name, mcp := range map[string]bool{"get_grant": true, "list_reviews": false, "decide_review": false, "revoke_grant": false} {
		d, ok := s.Tool(name)
		if !ok || d.MCP() != mcp {
			t.Fatal(name, "transport", ok, d.Transports)
		}
	}
	reply, err := s.Call(t.Context(), f, "get_grant", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1"}`))
	var out struct {
		Status string    `json:"status"`
		Data   grantData `json:"data"`
	}
	if err != nil || json.Unmarshal(reply.Body, &out) != nil || out.Status != "ok" || out.Data.Phase != "Pending" || !out.Data.CanDecide || out.Data.Actions[0].Filter != "tcp[13] & 2 != 0" || out.Data.ResultAccess.MaxBytes != 100 || *out.Data.RemainingBytes != 100 || out.Data.NavigationURI != "https://console.invalid/approvals/00000000-0000-4000-8000-0000000009a1" {
		t.Fatalf("get_grant: %v %s", err, reply.Body)
	}
	if out.Data.CaptureDeadlineRule != "previewDeadline" || !out.Data.PreviewDeadline.Equal(uc.view.Review.Deadline) || out.Data.CaptureWindowSeconds != 0 {
		t.Fatal("legacy timing changed")
	}
	uc.view.Grant.Scope = []byte(`{"timing":"approvedAcceptance/v1"}`)
	marked, e := s.Call(t.Context(), f, "get_grant", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1"}`))
	if e != nil || json.Unmarshal(marked.Body, &out) != nil || out.Data.CaptureDeadlineRule != "acceptanceWithinGrant" || out.Data.CaptureWindowSeconds != 300 || !out.Data.PreviewDeadline.Equal(uc.view.Review.Deadline) {
		t.Fatalf("approved timing: %v %s", e, marked.Body)
	}
	if len(reply.Body) > 24<<10 {
		t.Fatal("get_grant exceeds the result budget")
	}
	if reply, err = s.Call(t.Context(), f, "list_reviews", []byte(`{"view":"pending"}`)); err != nil || !strings.Contains(string(reply.Body), `"approvals":[{`) || strings.Contains(string(reply.Body), `"actions"`) {
		t.Fatalf("list_reviews: %v %s", err, reply.Body)
	}
	if reply, err = s.Call(t.Context(), f, "decide_review", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1","decision":"approve","reason":"incident 42","idempotency_key":"d1"}`)); err != nil || !uc.decided.approve || uc.decided.reason != "incident 42" || !strings.Contains(string(reply.Body), `"revision":2`) {
		t.Fatalf("decide_review: %v %s", err, reply.Body)
	}
	for code, failure := range map[string]error{"SelfApprovalRefused": authorization.ErrSelfApproval, "StepUpRequired": authorization.ErrStepUpRequired, "NotAvailable": authorization.ErrNotApprover, "ApprovalNotPending": authorization.ErrGrantNotPending} {
		uc.err = failure
		if reply, err = s.Call(t.Context(), f, "decide_review", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1","decision":"approve","reason":"x","idempotency_key":"d2"}`)); err != nil || !strings.Contains(string(reply.Body), `"code":"`+code+`"`) {
			t.Fatalf("%s: %v %s", code, err, reply.Body)
		}
	}
	// A grant the caller may not see and an unknown one reply identically.
	uc.err = authapp.ErrGrantNotFound
	unknown, _ := s.Call(t.Context(), f, "get_grant", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1"}`))
	uc.err = authorization.ErrNotApprover
	hidden, _ := s.Call(t.Context(), f, "get_grant", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1"}`))
	if string(unknown.Body) != string(hidden.Body) || !strings.Contains(string(hidden.Body), `"NotAvailable"`) {
		t.Fatalf("existence oracle: %s / %s", unknown.Body, hidden.Body)
	}
	uc.err = nil
	if reply, err = s.Call(t.Context(), f, "revoke_grant", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1","expected_revision":1,"idempotency_key":"r1"}`)); err != nil || !strings.Contains(string(reply.Body), `"phase":"Revoked"`) {
		t.Fatalf("revoke_grant: %v %s", err, reply.Body)
	}
	if _, err = s.Call(t.Context(), f, "decide_review", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1","decision":"maybe","reason":"x","idempotency_key":"d3"}`)); err == nil {
		t.Fatal("unknown decision accepted")
	}
}
