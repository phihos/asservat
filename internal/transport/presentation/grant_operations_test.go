package presentation

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	replay                   bool
	decideCalls, revokeCalls int
	until                    time.Time
	view                     authapp.GrantView
	next                     authapp.GrantCursor
	err                      error
	decided                  struct {
		id, reason, key string
		approve         bool
	}
}

func (g *grantUseCase) Get(context.Context, identities.CurrentIdentity, string) (authapp.GrantView, time.Time, error) {
	return g.view, g.until, g.err
}
func (g *grantUseCase) List(context.Context, identities.CurrentIdentity, string, authapp.GrantCursor, int) ([]authapp.GrantView, authapp.GrantCursor, time.Time, error) {
	return []authapp.GrantView{g.view}, g.next, g.until, g.err
}
func (g *grantUseCase) Decide(_ context.Context, _ identities.CurrentIdentity, id string, approve bool, reason, key string) (authorization.Grant, bool, error) {
	g.decideCalls++
	g.decided.id, g.decided.approve, g.decided.reason, g.decided.key = id, approve, reason, key
	out := g.view.Grant
	out.Revision = 2
	now := out.RequestedAt
	out.Decision = &authorization.GrantDecision{Approved: approve, Approver: identity.Principal{Issuer: out.Requester.Issuer, Subject: "lead", ClientID: "console", Kind: identity.Human}, Reason: reason, ACR: "mfa", AuthenticatedAt: now, DecidedAt: now}
	if approve {
		out.ExpiresAt = now.Add(out.Lifetime)
	}
	return out, g.replay, g.err
}
func (g *grantUseCase) Revoke(context.Context, identities.CurrentIdentity, string, int64, string) (authorization.Grant, bool, error) {
	g.revokeCalls++
	out := g.view.Grant
	out.Revision = 3
	return out, g.replay, g.err
}

func grantView(now time.Time) authapp.GrantView {
	g := authorization.Grant{ID: "00000000-0000-4000-8000-0000000009a1", RootID: "00000000-0000-4000-8000-000000000001", Kind: authorization.GrantAdHocCapture, PreviewID: "00000000-0000-4000-8000-000000000020", CaptureID: "00000000-0000-4000-8000-000000000045",
		Target: authorization.Target{ClusterID: "00000000-0000-4000-8000-000000000004", NamespaceUID: "ns", WorkloadUID: "w", PodUID: "pod"}, ExecutionDigest: artifact.Digest{1}, ReviewDigest: artifact.Digest{2}, DataClass: "extract",
		Reasons: []authorization.SensitiveReason{{ActionID: "a1", Code: "rawBytePredicate"}}, Scope: []byte("{}"), Review: []byte("{}"),
		Requester:   identity.Principal{Issuer: "https://id.example.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human},
		RequestedAt: now, Lifetime: time.Hour, Revision: 1,
		ResultAccess: &authorization.ResultAccess{ActionIDs: []string{"a1"}, Operations: []string{"download_artifact"}, MaxArtifacts: 1, MaxBytes: 100, MaxOperations: 2, NotAfter: now.Add(2 * time.Hour)}, ResultAccessDigest: artifact.Digest{3}}
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
	if out.Data.CanResume == nil || *out.Data.CanResume {
		t.Fatal("detail must carry explicit advisory flags")
	}
	if out.Data.CaptureDeadlineRule != "previewDeadline" || !out.Data.PreviewDeadline.Equal(uc.view.Review.Deadline) || out.Data.CaptureWindowSeconds != 0 {
		t.Fatal("legacy timing changed")
	}
	uc.view.CanResume = true
	uc.view.Grant.Scope = []byte(`{"timing":"approvedAcceptance/v1"}`)
	marked, e := s.Call(t.Context(), f, "get_grant", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1"}`))
	if e != nil || json.Unmarshal(marked.Body, &out) != nil || out.Data.CaptureDeadlineRule != "acceptanceWithinGrant" || out.Data.CaptureWindowSeconds != 300 || !*out.Data.CanResume || !out.Data.PreviewDeadline.Equal(uc.view.Review.Deadline) {
		t.Fatalf("approved timing: %v %s", e, marked.Body)
	}
	if len(reply.Body) > 24<<10 {
		t.Fatal("get_grant exceeds the result budget")
	}
	if reply, err = s.Call(t.Context(), f, "list_reviews", []byte(`{"view":"pending"}`)); err != nil || !strings.Contains(string(reply.Body), `"approvals":[{`) || strings.Contains(string(reply.Body), `"actions"`) || !strings.Contains(string(reply.Body), `"next_cursor":null`) || strings.Contains(string(reply.Body), `"can_resolve"`) || strings.Contains(string(reply.Body), `"resume_requires_original_client"`) {
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

func TestProfileGrantReviewWire(t *testing.T) {
	base, f := operationFixture(t, true)
	uc := &grantUseCase{view: grantView(f.i.VerifiedAt), until: f.metadataUntil}
	uc.view.Review.Actions = []authapp.GrantReviewAction{{ActionID: "cpu", Kind: "profile", ExecutionMode: "onTrigger", MaxBytes: 16 << 20, Sensitive: []string{"liveProfile"}, Profile: &authapp.GrantReviewProfile{Runtime: "go", Type: "heap", Mode: "snapshot", Source: "httpEndpoint", Timeout: "5s", ForceGC: true, SourceRef: "go-endpoint", SourceName: "go-pprof-loopback", AddressMode: "targetLoopback", Port: 6060, PathPolicy: "go-pprof/v1", EndpointDigest: strings.Repeat("ab", 32)}}}
	s, err := NewGrantOperations("https://console.invalid", base.config.Now, func() string { return "00000000-0000-4000-8000-000000000099" }, uc)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := s.Call(t.Context(), f, "get_grant", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1"}`))
	if err != nil || !strings.Contains(string(reply.Body), `"status":"ok"`) {
		t.Fatalf("profile review: %v %s", err, reply.Body)
	}
	var out struct {
		Data grantData `json:"data"`
	}
	if json.Unmarshal(reply.Body, &out) != nil || len(out.Data.Actions) != 1 || out.Data.Actions[0].Profile == nil || out.Data.Actions[0].Profile.Type != "heap" || !out.Data.Actions[0].Profile.ForceGC || out.Data.Actions[0].Profile.Port != 6060 || strings.Contains(string(reply.Body), `"ring_max_bytes"`) {
		t.Fatalf("profile review changed facts or invented ring: %s", reply.Body)
	}
}

func TestPolicyProfileGrantReviewUsesDefinitionWithoutConcretePodEndpoint(t *testing.T) {
	for _, kind := range []string{"templateBinding", "administratorProfile"} {
		t.Run(kind, func(t *testing.T) {
			base, f := operationFixture(t, true)
			v := policyRequestWireView(f.i.VerifiedAt, f.i.Principal)
			v.Grant.DataClass = "raw"
			v.Grant.Policy.Authority.Actions = []string{"profile"}
			p := &authapp.GrantReviewProfile{Runtime: "go", Type: "cpu", Mode: "interval", Source: "httpEndpoint", Duration: "10s", Timeout: "15s", SourceRef: "go-endpoint", SourceName: "go-pprof-loopback", AddressMode: "targetLoopback", PathPolicy: "go-pprof/v1", SourceKind: kind, DefinitionDigest: strings.Repeat("cd", 32)}
			if kind == "templateBinding" {
				p.DeclaredPortName, p.MinimumPort, p.MaximumPort = "pprof", 6000, 7000
			} else {
				p.Port = 6060
			}
			v.Review.Actions = []authapp.GrantReviewAction{{ActionID: "cpu", Kind: "profile", ExecutionMode: "onTrigger", MaxBytes: 16 << 20, Sensitive: []string{"liveProfile"}, Profile: p}}
			uc := &grantUseCase{view: v, until: f.metadataUntil}
			s, err := NewGrantOperations("https://console.invalid", base.config.Now, func() string { return "00000000-0000-4000-8000-000000000099" }, uc)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := s.Call(t.Context(), f, "get_grant", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1"}`))
			var out struct {
				Data grantData `json:"data"`
			}
			if err != nil || json.Unmarshal(reply.Body, &out) != nil || len(out.Data.Actions) != 1 || out.Data.Actions[0].Profile == nil {
				t.Fatal("policy profile review", err)
			}
			got := out.Data.Actions[0].Profile
			if got.DefinitionDigest != p.DefinitionDigest || got.SourceKind != kind || got.DeclaredPortName != p.DeclaredPortName || got.MinimumPort != p.MinimumPort || got.MaximumPort != p.MaximumPort || got.Port != p.Port || strings.Contains(string(reply.Body), `"endpoint_digest"`) || strings.Contains(string(reply.Body), `"pod_name"`) || strings.Contains(string(reply.Body), `"observation_limits"`) {
				t.Fatal("policy review lost definition or fabricated concrete source", string(reply.Body))
			}
			if kind == "templateBinding" && strings.Contains(string(reply.Body), `"port":`) {
				t.Fatal("named-port policy review invented concrete port")
			}
			// A mixed concrete endpoint cannot cross either public contract.
			p.EndpointDigest = strings.Repeat("ab", 32)
			if mixed, e := s.Call(t.Context(), f, "get_grant", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1"}`)); e == nil && strings.Contains(string(mixed.Body), `"status":"ok"`) {
				t.Fatal("mixed policy/concrete endpoint review accepted")
			}
		})
	}
}

func TestGrantReviewShowsArgumentReason(t *testing.T) {
	base, f := operationFixture(t, true)
	v := grantView(f.i.VerifiedAt)
	v.Grant.Reasons = []authorization.SensitiveReason{{ActionID: "a1", Code: "syscallArguments"}}
	v.Review.ObservationLimits.MaxObservedEvents = 1234
	uc := &grantUseCase{view: v, until: f.metadataUntil}
	s, err := NewGrantOperations("https://console.invalid", base.config.Now, func() string { return "00000000-0000-4000-8000-000000000099" }, uc)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := s.Call(t.Context(), f, "get_grant", []byte(`{"grant_id":"00000000-0000-4000-8000-0000000009a1"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw := reply.Body
	if !bytes.Contains(raw, []byte(`"syscallArguments"`)) || bytes.Contains(raw, []byte(`"max_observed_events"`)) {
		t.Fatalf("argument reason lost: %s %v", raw, err)
	}
}

// policyRequestWireView is a team policy grant view (kind policy).
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

func TestListReviewsCursor(t *testing.T) {
	base, f := operationFixture(t, true)
	uc := &grantUseCase{view: grantView(f.i.VerifiedAt), until: f.metadataUntil}
	uc.next = authapp.GrantCursor{RequestedAt: uc.view.Grant.RequestedAt, ID: uc.view.Grant.ID}
	s, err := NewGrantOperations("https://console.invalid", base.config.Now, func() string { return "00000000-0000-4000-8000-000000000099" }, uc)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := s.Call(t.Context(), f, "list_reviews", []byte(`{"view":"pending","limit":1}`))
	var out struct {
		NextCursor *string `json:"next_cursor"`
	}
	if err != nil || json.Unmarshal(reply.Body, &out) != nil || out.NextCursor == nil {
		t.Fatalf("next cursor: %v %s", err, reply.Body)
	}
	if c, ok := decodeGrantCursor(*out.NextCursor); !ok || c != uc.next {
		t.Fatal("cursor round trip", c, ok)
	}
	if reply, err = s.Call(t.Context(), f, "list_reviews", []byte(`{"view":"pending","cursor":"not-a-cursor"}`)); err != nil || !strings.Contains(string(reply.Body), `"code":"InvalidCursor"`) {
		t.Fatalf("invalid cursor: %v %s", err, reply.Body)
	}
}
