package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// Test-only service values exercise the wire projection. They do not implement
// production authorization or qualify the SQL/execution workflow.
type contextOperationFixture struct {
	i             identity.Identity
	input         value.ContextIntent
	err           error
	revoke        bool
	requests      int
	key           string
	plan          artifact.Digest
	submission    []byte
	metadataUntil time.Time
	afterResolve  func()
	sharing       *value.ContextSharingStatus
}

func (f *contextOperationFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	if f.revoke {
		return identity.Identity{}, identity.ErrDenied
	}
	if f.afterResolve != nil {
		f.afterResolve()
	}
	return f.i, nil
}
func (f *contextOperationFixture) CheckDiagnostic(context.Context, identities.CurrentIdentity, targets.WorkloadRequest) (time.Time, error) {
	return f.metadataUntil, f.err
}
func (f *contextOperationFixture) Preview(_ context.Context, _ identities.CurrentIdentity, in value.ContextIntent) (app.ContextPreviewResult, error) {
	f.input = in
	p := value.ContextPreview{ID: "00000000-0000-4000-8000-000000000020", Intent: in, Deadline: f.i.VerifiedAt.Add(5 * time.Minute), ScopeDigest: artifact.Digest{1}, Target: targets.Request{ClusterID: in.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: in.Target.Namespace, UID: "ns"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-a", PodUID: "pod"}}
	return app.ContextPreviewResult{Preview: p, ValidUntil: f.metadataUntil, Assessment: assessmentFixture()}, f.err
}
func (f *contextOperationFixture) Request(_ context.Context, _ identities.CurrentIdentity, in app.CaptureRequest) (value.Accepted, error) {
	f.requests++
	f.key, f.plan, f.submission = in.Key, in.Plan, in.Submission
	return value.Accepted{MetadataValidUntil: f.metadataUntil, CaptureID: "00000000-0000-4000-8000-000000000030"}, f.err
}
func (f *contextOperationFixture) Get(context.Context, identities.CurrentIdentity, string) (value.ContextProgress, error) {
	return value.ContextProgress{ValidUntil: f.metadataUntil, CaptureID: "00000000-0000-4000-8000-000000000030", Revision: 3, Phase: "Finalizing", ActionPhase: "Finalizing", ReasonCode: "PublicationPending", Sharing: f.sharing}, f.err
}

func operationFixture(t *testing.T, enabled bool) (*ContextOperations, *contextOperationFixture) {
	t.Helper()
	now := assessmentFixture().GeneratedAt
	f := &contextOperationFixture{i: identity.Identity{Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, Scopes: []string{"evidence:read", "evidence:capture"}, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}}
	f.metadataUntil = f.i.ValidUntil
	s, err := NewContextOperations(ContextOperationsConfig{PublicOrigin: "https://console.invalid", CollectionEnabled: enabled, Now: func() time.Time { return now }, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f, f)
	if err != nil {
		t.Fatal(err)
	}
	return s, f
}

const wireTarget = `"target_ref":{"cluster_id":"00000000-0000-4000-8000-000000000001","namespace":"payments","kind":"Deployment","name":"api"}`
const wirePreview = `{` + wireTarget + `,"preset_ref":{"name":"pod-status","version":"v1"},"requested_retention_seconds":60}`
const wirePlanDigest = "1111111111111111111111111111111111111111111111111111111111111111"
const wireRequest = `{"preview":` + wirePreview + `,"expected_plan_digest":"` + wirePlanDigest + `","idempotency_key":"same-key"}`

type privatePreviewStep struct{ cause error }

func (e privatePreviewStep) Error() string     { return "private target and provider detail" }
func (e privatePreviewStep) Unwrap() error     { return e.cause }
func (e privatePreviewStep) FixedStep() string { return "facts/retention" }

func TestContextOperationsPrivatePreviewStepPreservesPublicWire(t *testing.T) {
	for _, cause := range []error{value.ErrDenied, value.ErrUnavailable, value.ErrProcessingCoverage, value.ErrChanged} {
		t.Run(cause.Error(), func(t *testing.T) {
			s, f := operationFixture(t, true)
			f.err = cause
			original, err := s.Call(t.Context(), f, "preview_capture", []byte(wirePreview))
			if err != nil {
				t.Fatal(err)
			}
			f.err = privatePreviewStep{cause: cause}
			observed, err := s.Call(t.Context(), f, "preview_capture", []byte(wirePreview))
			if err != nil || string(observed.Body) != string(original.Body) || observed.auditDecision != original.auditDecision || observed.ValidUntil != original.ValidUntil {
				t.Fatalf("private step changed public wire, audit classification or deadline: %v", err)
			}
		})
	}
}

func TestContextOperationsProjectBoundedSharedWorkflow(t *testing.T) {
	s, f := operationFixture(t, true)
	for name, in := range map[string]string{"list_diagnostics": `{` + wireTarget + `}`, "preview_capture": wirePreview, "request_capture": wireRequest, "get_capture": `{"capture_id":"00000000-0000-4000-8000-000000000030"}`} {
		b, err := s.Call(context.Background(), f, name, json.RawMessage(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s.contracts.ValidateOutput(name, b.Body) != nil {
			t.Fatal("invalid output")
		}
		var out struct {
			Status string
			Data   map[string]any
		}
		if json.Unmarshal(b.Body, &out) != nil || out.Status != "ok" {
			t.Fatalf("%s: %s", name, b.Body)
		}
		if name == "request_capture" && out.Data["phase"] != "Accepted" {
			t.Fatal("accepted retry claimed new Pending execution")
		}
		if strings.Contains(string(b.Body), "DefaultAudience") || strings.Contains(string(b.Body), "CollectorImageDigest") || strings.Contains(string(b.Body), "IssuerEpoch") {
			t.Fatal("private accepted scope leaked")
		}
		if name == "preview_capture" && strings.Contains(out.Data["navigation_uri"].(string), "preview_id") {
			t.Fatal("MCP review promoted into browser submission authority")
		}
	}
	if f.input.RequestedSeconds != 60 || f.input.Diagnostic != value.ContextDiagnosticName {
		t.Fatal("retention/preset not mapped")
	}
}

func TestContextOperationsDisabledScopesUnknownRepliesAndNoSilentFeatures(t *testing.T) {
	s, f := operationFixture(t, false)
	b, err := s.Call(context.Background(), f, "request_capture", []byte(wireRequest))
	if err != nil || f.requests != 0 || !strings.Contains(string(b.Body), "CollectionDisabled") {
		t.Fatal("disabled request dispatched")
	}
	if _, ok := s.Tool("request_capture"); ok {
		t.Fatal("disabled mutation advertised")
	}
	s, f = operationFixture(t, true)
	f.i.Scopes = []string{"evidence:read"}
	if _, err = s.Call(context.Background(), f, "request_capture", []byte(wireRequest)); err != nil || f.requests != 0 {
		t.Fatal("capture scope bypass")
	}
	for _, extra := range []string{`,"reason":"private-value"`, `,"sharing":{}`, `,"history_capture_id":"00000000-0000-4000-8000-000000000030"`} {
		if _, err = s.Call(context.Background(), f, "preview_capture", []byte(strings.TrimSuffix(wirePreview, "}")+extra+"}")); err == nil {
			t.Fatal("unsupported feature silently discarded")
		}
	}
	f.i.Scopes = append(f.i.Scopes, "evidence:capture")
	f.err = errors.New("secret host/database/workload not found")
	for range 2 {
		b, err = s.Call(context.Background(), f, "request_capture", []byte(wireRequest))
		if err != nil || !strings.Contains(string(b.Body), "OutcomeUnknown") || strings.Contains(string(b.Body), "secret host") {
			t.Fatal("unknown outcome exposed internal error or reported failure")
		}
		if f.key != "same-key" || f.plan[0] != 0x11 || f.plan[31] != 0x11 {
			t.Fatal("retry changed identity")
		}
	}
	f.revoke = true
	if _, err = s.Call(context.Background(), f, "list_diagnostics", []byte(`{`+wireTarget+`}`)); err == nil {
		t.Fatal("revoked identity got metadata")
	}
}

func TestContextOperationsRetainOriginalMetadataDeadline(t *testing.T) {
	for name, in := range map[string]string{"list_diagnostics": `{` + wireTarget + `}`, "preview_capture": wirePreview, "request_capture": wireRequest, "get_capture": `{"capture_id":"00000000-0000-4000-8000-000000000030"}`} {
		t.Run(name, func(t *testing.T) {
			s, f := operationFixture(t, true)
			now := f.i.VerifiedAt
			s.config.Now = func() time.Time { return now }
			f.metadataUntil = now.Add(time.Second)
			out, err := s.Call(context.Background(), f, name, []byte(in))
			if err != nil || !out.ValidUntil.Equal(f.metadataUntil) {
				t.Fatalf("lost original permission deadline: %v %v", out.ValidUntil, err)
			}
			calls := 0
			f.afterResolve = func() {
				calls++
				if calls == 2 {
					now = f.metadataUntil
				}
			}
			out, err = s.Call(context.Background(), f, name, []byte(in))
			if !errors.Is(err, value.ErrUnavailable) || len(out.Body) != 0 || !f.i.Valid(now) {
				t.Fatalf("final identity check extended metadata authority: %+v %v", out, err)
			}
			f.afterResolve = nil
			f.metadataUntil = time.Time{}
			if out, err = s.Call(context.Background(), f, name, []byte(in)); err == nil || len(out.Body) != 0 {
				t.Fatal("missing service deadline received identity fallback")
			}
		})
	}
}

func TestContextOperationsKeepFinalShorterIdentityDeadline(t *testing.T) {
	s, f := operationFixture(t, false)
	original := f.i.ValidUntil
	count := 0
	f.afterResolve = func() {
		count++
		if count == 2 {
			f.i.ValidUntil = original.Add(-time.Second)
		}
	}
	out, err := s.Call(t.Context(), f, "get_capture", []byte(`{"capture_id":"00000000-0000-4000-8000-000000000030"}`))
	if err != nil || !out.ValidUntil.Equal(f.i.ValidUntil) || !out.ValidUntil.Before(original) {
		t.Fatalf("lost final shortened identity: %v %v", out.ValidUntil, err)
	}
}
