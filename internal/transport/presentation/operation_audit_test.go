package presentation

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type presentationAuditGate struct {
	intents               []audit.OperationIntent
	outcomes              []audit.OperationOutcome
	beginFail, finishFail bool
	onBegin, onFinish     func()
}

func (g *presentationAuditGate) Begin(_ context.Context, in audit.OperationIntent) error {
	g.intents = append(g.intents, in)
	if g.onBegin != nil {
		g.onBegin()
	}
	if g.beginFail {
		return auditapp.ErrUnavailable
	}
	return nil
}
func (g *presentationAuditGate) Finish(_ context.Context, out audit.OperationOutcome) error {
	g.outcomes = append(g.outcomes, out)
	if g.onFinish != nil {
		g.onFinish()
	}
	if g.finishFail {
		return auditapp.ErrUnavailable
	}
	return nil
}
func auditedFixture(t *testing.T) (*AuditedOperations, *contextOperationFixture, *presentationAuditGate) {
	t.Helper()
	inner, f := operationFixture(t, true)
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.i.VerifiedAt = now
	f.i.ValidUntil = now.Add(5 * time.Second)
	f.metadataUntil = f.i.ValidUntil
	inner.config.Now = func() time.Time { return now }
	combined, e := NewInvestigationOperations(inner, nil)
	if e != nil {
		t.Fatal(e)
	}
	mac, e := auditapp.NewOperationMAC("audit-v1", bytes.Repeat([]byte{1}, 32), "accounts-v1", bytes.Repeat([]byte{2}, 32))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(mac.Close)
	gate := &presentationAuditGate{}
	s := &AuditedOperations{config: AuditedOperationsConfig{RootID: "00000000-0000-4000-8000-000000000010", Retention: time.Hour, PerPrincipalConcurrency: 1, NormalPerSecond: 100, ResolutionPerSecond: 100, Now: inner.config.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000080" }}, inner: combined, audit: map[string]auditGate{"normal": gate, "resolution": gate}, mac: mac, contracts: inner.contracts, lanes: map[string]chan struct{}{"normal": make(chan struct{}, 1), "resolution": make(chan struct{}, 1)}, active: map[string]int{}, rate: map[string]auditRate{}}
	return s, f, gate
}
func TestAuditedOperationsUseOneServerIDAndNoPreAuditEffects(t *testing.T) {
	s, f, g := auditedFixture(t)
	reply, e := s.Call(context.Background(), f, "request_capture", []byte(wireRequest))
	if e != nil {
		t.Fatal(e)
	}
	var b OperationEnvelope
	if json.Unmarshal(reply.Body, &b) != nil || b.RequestID != g.intents[0].ID || b.RequestID != "00000000-0000-4000-8000-000000000080" {
		t.Fatal("inner generated second correlation ID")
	}
	if len(g.outcomes) != 1 || g.outcomes[0].Effect != "accepted" || g.outcomes[0].ClientReceipt != "unknown" || f.requests != 1 {
		t.Fatal(g, f.requests)
	}
	s, f, g = auditedFixture(t)
	g.beginFail = true
	if reply, e = s.Call(context.Background(), f, "request_capture", []byte(wireRequest)); e == nil || len(reply.Body) != 0 || f.requests != 0 {
		t.Fatal("unaudited operation ran")
	}
	s, f, g = auditedFixture(t)
	g.finishFail = true
	if reply, e = s.Call(context.Background(), f, "request_capture", []byte(wireRequest)); e == nil || len(reply.Body) != 0 || f.requests != 1 {
		t.Fatal("unaudited result escaped")
	}
}
func TestAuditedOperationsOriginalDeadlineRevocationAndCancellation(t *testing.T) {
	for _, mode := range []string{"deadline", "groups", "scope", "policy", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			s, f, g := auditedFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g.onFinish = func() {
				switch mode {
				case "deadline":
					s.config.Now = func() time.Time { return f.metadataUntil }
				case "groups":
					f.i.Groups = []string{"changed"}
				case "scope":
					f.i.Scopes = nil
				case "policy":
					f.i.Policy.Generation++
				case "cancel":
					cancel()
				}
			}
			reply, e := s.Call(ctx, f, "request_capture", []byte(wireRequest))
			if e == nil || len(reply.Body) != 0 || len(g.outcomes) != 1 || f.requests != 1 {
				t.Fatal("late audit renewed result", e)
			}
			if g.outcomes[0].ClientReceipt != "unknown" {
				t.Fatal("delivery claimed")
			}
		})
	}
}
func TestAuditedOperationsRecordInvalidScopeAndUnknownCommitWithoutArguments(t *testing.T) {
	s, f, g := auditedFixture(t)
	f.i.Scopes = nil
	if _, e := s.Call(context.Background(), f, "request_capture", []byte(wireRequest)); !errors.Is(e, identity.ErrDenied) || f.requests != 0 || len(g.outcomes) != 1 || g.outcomes[0].Status != "denied" {
		t.Fatal("scope denial not audited", e)
	}
	s, f, g = auditedFixture(t)
	if _, e := s.Call(context.Background(), f, "preview_capture", []byte(`{"reason":"private-free-text"}`)); e == nil || f.requests != 0 || len(g.outcomes) != 1 || g.outcomes[0].Status != "invalid" {
		t.Fatal("invalid request not audited")
	}
	b, _ := json.Marshal(g.intents)
	if bytes.Contains(b, []byte("private-free-text")) {
		t.Fatal("raw request persisted")
	}
	s, f, g = auditedFixture(t)
	f.err = errors.New("secret SQL connection details")
	reply, e := s.Call(context.Background(), f, "request_capture", []byte(wireRequest))
	if e != nil || g.outcomes[0].Effect != "unknown" || len(g.outcomes[0].CaptureIDs) != 0 || bytes.Contains(reply.Body, []byte("secret")) {
		t.Fatal("unknown commit misreported", e)
	}
}
func TestAuditedOperationsNormalizationAndReservedResolutionLane(t *testing.T) {
	s, f, _ := auditedFixture(t)
	a, e := s.normalize("request_capture", []byte(wireRequest))
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.normalize("request_capture", []byte(`{ "idempotency_key": "same-key", "preview_id":"00000000-0000-4000-8000-000000000020" }`))
	if e != nil || !bytes.Equal(a, b) {
		t.Fatal("normalization depends on input order")
	}
	p, _ := s.mac.Principal(f.i.Principal)
	release, ok := s.acquire("normal", p)
	if !ok {
		t.Fatal("first slot unavailable")
	}
	defer release()
	if _, e = s.Call(context.Background(), f, "get_capture", []byte(`{"capture_id":"00000000-0000-4000-8000-000000000030"}`)); e == nil {
		t.Fatal("normal pool unlimited")
	}
	if _, e = s.Call(context.Background(), f, "resolve_capture_request", []byte(wireRequest)); e != nil || f.resolutions != 1 {
		t.Fatal("normal pool starved resolution", e)
	}
	if len(s.active) != 1 {
		t.Fatal("completed account map leaked")
	}
}

func TestAuditedOperationFloorsSQLPrecisionWithoutExtendingCaller(t *testing.T) {
	s, f, g := auditedFixture(t)
	deadline := time.Now().Add(4*time.Second + 321*time.Nanosecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	reply, e := s.Call(ctx, f, "get_capture", []byte(`{"capture_id":"00000000-0000-4000-8000-000000000030"}`))
	if e != nil || len(g.intents) != 1 || g.intents[0].RequestUntil.After(deadline) || g.intents[0].RequestUntil.Nanosecond()%1000 != 0 || reply.ValidUntil.After(deadline) {
		t.Fatal("SQL precision reset deadline", e)
	}
}

func TestAuditedOperationsCaseUsesSameIDAndOnlyAuthorizedReferences(t *testing.T) {
	s, f, g := auditedFixture(t)
	cases, view, _ := caseOperationsFixture(t)
	now := f.i.VerifiedAt
	cases.config.Now = func() time.Time { return now }
	view.view.ObservedAt = now
	view.view.ValidUntil = now.Add(time.Second)
	view.view.Artifacts[0].ExpiresAt = now.Add(time.Hour)
	view.view.Artifacts[0].DeleteBy = now.Add(2 * time.Hour)
	var e error
	s.inner, e = NewInvestigationOperations(nil, cases)
	if e != nil {
		t.Fatal(e)
	}
	reply, e := s.Call(context.Background(), f, "get_case", []byte(caseInput))
	if e != nil {
		t.Fatal(e)
	}
	var envelope OperationEnvelope
	if json.Unmarshal(reply.Body, &envelope) != nil || envelope.RequestID != g.intents[0].ID || len(g.outcomes[0].CaseIDs) != 1 || g.outcomes[0].CaseIDs[0] != caseID || len(g.outcomes[0].ArtifactIDs) != 1 || g.outcomes[0].ArtifactIDs[0] != artifactID || len(g.outcomes[0].CaptureIDs) != 0 {
		t.Fatal("case audit projected private or wrong references")
	}
	if !reply.ValidUntil.Equal(view.view.ValidUntil) {
		t.Fatal("audit extended case metadata")
	}
}
func TestAuditedOperationsPreserveDisabledBrowserExplanation(t *testing.T) {
	s, f, g := auditedFixture(t)
	captures, _ := operationFixture(t, false)
	captures.config.Now = s.config.Now
	captures.captures = f
	captures.progress = f
	var e error
	s.inner, e = NewInvestigationOperations(captures, nil)
	if e != nil {
		t.Fatal(e)
	}
	if !BrowserOperationSupported(s, "request_capture") {
		t.Fatal("audit wrapper lost browser disabled explanation")
	}
	if _, ok := s.Tool("request_capture"); ok {
		t.Fatal("audit wrapper enabled mutation")
	}
	reply, e := s.Call(context.Background(), f, "request_capture", []byte(wireRequest))
	if e != nil || f.requests != 0 || len(g.outcomes) != 1 || !bytes.Contains(reply.Body, []byte("CollectionDisabled")) {
		t.Fatal("disabled request changed behavior", e)
	}
}

// Business services deliberately collapse denials into nondisclosing public
// envelopes. Audit must retain the private decision without interpreting that
// envelope as proof that an earlier same-key request was never admitted.
func TestAuditedOperationsPreservePrivateDenialDecision(t *testing.T) {
	for _, tt := range []struct {
		name, operation, input, status, reason, effect string
		serviceError                                   error
		readOnly, disabled                             bool
		dispatches, resolves                           int
	}{
		{name: "capture scope absent", operation: "request_capture", input: wireRequest, readOnly: true, status: "denied", reason: "not_available", effect: "none"},
		{name: "capture target denied", operation: "request_capture", input: wireRequest, serviceError: capturevalue.ErrDenied, dispatches: 1, status: "denied", reason: "not_available", effect: "unknown"},
		{name: "resolution target denied", operation: "resolve_capture_request", input: wireRequest, serviceError: capturevalue.ErrDenied, resolves: 1, status: "denied", reason: "not_available", effect: "unknown"},
		{name: "identity denied by service", operation: "request_capture", input: wireRequest, serviceError: identity.ErrDenied, dispatches: 1, status: "denied", reason: "not_available", effect: "unknown"},
		{name: "target resolver denied", operation: "request_capture", input: wireRequest, serviceError: targets.ErrDenied, dispatches: 1, status: "denied", reason: "not_available", effect: "unknown"},
		{name: "invalid service request", operation: "request_capture", input: wireRequest, serviceError: capturevalue.ErrInvalid, dispatches: 1, status: "invalid", reason: "invalid_input", effect: "unknown"},
		{name: "ambiguous commit", operation: "request_capture", input: wireRequest, serviceError: errors.New("private SQL detail"), dispatches: 1, status: "unavailable", reason: "authority_unavailable", effect: "unknown"},
		{name: "service deadline", operation: "request_capture", input: wireRequest, serviceError: context.DeadlineExceeded, dispatches: 1, status: "unavailable", reason: "authority_unavailable", effect: "unknown"},
		{name: "conflict is unresolved", operation: "request_capture", input: wireRequest, serviceError: capturevalue.ErrConflict, dispatches: 1, status: "unavailable", reason: "authority_unavailable", effect: "unknown"},
		{name: "collection disabled", operation: "request_capture", input: wireRequest, disabled: true, status: "unavailable", reason: "authority_unavailable", effect: "none"},
		{name: "read target denied", operation: "get_capture", input: `{"capture_id":"00000000-0000-4000-8000-000000000030"}`, serviceError: capturevalue.ErrDenied, status: "denied", reason: "not_available", effect: "none"},
		{name: "same public NotAvailable provider failure", operation: "get_capture", input: `{"capture_id":"00000000-0000-4000-8000-000000000030"}`, serviceError: errors.New("private provider detail"), status: "unavailable", reason: "authority_unavailable", effect: "none"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, f, g := auditedFixture(t)
			f.err = tt.serviceError
			if tt.readOnly {
				f.i.Scopes = []string{"evidence:read"}
			}
			if tt.disabled {
				s.inner.(*InvestigationOperations).captures.config.CollectionEnabled = false
			}
			reply, err := s.Call(context.Background(), f, tt.operation, []byte(tt.input))
			if err != nil || f.requests != tt.dispatches || f.resolutions != tt.resolves || len(g.outcomes) != 1 {
				t.Fatalf("canonical error envelope lost: err=%v dispatches=%d outcomes=%d", err, f.requests, len(g.outcomes))
			}
			out := g.outcomes[0]
			if out.Status != tt.status || out.Reason != tt.reason || out.Effect != tt.effect {
				t.Fatalf("audit decision = %s/%s/%s, want %s/%s/%s", out.Status, out.Reason, out.Effect, tt.status, tt.reason, tt.effect)
			}
			if out.ClientReceipt != "unknown" || len(out.CaptureIDs) != 0 || len(out.CaseIDs) != 0 || len(out.ArtifactIDs) != 0 || out.OutputBytes != int64(len(reply.Body)) {
				t.Fatal("error audit invented a result or lost exact output size")
			}
			expectedDigest, digestErr := s.mac.Digest("mcp-result/v1", reply.Body)
			if digestErr != nil || out.OutputDigest != expectedDigest {
				t.Fatal("private classification replaced the exact prepared-output digest")
			}
			if s.contracts.ValidateOutput(tt.operation, reply.Body) != nil || bytes.Contains(reply.Body, []byte("private")) || bytes.Contains(reply.Body, []byte("audit")) {
				t.Fatal("private classification escaped public envelope")
			}
		})
	}
}

func TestAuditedOperationsPreDispatchRejectionsHaveNoInvocationEffect(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		s, f, g := auditedFixture(t)
		input := wireRequest
		if invalid {
			input = `{"preview_id":"invalid"}`
		} else {
			f.i.Scopes = nil
		}
		if _, err := s.Call(context.Background(), f, "request_capture", []byte(input)); err == nil || f.requests != 0 || len(g.outcomes) != 1 || g.outcomes[0].Effect != "none" {
			t.Fatal("known pre-dispatch rejection has an uncertain invocation effect", err)
		}
	}
}

func TestContinuationAuditBindsExplicitActionWithoutChangingBusinessKey(t *testing.T) {
	s, f, g := auditedFixture(t)
	original, err := s.normalize("request_capture", []byte(wireRequest))
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"preview_id":"00000000-0000-4000-8000-000000000020","idempotency_key":"same-key","continue_acquisition":true}`)
	continuation, err := s.normalize("request_capture", input)
	if err != nil || bytes.Equal(original, continuation) || !bytes.Contains(continuation, []byte(`"continue_acquisition":true`)) {
		t.Fatal("audit lost explicit effect selection", err)
	}
	if _, err = s.Call(context.Background(), f, "request_capture", input); err != nil || f.continuations != 1 || f.requests != 0 || len(g.outcomes) != 1 {
		t.Fatal("continuation bypassed audited dispatch", err)
	}
}
