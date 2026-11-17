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

// presentationAuditGate records the call rows the wrapper writes.
type presentationAuditGate struct {
	events   []audit.Event
	fail     bool
	onRecord func()
}

func (g *presentationAuditGate) Record(_ context.Context, e audit.Event) error {
	g.events = append(g.events, e)
	if g.onRecord != nil {
		g.onRecord()
	}
	if g.fail {
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
	s := &AuditedOperations{config: AuditedOperationsConfig{RootID: "00000000-0000-4000-8000-000000000010", Now: inner.config.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000080" }}, inner: combined, recorder: gate, mac: mac, contracts: inner.contracts, stopSlots: make(chan struct{}, 4)}
	return s, f, gate
}
func TestAuditedOperationsUseOneServerIDAndNoPreAuditEffects(t *testing.T) {
	s, f, g := auditedFixture(t)
	reply, e := s.Call(context.Background(), f, "request_capture", []byte(wireRequest))
	if e != nil {
		t.Fatal(e)
	}
	var b OperationEnvelope
	if json.Unmarshal(reply.Body, &b) != nil || b.RequestID != g.events[0].OperationID || b.RequestID != "00000000-0000-4000-8000-000000000080" {
		t.Fatal("inner generated second correlation ID")
	}
	if len(g.events) != 1 || g.events[0].Kind != "call" || g.events[0].Operation != "request_capture" || g.events[0].Effect != "accepted" || f.requests != 1 {
		t.Fatal(g, f.requests)
	}
	s, f, g = auditedFixture(t)
	g.fail = true
	if reply, e = s.Call(context.Background(), f, "request_capture", []byte(wireRequest)); e == nil || len(reply.Body) != 0 || f.requests != 1 {
		t.Fatal("unaudited result escaped")
	}
}
func TestAuditedOperationsOriginalDeadline(t *testing.T) {
	for _, mode := range []string{"deadline"} {
		t.Run(mode, func(t *testing.T) {
			s, f, g := auditedFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g.onRecord = func() {
				s.config.Now = func() time.Time { return f.metadataUntil }
			}
			reply, e := s.Call(ctx, f, "request_capture", []byte(wireRequest))
			if e == nil || len(reply.Body) != 0 || len(g.events) != 1 || f.requests != 1 {
				t.Fatal("late audit renewed result", e)
			}
		})
	}
}
func TestAuditedOperationsRecordInvalidScopeAndUnknownCommitWithoutArguments(t *testing.T) {
	s, f, g := auditedFixture(t)
	f.i.Scopes = nil
	if _, e := s.Call(context.Background(), f, "request_capture", []byte(wireRequest)); !errors.Is(e, identity.ErrDenied) || f.requests != 0 || len(g.events) != 1 || g.events[0].Status != "denied" {
		t.Fatal("scope denial not audited", e)
	}
	s, f, g = auditedFixture(t)
	if _, e := s.Call(context.Background(), f, "preview_capture", []byte(`{"reason":"private-free-text"}`)); e == nil || f.requests != 0 || len(g.events) != 1 || g.events[0].Status != "invalid" {
		t.Fatal("invalid request not audited")
	}
	b, _ := json.Marshal(g.events)
	if bytes.Contains(b, []byte("private-free-text")) {
		t.Fatal("raw request persisted")
	}
	s, f, g = auditedFixture(t)
	f.err = errors.New("secret SQL connection details")
	reply, e := s.Call(context.Background(), f, "request_capture", []byte(wireRequest))
	if e != nil || g.events[0].Effect != "unknown" || len(g.events[0].CaptureIDs) != 0 || bytes.Contains(reply.Body, []byte("secret")) {
		t.Fatal("unknown commit misreported", e)
	}
}
func TestAuditedOperationsNormalizationIgnoresInputOrder(t *testing.T) {
	s, _, _ := auditedFixture(t)
	a, e := s.normalize("request_capture", []byte(wireRequest))
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.normalize("request_capture", []byte(`{ "idempotency_key": "same-key", "expected_plan_digest": "`+wirePlanDigest+`", "preview": {"requested_retention_seconds":60, "preset_ref":{"version":"v1","name":"pod-status"}, `+wireTarget+`} }`))
	if e != nil || !bytes.Equal(a, b) {
		t.Fatal("normalization depends on input order")
	}
}

func TestAuditedOperationDoesNotExtendCallerDeadline(t *testing.T) {
	s, f, g := auditedFixture(t)
	deadline := time.Now().Add(4*time.Second + 321*time.Nanosecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	reply, e := s.Call(ctx, f, "get_capture", []byte(`{"capture_id":"00000000-0000-4000-8000-000000000030"}`))
	if e != nil || len(g.events) != 1 || reply.ValidUntil.After(deadline) {
		t.Fatal("reply outlived caller deadline", e)
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
	if json.Unmarshal(reply.Body, &envelope) != nil || envelope.RequestID != g.events[0].OperationID || len(g.events[0].CaseIDs) != 1 || g.events[0].CaseIDs[0] != caseID || len(g.events[0].ArtifactIDs) != 1 || g.events[0].ArtifactIDs[0] != artifactID || len(g.events[0].CaptureIDs) != 0 {
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
	if e != nil || f.requests != 0 || len(g.events) != 1 || !bytes.Contains(reply.Body, []byte("CollectionDisabled")) {
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
		dispatches                                     int
	}{
		{name: "capture scope absent", operation: "request_capture", input: wireRequest, readOnly: true, status: "denied", reason: "not_available", effect: "none"},
		{name: "capture target denied", operation: "request_capture", input: wireRequest, serviceError: capturevalue.ErrDenied, dispatches: 1, status: "denied", reason: "not_available", effect: "unknown"},
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
			if err != nil || f.requests != tt.dispatches || len(g.events) != 1 {
				t.Fatalf("canonical error envelope lost: err=%v dispatches=%d outcomes=%d", err, f.requests, len(g.events))
			}
			out := g.events[0]
			if out.Status != tt.status || out.Reason != tt.reason || out.Effect != tt.effect {
				t.Fatalf("audit decision = %s/%s/%s, want %s/%s/%s", out.Status, out.Reason, out.Effect, tt.status, tt.reason, tt.effect)
			}
			if len(out.CaptureIDs) != 0 || len(out.CaseIDs) != 0 || len(out.ArtifactIDs) != 0 || out.OutputBytes != int64(len(reply.Body)) {
				t.Fatal("error audit invented a result or lost exact output size")
			}
			expectedDigest, digestErr := s.mac.Digest("mcp-result/v1", reply.Body)
			if digestErr != nil || out.OutputDigest == nil || *out.OutputDigest != expectedDigest {
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
		if _, err := s.Call(context.Background(), f, "request_capture", []byte(input)); err == nil || f.requests != 0 || len(g.events) != 1 || g.events[0].Effect != "none" {
			t.Fatal("known pre-dispatch rejection has an uncertain invocation effect", err)
		}
	}
}

// native61/62: a read-only session asking for a download gets the audited
// NotAvailable reply, not a transport failure; nothing is dispatched.
func TestAuditedDownloadWithoutDownloadScopeIsADenialReply(t *testing.T) {
	s, f, g := auditedFixture(t)
	f.i.Scopes = []string{"evidence:read"}
	reply, err := s.Call(context.Background(), f, "download_artifact", []byte(`{"action":"prepare","artifact_id":"00000000-0000-4000-8000-000000000030","idempotency_key":"key"}`))
	if err != nil || len(g.events) != 1 || g.events[0].Effect != "none" || !bytes.Contains(reply.Body, []byte(`"status":"error"`)) || s.contracts.ValidateOutput("download_artifact", reply.Body) != nil {
		t.Fatalf("err=%v outcomes=%d body=%s", err, len(g.events), reply.Body)
	}
}
