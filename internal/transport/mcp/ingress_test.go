package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

// Explicit test-only journal with pre-acknowledged synthetic receipts. It proves
// transport composition, not SQL/object custody or production audit authority.
type ingressAuditFixture struct {
	mu        sync.Mutex
	intents   []audit.OperationIntent
	outcomes  []audit.OperationOutcome
	onReserve func(context.Context)
	onOutcome func()
	onCreate  func(context.Context) error
	claims    atomic.Int64
	creates   atomic.Int64
	fail      bool
}

func ingressReceipt(in audit.OperationIntent, phase string) *audit.Receipt {
	return &audit.Receipt{Key: audit.OperationAuditKey(in.RootID, in.ID, phase), ETag: "synthetic", Bytes: 100, SHA256: artifact.Digest{1}}
}
func (f *ingressAuditFixture) ReserveOperation(ctx context.Context, in audit.OperationIntent) (audit.OperationSnapshot, error) {
	f.mu.Lock()
	f.intents = append(f.intents, in)
	f.mu.Unlock()
	if f.onReserve != nil {
		f.onReserve(ctx)
	}
	if f.fail {
		return audit.OperationSnapshot{}, errors.New("private provider error")
	}
	if f.onCreate != nil {
		return audit.OperationSnapshot{Intent: in}, nil
	}
	return audit.OperationSnapshot{Intent: in, IntentReceipt: ingressReceipt(in, "intent")}, nil
}
func (f *ingressAuditFixture) FreezeOperationOutcome(_ context.Context, out audit.OperationOutcome) (audit.OperationSnapshot, error) {
	f.mu.Lock()
	f.outcomes = append(f.outcomes, out)
	f.mu.Unlock()
	if f.onOutcome != nil {
		f.onOutcome()
	}
	return audit.OperationSnapshot{Intent: out.Intent, IntentReceipt: ingressReceipt(out.Intent, "intent"), Outcome: &out, OutcomeReceipt: ingressReceipt(out.Intent, "outcome")}, nil
}
func (f *ingressAuditFixture) ClaimOperationWrite(context.Context, audit.OperationIntent, string) (bool, error) {
	if f.onCreate != nil {
		f.claims.Add(1)
		return true, nil
	}
	panic("fixture receipt must exist")
}
func (*ingressAuditFixture) AcknowledgeOperation(context.Context, audit.OperationIntent, string, audit.Receipt) error {
	panic("fixture receipt must exist")
}
func (f *ingressAuditFixture) CreateOperationIntent(ctx context.Context, _ audit.OperationIntent) (audit.Receipt, error) {
	if f.onCreate != nil {
		f.creates.Add(1)
		return audit.Receipt{}, f.onCreate(ctx)
	}
	panic("fixture receipt must exist")
}
func (*ingressAuditFixture) FindOperationIntent(context.Context, audit.OperationIntent) (audit.Receipt, error) {
	panic("fixture receipt must exist")
}
func (*ingressAuditFixture) CreateOperationOutcome(context.Context, audit.OperationOutcome) (audit.Receipt, error) {
	panic("fixture receipt must exist")
}
func (*ingressAuditFixture) FindOperationOutcome(context.Context, audit.OperationOutcome) (audit.Receipt, error) {
	panic("fixture receipt must exist")
}
func (f *ingressAuditFixture) count() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.intents), len(f.outcomes)
}
func (f *ingressAuditFixture) auditor(now func() time.Time) auditapp.OperationAuditor {
	return auditapp.OperationAuditor{Journal: f, Objects: f, Acknowledgements: f, Now: now}
}
func auditedMCPFixture(t *testing.T) (*Handler, *httptest.Server, *mcpCaptureFixture, *ingressAuditFixture, *ingressAuditFixture, *atomic.Bool) {
	t.Helper()
	var h *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(server.Close)
	capture := &mcpCaptureFixture{}
	ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, CollectionEnabled: true, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, capture, capture)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := presentation.NewInvestigationOperations(ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := auditapp.NewOperationMAC("audit-v1", bytes.Repeat([]byte{1}, 32), "accounts-v1", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mac.Close)
	normal, resolution := &ingressAuditFixture{}, &ingressAuditFixture{}
	var sequence atomic.Uint64
	audited, err := presentation.NewAuditedOperations(presentation.AuditedOperationsConfig{RootID: "00000000-0000-4000-8000-000000000010", Retention: time.Hour, NormalConcurrency: 2, ResolutionConcurrency: 1, PerPrincipalConcurrency: 2, NormalPerSecond: 100, ResolutionPerSecond: 100, Now: time.Now, NewID: func() string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", sequence.Add(1)) }}, inner, normal.auditor(time.Now), resolution.auditor(time.Now), mac)
	if err != nil {
		t.Fatal(err)
	}
	denied := &atomic.Bool{}
	h, err = NewAuditedContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
		i := testIdentity()
		i.Scopes = append(i.Scopes, "evidence:capture")
		if denied.Load() {
			i.Scopes = nil
		}
		return i, nil
	}), audited)
	if err != nil {
		t.Fatal(err)
	}
	return h, server, capture, normal, resolution, denied
}
func TestAuditedMCPIngressRejectsOnceBeforeDispatchAcrossRevisions(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		for _, mode := range []string{"unknown", "schema", "scope", "sdk-params", "sdk-meta", "request-state", "missing-id", "null-id", "object-id", "oversized-name"} {
			t.Run(version+"/"+mode, func(t *testing.T) {
				_, server, capture, normal, resolution, denied := auditedMCPFixture(t)
				params := map[string]any{"name": "resolve_capture_request", "arguments": map[string]any{"preview_id": "00000000-0000-4000-8000-000000000020", "idempotency_key": "same-key"}}
				switch mode {
				case "unknown":
					params["name"] = "private-user-input"
				case "schema":
					params["arguments"] = map[string]any{"private-user-input": "x"}
				case "scope":
					denied.Store(true)
				case "sdk-params":
					params["requestState"] = 42
				case "request-state":
					params["requestState"] = "private-user-input"
				case "oversized-name":
					params["name"] = strings.Repeat("x", 9000)
				}
				req := rpcRequest(t, server, version, "tools/call", params)
				if mode == "sdk-meta" || mode == "missing-id" || mode == "null-id" || mode == "object-id" {
					raw, _ := io.ReadAll(req.Body)
					var frame map[string]any
					_ = json.Unmarshal(raw, &frame)
					switch mode {
					case "sdk-meta":
						frame["params"].(map[string]any)["_meta"] = "private-user-input"
					case "missing-id":
						delete(frame, "id")
					case "null-id":
						frame["id"] = nil
					case "object-id":
						frame["id"] = map[string]any{"private-user-input": true}
					}
					raw, _ = json.Marshal(frame)
					req.Body = io.NopCloser(bytes.NewReader(raw))
					req.ContentLength = int64(len(raw))
				}
				response, body := send(t, server, req)
				ni, no := normal.count()
				ri, ro := resolution.count()
				if ni != 1 || no != 1 || ri != 0 || ro != 0 || capture.calls.Load() != 0 {
					t.Fatalf("not exactly one normal rejection: normal=%d/%d resolution=%d/%d effects=%d status=%d body=%s", ni, no, ri, ro, capture.calls.Load(), response.StatusCode, body)
				}
				if normal.intents[0].Name != "invalid_operation" || normal.outcomes[0].Effect != "none" || bytes.Contains(body, []byte("private-user-input")) || len(body) > MaxResponseBytes {
					t.Fatalf("rejection leaked/dispatched: %s", body)
				}
				if mode == "scope" && normal.outcomes[0].Status != "denied" {
					t.Fatal("scope misclassified")
				}
			})
		}
	}
}
func TestAuditedMCPValidCallsHaveOneOwnerAndProtocolIsNotAnOperation(t *testing.T) {
	_, server, capture, normal, resolution, _ := auditedMCPFixture(t)
	for _, method := range []string{"initialize", "tools/list", "ping"} {
		params := map[string]any{}
		if method == "initialize" {
			params = map[string]any{"protocolVersion": "2025-11-25", "clientInfo": map[string]any{"name": "test", "version": "1"}, "capabilities": map[string]any{}}
		}
		send(t, server, rpcRequest(t, server, "2025-11-25", method, params))
	}
	if n, _ := normal.count(); n != 0 {
		t.Fatal("handshake/list consumed audit")
	}
	args := map[string]any{"preview_id": "00000000-0000-4000-8000-000000000020", "idempotency_key": "same-key"}
	for _, name := range []string{"request_capture", "resolve_capture_request"} {
		response, b := send(t, server, rpcRequest(t, server, "2025-11-25", "tools/call", map[string]any{"name": name, "arguments": args}))
		if response.StatusCode != 200 || bytes.Contains(b, []byte(`"error"`)) {
			t.Fatalf("valid call rejected %d %s", response.StatusCode, b)
		}
	}
	n, o := normal.count()
	r, ro := resolution.count()
	if n != 1 || o != 1 || r != 1 || ro != 1 || capture.calls.Load() != 1 {
		t.Fatal("duplicate audit or dispatch", n, o, r, ro, capture.calls.Load())
	}
}
func TestAuditedMCPUnavailableAuditBlocksEffectsAndCountsBoundedly(t *testing.T) {
	h, server, capture, normal, _, _ := auditedMCPFixture(t)
	normal.fail = true
	response, b := send(t, server, rpcRequest(t, server, "2025-11-25", "tools/call", map[string]any{"name": "unknown", "arguments": map[string]any{}}))
	if response.StatusCode != 503 || capture.calls.Load() != 0 || bytes.Contains(b, []byte("private")) || h.SecurityCounters().AuditUnavailable != 1 {
		t.Fatalf("failed audit escaped %d %s %#v", response.StatusCode, b, h.SecurityCounters())
	}
}
func TestAuditedMCPOriginalHTTPCancellationReachesBothRevisions(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			_, server, capture, normal, _, _ := auditedMCPFixture(t)
			entered, observed := make(chan struct{}), make(chan struct{})
			normal.onReserve = func(ctx context.Context) { close(entered); <-ctx.Done(); close(observed) }
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			req := rpcRequest(t, server, version, "tools/call", map[string]any{"name": "request_capture", "arguments": map[string]any{"preview_id": "00000000-0000-4000-8000-000000000020", "idempotency_key": "same-key"}}).WithContext(ctx)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				response, _ := server.Client().Do(req)
				if response != nil {
					response.Body.Close()
				}
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("audit not entered")
			}
			cancel()
			select {
			case <-observed:
			case <-time.After(time.Second):
				t.Fatal("SDK detached original HTTP cancellation")
			}
			<-finished
			if capture.calls.Load() != 0 {
				t.Fatal("canceled request dispatched")
			}
		})
	}
}
func TestMCPAttemptCASPreventsLateDispatchAndAuditDuplication(t *testing.T) {
	for _, cancelFirst := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		a := &operationAttempt{owner: ctx}
		if cancelFirst {
			cancel()
		}
		var winners atomic.Int64
		var wg sync.WaitGroup
		for i := range 32 {
			wg.Go(func() {
				kind := attemptDispatched
				if i%2 == 0 {
					kind = attemptRejected
				}
				if a.claim(kind) {
					winners.Add(1)
				}
			})
		}
		wg.Wait()
		cancel()
		a.close()
		want := int64(1)
		if cancelFirst {
			want = 0
		}
		if winners.Load() != want || a.claim(attemptDispatched) {
			t.Fatal("multiple/late invocation owners")
		}
	}
}

// Explicit identity fake tests the transport's own bound independently of the
// production CurrentIdentity's additional original-request lifetime fence.
type finalRejectionIdentity struct {
	until time.Time
	calls int
	late  bool
}

func (f *finalRejectionIdentity) ResolveIdentity(context.Context) (identity.Identity, error) {
	f.calls++
	if f.late && f.calls == 3 {
		<-time.After(time.Until(f.until.Add(time.Millisecond)))
	}
	now := time.Now()
	until := f.until
	if f.calls == 3 {
		until = now.Add(5 * time.Second)
	}
	return identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, Scopes: []string{"evidence:read"}, VerifiedAt: now, ValidUntil: until}, nil
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	until time.Time
}

func (w *deadlineRecorder) SetWriteDeadline(until time.Time) error { w.until = until; return nil }

func TestMCPRejectionPreservesOriginalDeadlineThroughFinalRead(t *testing.T) {
	for _, late := range []bool{false, true} {
		h, _, _, normal, _, _ := auditedMCPFixture(t)
		current := &finalRejectionIdentity{until: time.Now().Add(100 * time.Millisecond), late: late}
		req := httptest.NewRequest("POST", "https://example.invalid/mcp", nil)
		w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		delivery := &operationDeadline{until: time.Now().Add(5 * time.Second)}
		ok := h.rejectIngress(w, req, current, delivery, "unknown", []byte("{}"), presentation.IngressInvalid)
		if n, o := normal.count(); n != 1 || o != 1 {
			t.Fatal("missing audit", n, o)
		}
		if late {
			if ok || w.Code != 503 || !w.until.IsZero() {
				t.Fatal("fresh identity renewed old rejection", w.Code, w.until)
			}
		} else if !ok || w.until.IsZero() || w.until.After(current.until) {
			t.Fatal("response socket not bounded", w.Code, w.until, current.until)
		}
	}
}
