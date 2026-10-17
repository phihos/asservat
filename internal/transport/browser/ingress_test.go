package browser

import (
	"bytes"
	"context"
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
	identities "asservat.local/asservat/internal/application/identity"
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
func (*ingressAuditFixture) ClaimOperationWrite(context.Context, audit.OperationIntent, string) (bool, error) {
	panic("fixture receipt must exist")
}
func (*ingressAuditFixture) AcknowledgeOperation(context.Context, audit.OperationIntent, string, audit.Receipt) error {
	panic("fixture receipt must exist")
}
func (*ingressAuditFixture) CreateOperationIntent(context.Context, audit.OperationIntent) (audit.Receipt, error) {
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

type auditBrowserSession struct {
	investigationSession
	denyRead atomic.Bool
}

func (s *auditBrowserSession) Resolve(ctx context.Context, cookie string, refresh bool) (identities.SessionView, error) {
	v, e := s.investigationSession.Resolve(ctx, cookie, refresh)
	if s.denyRead.Load() {
		v.Identity.Scopes = nil
	}
	return v, e
}
func auditedBrowserFixture(t *testing.T) (*InvestigationHandler, *httptest.Server, *investigationCalls, *ingressAuditFixture, *ingressAuditFixture, *auditBrowserSession) {
	t.Helper()
	var h *InvestigationHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(server.Close)
	sessions := &auditBrowserSession{}
	calls := &investigationCalls{}
	ops, e := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, CollectionEnabled: true, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, calls, calls)
	if e != nil {
		t.Fatal(e)
	}
	inner, e := presentation.NewInvestigationOperations(ops, nil)
	if e != nil {
		t.Fatal(e)
	}
	mac, e := auditapp.NewOperationMAC("audit-v1", bytes.Repeat([]byte{1}, 32), "accounts-v1", bytes.Repeat([]byte{2}, 32))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(mac.Close)
	normal, resolution := &ingressAuditFixture{}, &ingressAuditFixture{}
	var sequence atomic.Uint64
	opsAudit, e := presentation.NewAuditedOperations(presentation.AuditedOperationsConfig{RootID: "00000000-0000-4000-8000-000000000010", Retention: time.Hour, NormalConcurrency: 2, ResolutionConcurrency: 1, PerPrincipalConcurrency: 2, NormalPerSecond: 100, ResolutionPerSecond: 100, Now: time.Now, NewID: func() string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", sequence.Add(1)) }}, inner, normal.auditor(time.Now), resolution.auditor(time.Now), mac)
	if e != nil {
		t.Fatal(e)
	}
	h, e = NewAuditedInvestigationHandler(SessionHandler{Origin: server.URL, Sessions: sessions}, opsAudit, 4)
	if e != nil {
		t.Fatal(e)
	}
	return h, server, calls, normal, resolution, sessions
}
func auditedBrowserRequest(t *testing.T, s *httptest.Server, name, body string) *http.Request {
	t.Helper()
	r, e := http.NewRequest("POST", s.URL+"/api/v1/operations/"+name, strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", s.URL)
	r.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
	if name == "request_capture" || name == "resolve_capture_request" {
		r.Header.Set("Idempotency-Key", "same-key")
	}
	return r
}
func sendAuditedBrowser(t *testing.T, s *httptest.Server, r *http.Request) (int, []byte) {
	t.Helper()
	response, e := s.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	b, e := io.ReadAll(response.Body)
	if e != nil {
		t.Fatal(e)
	}
	return response.StatusCode, b
}
func TestAuditedBrowserIngressRejectionsShareOneOwner(t *testing.T) {
	const body = `{"preview_id":"00000000-0000-4000-8000-000000000020","idempotency_key":"same-key"}`
	for _, mode := range []string{"key", "unknown", "media", "schema", "scope"} {
		t.Run(mode, func(t *testing.T) {
			_, server, calls, normal, resolution, sessions := auditedBrowserFixture(t)
			name, input := "resolve_capture_request", body
			if mode == "unknown" {
				name = "unknown-private-name"
			}
			if mode == "schema" {
				input = `{"idempotency_key":"same-key","private-user-input":"data"}`
			}
			if mode == "scope" {
				sessions.denyRead.Store(true)
			}
			req := auditedBrowserRequest(t, server, name, input)
			if mode == "key" {
				req.Header.Set("Idempotency-Key", "other")
			}
			if mode == "media" {
				req.Header.Set("Content-Type", "text/plain")
			}
			status, b := sendAuditedBrowser(t, server, req)
			n, o := normal.count()
			r, ro := resolution.count()
			if status < 400 || n != 1 || o != 1 || r != 0 || ro != 0 || calls.requests != 0 || normal.intents[0].Name != "invalid_operation" || normal.outcomes[0].Effect != "none" || bytes.Contains(b, []byte("private-user-input")) {
				t.Fatalf("rejection audit/dispatch %d %s normal=%d/%d resolution=%d/%d requests=%d", status, b, n, o, r, ro, calls.requests)
			}
		})
	}
}
func TestAuditedBrowserAuthenticationAndOversizeStayPreAdmission(t *testing.T) {
	for _, mode := range []string{"csrf", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			h, server, calls, normal, resolution, _ := auditedBrowserFixture(t)
			body := "{}"
			if mode == "oversize" {
				body = strings.Repeat("x", (32<<10)+1)
			}
			req := auditedBrowserRequest(t, server, "preview_capture", body)
			if mode == "csrf" {
				req.Header.Set("X-CSRF-Token", "invalid")
			}
			status, _ := sendAuditedBrowser(t, server, req)
			n, _ := normal.count()
			r, _ := resolution.count()
			count := h.SecurityCounters()
			if status < 400 || n != 0 || r != 0 || calls.requests != 0 || count.PreAdmission+count.Oversized != 1 {
				t.Fatal("unbounded pre-admission audit", status, n, r, count)
			}
		})
	}
}
func TestAuditedBrowserCallsDoNotDuplicateAudit(t *testing.T) {
	_, server, calls, normal, resolution, _ := auditedBrowserFixture(t)
	const body = `{"preview_id":"00000000-0000-4000-8000-000000000020","idempotency_key":"same-key"}`
	for _, name := range []string{"request_capture", "resolve_capture_request"} {
		status, b := sendAuditedBrowser(t, server, auditedBrowserRequest(t, server, name, body))
		if status != 200 {
			t.Fatalf("valid call failed %d %s", status, b)
		}
	}
	n, o := normal.count()
	r, ro := resolution.count()
	if n != 1 || o != 1 || r != 1 || ro != 1 || calls.collections != 1 || calls.requests != 2 {
		t.Fatal("duplicate audit/dispatch", n, o, r, ro, calls)
	}
}
func TestAuditedBrowserRejectRequiresAcknowledgement(t *testing.T) {
	h, server, calls, normal, _, _ := auditedBrowserFixture(t)
	normal.fail = true
	status, b := sendAuditedBrowser(t, server, auditedBrowserRequest(t, server, "unknown", "{}"))
	if status != 503 || calls.requests != 0 || bytes.Contains(b, []byte("provider")) || h.SecurityCounters().AuditUnavailable != 1 {
		t.Fatalf("unaudited rejection escaped: %d %s", status, b)
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
func TestBrowserRejectionPreservesOriginalDeadlineThroughFinalRead(t *testing.T) {
	for _, late := range []bool{false, true} {
		h, _, _, normal, _, _ := auditedBrowserFixture(t)
		current := &finalRejectionIdentity{until: time.Now().Add(100 * time.Millisecond), late: late}
		req := httptest.NewRequest("POST", "https://example.invalid/api/v1/operations/unknown", nil)
		w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		h.rejectIngress(w, req, current, "unknown", []byte("{}"), 400)
		if n, o := normal.count(); n != 1 || o != 1 {
			t.Fatal("missing audit", n, o)
		}
		if late {
			if w.Code != 503 || !w.until.IsZero() {
				t.Fatal("fresh identity renewed old rejection", w.Code, w.until)
			}
		} else if w.Code != 400 || w.until.IsZero() || w.until.After(current.until) {
			t.Fatal("response socket not bounded", w.Code, w.until, current.until)
		}
	}
}
