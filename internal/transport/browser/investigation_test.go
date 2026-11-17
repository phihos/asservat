package browser

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	captureapp "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/presentation"
)

type investigationSession struct {
	transportSession
	beforeResolve func()
	readOnly      bool
	finalUntil    time.Time
}

func (s *investigationSession) Resolve(ctx context.Context, cookie string, refresh bool) (identities.SessionView, error) {
	if s.beforeResolve != nil {
		s.beforeResolve()
	}
	v, err := s.transportSession.Resolve(ctx, cookie, refresh)
	v.Identity.Scopes = []string{"evidence:read"}
	if !s.readOnly {
		v.Identity.Scopes = append(v.Identity.Scopes, "evidence:capture")
	}
	if !s.finalUntil.IsZero() {
		v.Identity.ValidUntil = s.finalUntil
	}
	return v, err
}

type investigationCalls struct {
	requests    int
	collections int
	after       func()
	validUntil  time.Time
	hidden      atomic.Bool
}

func (f *investigationCalls) CheckDiagnostic(context.Context, identities.CurrentIdentity, targets.WorkloadRequest) (time.Time, error) {
	return time.Now().Add(time.Second), nil
}
func (f *investigationCalls) Preview(context.Context, identities.CurrentIdentity, value.ContextIntent) (captureapp.ContextPreviewResult, error) {
	return captureapp.ContextPreviewResult{}, value.ErrUnavailable
}
func (f *investigationCalls) Request(context.Context, identities.CurrentIdentity, captureapp.CaptureRequest) (value.Accepted, error) {
	f.collections++
	return f.receipt()
}
func (f *investigationCalls) receipt() (value.Accepted, error) {
	f.requests++
	if f.after != nil {
		f.after()
	}
	until := f.validUntil
	if until.IsZero() {
		until = time.Now().Add(time.Second)
	}
	return value.Accepted{MetadataValidUntil: until, CaptureID: "00000000-0000-4000-8000-000000000030"}, nil
}
func (f *investigationCalls) Get(context.Context, identities.CurrentIdentity, string) (value.ContextProgress, error) {
	if f.hidden.Load() {
		return value.ContextProgress{}, value.ErrDenied
	}
	until := f.validUntil
	if until.IsZero() {
		until = time.Now().Add(time.Second)
	}
	return value.ContextProgress{ValidUntil: until, CaptureID: "00000000-0000-4000-8000-000000000030", Revision: 1, Phase: "Pending", ActionPhase: "Pending", ReasonCode: "IntentAuditPending"}, nil
}

func TestInvestigationBrowserUsesCurrentSessionAndExactIdempotency(t *testing.T) {
	const op = "request_capture"
	var handler *InvestigationHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	sessions := &investigationSession{}
	calls := &investigationCalls{}
	ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{Clusters: localCluster, PublicOrigin: server.URL, CollectionEnabled: true, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, calls, calls)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewInvestigationHandler(SessionHandler{Origin: server.URL, Sessions: sessions}, ops, 4)
	if err != nil {
		t.Fatal(err)
	}
	const request = `{"preview":{"target_ref":{"cluster":"local","namespace":"payments","kind":"Deployment","name":"api"},"preset_ref":{"name":"pod-status","version":"v1"}},"expected_plan_digest":"1111111111111111111111111111111111111111111111111111111111111111","idempotency_key":"stable-key"`
	body := request + "}"
	makeRequest := func() *http.Request {
		r, e := http.NewRequest("POST", server.URL+"/api/v1/operations/"+op, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", server.URL)
		r.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
		r.Header.Set("Idempotency-Key", "stable-key")
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
		return r
	}
	send := func(r *http.Request) (int, string) {
		response, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		b, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		if response.Header.Get("Cache-Control") != "no-store, private" {
			t.Fatal("cacheable metadata")
		}
		return response.StatusCode, string(b)
	}
	for name, change := range map[string]func(*http.Request){
		"missing origin": func(r *http.Request) { r.Header.Del("Origin") },
		"bad csrf":       func(r *http.Request) { r.Header.Set("X-CSRF-Token", "wrong") },
		"different key":  func(r *http.Request) { r.Header.Set("Idempotency-Key", "other") },
		"duplicate key":  func(r *http.Request) { r.Header.Add("Idempotency-Key", "stable-key") },
		"missing key":    func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"mixed bearer":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer token") },
		"query":          func(r *http.Request) { r.URL.RawQuery = "x=y" },
		"encoding":       func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
		"unknown field": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(request + `,"sharing":{}}`))
			r.ContentLength = -1
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := makeRequest()
			change(r)
			code, _ := send(r)
			if code < 400 || calls.requests != 0 {
				t.Fatal("invalid ingress reached capture")
			}
		})
	}
	code, b := send(makeRequest())
	if code != 200 || calls.requests != 1 || !strings.Contains(b, `"phase":"Accepted"`) {
		t.Fatalf("valid request: %d %s", code, b)
	}

	// The final transport identity check is later than the service/presentation
	// checks. It must not extend a shorter permission observation while identity
	// remains valid. Wait only inside the injected identity service, never crypto.
	calls.validUntil = time.Now().Add(150 * time.Millisecond)
	startCalls := sessions.calls
	sessions.beforeResolve = func() {
		if sessions.calls-startCalls == 3 {
			<-time.After(time.Until(calls.validUntil.Add(time.Millisecond)))
		}
	}
	code, b = send(makeRequest())
	if code != 503 || strings.Contains(b, "00000000-0000-4000-8000-000000000030") {
		t.Fatalf("expired metadata disclosed after identity wait: %d %s", code, b)
	}
	sessions.beforeResolve = nil
	calls.validUntil = time.Time{}
	// One initial refresh is permitted; later checks remain read-only. Revocation
	// after an accepted effect suppresses the response without implying rollback.
	calls.after = func() { sessions.revoked = true }
	code, b = send(makeRequest())
	if code != 401 || calls.requests != 3 || strings.Contains(b, "00000000-0000-4000-8000-000000000030") {
		t.Fatal("revoked session disclosed receipt")
	}
}

type investigationDeadlineWriter struct {
	http.ResponseWriter
	observed chan time.Time
}

func (w investigationDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w investigationDeadlineWriter) SetWriteDeadline(d time.Time) error {
	w.observed <- d
	return http.NewResponseController(w.ResponseWriter).SetWriteDeadline(d)
}
func TestInvestigationFinalIdentityShorteningReachesSocket(t *testing.T) {
	var until, shorter time.Time
	calls := &investigationCalls{validUntil: until}
	sessions := &investigationSession{readOnly: true}
	sessions.beforeResolve = func() {
		if sessions.calls == 3 {
			sessions.finalUntil = shorter
		}
	}
	observed := make(chan time.Time, 4)
	var handler *InvestigationHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(investigationDeadlineWriter{w, observed}, r)
	}))
	defer server.Close()
	ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{Clusters: localCluster, PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, calls, calls)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewInvestigationHandler(SessionHandler{Origin: server.URL, Sessions: sessions}, ops, 4)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", server.URL+"/api/v1/operations/get_capture", strings.NewReader(`{"capture_id":"00000000-0000-4000-8000-000000000030"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", server.URL)
	req.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
	// Fixture setup is outside the measured request. Retain the exact
	// original2s/shorter1s intervals for the actual HTTP invocation.
	until = time.Now().Add(2 * time.Second)
	shorter = until.Add(-time.Second)
	calls.validUntil = until
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || sessions.calls != 4 || len(observed) != 2 {
		t.Fatalf("unexpected response %d %s calls=%d writes=%d error=%v", response.StatusCode, body, sessions.calls, len(observed), err)
	}
	<-observed
	if final := <-observed; !final.Equal(shorter) {
		t.Fatalf("lost final shorter identity: got=%v want=%v", final, shorter)
	}
}
