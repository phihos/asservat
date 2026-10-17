package browser

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/transport/presentation"
)

// Synthetic C-16 result; this test qualifies HTTP/session fencing only.
type browserCaseFixture struct {
	calls int
	until time.Time
	after func()
}

const browserCaseID = "00000000-0000-4000-8000-000000000080"

func (f *browserCaseFixture) GetContextCase(context.Context, identities.CurrentIdentity, string) (catalog.ContextCase, error) {
	f.calls++
	now := time.Now()
	until := f.until
	if until.IsZero() {
		until = now.Add(time.Second)
	}
	if f.after != nil {
		f.after()
	}
	return catalog.ContextCase{CaseID: browserCaseID, ObservedAt: now, ValidUntil: until, Artifacts: []catalog.ContextCaseArtifact{{ArtifactID: "00000000-0000-4000-8000-000000000081", CaptureID: "00000000-0000-4000-8000-000000000082", Target: authorization.Target{ClusterID: browserCaseID, NamespaceUID: "private-ns", WorkloadUID: "private-workload", PodUID: "private-pod"}, Version: artifact.Digest{1}, ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}}}, nil
}
func TestCaseBrowserUsesCurrentSessionCSRFAndNoUnavailableRoutes(t *testing.T) {
	var handler *InvestigationHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	sessions := &investigationSession{readOnly: true}
	cases := &browserCaseFixture{}
	ops, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, cases)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := presentation.NewInvestigationOperations(nil, ops)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewInvestigationHandler(SessionHandler{Origin: server.URL, Sessions: sessions}, combined, 4)
	if err != nil {
		t.Fatal(err)
	}
	request := func() *http.Request {
		r, e := http.NewRequest("POST", server.URL+"/api/v1/operations/get_case", strings.NewReader(`{"case_id":"`+browserCaseID+`"}`))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", server.URL)
		r.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
		return r
	}
	sendCase := func(r *http.Request) (int, string) {
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
			t.Fatal("cacheable evidence metadata")
		}
		return response.StatusCode, string(b)
	}
	for name, change := range map[string]func(*http.Request){
		"bad origin":             func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") },
		"bad CSRF":               func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"bearer mixed":           func(r *http.Request) { r.Header.Set("Authorization", "Bearer secret") },
		"unexpected idempotency": func(r *http.Request) { r.Header.Set("Idempotency-Key", "not-needed") },
		"unsupported input": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"case_id":"` + browserCaseID + `","include_raw":true}`))
			r.ContentLength = -1
		},
		"GET":                  func(r *http.Request) { r.Method = "GET" },
		"query":                func(r *http.Request) { r.URL.RawQuery = "case_id=other" },
		"capture unavailable":  func(r *http.Request) { r.URL.Path = "/api/v1/operations/request_capture" },
		"download unavailable": func(r *http.Request) { r.URL.Path = "/api/v1/operations/prepare_artifact_download" },
	} {
		t.Run(name, func(t *testing.T) {
			r := request()
			change(r)
			code, b := sendCase(r)
			if code < 400 || cases.calls != 0 || strings.Contains(b, "pod-status") {
				t.Fatal("invalid ingress reached case service", code, b)
			}
			if strings.Contains(name, "unavailable") && code != 404 {
				t.Fatal("unconfigured route did not return404", code)
			}
		})
	}
	code, b := sendCase(request())
	if code != 200 || cases.calls != 1 || !strings.Contains(b, `"kind":"pod-status"`) || strings.Contains(b, "private-") {
		t.Fatalf("valid case: %d %s", code, b)
	}
	// The final transport check happens after the mapper's output fence.
	cases.until = time.Now().Add(150 * time.Millisecond)
	before := sessions.calls
	sessions.beforeResolve = func() {
		if sessions.calls-before == 3 {
			<-time.After(time.Until(cases.until.Add(time.Millisecond)))
		}
	}
	code, b = sendCase(request())
	if code != 503 || strings.Contains(b, browserCaseID) {
		t.Fatalf("expired case delivered after final identity: %d %s", code, b)
	}
	sessions.beforeResolve = nil
	cases.until = time.Time{}
	cases.after = func() { sessions.revoked = true }
	code, b = sendCase(request())
	if code != 401 || strings.Contains(b, browserCaseID) {
		t.Fatalf("revoked session delivered case: %d %s", code, b)
	}
}
func TestBrowserRejectsTypedNilOperations(t *testing.T) {
	var cases *presentation.ContextCaseOperations
	if _, e := NewInvestigationHandler(SessionHandler{Origin: "https://console.invalid", Sessions: &investigationSession{}}, cases, 4); e == nil {
		t.Fatal("typed nil case operations")
	}
	var captures *presentation.ContextOperations
	if _, e := NewInvestigationHandler(SessionHandler{Origin: "https://console.invalid", Sessions: &investigationSession{}}, captures, 4); e == nil {
		t.Fatal("typed nil capture operations")
	}
}
