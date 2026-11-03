package browser

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/transport/presentation"
)

// Transport-only refusal fixture. No synthetic approval or evidence is issued.
type browserRawRequest struct {
	presentation.GrantUseCase
	calls int
}

func (f *browserRawRequest) RequestRaw(context.Context, identities.CurrentIdentity, authapp.RawQueryRequestInput) (authorization.Grant, bool, error) {
	f.calls++
	return authorization.Grant{}, false, authapp.ErrGrantUnavailable
}
func TestRawAccessBrowserKeepsCSRFAndExactIdempotencyHeader(t *testing.T) {
	var handler *InvestigationHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	calls := &browserRawRequest{}
	operations, err := presentation.NewGrantOperations(server.URL, time.Now, func() string { return "00000000-0000-4000-8000-000000000099" }, calls)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewInvestigationHandler(SessionHandler{Origin: server.URL, Sessions: &investigationSession{}}, operations, 4)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"case_id":"00000000-0000-4000-8000-000000000001","artifact_digests":["` + strings.Repeat("1", 64) + `"],"operations":["download_artifact"],"reason":"inspect saved output","max_bytes":512,"expires_in_seconds":3600,"idempotency_key":"same-key"}`
	for _, mode := range []string{"missing csrf", "missing key", "wrong key", "duplicate key", "valid"} {
		req, _ := http.NewRequest("POST", server.URL+"/api/v1/operations/request_raw_access", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
		req.Header.Set("Idempotency-Key", "same-key")
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
		switch mode {
		case "missing csrf":
			req.Header.Del("X-CSRF-Token")
		case "missing key":
			req.Header.Del("Idempotency-Key")
		case "wrong key":
			req.Header.Set("Idempotency-Key", "different")
		case "duplicate key":
			req.Header.Add("Idempotency-Key", "same-key")
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if mode == "valid" {
			if response.StatusCode != 200 || calls.calls != 1 || !strings.Contains(string(b), `"code":"NotAvailable"`) {
				t.Fatal("valid request did not reach existing service", response.StatusCode, calls.calls, string(b))
			}
		} else if response.StatusCode == 200 || calls.calls != 0 {
			t.Fatal("invalid ingress reached grant service", mode, response.StatusCode, calls.calls)
		}
	}
}
