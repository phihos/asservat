package browser

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/transport/presentation"
)

type browserDownloadFixture struct{ stops int }

func (f *browserDownloadFixture) PrepareContextDownload(context.Context, identities.CurrentIdentity, string, string) (evidence.ContextDownloadView, error) {
	return evidence.ContextDownloadView{}, artifact.ErrDownloadUnavailable
}
func (f *browserDownloadFixture) GetContextDownload(context.Context, identities.CurrentIdentity, string) (evidence.ContextDownloadView, error) {
	return evidence.ContextDownloadView{}, artifact.ErrDownloadUnavailable
}
func (f *browserDownloadFixture) CancelContextDownload(ctx context.Context, current identities.CurrentIdentity, id, key, request string) (artifact.DownloadStopReceipt, error) {
	i, e := current.ResolveIdentity(ctx)
	if e != nil {
		return artifact.DownloadStopReceipt{}, e
	}
	f.stops++
	return artifact.DownloadStopReceipt{DownloadID: id, RequestID: request, State: "Cancelled", AuditState: "pending", ObservedAt: time.Now(), ValidUntil: i.ValidUntil}, nil
}
func TestBrowserStopWithoutEvidenceScopesSurvivesNormalSaturation(t *testing.T) {
	var h *InvestigationHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	defer server.Close()
	sessions := &transportSession{}
	f := &browserDownloadFixture{}
	ops, e := presentation.NewContextDownloadOperations(presentation.ContextDownloadOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000080" }}, f, f)
	if e != nil {
		t.Fatal(e)
	}
	h, e = NewInvestigationHandler(SessionHandler{Origin: server.URL, Sessions: sessions}, ops, 1)
	if e != nil {
		t.Fatal(e)
	}
	h.slots <- struct{}{}
	defer func() { <-h.slots }()
	const body = `{"download_id":"00000000-0000-4000-8000-000000000090","idempotency_key":"same-key"}`
	r, e := http.NewRequest("POST", server.URL+"/api/v1/operations/cancel_artifact_download", strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Origin", server.URL)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
	r.Header.Set("Idempotency-Key", "same-key")
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
	response, e := server.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	b, e := io.ReadAll(response.Body)
	if e != nil || response.StatusCode != 200 || f.stops != 1 || !strings.Contains(string(b), `"state":"Cancelled"`) {
		t.Fatal(response.StatusCode, string(b), e)
	}
	// Invalid input is ordinary rejected work, never a reservation in the
	// protected Stop lane. The saturated normal lane must reject it promptly.
	bad, e := http.NewRequest("POST", server.URL+"/api/v1/operations/cancel_artifact_download", strings.NewReader(`{"download_id":"invalid","idempotency_key":"same-key"}`))
	if e != nil {
		t.Fatal(e)
	}
	bad.Header = r.Header.Clone()
	invalid, e := server.Client().Do(bad)
	if e != nil {
		t.Fatal(e)
	}
	defer invalid.Body.Close()
	if invalid.StatusCode != 429 || f.stops != 1 {
		t.Fatal("invalid input used Stop lane", invalid.StatusCode, f.stops)
	}
	// The explicit authenticated POST retains normal SessionHandler refresh
	// semantics. This fake counts refresh permission, not an actual rotation.
}
