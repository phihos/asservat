package browser

import (
	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/presentation"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type browserRecordingFixture struct{ calls int }

func (f *browserRecordingFixture) List(context.Context, identities.CurrentIdentity, targets.WorkloadRequest, string, string, int) (app.RecordingPage, error) {
	f.calls++
	now := time.Now()
	return app.RecordingPage{ExpiresAt: now.Add(time.Minute), ValidUntil: now.Add(time.Second)}, nil
}
func (*browserRecordingFixture) Preview(context.Context, identities.CurrentIdentity, app.RecordingSavePreviewRequest) (app.ContextPreviewResult, error) {
	return app.ContextPreviewResult{}, value.ErrUnavailable
}
func (f *browserRecordingFixture) Cancel(_ context.Context, _ identities.CurrentIdentity, r value.CancellationRequest) (value.Cancellation, error) {
	f.calls++
	now := time.Now()
	return value.Cancellation{CaptureID: r.CaptureID, Revision: 2, Phase: "Running", Requested: true, ObservedAt: now, ValidUntil: now.Add(time.Second)}, nil
}
func TestRecordingSaveBrowserRoutesPreserveCSRFAndCancellationIdempotency(t *testing.T) {
	var handler *InvestigationHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	ordinary := &investigationCalls{}
	base, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, CollectionEnabled: true, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, ordinary, ordinary)
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := presentation.NewInvestigationOperations(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &browserRecordingFixture{}
	saves, err := presentation.NewRecordingSaveOperations(presentation.RecordingSaveOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f, f)
	if err != nil {
		t.Fatal(err)
	}
	composed, err := presentation.NewInvestigationRecordingSaveOperations(aggregate, saves)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewInvestigationHandler(SessionHandler{Origin: server.URL, Sessions: &investigationSession{}}, composed, 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"list_recordings", "preview_recording_save", "cancel_capture"} {
		if _, ok := composed.Tool(name); !ok {
			t.Fatal("missing route", name)
		}
	}
	body := `{"capture_id":"00000000-0000-4000-8000-000000000030","expected_revision":1,"idempotency_key":"cancel-once"}`
	for _, mode := range []string{"csrf missing", "key mismatch", "valid"} {
		req, _ := http.NewRequest("POST", server.URL+"/api/v1/operations/cancel_capture", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
		req.Header.Set("Idempotency-Key", "cancel-once")
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
		if mode == "csrf missing" {
			req.Header.Del("X-CSRF-Token")
		}
		if mode == "key mismatch" {
			req.Header.Set("Idempotency-Key", "other")
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if mode == "valid" {
			if response.StatusCode != 200 || !strings.Contains(string(b), `"cancellation_requested":true`) || !strings.Contains(string(b), `"phase":"Running"`) || f.calls != 1 {
				t.Fatal(response.StatusCode, string(b), f.calls)
			}
		} else if response.StatusCode == 200 || f.calls != 0 {
			t.Fatal("invalid request reached cancellation", mode, response.StatusCode, f.calls)
		}
	}
}
