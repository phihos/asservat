package browser

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

type processingService struct {
	changes []value.ProcessingChange
	err     error
}

func (s *processingService) Change(ctx context.Context, current identities.CurrentIdentity, c value.ProcessingChange) (value.ProcessingReceipt, error) {
	if _, err := current.ResolveIdentity(ctx); err != nil {
		return value.ProcessingReceipt{}, err
	}
	s.changes = append(s.changes, c)
	if s.err != nil {
		return value.ProcessingReceipt{}, s.err
	}
	now := time.Now().UTC()
	return value.ProcessingReceipt{RootID: "00000000-0000-4000-8000-000000000041", Epoch: "00000000-0000-4000-8000-000000000042", RequestID: c.RequestID,
		OperationID: "00000000-0000-4000-8000-000000000043", State: "initialized", Sequence: 2, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}, nil
}

// ADR-210: the route needs the session, CSRF and one UUID Idempotency-Key,
// which becomes the change's request ID; it forwards only the change fields
// and answers every service refusal with 503.
func TestProcessingChangeRoute(t *testing.T) {
	var handler *ProcessingHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	service := &processingService{}
	var err error
	handler, err = NewProcessingHandler(SessionHandler{Origin: server.URL, Sessions: &investigationSession{}}, service)
	if err != nil {
		t.Fatal(err)
	}
	const key = "00000000-0000-4000-8000-000000000044"
	send := func(body string, header func(*http.Request)) (int, string) {
		r, _ := http.NewRequest("POST", server.URL+ProcessingChangesPath, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", server.URL)
		r.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
		r.Header.Set("Idempotency-Key", key)
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
		if header != nil {
			header(r)
		}
		response, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		b, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(b)
	}
	body := `{"action":"initialize_processing"}`
	status, reply := send(body, nil)
	var out map[string]any
	if status != http.StatusOK || json.Unmarshal([]byte(reply), &out) != nil || out["state"] != "initialized" || out["requestID"] != key || len(service.changes) != 1 || service.changes[0].RequestID != key || service.changes[0].Action != "initialize_processing" {
		t.Fatal("initialization reply", status, reply)
	}
	for name, mutate := range map[string]func(*http.Request){
		"missing CSRF":   func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"missing key":    func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"non-UUID key":   func(r *http.Request) { r.Header.Set("Idempotency-Key", "operator-key-0123456789") },
		"two keys":       func(r *http.Request) { r.Header.Add("Idempotency-Key", key) },
		"foreign origin": func(r *http.Request) { r.Header.Set("Origin", "https://attacker.invalid") },
		"text body":      func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
	} {
		if status, _ := send(body, mutate); status < 400 {
			t.Fatal("request accepted without", name, status)
		}
	}
	for _, bad := range []string{`{"action":"initialize_processing","requestID":"chosen"}`, `{"action":"delete_everything"}`, `{"action":"restrict_processing"}`} {
		if status, _ := send(bad, nil); status != http.StatusBadRequest {
			t.Fatal("invalid change accepted", bad, status)
		}
	}
	service.err = value.ErrUnavailable
	if status, _ := send(body, nil); status != http.StatusServiceUnavailable {
		t.Fatal("refusal not mapped to 503", status)
	}
	if len(service.changes) != 2 {
		t.Fatal("refused requests reached the service", len(service.changes))
	}
}
