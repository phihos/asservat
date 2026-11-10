package browser

import (
	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type processingInventoryService struct {
	calls   int
	query   value.ProcessingInventoryQuery
	err     error
	expired bool
}

func (s *processingInventoryService) List(ctx context.Context, current app.CurrentIdentity, q value.ProcessingInventoryQuery) (value.ProcessingInventoryPage, error) {
	s.calls++
	s.query = q
	if _, err := current.ResolveIdentity(ctx); err != nil {
		return value.ProcessingInventoryPage{}, err
	}
	n := time.Now().UTC()
	until := n.Add(5 * time.Second)
	if s.expired {
		until = n.Add(-time.Second)
	}
	return value.ProcessingInventoryPage{RootID: "00000000-0000-4000-8000-000000000041", Epoch: "00000000-0000-4000-8000-000000000042", Initialized: true, Sequence: 3, Rules: []value.ProcessingInventoryRule{{ID: "00000000-0000-4000-8000-000000000043", Revision: 1, State: "restricted", Scope: value.ProcessingScope{Kind: "artifact", Location: artifact.Location{ClusterID: "00000000-0000-4000-8000-000000000044", ArtifactID: "00000000-0000-4000-8000-000000000045", AttemptID: "00000000-0000-4000-8000-000000000046"}}, AdministrationUntil: n.Add(time.Hour), RetireBy: n.Add(2 * time.Hour)}}, ObservedAt: n, ValidUntil: until}, s.err
}
func TestProcessingInventoryRouteIsBoundedAuthenticatedAndCanonical(t *testing.T) {
	var handler *ProcessingInventoryHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	service := &processingInventoryService{}
	var err error
	handler, err = NewProcessingInventoryHandler(SessionHandler{Origin: server.URL, Sessions: &investigationSession{}}, service)
	if err != nil {
		t.Fatal(err)
	}
	send := func(query string, edit func(*http.Request)) (int, []byte, http.Header) {
		t.Helper()
		r, _ := http.NewRequest(http.MethodGet, server.URL+ProcessingRulesPath+query, nil)
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
		if edit != nil {
			edit(r)
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		return response.StatusCode, raw, response.Header
	}
	status, raw, headers := send("", nil)
	var out processingInventoryReply
	if status != 200 || json.Unmarshal(raw, &out) != nil || len(out.Rules) != 1 || out.Rules[0].Scope.Kind != "artifact" || service.query.Limit != 50 || headers.Get("Cache-Control") != "no-store, private" {
		t.Fatal(status, string(raw), headers)
	}
	var wire map[string]any
	_ = json.Unmarshal(raw, &wire)
	scope := wire["rules"].([]any)[0].(map[string]any)["scope"].(map[string]any)
	if _, ok := scope["Kind"]; ok {
		t.Fatal("domain field names leaked into browser scope")
	}
	if len(scope) != 2 || scope["kind"] != "artifact" {
		t.Fatal(scope)
	}
	before := service.calls
	for _, query := range []string{"?limit=0", "?limit=101", "?limit=1&limit=2", "?after=", "?after=unknown", "?other=1", "?after=00000000-0000-4000-8000-000000000042&after=00000000-0000-4000-8000-000000000043"} {
		if status, _, _ := send(query, nil); status != 400 {
			t.Fatal("invalid page query", query, status)
		}
	}
	if service.calls != before {
		t.Fatal("invalid query reached operator service")
	}
	if status, _, _ := send("", func(r *http.Request) { r.Header.Set("Cookie", "") }); status < 400 {
		t.Fatal("anonymous inventory")
	}
	service.err = value.ErrUnavailable
	if status, _, _ := send("", nil); status != 503 {
		t.Fatal("operator refusal leaked inventory", status)
	}
	service.err = nil
	service.expired = true
	if status, _, _ := send("", nil); status != 503 {
		t.Fatal("expired page disclosed", status)
	}
}
func TestProcessingCanonicalScopeAndArtifactSelectorRequests(t *testing.T) {
	var handler *ProcessingHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	service := &processingService{}
	handler, _ = NewProcessingHandler(SessionHandler{Origin: server.URL, Sessions: &investigationSession{}}, service)
	send := func(body string) int {
		t.Helper()
		r, _ := http.NewRequest(http.MethodPost, server.URL+ProcessingChangesPath, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", server.URL)
		r.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
		r.Header.Set("Idempotency-Key", "00000000-0000-4000-8000-000000000041")
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	const rule = "00000000-0000-4000-8000-000000000043"
	const artifactID = "00000000-0000-4000-8000-000000000045"
	if code := send(`{"action":"restrict_processing","ruleID":"` + rule + `","expectedRevision":0,"artifactID":"` + artifactID + `"}`); code != 200 || len(service.changes) != 1 || service.changes[0].RequestedArtifactID != artifactID || service.changes[0].Valid() {
		t.Fatal("transient artifact selector", code)
	}
	const scope = `{"kind":"artifact","location":{"clusterID":"00000000-0000-4000-8000-000000000044","artifactID":"` + artifactID + `","attemptID":"00000000-0000-4000-8000-000000000046"}}`
	release := `{"action":"release_processing","ruleID":"` + rule + `","expectedRevision":1,"scope":` + scope + `}`
	if code := send(release); code != 200 || len(service.changes) != 2 || !service.changes[1].Valid() || service.changes[1].Scope.Location.ArtifactID != artifactID {
		t.Fatal("canonical release scope", code)
	}
	for _, bad := range []string{`{"action":"initialize_processing","scope":{}}`, `{"action":"initialize_processing","expectedRevision":0}`, `{"action":"initialize_processing","artifactID":""}`, `{"action":"initialize_processing","scope":null}`, `{"action":"initialize_processing","expectedRevision":null}`, `{"action":"initialize_processing","ruleID":null}`, `{"action":"initialize_processing","artifactID":null}`, `{"action":"restrict_processing","ruleID":"` + rule + `","expectedRevision":null,"artifactID":"` + artifactID + `"}`, `{"Action":"initialize_processing"}`, `{"action":"release_processing","ruleID":"` + rule + `","expectedRevision":1,"artifactID":"` + artifactID + `"}`, `{"action":"restrict_processing","ruleID":"` + rule + `","artifactID":"` + artifactID + `","scope":` + scope + `}`, release + `{}`} {
		if code := send(bad); code != 400 {
			t.Fatal("invalid scope/selector accepted", code)
		}
	}
	service.err = value.ErrConflict
	if code := send(release); code != 409 {
		t.Fatal("definite conflict treated as uncertain effect", code)
	}
}
