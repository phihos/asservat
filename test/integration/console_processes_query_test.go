package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/console"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/transport/browser"
	"asservat.local/asservat/internal/transport/presentation"
)

type consoleProcessHistory struct{ *consoleSyntheticHistory }

func (h consoleProcessHistory) Settings(ctx context.Context, current identities.CurrentIdentity, id string) (value.CaptureSettings, error) {
	s, err := h.consoleSyntheticHistory.Settings(ctx, current, id)
	if err == nil {
		s.RecipeJSON = []byte(`{"description":"Synthetic saved process metadata","actions":[{"id":"inventory","kind":"processSnapshot","parameters":{"include":["identity","status","threads","cgroups"]},"executionMode":"onTrigger","required":true,"impact":"observe","limits":{"maxBytes":2097152,"timeout":"5s"}}],"maxTotalBytes":2097152,"maxDuration":"10s"}`)
	}
	return s, err
}

type consoleProcessOperations struct {
	mu                sync.Mutex
	origin            string
	wire              *contracts.InvestigationContracts
	captures          *presentation.ContextOperations
	source            savedProcessesBrowserSource
	starts, polls     int
	observed, expires time.Time
}

func (s *consoleProcessOperations) PublicOrigin() string { return s.origin }
func (s *consoleProcessOperations) ToolNames() []string {
	return []string{"get_capture", "get_capture_settings", "get_target_discovery", "get_query_result"}
}
func (s *consoleProcessOperations) Tool(n string) (contracts.InvestigationTool, bool) {
	return s.wire.Tool(n)
}
func (s *consoleProcessOperations) Call(ctx context.Context, i identities.CurrentIdentity, name string, input json.RawMessage) (presentation.OperationReply, error) {
	if name == "get_capture" || name == "get_capture_settings" {
		return s.captures.Call(ctx, i, name, input)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := i.ResolveIdentity(ctx); err != nil {
		return presentation.OperationReply{}, err
	}
	if s.wire.ValidateInput(name, input) != nil {
		return presentation.OperationReply{}, contracts.ErrInvestigationWire
	}
	var in map[string]any
	if json.Unmarshal(input, &in) != nil {
		return presentation.OperationReply{}, contracts.ErrInvestigationWire
	}
	now := time.Now().UTC()
	envelope := map[string]any{"schema_version": "mcp-result/v1", "request_id": consoleCaptureID(500 + s.polls), "data_class": "extract", "status": "ok", "truncated": false, "next_cursor": nil, "narrowing_hint": nil, "warnings": []string{}, "provenance": []any{}}
	handle := consoleCaptureID(90)
	switch name {
	case "get_target_discovery":
		if s.starts != 0 || in["capture_id"] != s.source.CaptureID || in["section"] != "processes" || in["limit"] != float64(20) {
			return presentation.OperationReply{}, contracts.ErrInvestigationWire
		}
		s.starts++
		s.observed, s.expires = now, now.Add(20*time.Second)
		envelope["status"] = "pending"
		envelope["data_class"] = "metadata"
		envelope["data"] = map[string]any{"query_handle": handle, "retry_after_seconds": 1, "query_observed_at": now, "query_expires_at": s.expires}
	case "get_query_result":
		if s.starts != 1 || s.polls != 0 || in["query_handle"] != handle {
			return presentation.OperationReply{}, contracts.ErrInvestigationWire
		}
		s.polls++
		inner := map[string]any{}
		for k, v := range envelope {
			inner[k] = v
		}
		inner["provenance"] = []any{map[string]any{"artifactID": s.source.ArtifactID, "digest": s.source.Version}}
		rows := []any{map[string]any{"process_ref": strings.Repeat("1", 64), "pod_uid": "synthetic-pod-uid", "display_pid": 7, "executable_name": "<img src=x>", "executable_path": "/app/<img src=x>", "runtime": "unknown", "identity_basis": map[string]string{"confidence": "observed", "reason": "Synthetic identity observation."}, "rss_bytes": 0, "observed_at": s.observed}}
		inner["data"] = map[string]any{"kind": "discoveryPage", "capture_id": s.source.CaptureID, "source_artifact_ids": []string{s.source.ArtifactID}, "expires_at": s.expires, "section": "processes", "summary": map[string]any{"started_at": s.observed.Add(-time.Second), "ended_at": s.observed, "observed_wire_bytes": 0, "retained_bytes": 1024, "coverage": map[string]any{"requested_pods": 1, "covered_pods": 1, "process_inventory_complete": true, "traffic_complete": false, "dropped_packets": 0, "stop_reason": "completed"}, "capture_mode": "none"}, "processes": rows, "gaps": []string{"socketOwnersUnsupported"}, "query_observed_at": now, "query_expires_at": s.expires}
		envelope["data"] = map[string]any{"query_handle": handle, "tool_name": "get_target_discovery", "result": inner, "query_observed_at": now, "query_expires_at": s.expires}
	default:
		return presentation.OperationReply{}, contracts.ErrInvestigationWire
	}
	body, err := json.Marshal(envelope)
	if err == nil {
		err = s.wire.ValidateOutput(name, body)
	}
	return presentation.OperationReply{Body: body, ValidUntil: now.Add(5 * time.Second)}, err
}

// Same installed Chromium driver and compiled React, real Go HTTPS/session/CSRF
// and canonical input/output validation. Capture/history/query authority and
// source rows are synthetic. No SQL, collector, native or installed claim.
func TestConsoleProcessesQueryWithBuiltPackage(t *testing.T) {
	if os.Getenv("ASSERVAT_CONSOLE_BROWSER_TEST") != "1" {
		t.Skip("set ASSERVAT_CONSOLE_BROWSER_TEST=1 after building web/dist")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	origin := "https://" + server.Listener.Addr().String()
	static, err := console.New(origin, os.DirFS(filepath.Join(root, "web", "dist")))
	if err != nil {
		t.Fatal(err)
	}
	sessions := &consoleSyntheticSessions{origin: origin, state: "ready", expiresAt: time.Now().Add(5 * time.Minute)}
	sh := browser.SessionHandler{Origin: origin, Issuer: "https://identity.invalid", Sessions: sessions}
	captures := &consoleSyntheticCaptures{state: "evidence-ready", key: "synthetic-original", historyMode: "history-ready"}
	captureOps, err := presentation.NewContextOperationsWithHistory(presentation.ContextOperationsConfig{PublicOrigin: origin, CollectionEnabled: true, Now: time.Now, NewID: func() string { return consoleCaptureID(500) }}, captures, captures, consoleProcessHistory{&consoleSyntheticHistory{captures: captures}})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	source := savedProcessesBrowserSource{CaptureID: consoleCaptureID(8), ArtifactID: consoleCaptureID(81), Version: strings.Repeat("09", 32)}
	ops := &consoleProcessOperations{origin: origin, wire: wire, captures: captureOps, source: source}
	operations, err := browser.NewInvestigationHandler(sh, ops, 4)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/session" || strings.HasPrefix(r.URL.Path, "/auth/") {
			sh.ServeHTTP(w, r)
		} else if strings.HasPrefix(r.URL.Path, "/api/v1/operations/") {
			operations.ServeHTTP(w, r)
		} else {
			static.ServeHTTP(w, r)
		}
	})
	server.StartTLS()
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(origin)
	jar.SetCookies(u, []*http.Cookie{{Name: browser.SessionCookie, Value: strings.Repeat("A", 43), Path: "/", Secure: true, HttpOnly: true}})
	client := server.Client()
	client.Jar = jar
	b := &installedBrowser{t: t, client: client, base: origin, csrf: strings.Repeat("C", 43), wire: wire}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	observed := 0
	call, finish := installedProcessesBrowser(t, ctx, b, server.Listener.Addr().String(), source, func(r installedComparisonReply) {
		observed++
		if r.RequestID == "" {
			t.Fatal("missing original request")
		}
	})
	defer finish()
	pending := call("get_target_discovery", map[string]any{"capture_id": source.CaptureID, "section": "processes", "limit": 20})
	var p struct {
		Handle  string    `json:"query_handle"`
		Expires time.Time `json:"query_expires_at"`
	}
	if pending.Status != "pending" || json.Unmarshal(pending.Data, &p) != nil || p.Handle == "" {
		t.Fatal("pending query")
	}
	if err := installedJourneyPause(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	ready := call("get_query_result", map[string]string{"query_handle": p.Handle})
	if ready.Status != "ok" {
		t.Fatal("saved process query not ready")
	}
	finish()
	ops.mu.Lock()
	defer ops.mu.Unlock()
	if ops.starts != 1 || ops.polls != 1 || observed != 2 {
		t.Fatal("unexpected browser effects", ops.starts, ops.polls, observed)
	}
	t.Log("Exact installed process driver: explicit one Begin/one poll, original source/expiry, escaped path, zero RSS, unknown runtime, joined Close; synthetic authority only")
}
