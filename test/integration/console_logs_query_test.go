package integration

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/console"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/catalog"
	identity "asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/browser"
	mcptransport "asservat.local/asservat/internal/transport/mcp"
	"asservat.local/asservat/internal/transport/presentation"
	"bufio"
	"context"
	"encoding/json"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type savedLogsBrowserSource struct {
	CaseID, ArtifactID, Version, PodUID, GrantID string
	Expires                                      time.Time
}

// Reuses the installed HttpOnly cookie tunnel and bounded line protocol. The
// caller owns scheduled polls and independent SQL/native checks; this helper
// owns Chromium through its final rendered-result/close acknowledgement only.
func savedLogsBrowser(t *testing.T, ctx context.Context, browser *installedBrowser, address string, source savedLogsBrowserSource, selection map[string]any, observed func(installedComparisonReply)) (func(string, any) installedComparisonReply, func()) {
	t.Helper()
	origin, err := url.Parse(browser.base)
	if err != nil || browser.client.Jar == nil || observed == nil {
		t.Fatal("logs browser original session missing")
	}
	var cookies []map[string]any
	for _, c := range browser.client.Jar.Cookies(origin) {
		cookies = append(cookies, map[string]any{"name": c.Name, "value": c.Value, "url": browser.base, "httpOnly": true, "secure": true, "sameSite": "Lax"})
	}
	if len(cookies) == 0 {
		t.Fatal("logs browser original cookie missing")
	}
	config, err := json.Marshal(map[string]any{"mode": "logs-query", "origin": browser.base, "proxy": installedHistoryBrowserTunnel(t, ctx, browser.base, address), "cookies": cookies, "caseID": source.CaseID, "artifactID": source.ArtifactID, "version": source.Version, "podUID": source.PodUID, "grantID": source.GrantID, "query_request": selection})
	if err != nil || len(config) > 16<<10 {
		clear(config)
		t.Fatal("logs browser private input bound")
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Minute)
	cmd := exec.CommandContext(call, "node", filepath.Join("..", "..", "web", "scripts", "saved-logs-browser.mjs"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	in, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var diagnostic consoleBoundedOutput
	cmd.Stderr = &diagnostic
	if err = cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	waited, closed := false, false
	t.Cleanup(func() {
		cancel()
		_ = in.Close()
		if !waited {
			_ = cmd.Wait()
			waited = true
		}
	})
	fail := func(stage string) {
		t.Helper()
		closed = true
		message := diagnostic.String()
		for _, c := range cookies {
			message = strings.ReplaceAll(message, c["value"].(string), "[session]")
		}
		t.Fatalf("installed React logs %s\n%s", stage, message)
	}
	if _, err = in.Write(append(config, '\n')); err != nil {
		clear(config)
		fail("input unavailable")
	}
	clear(config)
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 1024), 64<<10)
	type event struct {
		Kind, Name   string
		Input, Reply json.RawMessage
		Transport    struct{ Post, SameOrigin, CSRF, NoBearer bool }
	}
	read := func() event {
		t.Helper()
		if !scanner.Scan() {
			cancel()
			_ = cmd.Wait()
			waited = true
			fail("event unavailable")
		}
		var e event
		if json.Unmarshal(scanner.Bytes(), &e) != nil {
			fail("invalid bounded event")
		}
		return e
	}
	if read().Kind != "ready" {
		fail("page not ready")
	}
	invoke := func(name string, args any) installedComparisonReply {
		t.Helper()
		if closed || name != "get_logs" && name != "get_query_result" {
			fail("unexpected operation")
		}
		encoded, err := json.Marshal(map[string]any{"kind": "call", "name": name, "input": args})
		if err != nil || len(encoded) > 16<<10 {
			fail("operation input bound")
		}
		if _, err = in.Write(append(encoded, '\n')); err != nil {
			fail("operation input unavailable")
		}
		e := read()
		var reply installedComparisonReply
		if e.Kind != "operation" || e.Name != name || json.Unmarshal(e.Reply, &reply) != nil {
			fail("operation association")
		}
		observed(reply)
		if !e.Transport.Post || !e.Transport.SameOrigin || !e.Transport.CSRF || !e.Transport.NoBearer {
			fail("original cookie transport")
		}
		var actual, wanted any
		input, err := json.Marshal(args)
		if err != nil || json.Unmarshal(input, &wanted) != nil || json.Unmarshal(e.Input, &actual) != nil {
			fail("canonical input unavailable")
		}
		if name == "get_logs" {
			a, aok := actual.(map[string]any)
			w, wok := wanted.(map[string]any)
			key, kok := a["idempotency_key"].(string)
			if !aok || !wok || !kok || len(key) < 1 || len(key) > 128 {
				fail("original UI key missing")
			}
			w["idempotency_key"] = key
			if original, ok := args.(map[string]any); ok {
				original["idempotency_key"] = key
			}
		}
		if !reflect.DeepEqual(actual, wanted) || browser.wire.ValidateOutput(name, e.Reply) != nil {
			fail("canonical request or reply")
		}
		return reply
	}
	finish := func() {
		t.Helper()
		if closed {
			return
		}
		closed = true
		if _, err := in.Write([]byte("{\"kind\":\"close\"}\n")); err != nil {
			fail("close command")
		}
		if read().Kind != "closed" {
			fail("close acknowledgement")
		}
		_ = in.Close()
		if err := cmd.Wait(); err != nil {
			waited = true
			fail("terminal failure")
		}
		waited = true
		cancel()
		t.Log("installed React logs rendered saved bytes and joined before caller terminal proof")
	}
	return invoke, finish
}

// Actual compiled React and the real TLS/session/CSRF/canonical operation routes.
// The source, authority, approval and query pages are synthetic; no acquisition,
// SQL/key authority or installed log API is exercised by this local fixture.
func TestConsoleLogsQueryWithBuiltPackage(t *testing.T) {
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
	sessions := consoleLogSessions{&consoleSyntheticSessions{origin: origin, state: "ready", expiresAt: time.Now().Add(5 * time.Minute)}}
	sh := browser.SessionHandler{Origin: origin, Issuer: "https://identity.invalid", Sessions: sessions}
	cases := &consoleSyntheticLogCases{&consoleSyntheticCases{state: "ready", expiresAt: time.Now().Add(time.Hour)}}
	caseOps, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: func() string { return consoleCaptureID(501) }}, cases)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	source := savedLogsBrowserSource{CaseID: consoleCaptureID(80), ArtifactID: consoleCaptureID(81), Version: "09" + strings.Repeat("00", 31), PodUID: "synthetic-pod-uid", GrantID: consoleCaptureID(41), Expires: time.Now().Add(time.Hour)}
	ops := &consoleSyntheticLogOperations{origin: origin, wire: wire, cases: caseOps, source: source}
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
	selection := map[string]any{"case_id": source.CaseID, "artifact_id": source.ArtifactID, "grant_id": source.GrantID, "idempotency_key": "not-injected", "limit": 100}
	observed := 0
	call, finish := savedLogsBrowser(t, ctx, b, server.Listener.Addr().String(), source, selection, func(r installedComparisonReply) {
		observed++
		if r.RequestID == "" {
			t.Fatal("missing original request")
		}
	})
	defer finish()
	for page := 0; page < 2; page++ {
		pending := call("get_logs", selection)
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
		var out struct {
			Tool   string `json:"tool_name"`
			Result struct {
				Next *string `json:"next_cursor"`
				Data struct {
					Entries []map[string]any `json:"entries"`
					Expires time.Time        `json:"query_expires_at"`
				}
			} `json:"result"`
		}
		if ready.Status != "ok" || json.Unmarshal(ready.Data, &out) != nil || out.Tool != "get_logs" || !out.Result.Data.Expires.Equal(p.Expires) {
			t.Fatal("nested exact original query")
		}
		if page == 0 {
			if out.Result.Next == nil {
				t.Fatal("whole-fragment next cursor")
			}
			selection["cursor"] = *out.Result.Next
		} else if out.Result.Next != nil {
			t.Fatal("terminal cursor")
		}
	}
	finish()
	ops.mu.Lock()
	defer ops.mu.Unlock()
	cases.mu.Lock()
	defer cases.mu.Unlock()
	if ops.approvals != 1 || ops.grantReads != 1 || ops.starts != 2 || ops.polls != 2 || observed != 4 || cases.calls != 1 {
		t.Fatal("unexpected effects", ops.approvals, ops.grantReads, ops.starts, ops.polls, observed, cases.calls)
	}
	t.Log("actual React/GoTLS: one approval+check, two explicit pages/two polls, exact saved UTF-8/invalid bytes/combined origins, cleared and joined; synthetic authority only")
}

type consoleSyntheticLogCases struct{ *consoleSyntheticCases }

func (s *consoleSyntheticLogCases) GetContextCase(ctx context.Context, i identities.CurrentIdentity, id string) (catalog.ContextCase, error) {
	v, e := s.consoleSyntheticCases.GetContextCase(ctx, i, id)
	if e == nil {
		v.Artifacts[0].EvidenceType = "logs"
		v.Artifacts[0].NativeType = artifact.LogsArtifact
		v.Artifacts[0].DataClass = "raw"
		n := int64(64 << 20)
		v.Artifacts[0].NativeBytes = &n
	}
	return v, e
}

type consoleSyntheticLogOperations struct {
	mu                                   sync.Mutex
	origin                               string
	wire                                 *contracts.InvestigationContracts
	cases                                *presentation.ContextCaseOperations
	source                               savedLogsBrowserSource
	approvals, grantReads, starts, polls int
	key, cursor                          string
	observed, expires                    time.Time
}

func (s *consoleSyntheticLogOperations) PublicOrigin() string { return s.origin }
func (s *consoleSyntheticLogOperations) ToolNames() []string {
	return []string{"get_case", "request_raw_access", "get_grant", "get_logs", "get_query_result"}
}
func (s *consoleSyntheticLogOperations) Tool(n string) (contracts.InvestigationTool, bool) {
	return s.wire.Tool(n)
}
func (s *consoleSyntheticLogOperations) Call(ctx context.Context, i identities.CurrentIdentity, n string, input json.RawMessage) (presentation.OperationReply, error) {
	if n == "get_case" {
		return s.cases.Call(ctx, i, n, input)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, e := i.ResolveIdentity(ctx); e != nil {
		return presentation.OperationReply{}, e
	}
	bad := func() (presentation.OperationReply, error) {
		return presentation.OperationReply{}, contracts.ErrInvestigationWire
	}
	if s.wire.ValidateInput(n, input) != nil {
		return bad()
	}
	var a map[string]any
	if json.Unmarshal(input, &a) != nil {
		return bad()
	}
	env := map[string]any{"schema_version": "mcp-result/v1", "request_id": consoleCaptureID(90 + s.starts), "status": "ok", "data_class": "metadata", "truncated": false, "next_cursor": nil, "narrowing_hint": nil, "warnings": []string{}, "provenance": []any{}}
	switch n {
	case "request_raw_access":
		ops, _ := a["operations"].([]any)
		ds, _ := a["artifact_digests"].([]any)
		if s.approvals != 0 || a["case_id"] != s.source.CaseID || len(ops) != 1 || ops[0] != "get_logs" || len(ds) != 1 || ds[0] != s.source.Version {
			return bad()
		}
		s.approvals++
		env["data"] = map[string]any{"grant_id": s.source.GrantID, "phase": "Pending"}
	case "get_grant":
		if s.approvals != 1 || s.grantReads != 0 || a["grant_id"] != s.source.GrantID {
			return bad()
		}
		s.grantReads++
		delegate := consoleSyntheticSyscallQueryOperations{origin: s.origin, source: installedSyscallQueryBrowserSource{CaseID: s.source.CaseID, ArtifactID: s.source.ArtifactID, Version: s.source.Version, PodUID: s.source.PodUID, GrantID: s.source.GrantID, Expires: s.source.Expires}}
		g := delegate.approvedGrant()
		raw := g["raw_access"].(map[string]any)
		raw["operations"] = []string{"get_logs"}
		item := raw["artifacts"].([]any)[0].(map[string]any)
		item["native_type"] = artifact.LogsArtifact
		item["native_bytes"] = 64 << 20
		item["action_id"] = "logs"
		env["data"] = g
	case "get_logs":
		if s.grantReads != 1 || s.starts >= 2 || a["case_id"] != s.source.CaseID || a["artifact_id"] != s.source.ArtifactID || a["grant_id"] != s.source.GrantID || a["limit"] != float64(100) {
			return bad()
		}
		if s.starts == 0 && a["cursor"] != nil || s.starts == 1 && a["cursor"] != s.cursor {
			return bad()
		}
		key, _ := a["idempotency_key"].(string)
		if key == "" || key == s.key {
			return bad()
		}
		s.key = key
		s.starts++
		s.observed = time.Now().UTC()
		s.expires = s.observed.Add(20 * time.Second)
		env["status"] = "pending"
		env["data"] = map[string]any{"query_handle": consoleCaptureID(90 + s.starts), "retry_after_seconds": 1, "query_observed_at": s.observed, "query_expires_at": s.expires}
	case "get_query_result":
		if s.starts < 1 || s.polls != s.starts-1 || a["query_handle"] != consoleCaptureID(90+s.starts) {
			return bad()
		}
		s.polls++
		body, e := os.ReadFile("../../examples/mcp-logs-result.json")
		if e != nil {
			return bad()
		}
		var inner map[string]any
		if json.Unmarshal(body, &inner) != nil {
			return bad()
		}
		inner["request_id"] = env["request_id"]
		inner["provenance"] = []any{map[string]any{"artifactID": s.source.ArtifactID, "digest": s.source.Version}}
		data := inner["data"].(map[string]any)
		data["pod_uid"] = s.source.PodUID
		now := time.Now().UTC()
		data["query_observed_at"] = now
		data["query_expires_at"] = s.expires
		origin := data["entries"].([]any)[0].(map[string]any)["origin"].(map[string]any)
		if s.starts == 1 {
			origin["restart_count"] = 0
			extra := map[string]any{"origin": origin, "fragment": 1, "line": 2, "offset": 1, "line_offset": 0, "continuation": false, "end_line": true, "source_time": nil, "text": nil, "bytes_base64": "/wo="}
			data["entries"] = append(data["entries"].([]any), extra)
			selection, e := query.NormalizeLogSelection(s.source.CaseID, s.source.ArtifactID, "", 100)
			if e != nil {
				return bad()
			}
			s.cursor = selection.Cursor(2, 0, artifact.Digest{9})
			inner["next_cursor"] = s.cursor
			inner["truncated"] = true
			inner["narrowing_hint"] = "Continue with the returned cursor to inspect more saved log bytes."
		} else {
			origin["source"] = "previous"
			origin["origin_id"] = 1
			origin["restart_count"] = nil
			data["entries"] = []any{map[string]any{"origin": origin, "fragment": 2, "line": 1, "offset": 0, "line_offset": 0, "continuation": false, "end_line": true, "source_time": nil, "text": "<script>not executable</script>\n", "bytes_base64": nil}}
		}
		coverage := data["coverage"].(map[string]any)
		coverage["source_bytes"] = 35
		coverage["origins"] = 3
		coverage["complete_origins"] = 2
		coverage["unavailable_origins"] = 1
		coverage["unknown_timestamp_origins"] = 2
		coverage["gapped_origins"] = 3
		coverage["total_fragments"] = 3
		env["data_class"] = "raw"
		env["data"] = map[string]any{"query_handle": consoleCaptureID(90 + s.starts), "tool_name": "get_logs", "result": inner, "query_observed_at": now, "query_expires_at": s.expires}
	default:
		return bad()
	}
	body, e := json.Marshal(env)
	if e == nil {
		e = s.wire.ValidateOutput(n, body)
	}
	return presentation.OperationReply{Body: body, ValidUntil: time.Now().Add(5 * time.Second)}, e
}

// Official SDK over real TLS reaches the same closed get_logs/pending/poll page
// contract as the React fixture. This synthetic transport proof confers no SQL
// or evidence/key authority; the C20 test separately exercises the real C18.
func TestRawLogsOfficialMCPBoundary(t *testing.T) {
	var handler *mcptransport.Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	source := savedLogsBrowserSource{CaseID: consoleCaptureID(80), ArtifactID: consoleCaptureID(81), Version: "09" + strings.Repeat("00", 31), PodUID: "synthetic-pod-uid", GrantID: consoleCaptureID(41), Expires: time.Now().Add(time.Hour)}
	ops := &consoleSyntheticLogOperations{origin: server.URL, wire: wire, source: source, approvals: 1, grantReads: 1}
	handler, err = mcptransport.NewContextHandler(mcptransport.Config{PublicOrigin: server.URL, Issuer: "https://identity.invalid", Version: "test", MaxConcurrent: 2, MaxPerIdentity: 1}, logsMCPResolver{}, ops)
	if err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "synthetic-logs", Version: "1"}, nil)
	hc := *server.Client()
	hc.Transport = logsMCPBearer{hc.Transport}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: server.URL + mcptransport.Path, HTTPClient: &hc, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, &sdk.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range tools.Tools {
		found = found || tool.Name == "get_logs"
	}
	if !found {
		t.Fatal("get_logs not discoverable")
	}
	begin, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "get_logs", Arguments: map[string]any{"case_id": source.CaseID, "artifact_id": source.ArtifactID, "grant_id": source.GrantID, "idempotency_key": "same-official-sdk-page", "limit": 100}})
	if err != nil || begin.IsError {
		t.Fatal("begin", err, begin)
	}
	raw, err := json.Marshal(begin.StructuredContent)
	if err != nil || wire.ValidateOutput("get_logs", raw) != nil {
		t.Fatal("closed pending SDK output", err)
	}
	var p struct {
		Status string `json:"status"`
		Data   struct {
			Handle string `json:"query_handle"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &p) != nil || p.Status != "pending" {
		t.Fatal("pending SDK result")
	}
	ready, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "get_query_result", Arguments: map[string]string{"query_handle": p.Data.Handle}})
	if err != nil || ready.IsError {
		t.Fatal("poll", err, ready)
	}
	raw, err = json.Marshal(ready.StructuredContent)
	if err != nil || wire.ValidateOutput("get_query_result", raw) != nil {
		t.Fatal("closed nested SDK output", err)
	}
	var r struct {
		Class string `json:"data_class"`
		Data  struct {
			Tool   string `json:"tool_name"`
			Result struct {
				Data struct {
					Entries []struct {
						Text  *string `json:"text"`
						Bytes *string `json:"bytes_base64"`
					} `json:"entries"`
				} `json:"data"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &r) != nil || r.Class != "raw" || r.Data.Tool != "get_logs" || len(r.Data.Result.Data.Entries) != 2 || r.Data.Result.Data.Entries[0].Text == nil || *r.Data.Result.Data.Entries[0].Text != "\n" || r.Data.Result.Data.Entries[1].Bytes == nil || *r.Data.Result.Data.Entries[1].Bytes != "/wo=" {
		t.Fatal("lossless primitive SDK payload")
	}
	ops.mu.Lock()
	defer ops.mu.Unlock()
	if ops.starts != 1 || ops.polls != 1 {
		t.Fatal("hidden query")
	}
}

type logsMCPResolver struct{}

func (logsMCPResolver) Resolve(_ context.Context, token string) (identity.Identity, error) {
	now := time.Now()
	if token != "synthetic-logs-token" {
		return identity.Identity{}, identity.ErrDenied
	}
	return identity.Identity{Principal: identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic-user", ClientID: "synthetic-mcp", Kind: identity.Human}, Scopes: []string{"evidence:read", "evidence:raw"}, Policy: identity.Revision{UID: "fixture-policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(time.Minute)}, nil
}

type logsMCPBearer struct{ http.RoundTripper }

func (b logsMCPBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer synthetic-logs-token")
	return b.RoundTripper.RoundTrip(r)
}

// This fixture uses an explicitly raw-capable synthetic console identity;
// grant approval never substitutes for the client's required raw scope.
type consoleLogSessions struct{ *consoleSyntheticSessions }

func (s consoleLogSessions) Resolve(ctx context.Context, cookie string, refresh bool) (identities.SessionView, error) {
	v, e := s.consoleSyntheticSessions.Resolve(ctx, cookie, refresh)
	if e == nil {
		v.Identity.Scopes = append(v.Identity.Scopes, "evidence:raw")
	}
	return v, e
}
