package integration

import (
	"context"
	"encoding/base64"
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
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/transport/browser"
	"asservat.local/asservat/internal/transport/presentation"
)

// Real compiled React + GoTLS/session/CSRF/canonical routes. Identity, approval,
// source and pages are synthetic. This does not qualify SQL, native or capture.
func TestConsoleSyscallQueryWithBuiltPackage(t *testing.T) {
	if os.Getenv("ASSERVAT_CONSOLE_BROWSER_TEST") != "1" {
		t.Skip("set ASSERVAT_CONSOLE_BROWSER_TEST=1 after building web/dist")
	}
	for _, large := range []bool{false, true} {
		name := "recorded-values-next-page"
		if large {
			name = "bounded-private-page"
		}
		t.Run(name, func(t *testing.T) { consoleSyscallQueryWithBuiltPackage(t, large) })
	}
}
func consoleSyscallQueryWithBuiltPackage(t *testing.T, large bool) {
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
	expires := time.Now().Add(time.Hour)
	sessions := &consoleSyntheticSessions{origin: origin, state: "ready", expiresAt: time.Now().Add(5 * time.Minute)}
	sessionHandler := browser.SessionHandler{Origin: origin, Issuer: "https://identity.invalid", Sessions: sessions}
	cases := &consoleSyntheticSyscallQueryCases{&consoleSyntheticCases{state: "ready", expiresAt: expires}}
	caseOps, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: func() string { return consoleCaptureID(501) }}, cases)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	source := installedSyscallQueryBrowserSource{CaseID: consoleCaptureID(80), ArtifactID: consoleCaptureID(81), Version: "09" + strings.Repeat("00", 31), PodUID: "synthetic-pod-uid", GrantID: consoleCaptureID(41), Expires: expires}
	op := &consoleSyntheticSyscallQueryOperations{origin: origin, wire: wire, cases: caseOps, source: source, large: large}
	operations, err := browser.NewInvestigationHandler(sessionHandler, op, 4)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/session" || strings.HasPrefix(r.URL.Path, "/auth/") {
			sessionHandler.ServeHTTP(w, r)
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
	ctx, stop := context.WithTimeout(t.Context(), time.Minute)
	defer stop()
	selection := map[string]any{"case_id": source.CaseID, "artifact_id": source.ArtifactID, "grant_id": source.GrantID, "idempotency_key": "not-injected", "limit": 100, "errors_only": false, "syscall_names": []string{"write"}}
	observed := 0
	call, closeBrowser := installedSyscallQueryBrowser(t, ctx, b, server.Listener.Addr().String(), source, selection, func(r installedComparisonReply) {
		observed++
		if r.RequestID == "" {
			t.Fatal("missing original operation")
		}
	})
	defer closeBrowser()
	var previousKey string
	for page := 0; page < 2; page++ {
		reply := call("syscall_query", selection)
		var pending struct {
			Handle            string    `json:"query_handle"`
			Observed, Expires time.Time `json:"-"`
		}
		var p map[string]json.RawMessage
		if reply.Status != "pending" || json.Unmarshal(reply.Data, &p) != nil {
			t.Fatal("expected original pending query")
		}
		_ = json.Unmarshal(p["query_handle"], &pending.Handle)
		_ = json.Unmarshal(p["query_observed_at"], &pending.Observed)
		_ = json.Unmarshal(p["query_expires_at"], &pending.Expires)
		key := selection["idempotency_key"].(string)
		if key == "not-injected" || page > 0 && key == previousKey {
			t.Fatal("actual UI fresh key not retained")
		}
		previousKey = key
		if err := installedJourneyPause(ctx, time.Second); err != nil {
			t.Fatal(err)
		}
		ready := call("get_query_result", map[string]string{"query_handle": pending.Handle})
		var outer struct {
			Handle, Tool      string
			Result            json.RawMessage
			Observed, Expires time.Time
		}
		var raw map[string]json.RawMessage
		if ready.Status != "ok" || json.Unmarshal(ready.Data, &raw) != nil {
			t.Fatal("expected nested raw page")
		}
		_ = json.Unmarshal(raw["query_handle"], &outer.Handle)
		_ = json.Unmarshal(raw["tool_name"], &outer.Tool)
		_ = json.Unmarshal(raw["query_observed_at"], &outer.Observed)
		_ = json.Unmarshal(raw["query_expires_at"], &outer.Expires)
		outer.Result = raw["result"]
		var result struct {
			Data struct {
				Kind     string                      `json:"kind"`
				Events   []artifact.RawArgumentEvent `json:"events"`
				Observed time.Time                   `json:"query_observed_at"`
				Expires  time.Time                   `json:"query_expires_at"`
			}
			Next      *string `json:"next_cursor"`
			Truncated bool    `json:"truncated"`
		}
		if json.Unmarshal(outer.Result, &result) != nil || outer.Handle != pending.Handle || outer.Tool != "syscall_query" || !outer.Expires.Equal(pending.Expires) || !outer.Observed.After(pending.Observed) || !result.Data.Observed.Equal(outer.Observed) || !result.Data.Expires.Equal(outer.Expires) || result.Data.Kind != "syscallQuery" || len(result.Data.Events) == 0 {
			t.Fatal("original source/current response clock binding")
		}
		for _, e := range result.Data.Events {
			if !e.WellFormed() || e.Identity.PodUID != source.PodUID {
				t.Fatal("synthetic recorded value invalid")
			}
		}
		if page == 0 {
			if !result.Truncated || result.Next == nil {
				t.Fatal("next page missing")
			}
			selection["cursor"] = *result.Next
		} else if result.Truncated || result.Next != nil {
			t.Fatal("final cursor retained")
		}
	}
	closeBrowser()
	op.mu.Lock()
	defer op.mu.Unlock()
	cases.mu.Lock()
	defer cases.mu.Unlock()
	if op.starts != 2 || op.polls != 2 || op.approvals != 1 || op.grantReads != 1 || observed != 4 || cases.calls != 1 {
		t.Fatal("unexpected effects", op.starts, op.polls, op.approvals, op.grantReads, observed, cases.calls)
	}
	if large && (op.privateBytes > query.SyscallQueryPageBytes || op.privateBytes < query.SyscallQueryPageBytes-1500) {
		t.Fatal("large fixture did not exercise actual private page bound", op.privateBytes)
	}
	t.Logf("synthetic authority only: pending approval/current getGrant, two explicit queries/two paid polls, original source/clock; private page bytes=%d/20480; no acquisition/native", op.privateBytes)
}

type consoleSyntheticSyscallQueryCases struct{ *consoleSyntheticCases }

func (s *consoleSyntheticSyscallQueryCases) GetContextCase(ctx context.Context, i identities.CurrentIdentity, id string) (catalog.ContextCase, error) {
	v, e := s.consoleSyntheticCases.GetContextCase(ctx, i, id)
	if e == nil {
		v.Artifacts[0].EvidenceType = "syscallTrace"
		v.Artifacts[0].NativeType = artifact.SyscallArgumentsArtifact
		v.Artifacts[0].DataClass = "raw"
		n := int64(8 << 20)
		v.Artifacts[0].NativeBytes = &n
	}
	return v, e
}

type consoleSyntheticSyscallQueryOperations struct {
	mu                                                 sync.Mutex
	origin                                             string
	wire                                               *contracts.InvestigationContracts
	cases                                              *presentation.ContextCaseOperations
	source                                             installedSyscallQueryBrowserSource
	large                                              bool
	starts, polls, approvals, grantReads, privateBytes int
	key, cursor                                        string
	observed, expires                                  time.Time
	events                                             []artifact.RawArgumentEvent
}

func (s *consoleSyntheticSyscallQueryOperations) PublicOrigin() string { return s.origin }
func (s *consoleSyntheticSyscallQueryOperations) ToolNames() []string {
	return []string{"get_case", "request_raw_access", "get_grant", "syscall_query", "get_query_result"}
}
func (s *consoleSyntheticSyscallQueryOperations) Tool(n string) (contracts.InvestigationTool, bool) {
	return s.wire.Tool(n)
}
func (s *consoleSyntheticSyscallQueryOperations) Call(ctx context.Context, i identities.CurrentIdentity, n string, input json.RawMessage) (presentation.OperationReply, error) {
	if n == "get_case" {
		return s.cases.Call(ctx, i, n, input)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, e := i.ResolveIdentity(ctx); e != nil {
		return presentation.OperationReply{}, e
	}
	if s.wire.ValidateInput(n, input) != nil {
		return presentation.OperationReply{}, contracts.ErrInvestigationWire
	}
	var a map[string]any
	if json.Unmarshal(input, &a) != nil {
		return presentation.OperationReply{}, contracts.ErrInvestigationWire
	}
	bad := func() (presentation.OperationReply, error) {
		return presentation.OperationReply{}, contracts.ErrInvestigationWire
	}
	envelope := map[string]any{"schema_version": "mcp-result/v1", "request_id": consoleCaptureID(90 + s.starts), "data_class": "metadata", "status": "ok", "truncated": false, "next_cursor": nil, "narrowing_hint": nil, "warnings": []string{}, "provenance": []any{}}
	switch n {
	case "request_raw_access":
		if s.approvals != 0 || a["case_id"] != s.source.CaseID {
			return bad()
		}
		ops, _ := a["operations"].([]any)
		digests, _ := a["artifact_digests"].([]any)
		if len(ops) != 1 || ops[0] != "syscall_query" || len(digests) != 1 || digests[0] != s.source.Version {
			return bad()
		}
		s.approvals++
		envelope["data"] = map[string]any{"grant_id": s.source.GrantID, "phase": "Pending"}
	case "get_grant":
		if s.approvals != 1 || s.grantReads != 0 || a["grant_id"] != s.source.GrantID {
			return bad()
		}
		s.grantReads++
		envelope["data"] = s.approvedGrant()
	case "syscall_query":
		if s.grantReads != 1 || s.starts >= 2 || a["case_id"] != s.source.CaseID || a["artifact_id"] != s.source.ArtifactID || a["grant_id"] != s.source.GrantID {
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
		s.events = s.fixtureEvents()
		envelope["status"] = "pending"
		envelope["data"] = map[string]any{"query_handle": consoleCaptureID(90 + s.starts), "retry_after_seconds": 1, "query_observed_at": s.observed, "query_expires_at": s.expires}
	case "get_query_result":
		if s.starts < 1 || s.polls != s.starts-1 || a["query_handle"] != consoleCaptureID(90+s.starts) {
			return bad()
		}
		s.polls++
		now := time.Now().UTC()
		inner := map[string]any{}
		for k, v := range envelope {
			inner[k] = v
		}
		inner["data_class"] = "raw"
		inner["provenance"] = []any{map[string]any{"artifactID": s.source.ArtifactID, "digest": s.source.Version}}
		inner["data"] = map[string]any{"kind": "syscallQuery", "events": s.events, "coverage": map[string]any{"dropped_events": nil, "unmatched_events": 0, "unfinished_events": 0, "unknown_events": 0, "record_count": 100, "truncated": nil, "gaps": []string{"Acquisition coverage is unknown."}}, "query_observed_at": now, "query_expires_at": s.expires}
		if s.starts == 1 {
			selection, err := query.NormalizeSyscallSelection(s.source.CaseID, s.source.ArtifactID, query.SyscallQueryView, "", 100, []string{"write"}, false)
			if err != nil {
				return bad()
			}
			s.cursor = selection.Cursor(len(s.events), artifact.Digest{9})
			inner["truncated"] = true
			inner["next_cursor"] = s.cursor
			inner["narrowing_hint"] = "Continue with the returned cursor to inspect more recorded calls."
		}
		envelope["data_class"] = "raw"
		envelope["data"] = map[string]any{"query_handle": consoleCaptureID(90 + s.starts), "tool_name": "syscall_query", "result": inner, "query_observed_at": now, "query_expires_at": s.expires}
	default:
		return bad()
	}
	body, e := json.Marshal(envelope)
	if e == nil {
		e = s.wire.ValidateOutput(n, body)
	}
	return presentation.OperationReply{Body: body, ValidUntil: time.Now().Add(5 * time.Second)}, e
}
func (s *consoleSyntheticSyscallQueryOperations) fixtureEvents() []artifact.RawArgumentEvent {
	zero := uint64(0)
	event := artifact.RawArgumentEvent{Identity: artifact.ArgumentIdentity{ProcessRef: "process-fixture", ThreadRef: "thread-fixture", PodUID: s.source.PodUID}, Syscall: "write", ABI: "x86_64", Timestamp: s.observed.Format(time.RFC3339Nano), DurationNS: &zero, Outcome: "success", Arguments: []artifact.ArgumentValue{{Name: "fd", Value: "decimal:0"}, {Name: "buffer", Value: "base64:", Truncated: true}, {Name: "path", Value: "unavailable:fault"}}}
	if s.large {
		event.Identity.ProcessRef = strings.Repeat("p", 128)
		event.Identity.ThreadRef = strings.Repeat("t", 128)
		event.Arguments = []artifact.ArgumentValue{{Name: "fd", Value: "decimal:-2147483648"}, {Name: "count", Value: "decimal:18446744073709551615"}, {Name: "path", Value: "base64:" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 128))), Truncated: true}, {Name: "buffer", Value: "base64:" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("y", 128))), Truncated: true}}
	}
	events := []artifact.RawArgumentEvent{event}
	p := query.SyscallArgumentPage{Version: artifact.Digest{9}, Events: events, TotalMatching: 100, SyscallRecordCounts: query.SyscallRecordCounts{RecordCount: 100}}
	if s.large && s.starts == 1 {
		for {
			p.Events = append(p.Events, event)
			if p.EncodedSize() > query.SyscallQueryPageBytes {
				p.Events = p.Events[:len(p.Events)-1]
				break
			}
		}
	}
	if p.EncodedSize() > s.privateBytes {
		s.privateBytes = p.EncodedSize()
	}
	return p.Events
}
func (s *consoleSyntheticSyscallQueryOperations) approvedGrant() map[string]any {
	now := time.Now().UTC()
	target := map[string]any{"cluster_id": consoleCaptureID(1), "namespace_uid": "synthetic-namespace-uid", "workload_uid": "synthetic-workload-uid", "pod_uid": s.source.PodUID}
	item := map[string]any{"artifact_id": s.source.ArtifactID, "capture_id": consoleCaptureID(8), "action_id": "arguments", "digest": s.source.Version, "execution_digest": s.source.Version, "native_type": artifact.SyscallArgumentsArtifact, "native_bytes": 8 << 20, "expires_at": s.source.Expires, "target": target}
	return map[string]any{"grant_id": s.source.GrantID, "phase": "Approved", "revision": 2, "kind": "rawQuery", "execution_digest": s.source.Version, "review_digest": s.source.Version, "data_class": "raw", "reasons": []any{}, "requested_by": map[string]any{"issuer": "https://identity.invalid", "subject": "synthetic-user", "client_id": "console"}, "requested_at": now, "review_until": now.Add(time.Minute), "lifetime_seconds": 3600, "can_decide": false, "can_revoke": true, "approval_navigation_uri": s.origin + "/approvals/" + s.source.GrantID, "raw_access": map[string]any{"case_id": s.source.CaseID, "reason": "Synthetic saved argument inspection", "operations": []string{"syscall_query"}, "max_bytes": 49152, "max_operations": 10000, "not_after": now.Add(time.Hour), "artifact_count": 1, "bytes_used": 0, "operations_used": 0, "artifacts": []any{item}}}
}
