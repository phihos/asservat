package integration

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/console"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/transport/browser"
	"asservat.local/asservat/internal/transport/presentation"
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
)

// Exact installed JS/Go bridge, real built React and GoTLS/session/case HTTP.
// Query data, identity and covering approval are synthetic; no SQL/KMS/native
// acquisition or actual grant qualification is supplied by this local fixture.
func TestConsolePacketQueryWithBuiltPackage(t *testing.T) {
	if os.Getenv("ASSERVAT_CONSOLE_BROWSER_TEST") != "1" {
		t.Skip("set ASSERVAT_CONSOLE_BROWSER_TEST=1 after building web/dist")
	}
	for _, tc := range []struct {
		name, mode string
		limited    bool
	}{
		{"metadata-ordinary", "networkHeaders", false},
		{"raw-zero-null-prefix", "rawPackets", false},
		{"raw-row-limited-nested", "rawPackets", true},
	} {
		t.Run(tc.name, func(t *testing.T) { consolePacketQueryWithBuiltPackage(t, tc.mode, tc.limited) })
	}
}
func consolePacketQueryWithBuiltPackage(t *testing.T, captureMode string, limited bool) {
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
	cases := &consoleSyntheticPacketQueryCases{consoleSyntheticPacketCases: &consoleSyntheticPacketCases{consoleSyntheticCases: &consoleSyntheticCases{state: "ready", expiresAt: expires}, captureMode: captureMode}}
	caseOps, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: func() string { return consoleCaptureID(501) }}, cases)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	source := installedPacketQuerySource{CaseID: consoleCaptureID(80), ArtifactID: consoleCaptureID(81), Version: "09" + strings.Repeat("00", 31), PodUID: "synthetic-pod-uid", GrantID: consoleCaptureID(41), Expires: expires, CaptureMode: captureMode}
	if captureMode == "networkHeaders" {
		source.GrantID = ""
	}
	packet := &consoleSyntheticPacketQueryOperations{origin: origin, wire: wire, cases: caseOps, source: source, limited: limited}
	operations, err := browser.NewInvestigationHandler(sessionHandler, packet, 4)
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
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	snapshots, checks := 0, 0
	request := installedPacketQueryRequest(source, "go-proposed-key-not-injected")
	// Include the short saved prefix honestly: a tcp/port filter would exclude
	// this incomplete header before projection in the real parser.
	delete(request, "packet_filter")
	result := queryInstalledPacketQueryBrowser(t, ctx, b, server.Listener.Addr().String(), source, request, func(artifactID string) func(string, string) func() {
		if artifactID != source.ArtifactID || packet.starts != 0 {
			t.Fatal("snapshot source/before effects")
		}
		snapshots++
		return func(handle, operation string) func() {
			checks++
			if handle != consoleCaptureID(90) || operation != consoleCaptureID(90) {
				t.Fatal("original query locator")
			}
			return func() {}
		}
	})
	packet.mu.Lock()
	defer packet.mu.Unlock()
	cases.mu.Lock()
	defer cases.mu.Unlock()
	if snapshots != 1 || checks != 1 || packet.starts != 1 || packet.polls != 1 || packet.approvals != map[bool]int{true: 1, false: 0}[captureMode == "rawPackets"] || cases.calls != 1 || result.RowLimitReached != limited {
		t.Fatal("unexpected calls/limits", snapshots, checks, packet.starts, packet.polls, packet.approvals, cases.calls)
	}
	if request["idempotency_key"] == "go-proposed-key-not-injected" || request["idempotency_key"] != packet.key {
		t.Fatal("actual UI key not retained")
	}
	if !limited && (len(result.Rows) != 2 || result.Rows[0][6].Number == nil || *result.Rows[0][6].Number != 0 || result.Rows[1][4].Text != nil || captureMode == "rawPackets" && (result.Rows[1][15].Text == nil || *result.Rows[1][15].Text != "aa")) {
		t.Fatal("zero/null/exact saved prefix changed")
	}
}

type consoleSyntheticPacketQueryCases struct{ *consoleSyntheticPacketCases }

func (s *consoleSyntheticPacketQueryCases) GetContextCase(ctx context.Context, i identities.CurrentIdentity, id string) (catalog.ContextCase, error) {
	v, e := s.consoleSyntheticPacketCases.GetContextCase(ctx, i, id)
	if e == nil {
		n := int64(8 << 20)
		v.Artifacts[0].NativeBytes = &n
	}
	return v, e
}

type consoleSyntheticPacketQueryOperations struct {
	mu                       sync.Mutex
	origin                   string
	wire                     *contracts.InvestigationContracts
	cases                    *presentation.ContextCaseOperations
	source                   installedPacketQuerySource
	limited                  bool
	starts, polls, approvals int
	key                      string
	observed, expires        time.Time
	page                     map[string]any
}

func (s *consoleSyntheticPacketQueryOperations) PublicOrigin() string { return s.origin }
func (s *consoleSyntheticPacketQueryOperations) ToolNames() []string {
	return []string{"get_case", "request_raw_access", "pcap_query", "get_query_result"}
}
func (s *consoleSyntheticPacketQueryOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	return s.wire.Tool(name)
}
func (s *consoleSyntheticPacketQueryOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, input json.RawMessage) (presentation.OperationReply, error) {
	if name == "get_case" {
		return s.cases.Call(ctx, current, name, input)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := current.ResolveIdentity(ctx); err != nil {
		return presentation.OperationReply{}, err
	}
	if s.wire.ValidateInput(name, input) != nil {
		return presentation.OperationReply{}, contracts.ErrInvestigationWire
	}
	var args map[string]any
	if json.Unmarshal(input, &args) != nil {
		return presentation.OperationReply{}, contracts.ErrInvestigationWire
	}
	envelope := map[string]any{"schema_version": "mcp-result/v1", "request_id": consoleCaptureID(90), "data_class": "metadata", "status": "ok", "truncated": false, "next_cursor": nil, "narrowing_hint": nil, "warnings": []string{}, "provenance": []any{}}
	switch name {
	case "request_raw_access":
		s.approvals++
		ops, _ := args["operations"].([]any)
		digests, _ := args["artifact_digests"].([]any)
		if len(ops) != 1 || ops[0] != "pcap_query" || len(digests) != 1 || digests[0] != s.source.Version {
			return presentation.OperationReply{}, contracts.ErrInvestigationWire
		}
		envelope["data"] = map[string]any{"grant_id": s.source.GrantID, "phase": "Approved"}
	case "pcap_query":
		if s.approvals != map[bool]int{true: 1, false: 0}[s.source.CaptureMode == "rawPackets"] || s.starts != 0 || (s.source.CaptureMode == "rawPackets" && args["grant_id"] != s.source.GrantID || s.source.CaptureMode == "networkHeaders" && args["grant_id"] != nil) || args["case_id"] != s.source.CaseID || args["artifact_id"] != s.source.ArtifactID {
			return presentation.OperationReply{}, contracts.ErrInvestigationWire
		}
		s.starts++
		s.key, _ = args["idempotency_key"].(string)
		s.observed = time.Now().UTC()
		s.expires = s.observed.Add(10 * time.Second)
		fields := args["fields"].([]any)
		row := []any{1, s.observed.Format(time.RFC3339Nano), 100, 1500, "192.0.2.1", "192.0.2.2", 0, 8080, "TCP", 24, 0, uint32(4294967295), 65535, nil, nil, strings.Repeat("ab", 64)}
		rows := []any{row, []any{2, s.observed.Format(time.RFC3339Nano), 1, 1500, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "aa"}}
		if s.source.CaptureMode == "networkHeaders" {
			for n := range rows {
				r := rows[n].([]any)
				rows[n] = r[:len(r)-1]
			}
		}
		count := 2
		scanned := 101
		if s.limited {
			rows = nil
			for n := 1; n <= 20; n++ {
				r := append([]any(nil), row...)
				r[0] = n
				rows = append(rows, r)
			}
			count = 20
			scanned = 2000
		}
		s.page = map[string]any{"capture_mode": s.source.CaptureMode, "fields": fields, "rows": rows, "scanned_bytes": scanned, "scanned_packets": count, "row_limit_reached": s.limited, "scan_limit_reached": false, "output_limit_reached": false, "query_observed_at": s.observed, "query_expires_at": s.expires}
		envelope["status"] = "pending"
		envelope["data"] = map[string]any{"query_handle": consoleCaptureID(90), "retry_after_seconds": 1, "query_observed_at": s.observed, "query_expires_at": s.expires}
	case "get_query_result":
		if s.starts != 1 || args["query_handle"] != consoleCaptureID(90) {
			return presentation.OperationReply{}, contracts.ErrInvestigationWire
		}
		s.polls++
		now := time.Now().UTC()
		s.page["query_observed_at"] = now
		inner := map[string]any{}
		for k, v := range envelope {
			inner[k] = v
		}
		inner["data_class"] = map[bool]string{true: "raw", false: "extract"}[s.source.CaptureMode == "rawPackets"]
		inner["data"] = s.page
		inner["truncated"] = s.limited
		if s.limited {
			inner["narrowing_hint"] = "Narrow packet selection."
		}
		inner["provenance"] = []any{map[string]any{"artifactID": s.source.ArtifactID, "digest": s.source.Version}}
		envelope["data_class"] = inner["data_class"]
		envelope["data"] = map[string]any{"query_handle": consoleCaptureID(90), "tool_name": "pcap_query", "result": inner, "query_observed_at": now, "query_expires_at": s.expires}
	default:
		return presentation.OperationReply{}, contracts.ErrInvestigationWire
	}
	body, err := json.Marshal(envelope)
	if err == nil {
		err = s.wire.ValidateOutput(name, body)
	}
	return presentation.OperationReply{Body: body, ValidUntil: time.Now().Add(5 * time.Second)}, err
}
