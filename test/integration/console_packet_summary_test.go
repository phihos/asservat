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
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/transport/browser"
	"asservat.local/asservat/internal/transport/presentation"
)

// The exact installed JS/Go driver exercises real GoTLS/static React, browser
// session/CSRF and case presentation. Identity, publication and query authority
// are synthetic here; this test supplies no SQL/KMS/acquisition qualification.
func TestConsolePacketSummaryWithBuiltPackage(t *testing.T) {
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
	expires := time.Now().Add(time.Hour)
	sessions := &consoleSyntheticSessions{origin: origin, state: "ready", expiresAt: time.Now().Add(5 * time.Minute)}
	sessionHandler := browser.SessionHandler{Origin: origin, Issuer: "https://identity.invalid", Sessions: sessions}
	cases := &consoleSyntheticPacketCases{&consoleSyntheticCases{state: "ready", expiresAt: expires}}
	caseOps, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: func() string { return consoleCaptureID(501) }}, cases)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(root, "examples", "mcp-packet-summary-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if json.Unmarshal(encoded, &result) != nil {
		t.Fatal("synthetic packet example")
	}
	data := result["data"].(map[string]any)
	observed := time.Now().UTC()
	data["query_observed_at"], data["query_expires_at"] = observed, observed.Add(time.Minute)
	version := "09" + strings.Repeat("00", 31)
	result["provenance"] = []any{map[string]any{"artifactID": consoleCaptureID(81), "digest": version}}
	packet := &consoleSyntheticPacketOperations{origin: origin, wire: wire, result: result, cases: caseOps}
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
	summary := queryInstalledPacketSummaryBrowser(t, ctx, b, server.Listener.Addr().String(), installedPacketSummarySource{CaseID: consoleCaptureID(80), ArtifactID: consoleCaptureID(81), Version: version, PodUID: "synthetic-pod-uid", Expires: expires}, func(artifactID string) func(string, string) func() {
		if artifactID != consoleCaptureID(81) || packet.starts != 0 {
			t.Fatal("synthetic snapshot before exact-source query")
		}
		snapshots++
		return func(handle, operation string) func() {
			checks++
			if handle != consoleCaptureID(90) || operation != consoleCaptureID(90) {
				t.Fatal("synthetic original query locators")
			}
			return func() {} // Explicitly synthetic: no SQL worker terminal assertion.
		}
	})
	packet.mu.Lock()
	defer packet.mu.Unlock()
	cases.mu.Lock()
	defer cases.mu.Unlock()
	if summary.Packets != 12 || summary.Drops == nil || *summary.Drops != 2 || len(summary.Conversations) != 1 || snapshots != 1 || checks != 1 || packet.starts != 1 || packet.polls != 1 || cases.calls != 1 || !packet.readyObserved.After(observed) {
		t.Fatal("actual rendered packet journey made extra calls or changed the result")
	}
}

type consoleSyntheticPacketCases struct{ *consoleSyntheticCases }

func (s *consoleSyntheticPacketCases) GetContextCase(ctx context.Context, current identities.CurrentIdentity, id string) (catalog.ContextCase, error) {
	view, err := s.consoleSyntheticCases.GetContextCase(ctx, current, id)
	if err == nil {
		view.Artifacts[0].EvidenceType = "packetCapture"
		view.Artifacts[0].NativeType = artifact.PCAPNGArtifact
		view.Artifacts[0].DataClass = "metadata"
	}
	return view, err
}

type consoleSyntheticPacketOperations struct {
	mu            sync.Mutex
	origin        string
	wire          *contracts.InvestigationContracts
	result        map[string]any
	starts, polls int
	readyObserved time.Time
	cases         *presentation.ContextCaseOperations
}

func (s *consoleSyntheticPacketOperations) PublicOrigin() string { return s.origin }
func (s *consoleSyntheticPacketOperations) ToolNames() []string {
	return []string{"get_case", "get_pcap_summary", "get_query_result"}
}
func (s *consoleSyntheticPacketOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	return s.wire.Tool(name)
}
func (s *consoleSyntheticPacketOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, input json.RawMessage) (presentation.OperationReply, error) {
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
	var args map[string]string
	if json.Unmarshal(input, &args) != nil {
		return presentation.OperationReply{}, contracts.ErrInvestigationWire
	}
	data := s.result["data"].(map[string]any)
	envelope := map[string]any{}
	for key, value := range s.result {
		envelope[key] = value
	}
	switch name {
	case "get_pcap_summary":
		if args["case_id"] != consoleCaptureID(80) || args["artifact_id"] != consoleCaptureID(81) {
			return presentation.OperationReply{}, contracts.ErrInvestigationWire
		}
		s.starts++
		envelope["status"], envelope["data_class"], envelope["provenance"] = "pending", "metadata", []any{}
		envelope["data"] = map[string]any{"query_handle": consoleCaptureID(90), "retry_after_seconds": 1, "query_observed_at": data["query_observed_at"], "query_expires_at": data["query_expires_at"]}
	case "get_query_result":
		if args["query_handle"] != consoleCaptureID(90) || s.starts != 1 {
			return presentation.OperationReply{}, contracts.ErrInvestigationWire
		}
		s.polls++
		// C18 observes each response at its current time. Only the admitted
		// query expiry remains fixed across pending and ready responses.
		s.readyObserved = time.Now().UTC()
		readyData := map[string]any{}
		for key, value := range data {
			readyData[key] = value
		}
		readyData["query_observed_at"] = s.readyObserved
		ready := map[string]any{}
		for key, value := range s.result {
			ready[key] = value
		}
		ready["data"] = readyData
		envelope["provenance"] = []any{}
		envelope["data"] = map[string]any{"query_handle": consoleCaptureID(90), "tool_name": "get_pcap_summary", "result": ready, "query_observed_at": s.readyObserved, "query_expires_at": data["query_expires_at"]}
	default:
		return presentation.OperationReply{}, contracts.ErrInvestigationWire
	}
	body, err := json.Marshal(envelope)
	if err == nil {
		err = s.wire.ValidateOutput(name, body)
	}
	return presentation.OperationReply{Body: body, ValidUntil: time.Now().Add(5 * time.Second)}, err
}
