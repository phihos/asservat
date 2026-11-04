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

// Same installed driver/wrapper, Go TLS/static/session/CSRF/case presentation and
// actual Evidence HTTP controller. Identity, case and comparison are synthetic;
// this is a local UI regression, not SQL/KMS/installed acquisition qualification.
func TestConsoleProfileComparisonWithBuiltPackage(t *testing.T) {
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
	sessionHandler := browser.SessionHandler{Origin: origin, Issuer: "https://identity.invalid", Sessions: sessions}
	cases := &consoleSyntheticProfileTimingCases{consoleSyntheticCases: &consoleSyntheticCases{state: "ready", profile: true, expiresAt: time.Now().Add(time.Hour)}}
	caseOps, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: func() string { return consoleCaptureID(501) }}, cases)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := os.ReadFile(filepath.Join(root, "examples", "mcp-profile-comparison-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if json.Unmarshal(reply, &result) != nil {
		t.Fatal("synthetic comparison example")
	}
	data := result["data"].(map[string]any)
	data["case_id"], data["baseline_case_id"] = consoleCaptureID(80), consoleCaptureID(80)
	data["artifact_id"], data["baseline_artifact_id"] = consoleCaptureID(81), consoleCaptureID(81)
	data["source_version"], data["baseline_source_version"] = "09"+strings.Repeat("00", 31), "09"+strings.Repeat("00", 31)
	data["baseline"] = data["incident"]
	observed := time.Now().UTC()
	expires := observed.Add(time.Minute)
	data["query_observed_at"], data["query_expires_at"] = observed, expires
	result["provenance"] = []any{map[string]any{"artifactID": consoleCaptureID(81), "digest": data["source_version"]}}
	comparison := &consoleSyntheticComparisonOperations{origin: origin, wire: wire, result: result, cases: caseOps, t: t}
	operations, err := browser.NewInvestigationHandler(sessionHandler, comparison, 4)
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
	events := 0
	call, finish := installedProfileComparisonBrowser(t, ctx, b, server.Listener.Addr().String(), installedProfileComparisonSource{CaseID: consoleCaptureID(80), ArtifactID: consoleCaptureID(81)}, func(installedComparisonReply) { events++ })
	defer finish()
	first := call("compare_profiles", map[string]any{"case_id": consoleCaptureID(80), "artifact_id": consoleCaptureID(81), "baseline_case_id": consoleCaptureID(80), "baseline_artifact_id": consoleCaptureID(81), "sample_type": "cpu", "normalization": "perSecond", "top_n": 20})
	if first.Status != "pending" {
		t.Fatal("synthetic comparison pending")
	}
	last := call("get_query_result", map[string]string{"query_handle": consoleCaptureID(90)})
	if last.Status != "ok" {
		t.Fatal("synthetic comparison result")
	}
	finish()
	comparison.mu.Lock()
	defer comparison.mu.Unlock()
	cases.mu.Lock()
	defer cases.mu.Unlock()
	if events != 2 || comparison.starts != 1 || comparison.polls != 1 || cases.calls != 1 {
		t.Fatal("installed driver made extra synthetic calls", events, comparison.starts, comparison.polls, cases.calls)
	}
}

// One already visible CPU source has known HTTP timing. A legacy Go trace
// supplies the explicit unknown-window row without introducing another pprof
// comparison choice, request or operation in the existing browser journey.
type consoleSyntheticProfileTimingCases struct {
	*consoleSyntheticCases
	heap bool
}

func (s *consoleSyntheticProfileTimingCases) GetContextCase(ctx context.Context, current identities.CurrentIdentity, id string) (catalog.ContextCase, error) {
	view, err := s.consoleSyntheticCases.GetContextCase(ctx, current, id)
	if err != nil {
		return view, err
	}
	start := time.Now().UTC().Truncate(time.Microsecond).Add(-11 * time.Second)
	view.Artifacts[0].ProfileAcquisition = &artifact.ProfileAcquisitionMetadata{Type: "cpu", Mode: "interval", DurationMillis: 10000, Acquisition: &artifact.AcquisitionWindow{StartedAt: start, CompletedAt: start.Add(10*time.Second + 222*time.Millisecond)}}
	if s.heap {
		view.Artifacts[0].ProfileAcquisition.Type, view.Artifacts[0].ProfileAcquisition.Mode, view.Artifacts[0].ProfileAcquisition.DurationMillis = "heap", "snapshot", 0
	}
	legacy := view.Artifacts[0]
	legacy.ArtifactID, legacy.CaptureID = consoleCaptureID(82), consoleCaptureID(9)
	legacy.NativeType = artifact.GoTraceArtifact
	legacy.ProfileAcquisition = &artifact.ProfileAcquisitionMetadata{Type: "runtimeTrace", Mode: "interval", DurationMillis: 1000}
	view.Artifacts = append(view.Artifacts, legacy)
	return view, nil
}

type consoleSyntheticComparisonOperations struct {
	mu            sync.Mutex
	t             *testing.T
	origin        string
	wire          *contracts.InvestigationContracts
	result        map[string]any
	starts, polls int
	heap          bool
	cases         *presentation.ContextCaseOperations
}

func (s *consoleSyntheticComparisonOperations) PublicOrigin() string { return s.origin }
func (s *consoleSyntheticComparisonOperations) ToolNames() []string {
	tool := "compare_profiles"
	if s.heap {
		tool = "get_profile_summary"
	}
	return []string{"get_case", tool, "get_query_result"}
}
func (s *consoleSyntheticComparisonOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	return s.wire.Tool(name)
}
func (s *consoleSyntheticComparisonOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, input json.RawMessage) (presentation.OperationReply, error) {
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
	data := s.result["data"].(map[string]any)
	envelope := map[string]any{}
	for key, value := range s.result {
		envelope[key] = value
	}
	tool := "compare_profiles"
	if s.heap {
		tool = "get_profile_summary"
	}
	if name == tool {
		s.starts++
		envelope["status"], envelope["data_class"], envelope["provenance"] = "pending", "metadata", []any{}
		envelope["data"] = map[string]any{"query_handle": consoleCaptureID(90), "retry_after_seconds": 1, "query_observed_at": data["query_observed_at"], "query_expires_at": data["query_expires_at"]}
	} else {
		s.polls++
		envelope["provenance"] = []any{}
		envelope["data"] = map[string]any{"query_handle": consoleCaptureID(90), "tool_name": tool, "result": s.result, "query_observed_at": data["query_observed_at"], "query_expires_at": data["query_expires_at"]}
	}
	body, err := json.Marshal(envelope)
	if err == nil {
		err = s.wire.ValidateOutput(name, body)
		if err != nil {
			s.t.Log("synthetic comparison reply", name, s.wire.OutputViolation(name, body))
		}
	}
	return presentation.OperationReply{Body: body, ValidUntil: time.Now().Add(5 * time.Second)}, err
}
