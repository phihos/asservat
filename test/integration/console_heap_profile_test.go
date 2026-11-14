package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	evidence "asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/console"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/transport/browser"
	"asservat.local/asservat/internal/transport/presentation"
	"github.com/google/pprof/profile"
)

// Real GoTLS/static React and the exact installed driver; source/profile,
// session, query and download facts are deliberately synthetic. No SQL/KMS proof.
func TestConsoleHeapProfileWithBuiltPackage(t *testing.T) {
	for _, expireDuringNative := range []bool{false, true} {
		name := "current-view"
		if expireDuringNative {
			name = "expires-during-native"
		}
		t.Run(name, func(t *testing.T) { testConsoleHeapProfileWithBuiltPackage(t, expireDuringNative) })
	}
	t.Run("session-refresh-during-native", func(t *testing.T) { testConsoleHeapProfileWithBuiltPackage(t, false, true) })
}

func testConsoleHeapProfileWithBuiltPackage(t *testing.T, expireDuringNative bool, restore ...bool) {
	if os.Getenv("ASSERVAT_CONSOLE_BROWSER_TEST") != "1" {
		t.Skip("set ASSERVAT_CONSOLE_BROWSER_TEST=1 after building web/dist")
	}
	restoreDuringNative := len(restore) == 1 && restore[0]
	refreshedCase := make(chan struct{})
	var refreshCalls atomic.Int64
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
	sessions := &consoleRestartSessions{&consoleSyntheticSessions{origin: origin, state: "ready", expiresAt: time.Now().Add(5 * time.Minute)}}
	sessionHandler := browser.SessionHandler{Origin: origin, Issuer: "https://identity.invalid", Sessions: sessions}
	cases := &consoleSyntheticProfileTimingCases{heap: true, acquiredAt: time.Now().UTC().Truncate(time.Microsecond).Add(-11 * time.Second), consoleSyntheticCases: &consoleSyntheticCases{state: "ready", profile: true, expiresAt: time.Now().Add(time.Hour)}}
	caseOps, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: func() string { return consoleCaptureID(501) }}, cases)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := os.ReadFile(filepath.Join(root, "examples", "mcp-profile-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if json.Unmarshal(reply, &result) != nil {
		t.Fatal("synthetic comparison example")
	}
	data := result["data"].(map[string]any)
	data["sample_type"], data["unit"], data["duration_seconds"], data["total"] = "inuse_space", "bytes", nil, 1003
	data["top"] = []any{map[string]any{"function": "main.main", "flat": 1003, "cumulative": 1003, "fraction": 1}}
	data["symbol_status"] = "complete"
	observed := time.Now().UTC()
	expires := observed.Add(time.Minute)
	const shortView = 3 * time.Second
	if expireDuringNative {
		expires = observed.Add(shortView)
	}
	data["query_observed_at"], data["query_expires_at"] = observed, expires
	result["provenance"] = []any{map[string]any{"artifactID": consoleCaptureID(81), "digest": "09" + strings.Repeat("00", 31)}}
	comparison := &consoleSyntheticComparisonOperations{heap: true, origin: origin, wire: wire, result: result, cases: caseOps, t: t}
	var payload bytes.Buffer
	function := &profile.Function{ID: 1, Name: "main.main"}
	location := &profile.Location{ID: 1, Line: []profile.Line{{Function: function}}}
	pp := &profile.Profile{SampleType: []*profile.ValueType{{Type: "inuse_space", Unit: "bytes"}}, Function: []*profile.Function{function}, Location: []*profile.Location{location}, Sample: []*profile.Sample{{Location: []*profile.Location{location}, Value: []int64{1003}}}}
	if err := pp.Write(&payload); err != nil {
		t.Fatal(err)
	}
	downloads := &consoleHeapDownloads{consoleRestartDownloads: consoleRestartDownloads{created: time.Now().UTC()}, native: payload.Bytes(), readyImmediately: expireDuringNative}
	downloadOps, err := presentation.NewContextDownloadOperations(presentation.ContextDownloadOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: func() string { return consoleCaptureID(502) }}, downloads, downloads)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := browser.NewInvestigationHandler(sessionHandler, &consoleHeapOperations{consoleSyntheticComparisonOperations: comparison, downloads: downloadOps}, 4)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/session" || strings.HasPrefix(r.URL.Path, "/auth/") {
			if r.URL.Path == "/auth/refresh" {
				refreshCalls.Add(1)
			}
			sessionHandler.ServeHTTP(w, r)
		} else if strings.HasPrefix(r.URL.Path, "/api/v1/operations/") {
			if expireDuringNative && r.URL.Path == "/api/v1/operations/get_profile_summary" {
				comparison.mu.Lock()
				observed = time.Now().UTC()
				expires = observed.Add(shortView)
				data["query_observed_at"], data["query_expires_at"] = observed, expires
				comparison.mu.Unlock()
			}
			operations.ServeHTTP(w, r)
			if restoreDuringNative && r.URL.Path == "/api/v1/operations/get_case" {
				cases.mu.Lock()
				second := cases.calls == 2
				cases.mu.Unlock()
				if second {
					downloads.mu.Lock()
					started := downloads.nativeCalls == 1
					downloads.mu.Unlock()
					if !started {
						t.Error("synthetic restoration preceded the original native request")
					}
					close(refreshedCase)
				}
			}
		} else if strings.HasPrefix(r.URL.Path, browser.DownloadContentPrefix) {
			cookie, e := r.Cookie(browser.SessionCookie)
			if e != nil {
				w.WriteHeader(401)
				return
			}
			if _, e = sessions.Resolve(r.Context(), cookie.Value, false); e != nil {
				w.WriteHeader(401)
				return
			}
			if r.Method != "GET" || r.URL.Path != "/api/v1/downloads/"+consoleCaptureID(90)+"/content" {
				w.WriteHeader(400)
				return
			}
			downloads.mu.Lock()
			downloads.nativeCalls++
			downloads.mu.Unlock()
			if expireDuringNative {
				// Native transfer has its own lifetime. Hold its body beyond the
				// summary's original interval without another query.
				timer := time.NewTimer(shortView + time.Second)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-r.Context().Done():
					return
				}
			}
			w.Header().Set("Content-Disposition", `attachment; filename="artifact-`+consoleCaptureID(81)+`.pb.gz"`)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(len(downloads.native)))
			body := downloads.native
			if restoreDuringNative {
				// Keep the real attachment open while the actual SessionGate
				// restoration listener performs a fresh same-human session/case read.
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(body[:1]) // Chromium starts the attachment after its first byte.
				body = body[1:]
				w.(http.Flusher).Flush()
				select {
				case <-refreshedCase:
				case <-r.Context().Done():
					return
				}
			}
			_, _ = w.Write(body)
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
	call, nativeDownload, finish := installedProfileBrowser(t, ctx, b, server.Listener.Addr().String(), installedProfileComparisonSource{CaseID: consoleCaptureID(80), ArtifactID: consoleCaptureID(81), Expires: cases.expiresAt}, "heap", func(installedComparisonReply) { events++ }, restoreDuringNative)
	defer finish()
	joined := false
	summary := queryInstalledProfileSummaryWithCall(t, ctx, consoleCaptureID(80), consoleCaptureID(81), "09"+strings.Repeat("00", 31), "inuse_space", cases.expiresAt, call, func(handle, operation string) func() {
		comparison.mu.Lock()
		defer comparison.mu.Unlock()
		if comparison.starts != 1 || comparison.polls != 1 || handle != consoleCaptureID(90) || operation == "" || len(downloads.stats.PrepareKeys) != 0 {
			t.Fatal("summary must join before one native preparation")
		}
		joined = true
		return func() {}
	})
	if !joined {
		t.Fatal("native before query join")
	}
	native, metadata := nativeDownload()
	if !bytes.Equal(native, downloads.native) || metadata.ArtifactID != consoleCaptureID(81) {
		t.Fatal("synthetic native attachment differs")
	}
	if err := installedProfileSummaryMatchesNative(summary, native, "main.main"); err != nil {
		t.Fatal(err)
	}
	finish()
	comparison.mu.Lock()
	defer comparison.mu.Unlock()
	cases.mu.Lock()
	defer cases.mu.Unlock()
	downloads.mu.Lock()
	defer downloads.mu.Unlock()
	wantPrepares := 2
	if expireDuringNative {
		wantPrepares = 1
	}
	wantCases := 1
	if restoreDuringNative {
		wantCases = 2
	}
	refreshes := refreshCalls.Load()
	if restoreDuringNative && (!time.Now().Before(expires) || refreshes != 2) {
		t.Fatal("short current same-human restoration must preserve original unexpired summary cutoff and make exactly two session reads", refreshes)
	}
	if events != 2 || comparison.starts != 1 || comparison.polls != 1 || cases.calls != wantCases || downloads.stats.Accepted != 1 || len(downloads.stats.PrepareKeys) != wantPrepares || wantPrepares == 2 && downloads.stats.PrepareKeys[0] != downloads.stats.PrepareKeys[1] || downloads.nativeCalls != 1 {
		t.Fatal("extra synthetic acquisition/query/download", events, comparison.starts, comparison.polls, cases.calls, downloads.stats, downloads.nativeCalls)
	}
	t.Logf("summary interval=%s; native body hold=%t", expires.Sub(observed), expireDuringNative)
	t.Log("Same installed heap driver/wrapper; real GoTLS/static React/Evidence HTTP/CSRF and one browser attachment; synthetic session/profile/summary/download service, no SQL/KMS/installed authority proof")
}

type consoleHeapOperations struct {
	*consoleSyntheticComparisonOperations
	downloads *presentation.ContextDownloadOperations
}

func (s *consoleHeapOperations) ToolNames() []string {
	return []string{"get_case", "get_profile_summary", "get_query_result", "prepare_artifact_download", "get_artifact_download", "cancel_artifact_download"}
}
func (s *consoleHeapOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, input json.RawMessage) (presentation.OperationReply, error) {
	if name == "prepare_artifact_download" || name == "get_artifact_download" || name == "cancel_artifact_download" {
		return s.downloads.Call(ctx, current, name, input)
	}
	return s.consoleSyntheticComparisonOperations.Call(ctx, current, name, input)
}

type consoleHeapDownloads struct {
	consoleRestartDownloads
	native           []byte
	nativeCalls      int
	readyImmediately bool
}

func (s *consoleHeapDownloads) metadata(v evidence.ContextDownloadView) evidence.ContextDownloadView {
	if v.Metadata != nil {
		v.Metadata.Filename = "artifact-" + consoleCaptureID(81) + ".pb.gz"
		v.Metadata.Format = "pprof"
		v.Metadata.Size = int64(len(s.native))
		v.Metadata.SHA256 = sha256.Sum256(s.native)
	}
	return v
}
func (s *consoleHeapDownloads) PrepareContextDownload(ctx context.Context, c identities.CurrentIdentity, id, key string) (evidence.ContextDownloadView, error) {
	v, e := s.consoleRestartDownloads.PrepareContextDownload(ctx, c, id, key)
	s.mu.Lock()
	first := len(s.stats.PrepareKeys) == 1
	s.mu.Unlock()
	if e == nil && first && !s.readyImmediately {
		v.Session.State = artifact.DownloadPreparing
		v.Metadata = nil
		v.ContinuePreparation = true
	}
	return s.metadata(v), e
}
func (s *consoleHeapDownloads) GetContextDownload(ctx context.Context, c identities.CurrentIdentity, id string) (evidence.ContextDownloadView, error) {
	v, e := s.consoleRestartDownloads.GetContextDownload(ctx, c, id)
	return s.metadata(v), e
}
