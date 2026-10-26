package bootstrap

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func publicRoutesFixture(handler http.Handler) *publicContextRoutes {
	return &publicContextRoutes{
		host: "asservat.invalid", sessions: handler, investigations: handler,
		mcp: handler, content: handler, console: handler,
		mcpPath: "/mcp", mcpMetadata: "/.well-known/oauth-protected-resource/mcp",
		contentPrefix: "/api/v1/downloads/", contentMetadata: "/.well-known/oauth-protected-resource/downloads",
	}
}

func TestPublicContextRoutesKeepDistinctProtocolOwners(t *testing.T) {
	owner := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test-Owner", name)
			w.WriteHeader(http.StatusAccepted)
		})
	}
	h := publicRoutesFixture(owner("unused"))
	h.sessions, h.investigations, h.mcp = owner("session"), owner("operation"), owner("mcp")
	h.content, h.console = owner("content"), owner("console")
	for _, tc := range []struct{ target, want string }{
		{"/auth/login?return_to=%2Fcases%2Fx", "session"},
		{"/auth/callback?state=opaque&code=opaque&iss=https%3A%2F%2Fidentity.invalid", "session"},
		{"/api/v1/session", "session"},
		{"/api/v1/operations/cancel_artifact_download", "operation"},
		{"/mcp", "mcp"},
		{"/.well-known/oauth-protected-resource/mcp", "mcp"},
		{"/.well-known/oauth-protected-resource/downloads", "content"},
		{"/api/v1/downloads/00000000-0000-4000-8000-000000000001/content", "content"},
		{"/captures/new", "console"},
		{"/policies", "console"},
		{"/shares", "console"},
		{"/cases/00000000-0000-4000-8000-000000000001", "console"},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.target, nil)
		r.Host, r.TLS = h.host, &tls.ConnectionState{}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusAccepted || w.Header().Get("X-Test-Owner") != tc.want {
			t.Fatalf("%s reached %q, want %q", tc.target, w.Header().Get("X-Test-Owner"), tc.want)
		}
	}
}

func TestPublicContextRoutesPreserveOriginalAuthAndEvidenceRequests(t *testing.T) {
	var calls int
	h := publicRoutesFixture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Range") != "bytes=8-15" || r.Header.Get("If-Range") != `"verified"` || r.Header.Get("Authorization") != "Bearer opaque-test-only" {
			t.Fatal("router changed the downstream protocol inputs")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	for _, target := range []string{
		"/auth/login?return_to=%2Fcaptures%2Fnew",
		"/auth/callback?state=opaque&code=a%2Bb&iss=https%3A%2F%2Fidentity.invalid",
		"/auth/backchannel-logout", "/auth/csrf", "/auth/refresh", "/auth/logout", "/api/v1/session",
		"/mcp", "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource/downloads",
		"/api/v1/operations/request_capture", "/api/v1/operations/cancel_artifact_download",
		"/api/v1/downloads/00000000-0000-4000-8000-000000000001/content",
		"/", "/assets/entry-12345678.js", "/captures/new", "/captures/00000000-0000-4000-8000-000000000001", "/cases/00000000-0000-4000-8000-000000000001",
	} {
		t.Run(target, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, target, nil)
			r.Host = h.host
			r.TLS = &tls.ConnectionState{}
			r.Header.Set("Range", "bytes=8-15")
			r.Header.Set("If-Range", `"verified"`)
			r.Header.Set("Authorization", "Bearer opaque-test-only")
			before := calls
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if calls != before+1 || w.Code != http.StatusAccepted || r.RequestURI != target || r.Method != http.MethodPost {
				t.Fatal("original request did not reach its owner exactly once")
			}
		})
	}
}

func TestPublicContextRoutesNeverNormalizeOrUseAPIAsConsoleFallback(t *testing.T) {
	var calls int
	h := publicRoutesFixture(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	for _, target := range []string{
		"/api", "/api/v1/operations", "/api/v1/downloads", "/auth", "/auth/unknown", "/mcp/", "/private/owner", "/metrics", "/healthz",
		"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/downloads/",
		"/api//v1/operations/request_capture", "/api/v1/../operations/request_capture", "/api/v1/./operations/request_capture",
		"/%61pi/v1/operations/request_capture", "/api%2fv1/operations/request_capture", "/api/v1/downloads/x%252fy/content",
		"/api/v1/operations/request_capture?", "/api/v1/operations/request_capture?token=x", "/mcp?access_token=x", "/api/v1/downloads/x/content?token=x", "/?token=x",
		"https://asservat.invalid/mcp",
	} {
		t.Run(target, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, target, nil)
			r.Host = h.host
			r.TLS = &tls.ConnectionState{}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if calls != 0 || w.Code < 400 || w.Header().Get("Location") != "" || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") || w.Header().Get("Content-Type") != "application/problem+json" {
				t.Fatal("invalid or private route reached a handler, redirected or lacked safe failure headers")
			}
		})
	}
}

func TestPublicContextRoutesRequireActualTLSAndOriginalHost(t *testing.T) {
	var called bool
	h := publicRoutesFixture(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	for _, tc := range []struct {
		host string
		tls  bool
	}{{h.host, false}, {"attacker.invalid", true}, {h.host + ".", true}} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
		r.Host = tc.host
		if tc.tls {
			r.TLS = &tls.ConnectionState{}
		}
		r.Header.Set("Forwarded", "proto=https;host=asservat.invalid")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", h.host)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if called || w.Code != http.StatusBadRequest {
			t.Fatal("forwarding headers replaced actual transport identity")
		}
	}
}

// This exercises the real net/http response writer: passing through the router
// must preserve the deadline/flush capabilities needed by native transfer.
func TestPublicContextRoutesRetainTLSResponseController(t *testing.T) {
	var seen atomic.Bool
	var capabilities atomic.Bool
	h := publicRoutesFixture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(true)
		control := http.NewResponseController(w)
		if control.SetReadDeadline(time.Now().Add(time.Second)) != nil || control.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="evidence.bin"`)
		w.WriteHeader(http.StatusPartialContent)
		if _, e := w.Write([]byte("native-test-bytes")); e != nil {
			return
		}
		if control.Flush() == nil {
			capabilities.Store(true)
		}
	}))
	server := httptest.NewTLSServer(h)
	defer server.Close()
	r, e := http.NewRequest(http.MethodGet, server.URL+"/api/v1/downloads/00000000-0000-4000-8000-000000000001/content", nil)
	if e != nil {
		t.Fatal(e)
	}
	r.Host = h.host
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		t.Fatal("router redirected native transfer")
		return http.ErrUseLastResponse
	}
	response, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 64))
	if e != nil || !seen.Load() || !capabilities.Load() || response.StatusCode != http.StatusPartialContent || string(body) != "native-test-bytes" || response.Header.Get("Content-Encoding") != "" || response.Header.Get("Content-Disposition") != `attachment; filename="evidence.bin"` {
		t.Fatal("router altered native response or hid response-controller capabilities")
	}
}

// ADR-194 D1: without a configured worker the content paths answer 503 and
// never reach the console; other routes are unchanged.
func TestPublicContextRoutesWithoutContentAnswerUnavailable(t *testing.T) {
	h := publicRoutesFixture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	h.content = nil
	for target, want := range map[string]int{
		"/.well-known/oauth-protected-resource/downloads":                http.StatusServiceUnavailable,
		"/api/v1/downloads/00000000-0000-4000-8000-000000000001/content": http.StatusServiceUnavailable,
		"/api/v1/operations/prepare_artifact_download":                   http.StatusAccepted,
		"/cases/00000000-0000-4000-8000-000000000001":                    http.StatusAccepted,
	} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Host, r.TLS = h.host, &tls.ConnectionState{}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s answered %d, want %d", target, w.Code, want)
		}
	}
}
