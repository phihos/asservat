package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "asservat.local/asservat/internal/domain/identity"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type resolverFunc func(context.Context, string) (identity.Identity, error)

func (f resolverFunc) Resolve(c context.Context, s string) (identity.Identity, error) { return f(c, s) }
func testIdentity() identity.Identity {
	now := time.Now()
	return identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid/realm", Subject: "developer", ClientID: "registered-agent", Kind: identity.Human}, Scopes: []string{"evidence:read"}, Groups: []string{"maintainers"}, Policy: identity.Revision{UID: "identity-policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(20 * time.Second)}
}
func newTestServer(t *testing.T, resolve resolverFunc) (*Handler, *httptest.Server) {
	t.Helper()
	var handler *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(server.Close)
	var err error
	handler, err = NewHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolve)
	if err != nil {
		t.Fatal(err)
	}
	return handler, server
}
func rpcRequest(t *testing.T, s *httptest.Server, version, method string, params any) *http.Request {
	t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	if version == "2026-07-28" {
		p := params.(map[string]any)
		p["_meta"] = map[string]any{sdk.MetaKeyProtocolVersion: version, sdk.MetaKeyClientInfo: map[string]any{"name": "synthetic-agent", "version": "1"}, sdk.MetaKeyClientCapabilities: map[string]any{}}
	}
	b, e := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if e != nil {
		t.Fatal(e)
	}
	r, e := http.NewRequest("POST", s.URL+Path, bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Authorization", "Bearer synthetic-token")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	if version != "" {
		r.Header.Set("Mcp-Protocol-Version", version)
	}
	if version == "2026-07-28" {
		r.Header.Set("Mcp-Method", method)
		if name, ok := params.(map[string]any)["name"].(string); ok {
			r.Header.Set("Mcp-Name", name)
		}
	}
	return r
}
func send(t *testing.T, s *httptest.Server, r *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxResponseBytes {
		t.Fatal("response exceeds bound")
	}
	if resp.Header.Get("Cache-Control") != "no-store, private" {
		t.Fatal("response caches")
	}
	if resp.Header.Get("Mcp-Session-Id") != "" {
		t.Fatal("transport session published")
	}
	return resp, b
}

func TestProtocolProfilesAuthenticateAcrossReplicas(t *testing.T) {
	var calls atomic.Int64
	resolve := resolverFunc(func(ctx context.Context, token string) (identity.Identity, error) {
		calls.Add(1)
		if token != "synthetic-token" {
			return identity.Identity{}, identity.ErrDenied
		}
		return testIdentity(), nil
	})
	_, a := newTestServer(t, resolve)
	h, b := newTestServer(t, resolve)
	// Both independently created protocol servers consume the same authority;
	// client identity never comes from MCP params or a transport session handle.
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			if version == "2025-11-25" {
				req := rpcRequest(t, a, "", "initialize", map[string]any{"protocolVersion": version, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}})
				resp, body := send(t, a, req)
				var got struct {
					Result sdk.InitializeResult `json:"result"`
				}
				if json.Unmarshal(body, &got) != nil || resp.StatusCode != 200 || got.Result.ProtocolVersion != version || got.Result.Capabilities.Logging != nil || got.Result.Capabilities.Tools != nil {
					t.Fatalf("initialize: %d %s", resp.StatusCode, body)
				}
			} else {
				resp, body := send(t, a, rpcRequest(t, a, version, "server/discover", nil))
				var got struct {
					Result sdk.DiscoverResult `json:"result"`
				}
				if json.Unmarshal(body, &got) != nil || resp.StatusCode != 200 || len(got.Result.SupportedVersions) != 2 || got.Result.SupportedVersions[0] != "2026-07-28" || got.Result.CacheScope != "private" || got.Result.TTLMs != 0 {
					t.Fatalf("discover: %d %s", resp.StatusCode, body)
				}
			}
			for _, server := range []*httptest.Server{a, b} {
				resp, body := send(t, server, rpcRequest(t, server, version, "tools/list", nil))
				var got struct {
					Result *sdk.ListToolsResult `json:"result"`
				}
				if json.Unmarshal(body, &got) != nil || resp.StatusCode != 200 || got.Result == nil || len(got.Result.Tools) != 0 {
					t.Fatalf("tools/list: %d %s", resp.StatusCode, body)
				}
			}
		})
	}
	if calls.Load() != 12 {
		t.Fatalf("authentication count %d, want ingress and delivery checks for each request", calls.Load())
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.inFlight) != 0 || len(h.slots) != 0 {
		t.Fatal("admission slots leaked")
	}
}

type bearerTransport struct{ inner http.RoundTripper }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer synthetic-token")
	return b.inner.RoundTrip(r)
}
func TestOfficialClientNegotiatesExactVersions(t *testing.T) {
	_, s := newTestServer(t, func(context.Context, string) (identity.Identity, error) { return testIdentity(), nil })
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			client := sdk.NewClient(&sdk.Implementation{Name: "test-agent", Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
			hc := *s.Client()
			hc.Transport = bearerTransport{hc.Transport}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: s.URL + Path, HTTPClient: &hc, MaxRetries: -1, DisableStandaloneSSE: true}, &sdk.ClientSessionOptions{ProtocolVersion: version})
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if got := session.InitializeResult().ProtocolVersion; got != version {
				t.Fatalf("negotiated %q", got)
			}
			result, err := session.ListTools(ctx, &sdk.ListToolsParams{})
			if err != nil || len(result.Tools) != 0 {
				t.Fatalf("list: %#v %v", result, err)
			}
		})
	}
}

func TestResourceMetadataAndOAuthChallenges(t *testing.T) {
	var count atomic.Int64
	var mode atomic.Int64
	_, s := newTestServer(t, func(context.Context, string) (identity.Identity, error) {
		count.Add(1)
		switch mode.Load() {
		case 1:
			return identity.Identity{}, identity.ErrDenied
		case 2:
			return identity.Identity{}, errors.New("private provider detail synthetic-secret")
		case 3:
			i := testIdentity()
			i.Scopes = []string{"evidence:raw"}
			return i, nil
		case 4:
			i := testIdentity()
			i.Principal.Issuer = "https://wrong.invalid"
			return i, nil
		}
		return testIdentity(), nil
	})
	req, _ := http.NewRequest("GET", s.URL+MetadataPath, nil)
	resp, body := send(t, s, req)
	var m struct {
		Resource string   `json:"resource"`
		Issuers  []string `json:"authorization_servers"`
		Scopes   []string `json:"scopes_supported"`
	}
	if json.Unmarshal(body, &m) != nil || resp.StatusCode != 200 || m.Resource != s.URL+Path || len(m.Issuers) != 1 || m.Issuers[0] != "https://id.example.invalid/realm" || len(m.Scopes) != 1 || m.Scopes[0] != "evidence:read" || count.Load() != 0 {
		t.Fatalf("metadata: %s", body)
	}
	for _, tc := range []struct {
		name   string
		mode   int64
		status int
		alter  func(*http.Request)
	}{
		{"missing", 0, 401, func(r *http.Request) { r.Header.Del("Authorization") }},
		{"duplicate", 0, 401, func(r *http.Request) { r.Header.Add("Authorization", "Bearer second") }},
		{"cookie", 0, 401, func(r *http.Request) { r.Header.Set("Cookie", "session=browser") }},
		{"denied", 1, 401, nil}, {"unavailable", 2, 503, nil}, {"scope", 3, 403, nil}, {"issuer", 4, 401, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode.Store(tc.mode)
			r := rpcRequest(t, s, "2025-11-25", "tools/list", nil)
			if tc.alter != nil {
				tc.alter(r)
			}
			resp, b := send(t, s, r)
			if resp.StatusCode != tc.status || bytes.Contains(b, []byte("synthetic-secret")) {
				t.Fatalf("%d %s", resp.StatusCode, b)
			}
			if tc.status == 401 || tc.status == 403 {
				c := resp.Header.Get("WWW-Authenticate")
				if !strings.Contains(c, s.URL+MetadataPath) {
					t.Fatal("missing resource challenge")
				}
				if tc.status == 403 && !strings.Contains(c, `scope="evidence:read"`) {
					t.Fatal("broad/missing scope escalation")
				}
			}
		})
	}
}

func TestIngressRejectsAmbiguityAndResourceAbuse(t *testing.T) {
	_, s := newTestServer(t, func(context.Context, string) (identity.Identity, error) { return testIdentity(), nil })
	for _, tc := range []struct {
		name   string
		status int
		alter  func(*http.Request)
	}{
		{"wrong host", 403, func(r *http.Request) { r.Host = "attacker.invalid" }},
		{"cross origin", 403, func(r *http.Request) { r.Header.Set("Origin", "https://attacker.invalid") }},
		{"duplicate origin", 403, func(r *http.Request) { r.Header.Add("Origin", s.URL); r.Header.Add("Origin", s.URL) }},
		{"null origin", 403, func(r *http.Request) { r.Header.Set("Origin", "null") }},
		{"fetch metadata", 403, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"token query", 403, func(r *http.Request) { r.URL.RawQuery = "access_token=synthetic" }},
		{"get stream", 405, func(r *http.Request) { r.Method = "GET" }},
		{"session replay", 400, func(r *http.Request) { r.Header.Set("Mcp-Session-Id", "made-up") }},
		{"event replay", 400, func(r *http.Request) { r.Header.Set("Last-Event-Id", "made-up") }},
		{"compressed", 400, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{"duplicate revision", 400, func(r *http.Request) { r.Header.Add("Mcp-Protocol-Version", "2026-07-28") }},
		{"unsupported revision", 400, func(r *http.Request) { r.Header.Set("Mcp-Protocol-Version", "2025-06-18") }},
		{"wrong type", 415, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
		{"oversize unknown length", 413, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", MaxRequestBytes+1)))
			r.ContentLength = -1
		}},
		{"duplicate JSON fields", 400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"method":"tools/list","method":"tools/call"}`))
			r.ContentLength = -1
		}},
		{"case alias", 400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping","Method":"tools/list","params":{}}`))
			r.ContentLength = -1
		}},
		{"excess depth", 400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"x":` + strings.Repeat("[", maxNesting) + "0" + strings.Repeat("]", maxNesting) + "}"))
			r.ContentLength = -1
		}},
		{"batch", 400, func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`[]`)); r.ContentLength = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := rpcRequest(t, s, "2025-11-25", "tools/list", nil)
			tc.alter(r)
			resp, b := send(t, s, r)
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d want %d: %s", resp.StatusCode, tc.status, b)
			}
		})
	}
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run("routing "+version, func(t *testing.T) {
			r := rpcRequest(t, s, version, "tools/call", map[string]any{"name": "request_capture", "arguments": map[string]any{}})
			r.Header.Set("Mcp-Method", "tools/list")
			resp, b := send(t, s, r)
			if resp.StatusCode != 400 {
				t.Fatalf("routing mismatch accepted %d %s", resp.StatusCode, b)
			}
		})
	}
}

func TestRevocationExpiryAndOutputLimitBeforeDelivery(t *testing.T) {
	for _, mode := range []string{"revoked", "expired", "policy changed", "groups changed", "scope changed", "oversized output"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int64
			i := testIdentity()
			h, s := newTestServer(t, func(context.Context, string) (identity.Identity, error) {
				n := calls.Add(1)
				v := i
				if n > 1 {
					switch mode {
					case "revoked":
						return identity.Identity{}, identity.ErrDenied
					case "expired":
						v.ValidUntil = time.Now().Add(-time.Second)
					case "policy changed":
						v.Policy.Generation++
					case "groups changed":
						v.Groups = []string{"different"}
					case "scope changed":
						v.Scopes = []string{"evidence:read", "evidence:raw"}
					}
				}
				return v, nil
			})
			h.protocol = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				b := []byte(`{"private":"must not be disclosed"}`)
				if mode == "oversized output" {
					b = bytes.Repeat([]byte("x"), MaxResponseBytes+1)
				}
				_, _ = w.Write(b)
			})
			resp, b := send(t, s, rpcRequest(t, s, "2025-11-25", "tools/list", nil))
			if resp.StatusCode != 401 && resp.StatusCode != 503 || bytes.Contains(b, []byte("must not be disclosed")) || bytes.Count(b, []byte("x")) > 20 {
				t.Fatalf("disclosed %d %s", resp.StatusCode, b)
			}
		})
	}
}

func TestConcurrentAdmissionReleasesAfterJoinedCompletion(t *testing.T) {
	h, s := newTestServer(t, func(context.Context, string) (identity.Identity, error) { return testIdentity(), nil })
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	h.protocol = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		_, _ = w.Write([]byte(`{}`))
	})
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { send(t, s, rpcRequest(t, s, "2025-11-25", "tools/list", nil)) })
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("did not enter")
		}
	}
	resp, _ := send(t, s, rpcRequest(t, s, "2025-11-25", "tools/list", nil))
	if resp.StatusCode != 429 {
		t.Fatalf("per-identity limit %d", resp.StatusCode)
	}
	close(release)
	wg.Wait()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.inFlight) != 0 || len(h.slots) != 0 {
		t.Fatal("slots leak")
	}
}

func TestInvalidConfigurationAndUntrustedPlaintext(t *testing.T) {
	resolve := resolverFunc(func(context.Context, string) (identity.Identity, error) { return testIdentity(), nil })
	good := Config{PublicOrigin: "https://asservat.invalid", Issuer: "https://id.invalid", Version: "test", MaxConcurrent: 8, MaxPerIdentity: 2}
	for _, change := range []func(*Config){func(c *Config) { c.PublicOrigin = "http://asservat.invalid" }, func(c *Config) { c.PublicOrigin += "/prefix" }, func(c *Config) { c.Issuer = "https://id.invalid?caller=selected" }, func(c *Config) { c.MaxConcurrent = 0 }, func(c *Config) { c.MaxPerIdentity = 5 }} {
		c := good
		change(&c)
		if _, err := NewHandler(c, resolve); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	h, err := NewHandler(good, resolve)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://asservat.invalid/mcp", strings.NewReader(`{}`))
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Authorization", "Bearer synthetic-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("plaintext trusted %d", w.Code)
	}
}

func TestGlobalCapacityBoundsAuthenticationWork(t *testing.T) {
	var authentication atomic.Int64
	h, s := newTestServer(t, func(_ context.Context, token string) (identity.Identity, error) {
		authentication.Add(1)
		i := testIdentity()
		i.Principal.Subject = token
		return i, nil
	})
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	h.protocol = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		_, _ = w.Write([]byte(`{}`))
	})
	var wg sync.WaitGroup
	for _, token := range []string{"one", "two", "three", "four"} {
		wg.Go(func() {
			r := rpcRequest(t, s, "2025-11-25", "tools/list", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			send(t, s, r)
		})
	}
	for range 4 {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("requests not admitted")
		}
	}
	resp, _ := send(t, s, rpcRequest(t, s, "2025-11-25", "tools/list", nil))
	if resp.StatusCode != 429 || authentication.Load() != 4 {
		close(release)
		t.Fatalf("capacity %d authentication %d", resp.StatusCode, authentication.Load())
	}
	close(release)
	wg.Wait()
}

func TestCancelledRequestRemainsChargedUntilCompletion(t *testing.T) {
	h, s := newTestServer(t, func(context.Context, string) (identity.Identity, error) { return testIdentity(), nil })
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	h.protocol = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(cancelled)
		<-release
	})
	request := rpcRequest(t, s, "2025-11-25", "tools/list", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request = request.WithContext(ctx)
	go func() {
		resp, _ := s.Client().Do(request)
		if resp != nil {
			resp.Body.Close()
		}
		close(finished)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("request not started")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("owner cancellation lost")
	}
	h.mu.Lock()
	slots := len(h.slots)
	principals := len(h.inFlight)
	h.mu.Unlock()
	if slots != 1 || principals != 1 {
		close(release)
		t.Fatal("cancelled but still running request released capacity")
	}
	close(release)
	<-finished
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		done := len(h.inFlight) == 0 && len(h.slots) == 0
		h.mu.Unlock()
		if done {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("finished request retained capacity")
}

func TestUnsupportedMethodsAndForgedNameNeverStartSDK(t *testing.T) {
	h, s := newTestServer(t, func(context.Context, string) (identity.Identity, error) { return testIdentity(), nil })
	var invoked atomic.Int64
	h.protocol = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { invoked.Add(1) })
	for _, tc := range []struct {
		method string
		alter  func(*http.Request)
	}{
		{"subscriptions/listen", nil}, {"logging/setLevel", nil}, {"resources/read", nil}, {"prompts/get", nil},
		{"tools/call", func(r *http.Request) { r.Header.Set("Mcp-Name", "different-tool") }},
		{"tools/list", func(r *http.Request) { r.Header.Set("Mcp-Param-Target", "foreign") }},
		{"tools/list", func(r *http.Request) { r.Header.Del("Mcp-Protocol-Version") }},
	} {
		r := rpcRequest(t, s, "2025-11-25", tc.method, map[string]any{"name": "request_capture", "arguments": map[string]any{}})
		if tc.alter != nil {
			tc.alter(r)
		}
		resp, _ := send(t, s, r)
		if resp.StatusCode != 400 {
			t.Fatalf("%s: %d", tc.method, resp.StatusCode)
		}
	}
	if invoked.Load() != 0 {
		t.Fatal("unavailable operation reached SDK")
	}
}
