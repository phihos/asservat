package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// installedIdentityGroup is the stable group ID the installed continuation's
// identity settings and AccessBindings already name.
const installedIdentityGroup = "synthetic-group"

// installedIdentity is the owned Keycloak realm of the installed journey
// (scripts/test-context-storage.py --installer-continuation): a confidential
// console client, a public MCP client whose access tokens carry exactly one
// resource audience (MCP or download content), and one user in the synthetic
// group. All values are
// synthetic; the realm exists only on the run's private network.
type installedIdentity struct {
	kc              *kcFixture
	Issuer          string
	RootPEM         string
	ReviewerSubject string
	// Imported bundled realms use their actual immutable identities and client
	// configuration. Empty fields preserve the original external fixture.
	UsersGroupID, ProcessingGroupID, SubjectID, UnrelatedSubjectID string
	MCPClientID, MCPScope, DownloadsScope                          string
}

// installedConsoleScopes produces the actual owned Keycloak console input.
func installedConsoleScopes() []string {
	// evidence:share is a default console scope so the browser can share (ADR-232 console).
	scopes := []string{"basic", "evidence:read", "evidence:download", "evidence:capture", "evidence:share"}
	if installedJourneyFocus() == "manual-raw" || installedJourneyFocus() == "manual-arguments" || installedLogsFocus() {
		scopes = append(scopes, "evidence:raw")
	}
	if installedRecordingFocus() || installedLogsFocus() {
		scopes = append(scopes, "acr")
	}
	return scopes
}

// unrelated returns the same realm's outsider user with its own HTTP client.
func (i *installedIdentity) unrelated() *installedIdentity {
	kc, client := *i.kc, *i.kc.http
	kc.http, kc.username = &client, "outsider"
	out := *i
	out.kc, out.SubjectID, out.ReviewerSubject = &kc, i.UnrelatedSubjectID, ""
	return &out
}

const installedMCPScope, installedDownloadsScope = "resource-mcp", "resource-downloads"

func (i *installedIdentity) mcpClient() string {
	if i.MCPClientID != "" {
		return i.MCPClientID
	}
	return "mcp"
}
func (i *installedIdentity) mcpResourceScope() string {
	if i.MCPScope != "" {
		return i.MCPScope
	}
	return installedMCPScope
}
func (i *installedIdentity) downloadResourceScope() string {
	if i.DownloadsScope != "" {
		return i.DownloadsScope
	}
	return installedDownloadsScope
}

// downloadToken returns the same client's access token for the download
// content route: a download is bound to the client that prepared it.
func (i *installedIdentity) downloadToken() string {
	return i.kc.loginScope(i.mcpClient(), i.downloadResourceScope()).Access
}

// installedJourneyTokenSource refreshes the real user's original OAuth session.
// Decoding exp is only client scheduling: every request still receives the
// server's full signature, current identity and authority checks. Refresh never
// extends an evidence, download or server request deadline.
type installedJourneyTokenSource struct {
	mu                         sync.Mutex
	issuer, resource, clientID string
	now                        func() time.Time
	login                      func() kcTokens
	refresh                    func(string) kcTokens
	tokens                     kcTokens
	subject                    string
	until                      time.Time
	approvedOnly               bool
	packetQueryOnly            bool
}

func (i *installedIdentity) mcpTokenSource(origin string) *installedJourneyTokenSource {
	return &installedJourneyTokenSource{issuer: i.Issuer, clientID: i.mcpClient(), resource: strings.TrimSuffix(origin, "/") + "/mcp", now: time.Now,
		login:   func() kcTokens { return i.kc.loginScope(i.mcpClient(), i.mcpResourceScope()) },
		refresh: func(token string) kcTokens { return i.kc.refresh(i.mcpClient(), token, http.StatusOK) }}
}

// The same configured MCP client/principal uses a distinct real OAuth session
// without native-download scope. Refresh keeps that original scope selection.
func (i *installedIdentity) approvedTokenSource(origin string) *installedJourneyTokenSource {
	return &installedJourneyTokenSource{issuer: i.Issuer, clientID: i.mcpClient(), resource: strings.TrimSuffix(origin, "/") + "/mcp", now: time.Now, approvedOnly: true,
		login:   func() kcTokens { return i.kc.loginScopes(i.mcpClient(), "openid evidence:read "+i.mcpResourceScope()) },
		refresh: func(token string) kcTokens { return i.kc.refresh(i.mcpClient(), token, http.StatusOK) }}
}

// shareTokenSource is the same principal's MCP session with the optional
// evidence:share scope (ADR-232) and, for the ADR-235 capture-time share, the
// evidence:capture scope; no download scope.
func (i *installedIdentity) shareTokenSource(origin string) *installedJourneyTokenSource {
	return &installedJourneyTokenSource{issuer: i.Issuer, clientID: i.mcpClient(), resource: strings.TrimSuffix(origin, "/") + "/mcp", now: time.Now,
		login: func() kcTokens {
			return i.kc.loginScopes(i.mcpClient(), "openid evidence:read evidence:share evidence:capture "+i.mcpResourceScope())
		},
		refresh: func(token string) kcTokens { return i.kc.refresh(i.mcpClient(), token, http.StatusOK) }}
}

func (s *installedJourneyTokenSource) client() string {
	if s.clientID != "" {
		return s.clientID
	}
	return "mcp"
}

func (s *installedJourneyTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if s.tokens.Access != "" && s.now().Add(30*time.Second).Before(s.until) {
		return s.tokens.Access, nil
	}
	var next kcTokens
	if s.tokens.Access == "" {
		next = s.login()
	} else {
		if s.tokens.Refresh == "" {
			return "", errors.New("installed identity has no refresh credential")
		}
		next = s.refresh(s.tokens.Refresh)
	}
	parts := strings.Split(next.Access, ".")
	if len(parts) != 3 {
		return "", errors.New("installed identity token shape")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Issuer   string          `json:"iss"`
		Subject  string          `json:"sub"`
		Client   string          `json:"azp"`
		Audience json.RawMessage `json:"aud"`
		Expires  int64           `json:"exp"`
		Scope    string          `json:"scope"`
	}
	if err != nil || json.Unmarshal(raw, &claims) != nil {
		return "", errors.New("installed identity token claims")
	}
	var audiences []string
	var single string
	if json.Unmarshal(claims.Audience, &single) == nil {
		audiences = []string{single}
	} else {
		_ = json.Unmarshal(claims.Audience, &audiences)
	}
	until := time.Unix(claims.Expires, 0)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if claims.Issuer != s.issuer || claims.Subject == "" || s.subject != "" && claims.Subject != s.subject || claims.Client != s.client() ||
		len(audiences) != 1 || audiences[0] != s.resource || !s.now().Add(30*time.Second).Before(until) || next.Refresh == "" {
		return "", errors.New("installed identity refresh changed its principal/resource or returned expired credentials")
	}
	if s.approvedOnly && !installedApprovedScopes(claims.Scope) {
		return "", errors.New("approved session lost read scope or gained download/capture scope")
	}
	if s.packetQueryOnly && !strings.Contains(" "+claims.Scope+" ", " evidence:raw ") {
		return "", errors.New("packet query session lacks raw scope")
	}
	s.tokens, s.subject, s.until = next, claims.Subject, until
	return next.Access, nil
}

// initializeProcessing logs the synthetic user in through the console client
// and, as the configured processing operator (ADR-210), initializes
// processing before the first preview. One Idempotency-Key names the change;
// a 503 is retried under that same key, so a lost reply resumes, never
// repeats, the audited change. The console origin is dialled at address.
func (i *installedIdentity) initializeProcessing(t *testing.T, ctx context.Context, publicRoot *x509.Certificate, address, origin string, diagnose func()) {
	t.Helper()
	if installedProcessingInitialized {
		// The product refuses a second initialization; an earlier focus of
		// this multi-focus run initialized processing through the console.
		t.Log("installed journey: processing already initialized by an earlier focus of this run")
		return
	}
	roots := x509.NewCertPool()
	roots.AddCert(publicRoot)
	if !roots.AppendCertsFromPEM([]byte(i.RootPEM)) {
		t.Fatal("console login roots")
	}
	u, err := url.Parse(origin)
	if err != nil {
		t.Fatal("console origin", err)
	}
	dial := &net.Dialer{Timeout: 5 * time.Second}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
				target = installedConsoleDialTarget(u, target, address)
				return dial.DialContext(ctx, network, target)
			}}}
	defer client.CloseIdleConnections()
	base := strings.TrimSuffix(origin, "/")
	request := func(method, target, media string, body []byte, header map[string]string) (int, []byte, http.Header) {
		t.Helper()
		r, _ := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if media != "" {
			r.Header.Set("Content-Type", media)
		}
		for k, v := range header {
			r.Header.Set(k, v)
		}
		response, e := client.Do(r)
		if e != nil {
			t.Fatal("console HTTP", method, e)
		}
		defer response.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(response.Body, 256<<10))
		return response.StatusCode, b, response.Header
	}
	status, _, headers := request("GET", base+"/auth/login?return_to=%2Finvestigations", "", nil, nil)
	if status != http.StatusSeeOther {
		t.Fatal("console login start", status)
	}
	status, page, _ := request("GET", headers.Get("Location"), "", nil, nil)
	match := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page)
	if status != http.StatusOK || len(match) != 2 {
		t.Fatal("console login form", status)
	}
	action := html.UnescapeString(string(match[1]))
	if !strings.HasPrefix(action, i.Issuer+"/login-actions/") {
		t.Fatal("console login form escaped the issuer")
	}
	status, _, headers = request("POST", action, "application/x-www-form-urlencoded", []byte(url.Values{"username": {"developer"}, "password": {i.kc.UserPassword}}.Encode()), nil)
	if status != http.StatusFound {
		t.Fatal("console provider login", status)
	}
	if status, _, _ = request("GET", headers.Get("Location"), "", nil, nil); status != http.StatusSeeOther {
		t.Fatal("console callback", status)
	}
	status, b, _ := request("GET", base+"/api/v1/session", "", nil, nil)
	var view struct {
		CSRF string `json:"csrf_token"`
	}
	if status != http.StatusOK || json.Unmarshal(b, &view) != nil || len(view.CSRF) != 43 {
		t.Fatal("console session", status)
	}
	key := uuid.NewString()
	header := map[string]string{"Origin": base, "X-CSRF-Token": view.CSRF, "Idempotency-Key": key}
	for until := time.Now().Add(time.Minute); ; {
		status, b, _ = request("POST", base+"/api/v1/processing/changes", "application/json", []byte(`{"action":"initialize_processing"}`), header)
		var receipt struct {
			State     string `json:"state"`
			RequestID string `json:"requestID"`
		}
		if status == http.StatusOK && json.Unmarshal(b, &receipt) == nil && receipt.State == "initialized" && receipt.RequestID == key {
			installedProcessingInitialized = true
			t.Log("installed journey: the processing operator initialized processing through the console")
			return
		}
		if status != http.StatusServiceUnavailable || !time.Now().Before(until) {
			diagnose()
			t.Fatal("processing initialization", status, string(b))
		}
		select {
		case <-ctx.Done():
			t.Fatal("processing initialization", ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
}
