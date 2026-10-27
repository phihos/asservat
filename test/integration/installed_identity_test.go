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
}

func newInstalledIdentity(t *testing.T, f fixture, origin, consoleSecret string) *installedIdentity {
	t.Helper()
	id := f.Identity
	if id == nil {
		t.Fatal("harness started no owned Keycloak")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(id.RootCA)) {
		t.Fatal("owned Keycloak root")
	}
	kc := &kcFixture{t: t, base: id.Base, Issuer: id.Base + "/realms/asservat", AdminUser: id.AdminUser, AdminPassword: id.AdminPassword, UserPassword: id.UserPassword}
	kc.http = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	kc.admin = kc.tokens(kc.base+"/realms/master/protocol/openid-connect/token", url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {kc.AdminUser}, "password": {kc.AdminPassword}}, 200).Access
	kc.json("POST", "/admin/realms", map[string]any{"realm": "asservat", "enabled": true, "registrationAllowed": false, "accessTokenLifespan": 300, "revokeRefreshToken": true, "refreshTokenMaxReuse": 0})
	prefix := "/admin/realms/asservat"
	var profile map[string]any
	if err := json.Unmarshal(kc.json("GET", prefix+"/users/profile", nil), &profile); err != nil {
		t.Fatal("user profile", err)
	}
	attributes, _ := profile["attributes"].([]any)
	profile["attributes"] = append(attributes, map[string]any{"name": "asservat_group_id", "multivalued": true, "permissions": map[string]any{"view": []string{"admin"}, "edit": []string{"admin"}}})
	delete(profile, "unmanagedAttributePolicy")
	kc.json("PUT", prefix+"/users/profile", profile)
	for _, scope := range []string{"evidence:read", "evidence:download", "evidence:capture", "evidence:share"} {
		kc.json("POST", prefix+"/client-scopes", map[string]any{"name": scope, "protocol": "openid-connect", "attributes": map[string]string{"include.in.token.scope": "true"}})
	}
	groups := map[string]any{"name": "stable-groups", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper", "config": map[string]string{"user.attribute": "asservat_group_id", "claim.name": "asservat_groups", "jsonType.label": "String", "multivalued": "true", "aggregate.attrs": "true", "access.token.claim": "true", "id.token.claim": "false", "userinfo.token.claim": "false"}}
	audience := func(value string) map[string]any {
		return map[string]any{"name": "audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": map[string]string{"included.custom.audience": value, "access.token.claim": "true", "id.token.claim": "false"}}
	}
	// evidence:share is a default console scope so the browser can share (ADR-232 console).
	scopes := []string{"basic", "evidence:read", "evidence:download", "evidence:capture", "evidence:share"}
	if installedJourneyFocus() == "approved-recording" {
		scopes = append(scopes, "acr")
	}
	kc.json("POST", prefix+"/clients", map[string]any{"clientId": "console", "protocol": "openid-connect", "publicClient": false, "secret": consoleSecret, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "serviceAccountsEnabled": false, "fullScopeAllowed": false, "redirectUris": []string{strings.TrimSuffix(origin, "/") + "/auth/callback"}, "defaultClientScopes": scopes, "optionalClientScopes": []string{}, "attributes": map[string]string{"pkce.code.challenge.method": "S256"}, "protocolMappers": []any{audience("asservat-api"), groups}})
	// Each MCP token names exactly one resource: the MCP endpoint, or the
	// download content route (ADR-204 decision 10). The client requests one
	// of two optional scopes, each carrying one audience.
	for name, resource := range map[string]string{installedMCPScope: "/mcp", installedDownloadsScope: "/api/v1/downloads"} {
		kc.json("POST", prefix+"/client-scopes", map[string]any{"name": name, "protocol": "openid-connect", "attributes": map[string]string{"include.in.token.scope": "false"}, "protocolMappers": []any{audience(strings.TrimSuffix(origin, "/") + resource)}})
	}
	kc.json("POST", prefix+"/clients", map[string]any{"clientId": "mcp", "protocol": "openid-connect", "publicClient": true, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "serviceAccountsEnabled": false, "fullScopeAllowed": false, "redirectUris": []string{"http://127.0.0.1:1/callback"}, "defaultClientScopes": []string{"basic", "evidence:read"}, "optionalClientScopes": []string{installedMCPScope, installedDownloadsScope, "evidence:download", "evidence:capture", "evidence:share"}, "attributes": map[string]string{"pkce.code.challenge.method": "S256"}, "protocolMappers": []any{groups}})
	created := func(path string, value any) string {
		t.Helper()
		body, _ := json.Marshal(value)
		status, _, headers := kc.request("POST", kc.base+prefix+path, kc.admin, "application/json", body)
		location := headers.Get("Location")
		if status != 201 || len(location) < 36 {
			t.Fatalf("realm create %s: status %d", path, status)
		}
		return location[strings.LastIndex(location, "/")+1:]
	}
	group := created("/groups", map[string]any{"name": "maintainers"})
	kc.json("PUT", prefix+"/groups/"+group, map[string]any{"name": "maintainers", "attributes": map[string]any{"asservat_group_id": []string{installedIdentityGroup}}})
	user := created("/users", map[string]any{"username": "developer", "enabled": true, "email": "synthetic@example.invalid", "firstName": "Synthetic", "lastName": "Developer", "credentials": []any{map[string]any{"type": "password", "value": kc.UserPassword, "temporary": false}}})
	kc.json("PUT", prefix+"/users/"+user+"/groups/"+group, nil)
	var reviewer string
	if installedJourneyFocus() == "approved-recording" {
		reviewer = created("/users", map[string]any{"username": "reviewer", "enabled": true, "email": "reviewer@example.invalid", "firstName": "Synthetic", "lastName": "Reviewer", "credentials": []any{map[string]any{"type": "password", "value": kc.UserPassword, "temporary": false}}})
		kc.json("PUT", prefix+"/users/"+reviewer+"/groups/"+group, nil)
	}
	// An organization member the installation accepts (eligible group) whom no
	// AccessBinding names: the S-02 unrelated principal.
	outsiders := created("/groups", map[string]any{"name": "outsiders"})
	kc.json("PUT", prefix+"/groups/"+outsiders, map[string]any{"name": "outsiders", "attributes": map[string]any{"asservat_group_id": []string{installedUnrelatedGroup}}})
	outsider := created("/users", map[string]any{"username": "outsider", "enabled": true, "email": "outsider@example.invalid", "firstName": "Synthetic", "lastName": "Outsider", "credentials": []any{map[string]any{"type": "password", "value": kc.UserPassword, "temporary": false}}})
	kc.json("PUT", prefix+"/users/"+outsider+"/groups/"+outsiders, nil)
	return &installedIdentity{kc: kc, Issuer: kc.Issuer, RootPEM: id.RootCA, ReviewerSubject: reviewer}
}

// installedUnrelatedGroup is eligible for sign-in but named by no AccessBinding.
const installedUnrelatedGroup = "synthetic-unrelated-group"

// unrelated returns the same realm's outsider user with its own HTTP client.
func (i *installedIdentity) unrelated() *installedIdentity {
	kc, client := *i.kc, *i.kc.http
	kc.http, kc.username = &client, "outsider"
	return &installedIdentity{kc: &kc, Issuer: i.Issuer, RootPEM: i.RootPEM}
}

const installedMCPScope, installedDownloadsScope = "resource-mcp", "resource-downloads"

// mcpToken logs the synthetic user in to the MCP client with authorization
// code and S256 PKCE and returns its access token for the MCP endpoint.
func (i *installedIdentity) mcpToken() string {
	return i.kc.loginScope("mcp", installedMCPScope).Access
}

// downloadToken returns the same client's access token for the download
// content route: a download is bound to the client that prepared it.
func (i *installedIdentity) downloadToken() string {
	return i.kc.loginScope("mcp", installedDownloadsScope).Access
}

// installedJourneyTokenSource refreshes the real user's original OAuth session.
// Decoding exp is only client scheduling: every request still receives the
// server's full signature, current identity and authority checks. Refresh never
// extends an evidence, download or server request deadline.
type installedJourneyTokenSource struct {
	mu               sync.Mutex
	issuer, resource string
	now              func() time.Time
	login            func() kcTokens
	refresh          func(string) kcTokens
	tokens           kcTokens
	subject          string
	until            time.Time
	approvedOnly     bool
}

func (i *installedIdentity) mcpTokenSource(origin string) *installedJourneyTokenSource {
	return &installedJourneyTokenSource{issuer: i.Issuer, resource: strings.TrimSuffix(origin, "/") + "/mcp", now: time.Now,
		login:   func() kcTokens { return i.kc.loginScope("mcp", installedMCPScope) },
		refresh: func(token string) kcTokens { return i.kc.refresh("mcp", token, http.StatusOK) }}
}

// The same configured MCP client/principal uses a distinct real OAuth session
// without native-download scope. Refresh keeps that original scope selection.
func (i *installedIdentity) approvedTokenSource(origin string) *installedJourneyTokenSource {
	return &installedJourneyTokenSource{issuer: i.Issuer, resource: strings.TrimSuffix(origin, "/") + "/mcp", now: time.Now, approvedOnly: true,
		login:   func() kcTokens { return i.kc.loginScopes("mcp", "openid evidence:read "+installedMCPScope) },
		refresh: func(token string) kcTokens { return i.kc.refresh("mcp", token, http.StatusOK) }}
}

// shareTokenSource is the same principal's MCP session with the optional
// evidence:share scope (ADR-232) and, for the ADR-235 capture-time share, the
// evidence:capture scope; no download scope.
func (i *installedIdentity) shareTokenSource(origin string) *installedJourneyTokenSource {
	return &installedJourneyTokenSource{issuer: i.Issuer, resource: strings.TrimSuffix(origin, "/") + "/mcp", now: time.Now,
		login: func() kcTokens {
			return i.kc.loginScopes("mcp", "openid evidence:read evidence:share evidence:capture "+installedMCPScope)
		},
		refresh: func(token string) kcTokens { return i.kc.refresh("mcp", token, http.StatusOK) }}
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
	if claims.Issuer != s.issuer || claims.Subject == "" || s.subject != "" && claims.Subject != s.subject || claims.Client != "mcp" ||
		len(audiences) != 1 || audiences[0] != s.resource || !s.now().Add(30*time.Second).Before(until) || next.Refresh == "" {
		return "", errors.New("installed identity refresh changed its principal/resource or returned expired credentials")
	}
	if s.approvedOnly && !installedApprovedScopes(claims.Scope) {
		return "", errors.New("approved session lost read scope or gained download/capture scope")
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
				if host, _, e := net.SplitHostPort(target); e == nil && host == u.Hostname() {
					target = address
				}
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
