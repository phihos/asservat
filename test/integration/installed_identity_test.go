package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
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

// Raw query inspection is a distinct OAuth session; it has no capture or native-download scope.
func (i *installedIdentity) packetQueryTokenSource(origin string) *installedJourneyTokenSource {
	return &installedJourneyTokenSource{issuer: i.Issuer, clientID: i.mcpClient(), resource: strings.TrimSuffix(origin, "/") + "/mcp", now: time.Now, approvedOnly: true, packetQueryOnly: true, login: func() kcTokens {
		return i.kc.loginScopes(i.mcpClient(), "openid evidence:read evidence:raw "+i.mcpResourceScope())
	}, refresh: func(token string) kcTokens { return i.kc.refresh(i.mcpClient(), token, http.StatusOK) }}
}
