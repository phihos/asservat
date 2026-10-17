package oidc

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestBrowserIDAndLogoutProfiles(t *testing.T) {
	f := newFixture(t)
	p := &BrowserProvider{trust: BrowserTrust{Access: f.v.trust, ClientID: "console"}, access: f.v}
	claims := func() map[string]any {
		return map[string]any{"iss": f.v.trust.Issuer, "sub": "developer", "aud": "console", "iat": f.now().Unix(), "exp": f.now().Add(time.Minute).Unix(), "sid": "session", "nonce": "expected", "auth_time": f.now().Unix()}
	}
	if _, e := p.idToken(context.Background(), sign(t, f.key, "key-1", "JWT", claims()), "expected", false); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(map[string]any){
		"wrong nonce":    func(c map[string]any) { c["nonce"] = "wrong" },
		"wrong audience": func(c map[string]any) { c["aud"] = "asservat-api" },
		"aliased nonce":  func(c map[string]any) { c["NONCE"] = c["nonce"]; delete(c, "nonce") },
		"future nbf":     func(c map[string]any) { c["nbf"] = f.now().Add(time.Hour).Unix() },
		"logout used as login": func(c map[string]any) {
			c["events"] = map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}
		},
		"bearer used as login": func(c map[string]any) { c["typ"] = "Bearer" },
	} {
		t.Run(name, func(t *testing.T) {
			c := claims()
			mutate(c)
			if _, e := p.idToken(context.Background(), sign(t, f.key, "key-1", "JWT", c), "expected", false); e == nil {
				t.Fatal("invalid ID token accepted")
			}
		})
	}
	logout := func() map[string]any {
		c := claims()
		delete(c, "nonce")

		c["jti"] = "one-use-logout"
		c["events"] = map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}
		return c
	}
	if _, e := p.VerifyLogout(context.Background(), sign(t, f.key, "key-1", "logout+jwt", logout())); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(map[string]any){
		"nonce in logout":       func(c map[string]any) { c["nonce"] = "forbidden" },
		"missing exp":           func(c map[string]any) { delete(c, "exp") },
		"missing jti":           func(c map[string]any) { delete(c, "jti") },
		"missing event":         func(c map[string]any) { delete(c, "events") },
		"wrong event":           func(c map[string]any) { c["events"] = map[string]any{"other": map[string]any{}} },
		"old event":             func(c map[string]any) { c["iat"] = f.now().Add(-5 * time.Minute).Unix() },
		"future event":          func(c map[string]any) { c["iat"] = f.now().Add(time.Second).Unix() },
		"future nbf":            func(c map[string]any) { c["nbf"] = f.now().Add(time.Hour).Unix() },
		"no target":             func(c map[string]any) { delete(c, "sub"); delete(c, "sid") },
		"access used as logout": func(c map[string]any) { c["typ"] = "Bearer" },
		"ID used as logout":     func(c map[string]any) { c["typ"] = "ID" },
	} {
		t.Run(name, func(t *testing.T) {
			c := logout()
			mutate(c)
			if _, e := p.VerifyLogout(context.Background(), sign(t, f.key, "key-1", "JWT", c)); e == nil {
				t.Fatal("invalid logout accepted")
			}
		})
	}
	c := claims()
	delete(c, "nonce")
	if _, e := p.idToken(context.Background(), sign(t, f.key, "key-1", "JWT", c), "expected", true); e != nil {
		t.Fatal("refresh nonce may be omitted")
	}
	c["nonce"] = "changed"
	if _, e := p.idToken(context.Background(), sign(t, f.key, "key-1", "JWT", c), "expected", true); e == nil {
		t.Fatal("changed refresh nonce accepted")
	}
}

func TestBrowserTrustAndAuthorizationURL(t *testing.T) {
	f := newFixture(t)
	p := &BrowserProvider{trust: BrowserTrust{Access: f.v.trust, ClientID: "console", AuthorizationEndpoint: f.server.URL + "/auth", RedirectURI: "https://console.invalid/auth/callback", Scopes: []string{"openid"}}, access: f.v}
	s := strings.Repeat("A", 43)
	u, e := p.AuthorizationURL(s, s, s)
	if e != nil || !strings.Contains(u, "code_challenge_method=S256") || strings.Contains(u, "code_verifier") {
		t.Fatal("PKCE URL")
	}
	if _, e = p.AuthorizationURL("short", s, s); e == nil {
		t.Fatal("weak state accepted")
	}
	trust := p.trust
	trust.TokenEndpoint = f.server.URL + "/token"
	trust.ClientSecret = "synthetic"
	trust.Scopes = []string{"openid", "offline_access"}
	if _, e = NewBrowser(trust, f.now); e == nil {
		t.Fatal("offline scope accepted")
	}
}
