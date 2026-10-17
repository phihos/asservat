package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"
	jose "github.com/go-jose/go-jose/v4"
)

type fixture struct {
	v       *Verifier
	server  *httptest.Server
	key     *rsa.PrivateKey
	ns      atomic.Int64
	mu      sync.Mutex
	body    []byte
	status  int
	calls   int
	blocked <-chan struct{}
	entered chan struct{}
}

func (f *fixture) now() time.Time          { return time.Unix(0, f.ns.Load()).UTC() }
func (f *fixture) advance(d time.Duration) { f.ns.Add(int64(d)) }
func (f *fixture) set(body []byte, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body = body
	f.status = status
}
func (f *fixture) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }
func jwks(t *testing.T, key *rsa.PrivateKey, kid string) []byte {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{status: 200}
	f.ns.Store(time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC).UnixNano())
	var err error
	f.key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.body = jwks(t, f.key, "key-1")
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls++
		body, status, blocked, entered := f.body, f.status, f.blocked, f.entered
		f.mu.Unlock()
		if r.URL.Path != "/keys" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("unexpected endpoint or credential forwarded")
		}
		if entered != nil {
			select {
			case entered <- struct{}{}:
			default:
			}
		}
		if blocked != nil {
			select {
			case <-blocked:
			case <-r.Context().Done():
				return
			}
		}
		if status == 302 {
			w.Header().Set("Location", f.server.URL+"/forbidden")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	f.v, err = New(Trust{Issuer: f.server.URL + "/issuer", Audience: "asservat-api", JWKSURL: f.server.URL + "/keys", RootCA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}), KeyMaxAge: time.Minute}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.v.Close(); f.server.Close() })
	return f
}
func (f *fixture) claims() map[string]any {
	return map[string]any{"iss": f.v.trust.Issuer, "sub": "developer", "client_id": "console", "aud": "asservat-api", "iat": f.now().Add(-time.Minute).Unix(), "exp": f.now().Add(10 * time.Minute).Unix(), "nbf": f.now().Add(-time.Second).Unix(), "jti": "opaque-token-id", "scope": "evidence:read evidence:download evidence:capture", "groups": []string{"team-a"}}
}
func sign(t *testing.T, key *rsa.PrivateKey, kid, typ string, claims any) string {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return signBytes(t, key, []byte(`{"alg":"RS256","typ":"`+typ+`","kid":"`+kid+`"}`), body)
}

// Exact malformed JSON is deliberately signed in this test helper only.
func signBytes(t *testing.T, key *rsa.PrivateKey, header, claims []byte) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestAccessTokenIdentity(t *testing.T) {
	f := newFixture(t)
	for _, typ := range []string{"at+jwt", "application/at+jwt", "at+JWT"} {
		t.Run(typ, func(t *testing.T) {
			raw := sign(t, f.key, "key-1", typ, f.claims())
			c, err := f.v.Verify(context.Background(), raw)
			if err != nil || c.Subject != "developer" || c.ClientID != "console" || len(c.Groups) != 1 || !c.KeyUntil.Equal(f.now().Add(time.Minute)) {
				t.Fatalf("valid access token: %v", err)
			}
		})
	}
	if f.count() != 1 {
		t.Fatal("valid cached key caused extra network calls")
	}
	claims := f.claims()
	claims["aud"] = []string{"asservat-api"}
	claims["azp"] = "console"
	if _, err := f.v.Verify(context.Background(), sign(t, f.key, "key-1", "at+jwt", claims)); err != nil {
		t.Fatal(err)
	}
}

func TestRejectTokenConfusionAndMalformedClaims(t *testing.T) {
	f := newFixture(t)
	tests := map[string]func(map[string]any){
		"wrong issuer":                    func(c map[string]any) { c["iss"] = "https://evil.example.invalid" },
		"issuer normalization forbidden":  func(c map[string]any) { c["iss"] = f.v.trust.Issuer + "/" },
		"wrong resource":                  func(c map[string]any) { c["aud"] = "another-api" },
		"client audience is not resource": func(c map[string]any) { c["aud"] = "console" },
		"ambiguous resources":             func(c map[string]any) { c["aud"] = []string{"asservat-api", "another-api"} },
		"null audience":                   func(c map[string]any) { c["aud"] = nil },
		"missing subject":                 func(c map[string]any) { delete(c, "sub") },
		"case-aliased subject":            func(c map[string]any) { c["SUB"] = c["sub"]; delete(c, "sub") },
		"case-aliased optional nbf":       func(c map[string]any) { c["NBF"] = f.now().Add(time.Hour).Unix(); delete(c, "nbf") },
		"null subject":                    func(c map[string]any) { c["sub"] = nil },
		"missing client":                  func(c map[string]any) { delete(c, "client_id") },
		"azp disagreement":                func(c map[string]any) { c["azp"] = "other-client" },
		"null azp":                        func(c map[string]any) { c["azp"] = nil },
		"missing expiry":                  func(c map[string]any) { delete(c, "exp") },
		"expiry reached":                  func(c map[string]any) { c["exp"] = f.now().Unix() },
		"fractional expiry":               func(c map[string]any) { c["exp"] = 1.5 },
		"numeric string":                  func(c map[string]any) { c["iat"] = "123" },
		"future issued":                   func(c map[string]any) { c["iat"] = f.now().Add(time.Second).Unix() },
		"future not before":               func(c map[string]any) { c["nbf"] = f.now().Add(time.Second).Unix() },
		"null not before":                 func(c map[string]any) { c["nbf"] = nil },
		"missing token id":                func(c map[string]any) { delete(c, "jti") },
		"ID nonce":                        func(c map[string]any) { c["nonce"] = "login-nonce" },
		"delegated actor":                 func(c map[string]any) { c["act"] = map[string]string{"sub": "admin"} },
		"delegation even null":            func(c map[string]any) { c["may_act"] = nil },
		"unsupported proof binding":       func(c map[string]any) { c["cnf"] = map[string]string{"jkt": "key"} },
		"null groups":                     func(c map[string]any) { c["groups"] = nil },
		"missing group assertion":         func(c map[string]any) { delete(c, "groups") },
		"duplicate group":                 func(c map[string]any) { c["groups"] = []string{"team-a", "team-a"} },
		"group overflow":                  func(c map[string]any) { c["groups"] = make([]string, 257) },
		"group not array":                 func(c map[string]any) { c["groups"] = "team-a" },
		"scope tabs":                      func(c map[string]any) { c["scope"] = "evidence:read\tevidence:capture" },
		"duplicate scope":                 func(c map[string]any) { c["scope"] = "evidence:read evidence:read" },
		"controls in identity":            func(c map[string]any) { c["sub"] = "not-for-logs\nsubject" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			claims := f.claims()
			mutate(claims)
			_, err := f.v.Verify(context.Background(), sign(t, f.key, "key-1", "at+jwt", claims))
			if err == nil {
				t.Fatal("invalid token accepted")
			}
			if strings.Contains(err.Error(), "not-for-logs") || strings.Contains(err.Error(), "evil.example") {
				t.Fatal("claims leaked in error")
			}
		})
	}
	for _, typ := range []string{"JWT", "ID", "Bearer", ""} {
		t.Run("wrong type "+typ, func(t *testing.T) {
			if _, err := f.v.Verify(context.Background(), sign(t, f.key, "key-1", typ, f.claims())); err == nil {
				t.Fatal("ID/untyped token accepted")
			}
		})
	}
	body, _ := json.Marshal(f.claims())
	for _, h := range []string{`{"alg":"RS256","alg":"RS256","typ":"at+jwt","kid":"key-1"}`, `{"alg":"none","typ":"at+jwt","kid":"key-1"}`, `{"alg":"HS256","typ":"at+jwt","kid":"key-1"}`, `{"alg":"RS256","typ":"at+jwt","kid":"key-1","jku":"https://evil.example.invalid"}`, `{"alg":"RS256","typ":"at+jwt","kid":"key-1","crit":[]}`, `{"alg":"RS256","typ":"at+jwt","kid":"key-1","b64":false}`} {
		if _, err := f.v.Verify(context.Background(), signBytes(t, f.key, []byte(h), body)); err == nil {
			t.Fatal("unapproved header accepted")
		}
	}
	duplicate := append([]byte(`{"sub":"attacker",`), body[1:]...)
	if _, err := f.v.Verify(context.Background(), signBytes(t, f.key, []byte(`{"alg":"RS256","typ":"at+jwt","kid":"key-1"}`), duplicate)); err == nil {
		t.Fatal("duplicate signed claim accepted")
	}
	if _, err := f.v.Verify(context.Background(), strings.Repeat("x", MaxTokenBytes+1)); err == nil {
		t.Fatal("oversized token accepted")
	}
	// No malformed preflight above should trigger even a JWKS request.
	if f.count() != 0 {
		t.Fatal("untrusted token selected a network request")
	}
}

func TestKeysRotateExpireAndBoundRequests(t *testing.T) {
	f := newFixture(t)
	old := sign(t, f.key, "key-1", "at+jwt", f.claims())
	if _, err := f.v.Verify(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			if _, err := f.v.Verify(context.Background(), sign(t, f.key, "unknown", "at+jwt", f.claims())); err == nil {
				t.Error("unknown key accepted")
			}
		})
	}
	wg.Wait()
	if f.count() != 1 {
		t.Fatal("unknown-kid storm caused unbounded key fetches")
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.set(jwks(t, newKey, "key-2"), 200)
	f.advance(2 * time.Second)
	newToken := sign(t, newKey, "key-2", "at+jwt", f.claims())
	if _, err = f.v.Verify(context.Background(), newToken); err != nil {
		t.Fatal(err)
	}
	if _, err = f.v.Verify(context.Background(), old); err == nil {
		t.Fatal("removed key survived new snapshot")
	}
	f.advance(time.Minute)
	f.set([]byte("sensitive-upstream-error"), 503)
	if _, err = f.v.Verify(context.Background(), newToken); !errors.Is(err, identity.ErrUnavailable) {
		t.Fatal("expired snapshot survived JWKS outage")
	}
	if f.count() != 3 {
		t.Fatal("unexpected refresh count")
	}
}

func TestSignatureTamperingDoesNotAuthenticateClaims(t *testing.T) {
	f := newFixture(t)
	raw := sign(t, f.key, "key-1", "at+jwt", f.claims())
	if _, err := f.v.Verify(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")
	claims := f.claims()
	claims["sub"] = "privileged-user"
	body, _ := json.Marshal(claims)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(body) + "." + parts[2]
	if _, err := f.v.Verify(context.Background(), forged); err == nil {
		t.Fatal("modified claims accepted without signature")
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.v.Verify(context.Background(), sign(t, other, "key-1", "at+jwt", f.claims())); err == nil {
		t.Fatal("foreign private key accepted under a trusted kid")
	}
	if f.count() != 1 {
		t.Fatal("bad signature unnecessarily refreshed known keys")
	}
}

func TestExpiryAndCancellationDuringKeyFetch(t *testing.T) {
	for _, what := range []string{"expiry", "cancel", "clock rollback"} {
		t.Run(what, func(t *testing.T) {
			f := newFixture(t)
			release := make(chan struct{})
			entered := make(chan struct{}, 1)
			f.mu.Lock()
			f.blocked = release
			f.entered = entered
			f.mu.Unlock()
			claims := f.claims()
			claims["exp"] = f.now().Add(time.Second).Unix()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			token := sign(t, f.key, "key-1", "at+jwt", claims)
			result := make(chan error, 1)
			go func() { _, err := f.v.Verify(ctx, token); result <- err }()
			<-entered
			if what == "expiry" {
				f.advance(2 * time.Second)
			} else if what == "clock rollback" {
				f.advance(-2 * time.Second)
			} else {
				cancel()
			}
			close(release)
			if err := <-result; err == nil {
				t.Fatal("authority survived blocking fetch")
			}
		})
	}
}

func TestJWKSAndEndpointBounds(t *testing.T) {
	for _, what := range []string{"redirect", "too large", "private key", "duplicate key", "duplicate JSON", "key operations", "wrong use"} {
		t.Run(what, func(t *testing.T) {
			f := newFixture(t)
			body := jwks(t, f.key, "key-1")
			status := 200
			switch what {
			case "redirect":
				status = 302
			case "too large":
				body = []byte(strings.Repeat("x", maxKeysBytes+1))
			case "private key":
				body, _ = json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: f.key, KeyID: "key-1", Use: "sig", Algorithm: "RS256"}}})
			case "duplicate key":
				var doc map[string][]any
				_ = json.Unmarshal(body, &doc)
				doc["keys"] = append(doc["keys"], doc["keys"][0])
				body, _ = json.Marshal(doc)
			case "duplicate JSON":
				body = []byte(`{"keys":[],"keys":[]}`)
			case "key operations":
				var doc map[string][]map[string]any
				_ = json.Unmarshal(body, &doc)
				doc["keys"][0]["key_ops"] = []string{"sign"}
				body, _ = json.Marshal(doc)
			case "wrong use":
				body = []byte(strings.ReplaceAll(string(body), `"use":"sig"`, `"use":"enc"`))
			}
			f.set(body, status)
			if _, err := f.v.Verify(context.Background(), sign(t, f.key, "key-1", "at+jwt", f.claims())); err == nil {
				t.Fatal("invalid key publication accepted")
			}
			if f.count() != 1 {
				t.Fatal("redirect or fetch amplification")
			}
		})
	}
	for _, s := range []string{"http://id.example.invalid", "https://user:password@id.example.invalid", "https://id.example.invalid?token=secret", "https://id.example.invalid/#fragment"} {
		if _, err := New(Trust{Issuer: s, Audience: "api", JWKSURL: s, KeyMaxAge: time.Minute}, time.Now); err == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	f := newFixture(t)
	v, err := New(Trust{Issuer: f.v.trust.Issuer, Audience: "asservat-api", JWKSURL: f.v.trust.JWKSURL, KeyMaxAge: time.Minute}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	// Fresh token relative to the fixture's injected verifier clock; use it here
	// too, so this tests TLS rather than an unrelated token-expiry rejection.
	v.now = f.now
	if _, err = v.Verify(context.Background(), sign(t, f.key, "key-1", "at+jwt", f.claims())); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
}

func FuzzAccessTokenSyntax(f *testing.F) {
	for _, s := range []string{"x.y.z", "", strings.Repeat("a", 64)} {
		f.Add(s)
	}
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"at+jwt","kid":"test"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://issuer.invalid","sub":"user","client_id":"console","aud":"api","iat":1,"exp":2,"jti":"id","scope":"evidence:read","groups":[]}`)) + ".c2lnbmF0dXJl")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > MaxTokenBytes+1 {
			return
		}
		_, _, _ = parse(s)
	})
}
