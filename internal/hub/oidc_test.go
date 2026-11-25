package hub_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"asservat.local/asservat/internal/hub"
)

// An OIDC ID token signs a user in with its name and groups; tokens for
// another client, expired tokens and tokens of another key are refused.
func TestOIDCBearer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer *httptest.Server
	var idToken func() string
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/keys", "authorization_endpoint": issuer.URL + "/auth",
				"token_endpoint": issuer.URL + "/token", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			// The code is the PKCE challenge that the sign-in began with.
			id, secret, _ := r.BasicAuth()
			challenge := sha256.Sum256([]byte(r.FormValue("code_verifier")))
			if id != "asservat" || secret != "client-secret" || r.FormValue("code") != base64.RawURLEncoding.EncodeToString(challenge[:]) ||
				!strings.HasSuffix(r.FormValue("redirect_uri"), "/auth/callback") {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "token_type": "Bearer", "id_token": idToken()})
		}
	}))
	defer issuer.Close()
	sign := func(signer *rsa.PrivateKey, claims map[string]any) string {
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signer}, (&jose.SignerOptions{}).WithHeader("kid", "k"))
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(claims)
		signed, err := s.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		token, _ := signed.CompactSerialize()
		return token
	}
	claims := func(audience string, expires time.Time) map[string]any {
		return map[string]any{"iss": issuer.URL, "aud": audience, "sub": "1234", "exp": expires.Unix(), "iat": time.Now().Unix(),
			"preferred_username": "alice", "groups": []string{"payments", "admins"}}
	}
	verify, endpoint, err := hub.OIDCVerifier(t.Context(), issuer.URL, "asservat", "preferred_username", "groups")
	if err != nil {
		t.Fatal(err)
	}
	oauth := &oauth2.Config{ClientID: "asservat", ClientSecret: "client-secret", Endpoint: endpoint, Scopes: []string{"openid"}}
	h, err := hub.New(hub.Config{MasterKey: bytes.Repeat([]byte{1}, 32), Retention: time.Hour, AdminGroups: []string{"admins"}, Verify: verify, OAuth: oauth})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h.Handler())
	defer server.Close()
	oauth.RedirectURL = server.URL + "/auth/callback"
	me := func(token string) (int, hub.User) {
		req, _ := http.NewRequest("GET", server.URL+"/api/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var u hub.User
		json.NewDecoder(res.Body).Decode(&u)
		return res.StatusCode, u
	}
	in := time.Now().Add(time.Hour)
	if code, u := me(sign(key, claims("asservat", in))); code != 200 || u.Name != "alice" || len(u.Groups) != 2 || !u.Admin {
		t.Fatal("valid token", code, u)
	}
	// Names that begin with "system:" are Kubernetes's own (system:masters
	// may do everything): an identity provider's user is none of them, and
	// neither is a group it names, whatever its users may call themselves.
	reserved := claims("asservat", in)
	reserved["groups"] = []string{"payments", "system:masters"}
	if code, u := me(sign(key, reserved)); code != 200 || len(u.Groups) != 1 || u.Groups[0] != "payments" {
		t.Fatal("a group of Kubernetes's own was taken from the token", code, u)
	}
	reserved["preferred_username"] = "system:admin"
	if code, _ := me(sign(key, reserved)); code != 401 {
		t.Fatal("a user name of Kubernetes's own was taken from the token", code)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, token := range map[string]string{
		"another client": sign(key, claims("other-app", in)),
		"expired":        sign(key, claims("asservat", time.Now().Add(-time.Hour))),
		"another key":    sign(other, claims("asservat", in)),
		"no user claim":  sign(key, map[string]any{"iss": issuer.URL, "aud": "asservat", "sub": "1", "exp": in.Unix()}),
		"garbage":        "not-a-token",
	} {
		if code, _ := me(token); code != 401 {
			t.Errorf("%s: accepted with status %d", name, code)
		}
	}

	// The browser sign-in: the hub sends the browser to the issuer, takes
	// the code it comes back with and keeps the user in a session cookie.
	idToken = func() string { return sign(key, claims("asservat", in)) }
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string) *http.Response {
		t.Helper()
		res, err := browser.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	if res := get("/api/me"); res.StatusCode != 401 {
		t.Fatal("signed in before the sign-in", res.StatusCode)
	}
	res := get("/auth/login")
	to, _ := url.Parse(res.Header.Get("Location"))
	q := to.Query()
	if res.StatusCode != 302 || to.Path != "/auth" || q.Get("client_id") != "asservat" || q.Get("code_challenge_method") != "S256" || q.Get("state") == "" {
		t.Fatal("redirect to the issuer", res.StatusCode, to)
	}
	if res := get("/auth/callback?code=" + q.Get("code_challenge") + "&state=other"); res.StatusCode != 400 {
		t.Fatal("a callback with another state", res.StatusCode)
	}
	if res := get("/auth/callback?code=wrong&state=" + q.Get("state")); res.StatusCode != 502 {
		t.Fatal("a callback with a code the issuer refuses", res.StatusCode)
	}
	if res := get("/auth/callback?code=" + q.Get("code_challenge") + "&state=" + q.Get("state")); res.StatusCode != 302 || res.Header.Get("Location") != "/" {
		t.Fatal("callback", res.StatusCode)
	}
	if res := get("/api/me"); res.StatusCode != 200 {
		t.Fatal("the session is not signed in", res.StatusCode)
	}
	if res, err := browser.Post(server.URL+"/auth/logout", "", nil); err != nil || res.StatusCode != 200 {
		t.Fatal("logout", err)
	}
	if res := get("/api/me"); res.StatusCode != 401 {
		t.Fatal("signed in after the sign-out", res.StatusCode)
	}
}
