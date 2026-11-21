package hub_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

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
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/keys", "authorization_endpoint": issuer.URL + "/auth",
				"token_endpoint": issuer.URL + "/token", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
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
	verify, err := hub.OIDCVerifier(t.Context(), issuer.URL, "asservat", "preferred_username", "groups")
	if err != nil {
		t.Fatal(err)
	}
	h, err := hub.New(hub.Config{MasterKey: bytes.Repeat([]byte{1}, 32), Retention: time.Hour, AdminGroups: []string{"admins"}, Verify: verify})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h.Handler())
	defer server.Close()
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
}
