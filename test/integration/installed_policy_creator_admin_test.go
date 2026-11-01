package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// This is fixture administration, not product or creator authority. Copy the
// current child test so a provider failure cannot FailNow its parent test.
// The existing pinned HTTPS client and its finite request timeout are retained.
func installedPolicyDisableCreator(t *testing.T, initial *kcFixture, subject string) {
	t.Helper()
	current := *initial
	current.t = t
	// The initial master token can be rejected after the lengthy native setup.
	// Reauthorize this one fixture action; never retry the mutation on a 401.
	current.admin = current.tokens(current.base+"/realms/master/protocol/openid-connect/token", url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {current.AdminUser}, "password": {current.AdminPassword}}, http.StatusOK).Access
	current.json("PUT", "/admin/realms/asservat/users/"+subject, map[string]any{"enabled": false})
	var creator struct {
		ID      string `json:"id"`
		Enabled *bool  `json:"enabled"`
	}
	if err := json.Unmarshal(current.json("GET", "/admin/realms/asservat/users/"+subject, nil), &creator); err != nil || creator.ID != subject || creator.Enabled == nil || *creator.Enabled {
		t.Fatal("creator departure lacks exact provider readback", err, creator)
	}
}

// Actual TLS/HTTP fixture helper calls, synthetic provider authorization. The
// old administrator token is refused; this is not a live Keycloak expiry test.
func TestInstalledPolicyCreatorUsesFreshAdminAuthorization(t *testing.T) {
	const subject = "11111111-1111-4111-8111-111111111111"
	calls := make(chan string, 4)
	record := func(call string) {
		select {
		case calls <- call:
		default:
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			record("token")
			if r.Method != "POST" || r.Header.Get("Authorization") != "" || r.ParseForm() != nil || r.Form.Get("grant_type") != "password" || r.Form.Get("client_id") != "admin-cli" || r.Form.Get("username") != "fixture-admin" || r.Form.Get("password") != "synthetic-only" {
				http.Error(w, "invalid fixture authorization", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"current-fixture-admin"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer current-fixture-admin" {
			http.Error(w, "cached administrator authorization rejected", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/admin/realms/asservat/users/"+subject {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case "PUT":
			record("disable")
			var value struct {
				Enabled *bool `json:"enabled"`
			}
			if json.NewDecoder(r.Body).Decode(&value) != nil || value.Enabled == nil || *value.Enabled {
				http.Error(w, "wrong update", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "GET":
			record("readback")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"` + subject + `","enabled":false}`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	original := &kcFixture{t: t, http: client, base: server.URL, AdminUser: "fixture-admin", AdminPassword: "synthetic-only", admin: "rejected-cached-admin"}
	parent := t
	t.Run("ordered authorization and offboarding", func(t *testing.T) {
		installedPolicyDisableCreator(t, original, subject)
		if original.admin != "rejected-cached-admin" || original.t != parent || original.http != client {
			t.Fatal("private administration changed original fixture")
		}
		for _, want := range []string{"token", "disable", "readback"} {
			select {
			case got := <-calls:
				if got != want {
					t.Fatalf("provider call=%s want=%s", got, want)
				}
			default:
				t.Fatal("missing provider call", want)
			}
		}
		select {
		case got := <-calls:
			t.Fatal("unexpected retry/provider call", got)
		default:
		}
	})
}
