package integration

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"github.com/google/uuid"
)

func TestInstalledBundledIdentityAttachesWithoutRealmOrClientMutation(t *testing.T) {
	for _, privacyOperator := range []bool{false, true} {
		t.Run(fmt.Sprint(privacyOperator), func(t *testing.T) {
			users := "41414141-4141-4141-8141-414141414141"
			processing := uuid.NewSHA1(uuid.MustParse(users), []byte("asservat-processing-operators")).String()
			developer, outsider := "42424242-4242-4242-8242-424242424242", "43434343-4343-4343-8343-434343434343"
			clientID := "44444444-4444-4444-8444-444444444444"
			var mu sync.Mutex
			calls := []string{}
			var endpoint string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				calls = append(calls, r.Method+" "+r.URL.RequestURI())
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token" {
					if r.ParseForm() != nil || r.Form.Get("client_id") != "admin-cli" || r.Form.Get("username") != "retained-admin" || r.Form.Get("password") != "retained-private-password" {
						t.Error("wrong original administration source")
					}
					fmt.Fprint(w, `{"access_token":"synthetic-component-admin"}`)
					return
				}
				if r.Header.Get("Authorization") != "Bearer synthetic-component-admin" {
					t.Error("lost original admin authentication")
					w.WriteHeader(403)
					return
				}
				switch {
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/admin/realms/asservat/groups/"):
					id := strings.TrimPrefix(r.URL.Path, "/admin/realms/asservat/groups/")
					if id != users && id != processing {
						t.Error("invented group lookup")
					}
					json.NewEncoder(w).Encode(map[string]any{"id": id, "attributes": map[string][]string{"asservat_group_id": {id}}})
				case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/asservat/clients":
					name := r.URL.Query().Get("clientId")
					public, secret, redirect := name == "asservat-mcp", "", "http://127.0.0.1:42000/callback"
					if !public {
						if name != "asservat-console" {
							t.Error("invented client")
						}
						secret = "original-console-secret"
						redirect = "https://console.example/auth/callback"
					}
					json.NewEncoder(w).Encode([]any{map[string]any{"id": clientID, "clientId": name, "publicClient": public, "secret": secret, "redirectUris": []string{redirect}}})
				case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/asservat/users":
					var in struct{ Username string }
					json.NewDecoder(r.Body).Decode(&in)
					id := developer
					if in.Username == "outsider" {
						id = outsider
					} else if in.Username != "developer" {
						t.Error("unexpected fixture human")
					}
					w.Header().Set("Location", endpoint+"/admin/realms/asservat/users/"+id)
					w.WriteHeader(201)
				case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/admin/realms/asservat/users/"):
					path := strings.TrimPrefix(r.URL.Path, "/admin/realms/asservat/users/")
					if path != developer+"/groups/"+users && path != outsider+"/groups/"+users && !(privacyOperator && path == developer+"/groups/"+processing) {
						t.Error("unrequested membership")
					}
					w.WriteHeader(204)
				default:
					t.Errorf("realm/client/profile/source mutation or unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(400)
				}
			}))
			defer server.Close()
			endpoint = server.URL
			f := fixture{}
			f.Identity = &struct{ Base, RootCA, AdminUser, AdminPassword, UserPassword string }{server.URL, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), "retained-admin", "retained-private-password", "fixture-human-password"}
			settings := contracts.SmallKeycloakSettings{Hostname: server.URL, Realm: "asservat", Origin: "https://console.example", ConsoleClientID: "asservat-console", MCPClientID: "asservat-mcp", MCPRedirectURIs: []string{"http://127.0.0.1:42000/callback"}, ProcessingOperators: true}
			id := newInstalledBundledIdentity(t, f, settings, users, "original-console-secret", privacyOperator)
			if id.SubjectID != developer || id.UnrelatedSubjectID != outsider || id.usersGroup() != users || id.ProcessingGroupID != processing || id.mcpClient() != "asservat-mcp" || id.mcpResourceScope() != "asservat:mcp" || id.downloadResourceScope() != "asservat:downloads" || id.kc.callback() != settings.MCPRedirectURIs[0] {
				t.Fatal("actual imported source was replaced by external defaults")
			}
			unrelated := id.unrelated()
			if unrelated.SubjectID != outsider || unrelated.kc.username != "outsider" || unrelated.mcpClient() != id.mcpClient() || unrelated.usersGroup() != users || unrelated.kc.callback() != id.kc.callback() {
				t.Fatal("unrelated session lost actual imported configuration")
			}
			mu.Lock()
			defer mu.Unlock()
			want := 9
			if privacyOperator {
				want++
			}
			if len(calls) != want {
				t.Fatal("unexpected additional provider setup calls", len(calls))
			}
		})
	}
}

func TestInstalledIdentityPreservesExternalDefaultsAndChecksActualClient(t *testing.T) {
	legacy := &installedIdentity{kc: &kcFixture{http: &http.Client{}}, ReviewerSubject: "reviewer"}
	if legacy.mcpClient() != "mcp" || legacy.mcpResourceScope() != installedMCPScope || legacy.downloadResourceScope() != installedDownloadsScope || legacy.kc.callback() != "http://127.0.0.1:1/callback" || legacy.usersGroup() != installedIdentityGroup {
		t.Fatal("external fixture defaults changed")
	}
	if legacy.unrelated().ReviewerSubject != "" {
		t.Fatal("unrelated external fixture inherited reviewer identity")
	}
	now := time.Now().UTC()
	for _, client := range []string{"asservat-mcp", "mcp"} {
		body, _ := json.Marshal(map[string]any{"iss": "https://issuer.example/realms/asservat", "sub": "actual-subject", "azp": client, "aud": "https://console.example/mcp", "exp": now.Add(time.Minute).Unix(), "scope": "openid evidence:read"})
		raw := "fixture." + base64.RawURLEncoding.EncodeToString(body) + ".fixture"
		source := &installedJourneyTokenSource{issuer: "https://issuer.example/realms/asservat", resource: "https://console.example/mcp", clientID: "asservat-mcp", now: func() time.Time { return now }, login: func() kcTokens { return kcTokens{Access: raw, Refresh: "fixture-refresh"} }}
		_, err := source.Token(t.Context())
		if (err == nil) != (client == "asservat-mcp") {
			t.Fatal("scheduler accepted replacement/default client or rejected configured client")
		}
	}
}

func TestInstalledIdentityUsesActualImportedCallbackInCodeExchange(t *testing.T) {
	callback := "http://127.0.0.1:42000/callback"
	var state string
	var base string
	var seen []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "GET /realms/asservat/protocol/openid-connect/auth":
			if r.URL.Query().Get("client_id") != "asservat-mcp" || r.URL.Query().Get("redirect_uri") != callback || r.URL.Query().Get("scope") != "openid evidence:read asservat:mcp" {
				t.Error("wrong imported login configuration")
			}
			state = r.URL.Query().Get("state")
			fmt.Fprint(w, `<form id="kc-form-login" action="`+html.EscapeString(base+"/realms/asservat/login-actions/authenticate?session=original")+`"></form>`)
		case "POST /realms/asservat/login-actions/authenticate":
			w.Header().Set("Location", callback+"?"+url.Values{"state": {state}, "code": {"actual-one-use-code"}}.Encode())
			w.WriteHeader(http.StatusFound)
		case "POST /realms/asservat/protocol/openid-connect/token":
			r.ParseForm()
			if r.Form.Get("redirect_uri") != callback || r.Form.Get("client_id") != "asservat-mcp" || r.Form.Get("code") != "actual-one-use-code" || r.Form.Get("code_verifier") == "" {
				t.Error("code exchange lost actual callback/client")
			}
			fmt.Fprint(w, `{"access_token":"fixture-token","refresh_token":"fixture-refresh"}`)
		default:
			t.Error("unexpected authentication request")
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	base = server.URL
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	f := &kcFixture{t: t, base: base, Issuer: base + "/realms/asservat", http: client, UserPassword: "fixture-password", redirectURI: callback}
	if got := f.loginScopes("asservat-mcp", "openid evidence:read asservat:mcp"); got.Access != "fixture-token" {
		t.Fatal("actual configured callback code exchange failed")
	}
	if !reflect.DeepEqual(seen, []string{"GET /realms/asservat/protocol/openid-connect/auth", "POST /realms/asservat/login-actions/authenticate", "POST /realms/asservat/protocol/openid-connect/token"}) {
		t.Fatal("auth code exchange added requests or retried")
	}
}
