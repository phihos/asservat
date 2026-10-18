package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	adapter "asservat.local/asservat/internal/adapters/oidc"
	"asservat.local/asservat/internal/domain/identity"
)

type kcFixture struct {
	Issuer, RootCA, AdminUser, AdminPassword, UserPassword, Postgres, KMS string
	S3                                                                    string
	CallbackHost, CallbackKey                                             string
	t                                                                     *testing.T
	http                                                                  *http.Client
	admin, base                                                           string
}
type kcTokens struct {
	Access  string `json:"access_token"`
	ID      string `json:"id_token"`
	Refresh string `json:"refresh_token"`
}

func (f *kcFixture) request(method, endpoint, token, contentType string, body []byte) (int, []byte, http.Header) {
	f.t.Helper()
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		f.t.Fatal("fixture request construction")
	}
	if strings.HasSuffix(endpoint, "/account") {
		req.Header.Set("Accept", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := f.http.Do(req)
	if err != nil {
		f.t.Fatal("fixture HTTPS request failed")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil || len(data) == 256<<10 {
		f.t.Fatal("fixture response limit")
	}
	return resp.StatusCode, data, resp.Header
}
func (f *kcFixture) json(method, path string, value any) []byte {
	f.t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		f.t.Fatal("fixture JSON")
	}
	status, data, _ := f.request(method, f.base+path, f.admin, "application/json", body)
	if status < 200 || status >= 300 {
		f.t.Fatalf("fixture admin %s %s status %d", method, path, status)
	}
	return data
}
func (f *kcFixture) tokens(endpoint string, values url.Values, want int) kcTokens {
	f.t.Helper()
	status, data, _ := f.request("POST", endpoint, "", "application/x-www-form-urlencoded", []byte(values.Encode()))
	if status != want {
		f.t.Fatalf("fixture token response status %d, want %d", status, want)
	}
	var tokens kcTokens
	if status == 200 && (json.Unmarshal(data, &tokens) != nil || tokens.Access == "") {
		f.t.Fatal("fixture token response shape")
	}
	return tokens
}
func randomPKCE() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func (f *kcFixture) login(client string, mode ...string) kcTokens {
	f.t.Helper()
	return f.loginScope(client, "", mode...)
}

// loginScope logs in like login and also requests the optional client scope
// extra when it is not empty.
func (f *kcFixture) loginScope(client, extra string, mode ...string) kcTokens {
	f.t.Helper()
	// Real authorization code + S256 PKCE. The loopback callback is never fetched;
	// the fixture observes Keycloak's redirect and exchanges the one-use code.
	jar, _ := cookiejar.New(nil)
	previous := f.http.Jar
	f.http.Jar = jar
	defer func() { f.http.Jar = previous }()
	verifier, state, nonce := randomPKCE(), randomPKCE(), randomPKCE()
	sum := sha256.Sum256([]byte(verifier))
	query := url.Values{"client_id": {client}, "redirect_uri": {"http://127.0.0.1:1/callback"}, "response_type": {"code"}, "scope": {strings.TrimSpace("openid evidence:read evidence:download evidence:capture " + extra)}, "state": {state}, "nonce": {nonce}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	status, page, _ := f.request("GET", f.Issuer+"/protocol/openid-connect/auth?"+query.Encode(), "", "", nil)
	if status != 200 {
		f.t.Fatalf("PKCE login page status %d", status)
	}
	match := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page)
	if len(match) != 2 {
		f.t.Fatal("fixture login form absent")
	}
	action := html.UnescapeString(string(match[1]))
	if !strings.HasPrefix(action, f.Issuer+"/login-actions/authenticate?") {
		f.t.Fatal("fixture login form escaped issuer")
	}
	credentials := url.Values{"username": {"developer"}, "password": {f.UserPassword}, "credentialId": {""}}
	status, _, headers := f.request("POST", action, "", "application/x-www-form-urlencoded", []byte(credentials.Encode()))
	if status != 302 {
		f.t.Fatalf("fixture login status %d", status)
	}
	callback, err := url.Parse(headers.Get("Location"))
	if err != nil || callback.Scheme != "http" || callback.Host != "127.0.0.1:1" || callback.Path != "/callback" || callback.Query().Get("state") != state || callback.Query().Get("code") == "" {
		f.t.Fatal("fixture callback binding")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "code": {callback.Query().Get("code")}, "redirect_uri": {"http://127.0.0.1:1/callback"}, "code_verifier": {verifier}}
	if len(mode) > 0 && mode[0] == "wrong-verifier" {
		form.Set("code_verifier", randomPKCE())
		f.tokens(f.Issuer+"/protocol/openid-connect/token", form, 400)
		return kcTokens{}
	}
	tokens := f.tokens(f.Issuer+"/protocol/openid-connect/token", form, 200)
	if len(mode) > 0 && mode[0] == "replay" {
		f.tokens(f.Issuer+"/protocol/openid-connect/token", form, 400)
	}
	return tokens
}
func (f *kcFixture) refresh(client, token string, want int) kcTokens {
	f.t.Helper()
	return f.tokens(f.Issuer+"/protocol/openid-connect/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {token}}, want)
}

func TestKeycloakProvider(t *testing.T) {
	path := os.Getenv("ASSERVAT_IDENTITY_FIXTURE")
	if path == "" {
		t.Skip("run make identity-integration")
	}
	data, err := os.ReadFile(path)
	var f kcFixture
	if err != nil || json.Unmarshal(data, &f) != nil {
		t.Fatal("invalid owned identity fixture")
	}
	f.t = t
	u, err := url.Parse(f.Issuer)
	if err != nil || u.Scheme != "https" || u.Hostname() != "localhost" || u.Path != "/realms/asservat-test" {
		t.Fatal("fixture is not owned loopback issuer")
	}
	f.base = "https://" + u.Host
	ca, err := os.ReadFile(f.RootCA)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("fixture CA")
	}
	f.http = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer f.http.CloseIdleConnections()
	f.admin = f.tokens(f.base+"/realms/master/protocol/openid-connect/token", url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {f.AdminUser}, "password": {f.AdminPassword}}, 200).Access
	f.json("POST", "/admin/realms", map[string]any{"realm": "asservat-test", "enabled": true, "registrationAllowed": false, "accessTokenLifespan": 120, "revokeRefreshToken": true, "refreshTokenMaxReuse": 0})
	prefix := "/admin/realms/asservat-test"
	// Retain the provider's default user-profile rules; add one admin-only field.
	var profile map[string]any
	if json.Unmarshal(f.json("GET", prefix+"/users/profile", nil), &profile) != nil {
		t.Fatal("user profile")
	}
	attributes, ok := profile["attributes"].([]any)
	if !ok {
		t.Fatal("profile attributes")
	}
	profile["attributes"] = append(attributes, map[string]any{"name": "asservat_group_id", "multivalued": true, "permissions": map[string]any{"view": []string{"admin"}, "edit": []string{"admin"}}})
	delete(profile, "unmanagedAttributePolicy") // nil is the provider's disabled setting
	f.json("PUT", prefix+"/users/profile", profile)
	for _, scope := range []string{"evidence:read", "evidence:download", "evidence:capture"} {
		f.json("POST", prefix+"/client-scopes", map[string]any{"name": scope, "protocol": "openid-connect", "attributes": map[string]string{"include.in.token.scope": "true"}})
	}
	common := []any{
		map[string]any{"name": "api-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": map[string]string{"included.custom.audience": "asservat-api", "access.token.claim": "true", "id.token.claim": "false"}},
		map[string]any{"name": "stable-groups", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper", "config": map[string]string{"user.attribute": "asservat_group_id", "claim.name": "asservat_groups", "jsonType.label": "String", "multivalued": "true", "aggregate.attrs": "true", "access.token.claim": "true", "id.token.claim": "false", "userinfo.token.claim": "false"}},
	}
	for _, client := range []string{"console", "account-test"} {
		scopes := []string{"basic", "evidence:read", "evidence:download", "evidence:capture"}
		mappers := common
		if client == "account-test" {
			scopes = append(scopes, "roles", "profile")
			mappers = nil
		}
		f.json("POST", prefix+"/clients", map[string]any{"clientId": client, "protocol": "openid-connect", "publicClient": true, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "serviceAccountsEnabled": false, "fullScopeAllowed": client == "account-test", "redirectUris": []string{"http://127.0.0.1:1/callback"}, "defaultClientScopes": scopes, "optionalClientScopes": []string{}, "attributes": map[string]string{"pkce.code.challenge.method": "S256"}, "protocolMappers": mappers})
	}
	secret := randomPKCE()
	f.json("POST", prefix+"/clients", map[string]any{"clientId": "automation", "protocol": "openid-connect", "publicClient": false, "secret": secret, "standardFlowEnabled": false, "directAccessGrantsEnabled": false, "serviceAccountsEnabled": true, "fullScopeAllowed": false, "defaultClientScopes": []string{"basic", "evidence:read"}, "optionalClientScopes": []string{}, "protocolMappers": common})
	createID := func(path string, value any) string {
		t.Helper()
		body, _ := json.Marshal(value)
		status, _, headers := f.request("POST", f.base+prefix+path, f.admin, "application/json", body)
		if status != 201 {
			t.Fatalf("fixture create %s status %d", path, status)
		}
		location := headers.Get("Location")
		id := location[strings.LastIndex(location, "/")+1:]
		if len(id) != 36 {
			t.Fatal("fixture created object identity")
		}
		return id
	}
	var groups []string
	for i := 0; i < 2; i++ {
		id := createID("/groups", map[string]any{"name": fmt.Sprintf("team-%d", i)})
		f.json("PUT", prefix+"/groups/"+id, map[string]any{"name": fmt.Sprintf("team-%d", i), "attributes": map[string]any{"asservat_group_id": []string{id}}})
		groups = append(groups, id)
	}
	groupA, groupB := groups[0], groups[1]
	userID := createID("/users", map[string]any{"username": "developer", "enabled": true, "email": "synthetic@example.invalid", "firstName": "Synthetic", "lastName": "Developer", "credentials": []any{map[string]any{"type": "password", "value": f.UserPassword, "temporary": false}}})
	f.json("PUT", prefix+"/users/"+userID+"/groups/"+groupA, nil)
	t.Run("product-browser-sessions", func(t *testing.T) { f.browserSessions(t, ca, common, userID, groupA) })
	v, err := adapter.New(adapter.Trust{Issuer: f.Issuer, Audience: "asservat-api", JWKSURL: f.Issuer + "/protocol/openid-connect/certs", RootCA: ca, KeyMaxAge: time.Minute, Profile: adapter.Keycloak}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	check := func(token string, groups ...string) identity.Claims {
		t.Helper()
		claims, err := v.Verify(context.Background(), token)
		if err != nil {
			parts := strings.Split(token, ".")
			if len(parts) == 3 {
				for i := 0; i < 2; i++ {
					decoded, _ := base64.RawURLEncoding.DecodeString(parts[i])
					var fields map[string]json.RawMessage
					_ = json.Unmarshal(decoded, &fields)
					var keys []string
					for key := range fields {
						keys = append(keys, key)
					}
					slices.Sort(keys)
					// Only field names and the public token-kind discriminator.
					t.Logf("provider part %d fields %v type %s", i, keys, fields["typ"])
				}
			}
			t.Fatalf("actual provider access token rejected: %v", err)
		}
		got, want := slices.Clone(claims.Groups), slices.Clone(groups)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatal("stable group assertion mismatch")
		}
		return claims
	}
	tokens := f.login("console")
	claims := check(tokens.Access, groupA)
	if claims.Subject != userID || claims.ClientID != "console" || tokens.ID == "" || tokens.Refresh == "" {
		t.Fatal("human access token binding")
	}
	for _, token := range []string{tokens.ID, tokens.Refresh} {
		if _, err := v.Verify(context.Background(), token); err == nil {
			t.Fatal("non-access credential accepted")
		}
	}
	f.json("PUT", prefix+"/groups/"+groupA, map[string]any{"name": "renamed-team", "attributes": map[string]any{"asservat_group_id": []string{groupA}}})
	refreshed := f.refresh("console", tokens.Refresh, 200)
	check(refreshed.Access, groupA)
	f.json("PUT", prefix+"/users/"+userID+"/groups/"+groupB, nil)
	refreshed = f.refresh("console", refreshed.Refresh, 200)
	check(refreshed.Access, groupA, groupB)
	f.json("DELETE", prefix+"/users/"+userID+"/groups/"+groupA, nil)
	refreshed = f.refresh("console", refreshed.Refresh, 200)
	check(refreshed.Access, groupB)
	f.json("DELETE", prefix+"/users/"+userID+"/groups/"+groupB, nil)
	refreshed = f.refresh("console", refreshed.Refresh, 200)
	check(refreshed.Access)
	t.Log("authorization code+S256, ID/refresh rejection, rotating refresh and current stable group rename/add/removal passed")

	// Nested group attributes are aggregated by the provider, including parents.
	// Names/paths (even names containing slashes) must never become group IDs.
	parentID := createID("/groups", map[string]any{"name": "parent/team"})
	f.json("PUT", prefix+"/groups/"+parentID, map[string]any{"name": "parent/team", "attributes": map[string]any{"asservat_group_id": []string{parentID}}})
	childID := createID("/groups/"+parentID+"/children", map[string]any{"name": "child/team"})
	f.json("PUT", prefix+"/groups/"+childID, map[string]any{"name": "child/team", "attributes": map[string]any{"asservat_group_id": []string{childID}}})
	f.json("PUT", prefix+"/users/"+userID+"/groups/"+childID, nil)
	refreshed = f.refresh("console", refreshed.Refresh, 200)
	check(refreshed.Access, parentID, childID)
	f.json("PUT", prefix+"/users/"+userID+"/groups/"+parentID, nil)
	refreshed = f.refresh("console", refreshed.Refresh, 200)
	check(refreshed.Access, parentID, childID) // direct + inherited is one stable ID
	f.json("DELETE", prefix+"/users/"+userID+"/groups/"+parentID, nil)
	f.json("PUT", prefix+"/groups/"+parentID, map[string]any{"name": "renamed/parent", "attributes": map[string]any{"asservat_group_id": []string{parentID}}})
	refreshed = f.refresh("console", refreshed.Refresh, 200)
	check(refreshed.Access, parentID, childID)
	f.json("DELETE", prefix+"/users/"+userID+"/groups/"+childID, nil)
	refreshed = f.refresh("console", refreshed.Refresh, 200)
	check(refreshed.Access)
	f.json("DELETE", prefix+"/groups/"+parentID, nil)
	t.Log("nested stable group IDs, ancestor inheritance, direct/inherited deduplication, slash-containing names and removal passed")

	// A separate ordinary account client proves that profile edits work but the
	// authority-bearing attribute cannot be self-assigned. It is not an API client.
	account := f.login("account-test")
	status, profileBody, _ := f.request("GET", f.Issuer+"/account", account.Access, "", nil)
	if status != 200 {
		t.Fatalf("account profile read %d", status)
	}
	var own map[string]any
	if json.Unmarshal(profileBody, &own) != nil {
		t.Fatal("account profile shape")
	}
	own["firstName"] = "Changed"
	ownBody, _ := json.Marshal(own)
	status, _, _ = f.request("POST", f.Issuer+"/account", account.Access, "application/json", ownBody)
	if status != 204 {
		t.Fatalf("ordinary profile update %d", status)
	}
	own["attributes"] = map[string]any{"asservat_group_id": []string{groupA}}
	ownBody, _ = json.Marshal(own)
	status, _, _ = f.request("POST", f.Issuer+"/account", account.Access, "application/json", ownBody)
	if status != 204 && status != 400 && status != 403 {
		t.Fatalf("protected profile update %d", status)
	}
	refreshed = f.refresh("console", refreshed.Refresh, 200)
	check(refreshed.Access)
	t.Log("ordinary profile update allowed; user cannot self-assign authority-bearing stable group IDs")

	// Client classes remain disjoint at the issuer, not guessed from usernames.
	f.tokens(f.Issuer+"/protocol/openid-connect/token", url.Values{"grant_type": {"password"}, "client_id": {"console"}, "username": {"developer"}, "password": {f.UserPassword}}, 400)
	f.tokens(f.Issuer+"/protocol/openid-connect/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {"console"}}, 401)
	service := f.tokens(f.Issuer+"/protocol/openid-connect/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {"automation"}, "client_secret": {secret}}, 200)
	serviceClaims := check(service.Access)
	now := time.Now()
	policy := identity.Policy{Revision: identity.Revision{UID: "fixture-policy", Generation: 1, Digest: [32]byte{1}}, Issuer: f.Issuer, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Clients: []identity.Client{{ID: "console", Kind: identity.Human, ClassQualified: true}, {ID: "automation", Kind: identity.Workload, ClassQualified: true}}, EligibleSubjects: []identity.Subject{{ID: userID, Kind: identity.Human}, {ID: serviceClaims.Subject, Kind: identity.Workload}}, GroupsAtIssueQualified: true, GroupMaxAge: 5 * time.Minute}
	for _, c := range []identity.Claims{claims, serviceClaims} {
		resolved, err := identity.Admit(c, policy, time.Now())
		if err != nil || c.ClientID == "automation" && resolved.Principal.Kind != identity.Workload || c.ClientID == "console" && resolved.Principal.Kind != identity.Human {
			t.Fatal("provider identity class")
		}
	}
	rotation := f.login("console")
	f.refresh("console", rotation.Refresh, 200)
	f.refresh("console", rotation.Refresh, 400)
	f.login("console", "replay")
	f.login("console", "wrong-verifier")
	t.Log("real authorization code replay and wrong PKCE verifier rejected")
	f.json("PUT", prefix+"/users/"+userID, map[string]any{"enabled": false})
	f.refresh("console", refreshed.Refresh, 400)
	// Offline JWT verification is intentionally not instant session revocation.
	// Current installation policy and finite original assertion age still apply.
	if _, err := v.Verify(context.Background(), refreshed.Access); err != nil {
		t.Fatal("unexpected offline-token semantics")
	}
	t.Log("separate human/workload clients, password grant denial and disabled-user refresh denial passed; existing JWT remains valid only within original application freshness bounds")
}
