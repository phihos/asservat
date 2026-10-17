package integration

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// installedIdentityGroup is the stable group ID the installed continuation's
// identity settings and AccessBindings already name.
const installedIdentityGroup = "synthetic-group"

// installedIdentity is the owned Keycloak realm of the installed journey
// (scripts/test-context-storage.py --installer-continuation): a confidential
// console client, a public MCP client whose access tokens carry exactly the
// MCP resource audience, and one user in the synthetic group. All values are
// synthetic; the realm exists only on the run's private network.
type installedIdentity struct {
	kc      *kcFixture
	Issuer  string
	RootPEM string
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
	for _, scope := range []string{"evidence:read", "evidence:download", "evidence:capture"} {
		kc.json("POST", prefix+"/client-scopes", map[string]any{"name": scope, "protocol": "openid-connect", "attributes": map[string]string{"include.in.token.scope": "true"}})
	}
	groups := map[string]any{"name": "stable-groups", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper", "config": map[string]string{"user.attribute": "asservat_group_id", "claim.name": "asservat_groups", "jsonType.label": "String", "multivalued": "true", "aggregate.attrs": "true", "access.token.claim": "true", "id.token.claim": "false", "userinfo.token.claim": "false"}}
	audience := func(value string) map[string]any {
		return map[string]any{"name": "audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": map[string]string{"included.custom.audience": value, "access.token.claim": "true", "id.token.claim": "false"}}
	}
	scopes := []string{"basic", "evidence:read", "evidence:download", "evidence:capture"}
	kc.json("POST", prefix+"/clients", map[string]any{"clientId": "console", "protocol": "openid-connect", "publicClient": false, "secret": consoleSecret, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "serviceAccountsEnabled": false, "fullScopeAllowed": false, "redirectUris": []string{strings.TrimSuffix(origin, "/") + "/auth/callback"}, "defaultClientScopes": scopes, "optionalClientScopes": []string{}, "attributes": map[string]string{"pkce.code.challenge.method": "S256"}, "protocolMappers": []any{audience("asservat-api"), groups}})
	kc.json("POST", prefix+"/clients", map[string]any{"clientId": "mcp", "protocol": "openid-connect", "publicClient": true, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "serviceAccountsEnabled": false, "fullScopeAllowed": false, "redirectUris": []string{"http://127.0.0.1:1/callback"}, "defaultClientScopes": scopes, "optionalClientScopes": []string{}, "attributes": map[string]string{"pkce.code.challenge.method": "S256"}, "protocolMappers": []any{audience(strings.TrimSuffix(origin, "/") + "/mcp"), groups}})
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
	return &installedIdentity{kc: kc, Issuer: kc.Issuer, RootPEM: id.RootCA}
}

// mcpToken logs the synthetic user in to the MCP client with authorization
// code and S256 PKCE and returns its access token.
func (i *installedIdentity) mcpToken() string { return i.kc.login("mcp").Access }
