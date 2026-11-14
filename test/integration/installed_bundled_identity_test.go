package integration

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

// newInstalledBundledIdentity attaches to the REAL product-imported realm and
// client configuration. The native driver supplies the actual retained source
// settings and console secret; f.Identity supplies the observed selected
// endpoint/CA/admin plus a synthetic human's test password. The realm's groups
// are looked up by name; an administrator joins /asservat-admins.
// Only fixture humans and deliberate memberships are created here. No realm,
// client, mapper, profile, source policy or identity configuration is replaced.
func newInstalledBundledIdentity(t *testing.T, f fixture, settings contracts.SmallKeycloakSettings, consoleSecret string, administrator bool) *installedIdentity {
	t.Helper()
	id := f.Identity
	if id == nil || id.Base != settings.Hostname || id.AdminUser == "" || id.AdminPassword == "" || id.UserPassword == "" || consoleSecret == "" || settings.ConsoleClientID == "" || settings.MCPClientID == "" || len(settings.MCPRedirectURIs) != 1 {
		t.Fatal("actual retained bundled identity source is incomplete or changed")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(id.RootCA)) {
		t.Fatal("actual bundled identity CA")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(client.CloseIdleConnections)
	kc := &kcFixture{t: t, base: id.Base, Issuer: settings.Hostname + "/realms/" + settings.Realm, http: client, AdminUser: id.AdminUser, AdminPassword: id.AdminPassword, UserPassword: id.UserPassword, redirectURI: settings.MCPRedirectURIs[0]}
	kc.admin = kc.tokens(kc.base+"/realms/master/protocol/openid-connect/token", url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {kc.AdminUser}, "password": {kc.AdminPassword}}, http.StatusOK).Access
	prefix := "/admin/realms/" + settings.Realm
	group := func(name string) string {
		t.Helper()
		var actual []struct{ ID, Name string }
		if json.Unmarshal(kc.json(http.MethodGet, prefix+"/groups?exact=true&search="+name, nil), &actual) != nil || len(actual) != 1 || actual[0].Name != name || !authorization.UUID(actual[0].ID) {
			t.Fatal("actual imported group missing", name)
		}
		return actual[0].ID
	}
	usersGroup, adminsGroup := group("asservat-users"), group("asservat-admins")
	for _, expected := range []struct {
		Name      string
		Public    bool
		Secret    string
		Redirects []string
	}{
		{settings.ConsoleClientID, false, consoleSecret, []string{settings.Origin + "/auth/callback"}},
		{settings.MCPClientID, true, "", settings.MCPRedirectURIs},
	} {
		var clients []struct {
			ID           string
			ClientID     string `json:"clientId"`
			PublicClient bool
			Secret       string
			RedirectURIs []string
		}
		if json.Unmarshal(kc.json(http.MethodGet, prefix+"/clients?clientId="+url.QueryEscape(expected.Name), nil), &clients) != nil || len(clients) != 1 || !authorization.UUID(clients[0].ID) || clients[0].ClientID != expected.Name || clients[0].PublicClient != expected.Public || !expected.Public && clients[0].Secret != expected.Secret || !slices.Equal(clients[0].RedirectURIs, expected.Redirects) {
			t.Fatal("actual imported client differs from original settings")
		}
	}
	createUser := func(name string) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"username": name, "enabled": true, "credentials": []any{map[string]any{"type": "password", "value": kc.UserPassword, "temporary": false}}})
		status, _, headers := kc.request(http.MethodPost, kc.base+prefix+"/users", kc.admin, "application/json", body)
		location := headers.Get("Location")
		subject := location[strings.LastIndex(location, "/")+1:]
		if status != http.StatusCreated || !authorization.UUID(subject) {
			t.Fatal("deliberate synthetic human creation did not return its actual subject")
		}
		kc.json(http.MethodPut, prefix+"/users/"+subject+"/groups/"+usersGroup, nil)
		return subject
	}
	developer, outsider := createUser("developer"), createUser("outsider")
	if administrator {
		kc.json(http.MethodPut, prefix+"/users/"+developer+"/groups/"+adminsGroup, nil)
	}
	// The operator's workload AccessBinding names developer's REAL User subject.
	// Both humans remain ordinary eligible members; outsider has no matching
	// workload binding and no administrator membership.
	return &installedIdentity{kc: kc, Issuer: kc.Issuer, RootPEM: id.RootCA, UsersGroupID: "/asservat-users", SubjectID: developer, UnrelatedSubjectID: outsider, MCPClientID: settings.MCPClientID, MCPScope: "asservat:mcp", DownloadsScope: "asservat:downloads"}
}
