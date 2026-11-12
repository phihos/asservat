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
	"github.com/google/uuid"
)

// newInstalledBundledIdentity attaches to the REAL product-imported realm and
// client configuration. The native driver supplies the actual retained source
// settings, original users UUID and console secret; f.Identity supplies the
// observed selected endpoint/CA/admin plus a synthetic human's test password.
// Only fixture humans and deliberate memberships are created here. No realm,
// client, mapper, profile, source policy or identity configuration is replaced.
func newInstalledBundledIdentity(t *testing.T, f fixture, settings contracts.SmallKeycloakSettings, usersGroup, consoleSecret string, processingOperator bool) *installedIdentity {
	t.Helper()
	id := f.Identity
	if id == nil || id.Base != settings.Hostname || id.AdminUser == "" || id.AdminPassword == "" || id.UserPassword == "" || consoleSecret == "" || !authorization.UUID(usersGroup) || settings.ConsoleClientID == "" || settings.MCPClientID == "" || len(settings.MCPRedirectURIs) != 1 || processingOperator && !settings.ProcessingOperators {
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
	group := func(want string) {
		t.Helper()
		var actual struct {
			ID         string
			Attributes map[string][]string
		}
		if json.Unmarshal(kc.json(http.MethodGet, prefix+"/groups/"+want, nil), &actual) != nil || actual.ID != want || !slices.Equal(actual.Attributes["asservat_group_id"], []string{want}) {
			t.Fatal("actual imported group differs from retained source")
		}
	}
	group(usersGroup)
	processingGroup := ""
	if settings.ProcessingOperators {
		original, err := uuid.Parse(usersGroup)
		if err != nil || original.Version() != 4 || original.String() != usersGroup {
			t.Fatal("original generated users UUID")
		}
		processingGroup = uuid.NewSHA1(original, []byte("asservat-processing-operators")).String()
		group(processingGroup)
	}
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
	if processingOperator {
		kc.json(http.MethodPut, prefix+"/users/"+developer+"/groups/"+processingGroup, nil)
	}
	// The operator's workload AccessBinding names developer's REAL User subject.
	// Both humans remain ordinary eligible members; outsider has no matching
	// workload binding and no processing membership. No extra realm group needed.
	return &installedIdentity{kc: kc, Issuer: kc.Issuer, RootPEM: id.RootCA, UsersGroupID: usersGroup, ProcessingGroupID: processingGroup, SubjectID: developer, UnrelatedSubjectID: outsider, MCPClientID: settings.MCPClientID, MCPScope: "asservat:mcp", DownloadsScope: "asservat:downloads"}
}
