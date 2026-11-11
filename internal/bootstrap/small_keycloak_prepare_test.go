package bootstrap

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func smallKeycloakTestSettings() contracts.SmallKeycloakSettings {
	return contracts.SmallKeycloakSettings{Namespace: "installation", SecretName: "trial-keycloak-state", Hostname: "https://identity.example", Realm: "asservat", Origin: "https://asservat.example", Database: contracts.SmallKeycloakDatabase{Host: "trial-postgres.installation.svc", Port: 5432, Database: "keycloak", Username: "keycloak"}, ConsoleClientID: "console", BrowserAudience: "asservat-api", MCPClientID: "mcp", MCPRedirectURIs: []string{"http://127.0.0.1:42000/callback"}}
}

func TestSmallKeycloakMaterialPreservesRealmClientAndStableIdentityContract(t *testing.T) {
	s := smallKeycloakTestSettings()
	material, err := BuildSmallKeycloakMaterial(s, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateSmallKeycloakMaterial(s, material); err != nil {
		t.Fatal(err)
	}
	var realm struct {
		Realm      string
		Attributes map[string]string
		Users      []json.RawMessage
		Groups     []struct {
			ID         string
			Attributes map[string][]string
		}
		ClientScopes []struct {
			Name            string
			ProtocolMappers []struct{ Config map[string]string }
		} `json:"clientScopes"`
		Clients []struct {
			ClientID                                                                                               string `json:"clientId"`
			Secret                                                                                                 string
			PublicClient, DirectAccessGrantsEnabled, ImplicitFlowEnabled, ServiceAccountsEnabled, FullScopeAllowed bool
			DefaultClientScopes, OptionalClientScopes, RedirectURIs                                                []string
			Attributes                                                                                             map[string]string
			ProtocolMappers                                                                                        []struct {
				ProtocolMapper string
				Config         map[string]string
			}
		}
	}
	if err = json.Unmarshal(material.Data[s.Realm+"-realm.json"], &realm); err != nil {
		t.Fatal(err)
	}
	if realm.Realm != s.Realm || len(realm.Users) != 0 || realm.Attributes["CreateDefaultClientScopes"] != "true" {
		t.Fatal("realm initialization lost empty-user/default basic+acr contract")
	}
	group := string(material.Data[contracts.SmallKeycloakUsersGroup])
	if len(realm.Groups) != 1 || realm.Groups[0].ID != group || len(realm.Groups[0].Attributes["asservat_group_id"]) != 1 || realm.Groups[0].Attributes["asservat_group_id"][0] != group {
		t.Fatal("stable group native ID changed")
	}
	if len(realm.Clients) != 2 {
		t.Fatal("unexpected client authority")
	}
	for i, c := range realm.Clients {
		if c.DirectAccessGrantsEnabled || c.ImplicitFlowEnabled || c.ServiceAccountsEnabled || c.FullScopeAllowed || c.Attributes["pkce.code.challenge.method"] != "S256" {
			t.Fatal("enabled unsupported client flow")
		}
		if !strings.Contains(strings.Join(c.DefaultClientScopes, ","), "basic") || !strings.Contains(strings.Join(c.DefaultClientScopes, ","), "acr") {
			t.Fatal("lost subject/assurance scopes")
		}
		foundGroups := false
		for _, m := range c.ProtocolMappers {
			if m.ProtocolMapper == "oidc-usermodel-attribute-mapper" {
				foundGroups = m.Config["user.attribute"] == "asservat_group_id" && m.Config["claim.name"] == "asservat_groups" && m.Config["aggregate.attrs"] == "true" && m.Config["id.token.claim"] == "false"
			}
		}
		if !foundGroups {
			t.Fatal("client changed stable-group mapper")
		}
		if i == 0 && (c.ClientID != s.ConsoleClientID || c.PublicClient || c.Secret != "${KC_ASSERVAT_CONSOLE_SECRET}" || len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != s.Origin+"/auth/callback") {
			t.Fatal("console flow changed")
		}
		if i == 1 && (c.ClientID != s.MCPClientID || !c.PublicClient || c.Secret != "" || len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != s.MCPRedirectURIs[0]) {
			t.Fatal("MCP flow changed")
		}
	}
	for _, key := range []string{contracts.SmallKeycloakAdminPassword, contracts.SmallKeycloakConsoleSecret} {
		if bytes.Contains(material.Data[s.Realm+"-realm.json"], material.Data[key]) {
			t.Fatal("realm contains actual credential instead of secret reference")
		}
	}
	changed := s
	changed.Origin = "https://replacement.example"
	if ValidateSmallKeycloakMaterial(changed, material) == nil {
		t.Fatal("retained realm adopted changed original origin")
	}
	material.Data[s.Realm+"-realm.json"] = bytes.ReplaceAll(material.Data[s.Realm+"-realm.json"], []byte("S256"), []byte("plain"))
	if ValidateSmallKeycloakMaterial(s, material) == nil {
		t.Fatal("retained client lost PKCE")
	}
}

func TestSmallKeycloakPreparationRejectsUnsafeInputsAndUnknownRetainedMaterial(t *testing.T) {
	for _, change := range []func(*contracts.SmallKeycloakSettings){func(s *contracts.SmallKeycloakSettings) { s.Hostname = "http://identity.example" }, func(s *contracts.SmallKeycloakSettings) { s.Origin = "https://asservat.example/path" }, func(s *contracts.SmallKeycloakSettings) { s.MCPRedirectURIs = []string{"https://client.example/*"} }, func(s *contracts.SmallKeycloakSettings) {
		s.MCPRedirectURIs = []string{"http://remote.example/callback"}
	}, func(s *contracts.SmallKeycloakSettings) { s.Realm = "master" }, func(s *contracts.SmallKeycloakSettings) { s.ConsoleClientID = s.MCPClientID }} {
		s := smallKeycloakTestSettings()
		change(&s)
		if _, err := BuildSmallKeycloakMaterial(s, rand.Reader); err == nil {
			t.Fatal("unsafe setup accepted")
		}
	}
	s := smallKeycloakTestSettings()
	if _, err := BuildSmallKeycloakMaterial(s, bytes.NewReader(nil)); err == nil {
		t.Fatal("missing randomness accepted")
	}
	a, err := BuildSmallKeycloakMaterial(s, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildSmallKeycloakMaterial(s, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Data[contracts.SmallKeycloakConsoleSecret], b.Data[contracts.SmallKeycloakConsoleSecret]) || bytes.Equal(a.Data[contracts.SmallKeycloakUsersGroup], b.Data[contracts.SmallKeycloakUsersGroup]) {
		t.Fatal("new installations reused credential or group identity")
	}
	a.Data["unknown"] = []byte("retained")
	if ValidateSmallKeycloakMaterial(s, a) == nil {
		t.Fatal("unknown retained payload adopted")
	}
}

func TestSmallKeycloakEmptyMCPRedirectsDoNotInventClientRegistration(t *testing.T) {
	s := smallKeycloakTestSettings()
	s.MCPRedirectURIs = []string{}
	material, err := BuildSmallKeycloakMaterial(s, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var realm struct {
		Clients []struct {
			ClientID string `json:"clientId"`
		}
	}
	if err := json.Unmarshal(material.Data[s.Realm+"-realm.json"], &realm); err != nil {
		t.Fatal(err)
	}
	if len(realm.Clients) != 1 || realm.Clients[0].ClientID != s.ConsoleClientID {
		t.Fatal("empty redirects created a phantom MCP registration")
	}
	if err := ValidateSmallKeycloakMaterial(s, material); err != nil {
		t.Fatal(err)
	}
}

func TestSmallKeycloakPreparationAcceptsFullConfiguredRedirectEnvelope(t *testing.T) {
	s := smallKeycloakTestSettings()
	s.Realm = "Organization_Identity"
	s.MCPRedirectURIs = nil
	for i := 0; i < 32; i++ {
		s.MCPRedirectURIs = append(s.MCPRedirectURIs, fmt.Sprintf("https://client.example/%d/%s", i, strings.Repeat("界", 2000)))
	}
	material, err := BuildSmallKeycloakMaterial(s, rand.Reader)
	if err != nil {
		t.Fatal("valid chart-sized redirect roster refused", err)
	}
	raw, err := json.Marshal(material)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 64<<10 || len(raw) > contracts.SmallKeycloakStateMaxBytes {
		t.Fatal("configured roster does not fit the actual state reader's bound")
	}
	if err := ValidateSmallKeycloakMaterial(s, material); err != nil {
		t.Fatal(err)
	}
	s.MCPRedirectURIs = append(s.MCPRedirectURIs, "https://client.example/33")
	if _, err = BuildSmallKeycloakMaterial(s, rand.Reader); err == nil {
		t.Fatal("exceeded declared redirect count")
	}
}

func TestSmallKeycloakProfileKeepsRequiredBuiltinEmailOptional(t *testing.T) {
	s := smallKeycloakTestSettings()
	material, err := BuildSmallKeycloakMaterial(s, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var realm struct {
		Components map[string][]struct{ Config map[string][]string }
	}
	if json.Unmarshal(material.Data[s.Realm+"-realm.json"], &realm) != nil {
		t.Fatal("realm shape")
	}
	components := realm.Components["org.keycloak.userprofile.UserProfileProvider"]
	if len(components) != 1 || len(components[0].Config["kc.user.profile.config"]) != 1 {
		t.Fatal("protected profile component absent")
	}
	var profile struct {
		Attributes []struct {
			Name        string
			Required    json.RawMessage
			Validations map[string]json.RawMessage
		}
	}
	if json.Unmarshal([]byte(components[0].Config["kc.user.profile.config"][0]), &profile) != nil {
		t.Fatal("protected profile shape")
	}
	found := false
	for _, attribute := range profile.Attributes {
		if attribute.Name == "email" {
			found = true
			if len(attribute.Required) != 0 || attribute.Validations["email"] == nil {
				t.Fatal("built-in email became mandatory or lost its maintained validation")
			}
		}
	}
	if !found {
		t.Fatal("Keycloak rejects removal of built-in email even when email is optional")
	}
}
