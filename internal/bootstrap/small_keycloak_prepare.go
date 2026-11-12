package bootstrap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"github.com/google/uuid"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	validation "k8s.io/apimachinery/pkg/util/validation"
)

func smallKeycloakOrigin(raw string) bool {
	u, err := url.Parse(raw)
	return utf8.ValidString(raw) && utf8.RuneCountInString(raw) <= 2048 && err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.String() == raw
}

var smallKeycloakRealmName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

func validSmallKeycloakSettings(s contracts.SmallKeycloakSettings) bool {
	if len(validation.IsDNS1123Label(s.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(s.SecretName)) != 0 || !smallKeycloakOrigin(s.Hostname) || !smallKeycloakOrigin(s.Origin) || !smallKeycloakRealmName.MatchString(s.Realm) || s.Realm == "master" || s.Realm == "." || s.Realm == ".." || s.ConsoleClientID == s.MCPClientID || len(s.MCPRedirectURIs) > 32 || !s.Database.Valid() {
		return false
	}
	for _, name := range []string{s.ConsoleClientID, s.MCPClientID, s.BrowserAudience} {
		if name == "" || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n \t${}") {
			return false
		}
	}
	seen := map[string]bool{}
	for _, raw := range s.MCPRedirectURIs {
		u, err := url.Parse(raw)
		if !utf8.ValidString(raw) || utf8.RuneCountInString(raw) > 2048 || err != nil || seen[raw] || u.User != nil || u.Fragment != "" || strings.ContainsAny(raw, "*${}") || u.Hostname() == "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"))) {
			return false
		}
		seen[raw] = true
	}
	return true
}

// BuildSmallKeycloakMaterial generates only initial material. The common
// preparation owner creates it once, before database initialization; a missing
// Secret over retained database state is recovery, never another call here.
func BuildSmallKeycloakMaterial(s contracts.SmallKeycloakSettings, random io.Reader) (*core.Secret, error) {
	if random == nil || !validSmallKeycloakSettings(s) {
		return nil, mounts.ErrUnavailable
	}
	credential := func() ([]byte, error) {
		var raw [32]byte
		if _, err := io.ReadFull(random, raw[:]); err != nil {
			return nil, err
		}
		defer clear(raw[:])
		return []byte(base64.RawURLEncoding.EncodeToString(raw[:])), nil
	}
	admin, err := credential()
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	console, err := credential()
	if err != nil {
		clear(admin)
		return nil, mounts.ErrUnavailable
	}
	group, err := uuid.NewRandomFromReader(random)
	if err != nil {
		clear(admin)
		clear(console)
		return nil, mounts.ErrUnavailable
	}
	settings, _ := json.Marshal(s)
	realm, err := smallKeycloakRealm(s, group.String())
	if err != nil {
		clear(admin)
		clear(console)
		return nil, mounts.ErrUnavailable
	}
	immutable := true
	return &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Namespace: s.Namespace, Name: s.SecretName, Labels: map[string]string{"asservat.io/private-role": "small-keycloak"}}, Type: core.SecretTypeOpaque, Immutable: &immutable, Data: map[string][]byte{
		contracts.SmallKeycloakSettingsFile:  settings,
		contracts.SmallKeycloakAdminUsername: []byte("asservat-bootstrap-admin"),
		contracts.SmallKeycloakAdminPassword: admin,
		contracts.SmallKeycloakConsoleSecret: console,
		contracts.SmallKeycloakUsersGroup:    []byte(group.String()),
		s.Realm + "-realm.json":              realm,
	}}, nil
}

// ValidateSmallKeycloakMaterial checks retained inputs without generating or
// rotating anything. The caller separately proves ownership of the Secret.
func ValidateSmallKeycloakMaterial(s contracts.SmallKeycloakSettings, secret *core.Secret) error {
	if !validSmallKeycloakSettings(s) || secret == nil || secret.APIVersion != "v1" || secret.Kind != "Secret" || secret.Namespace != s.Namespace || secret.Name != s.SecretName || len(secret.Labels) != 1 || secret.Labels["asservat.io/private-role"] != "small-keycloak" || secret.DeletionTimestamp != nil || len(secret.OwnerReferences) != 0 || len(secret.Finalizers) != 0 || secret.Type != core.SecretTypeOpaque || secret.Immutable == nil || !*secret.Immutable || len(secret.Data) != 6 || len(secret.StringData) != 0 {
		return mounts.ErrUnavailable
	}
	expected, _ := json.Marshal(s)
	if !bytes.Equal(secret.Data[contracts.SmallKeycloakSettingsFile], expected) || string(secret.Data[contracts.SmallKeycloakAdminUsername]) != "asservat-bootstrap-admin" {
		return mounts.ErrUnavailable
	}
	for _, key := range []string{contracts.SmallKeycloakAdminPassword, contracts.SmallKeycloakConsoleSecret} {
		raw, err := base64.RawURLEncoding.DecodeString(string(secret.Data[key]))
		valid := err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == string(secret.Data[key])
		clear(raw)
		if !valid {
			return mounts.ErrUnavailable
		}
	}
	group := string(secret.Data[contracts.SmallKeycloakUsersGroup])
	parsed, err := uuid.Parse(group)
	if err != nil || parsed.String() != group || parsed.Version() != 4 {
		return mounts.ErrUnavailable
	}
	realm, err := smallKeycloakRealm(s, group)
	if err != nil || !bytes.Equal(realm, secret.Data[s.Realm+"-realm.json"]) {
		return mounts.ErrUnavailable
	}
	return nil
}

func smallKeycloakRealm(s contracts.SmallKeycloakSettings, group string) ([]byte, error) {
	audience := func(value string) map[string]any {
		return map[string]any{"name": "audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": map[string]string{"included.custom.audience": value, "access.token.claim": "true", "id.token.claim": "false"}}
	}
	groups := map[string]any{"name": "stable-groups", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper", "config": map[string]string{"user.attribute": "asservat_group_id", "claim.name": "asservat_groups", "jsonType.label": "String", "multivalued": "true", "aggregate.attrs": "true", "access.token.claim": "true", "id.token.claim": "false", "userinfo.token.claim": "false"}}
	scopes := []any{}
	for _, name := range []string{"evidence:read", "evidence:download", "evidence:capture", "evidence:share", "evidence:raw"} {
		scopes = append(scopes, map[string]any{"name": name, "protocol": "openid-connect", "attributes": map[string]string{"include.in.token.scope": "true"}})
	}
	for _, resource := range []struct{ name, path string }{{"asservat:mcp", "/mcp"}, {"asservat:downloads", "/api/v1/downloads"}} {
		scopes = append(scopes, map[string]any{"name": resource.name, "protocol": "openid-connect", "attributes": map[string]string{"include.in.token.scope": "false"}, "protocolMappers": []any{audience(s.Origin + resource.path)}})
	}
	client := func(id string, public bool, redirects, defaults, optional []string, mappers []any) map[string]any {
		return map[string]any{"clientId": id, "protocol": "openid-connect", "enabled": true, "publicClient": public, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "serviceAccountsEnabled": false, "fullScopeAllowed": false, "redirectUris": redirects, "webOrigins": []string{}, "defaultClientScopes": defaults, "optionalClientScopes": optional, "attributes": map[string]string{"pkce.code.challenge.method": "S256"}, "protocolMappers": mappers}
	}
	console := client(s.ConsoleClientID, false, []string{s.Origin + "/auth/callback"}, []string{"basic", "acr", "evidence:read", "evidence:download", "evidence:capture", "evidence:share"}, []string{"evidence:raw"}, []any{audience(s.BrowserAudience), groups})
	console["secret"] = "${KC_ASSERVAT_CONSOLE_SECRET}"
	console["attributes"].(map[string]string)["backchannel.logout.url"] = s.Origin + "/auth/backchannel-logout"
	console["attributes"].(map[string]string)["backchannel.logout.session.required"] = "true"
	mcp := client(s.MCPClientID, true, s.MCPRedirectURIs, []string{"basic", "acr", "evidence:read"}, []string{"asservat:mcp", "asservat:downloads", "evidence:download", "evidence:capture", "evidence:share", "evidence:raw"}, []any{groups})
	clients := []any{console}
	if len(s.MCPRedirectURIs) > 0 {
		clients = append(clients, mcp)
	}
	// Keycloak requires both built-in definitions even when email is optional.
	// Keep upstream validation without requiring email delivery or collection.
	profile, _ := json.Marshal(map[string]any{"attributes": []any{
		map[string]any{"name": "username", "permissions": map[string]any{"view": []string{"admin", "user"}, "edit": []string{"admin", "user"}}, "validations": map[string]any{"length": map[string]int{"min": 3, "max": 255}, "username-prohibited-characters": map[string]any{}, "up-username-not-idn-homograph": map[string]any{}}},
		map[string]any{"name": "email", "permissions": map[string]any{"view": []string{"admin", "user"}, "edit": []string{"admin", "user"}}, "validations": map[string]any{"email": map[string]any{}, "length": map[string]int{"max": 255}}},
		map[string]any{"name": "asservat_group_id", "multivalued": true, "permissions": map[string]any{"view": []string{"admin"}, "edit": []string{"admin"}}},
	}, "groups": []any{}})
	realmGroups := []any{map[string]any{"id": group, "name": "asservat-users", "attributes": map[string]any{"asservat_group_id": []string{group}}}}
	if s.ProcessingOperators {
		id, err := smallKeycloakProcessingGroup(group)
		if err != nil {
			return nil, err
		}
		realmGroups = append(realmGroups, map[string]any{"id": id, "name": smallKeycloakProcessingGroupName, "attributes": map[string]any{"asservat_group_id": []string{id}}})
	}
	return json.Marshal(map[string]any{"realm": s.Realm, "attributes": map[string]string{"CreateDefaultClientScopes": "true"}, "enabled": true, "sslRequired": "all", "registrationAllowed": false, "resetPasswordAllowed": false, "loginWithEmailAllowed": false, "accessTokenLifespan": 300, "revokeRefreshToken": true, "refreshTokenMaxReuse": 0, "bruteForceProtected": true, "clientScopes": scopes, "clients": clients, "users": []any{}, "groups": realmGroups, "components": map[string]any{"org.keycloak.userprofile.UserProfileProvider": []any{map[string]any{"providerId": "declarative-user-profile", "config": map[string]any{"kc.user.profile.config": []string{string(profile)}}}}}})
}

// Public identity derivation only; no secret payload or human membership enters
// this UUID. The original random users group remains the namespace anchor.
const smallKeycloakProcessingGroupName = "asservat-processing-operators"

func smallKeycloakProcessingGroup(users string) (string, error) {
	source, err := uuid.Parse(users)
	if err != nil || source.String() != users || source.Version() != 4 {
		return "", mounts.ErrUnavailable
	}
	return uuid.NewSHA1(source, []byte(smallKeycloakProcessingGroupName)).String(), nil
}
