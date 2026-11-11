package contracts

import "regexp"

// SmallKeycloakSettings are public inputs to the create-once small-installation
// preparation. No password, client secret or human identity belongs here.
type SmallKeycloakSettings struct {
	Namespace       string                `json:"namespace"`
	SecretName      string                `json:"secretName"`
	Hostname        string                `json:"hostname"`
	Realm           string                `json:"realm"`
	Origin          string                `json:"origin"`
	ConsoleClientID string                `json:"consoleClientID"`
	BrowserAudience string                `json:"browserAudience"`
	MCPClientID     string                `json:"mcpClientID"`
	MCPRedirectURIs []string              `json:"mcpRedirectURIs"`
	Database        SmallKeycloakDatabase `json:"database"`
}

var smallKeycloakDBHost = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
var smallKeycloakDBName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,62}$`)

// These names enter the fixed JDBC URL. Restrict metacharacters rather than
// letting a database name or host inject a different TLS/query option.
func (d SmallKeycloakDatabase) Valid() bool {
	return smallKeycloakDBHost.MatchString(d.Host) && d.Port > 0 && d.Port < 65536 && smallKeycloakDBName.MatchString(d.Database) && smallKeycloakDBName.MatchString(d.Username)
}

const (
	SmallKeycloakVersion       = "26.8.2"
	SmallKeycloakImage         = "quay.io/keycloak/keycloak@sha256:723b1d6e254c0fc96d5cffec860c7e0744d6a3277822b865bb538cf891575e41"
	SmallKeycloakSettingsFile  = "settings.json"
	SmallKeycloakAdminUsername = "bootstrap-admin-username"
	SmallKeycloakAdminPassword = "bootstrap-admin-password"
	SmallKeycloakConsoleSecret = "console-client-secret"
	SmallKeycloakUsersGroup    = "users-group-id"
	SmallKeycloakStateMaxBytes = 1 << 20
)
