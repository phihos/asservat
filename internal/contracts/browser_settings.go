package contracts

// BrowserSettings is browser.json of the Helm-rendered settings ConfigMap
// (specs/contracts/browser-settings.schema.json). It holds no credentials.
type BrowserSettings struct {
	SchemaVersion            string `json:"schemaVersion"`
	Issuer                   string `json:"issuer"`
	ClientID                 string `json:"clientID"`
	Origin                   string `json:"origin"`
	MaxLifetimeSeconds       int64  `json:"maxLifetimeSeconds,omitempty"`
	InactivityTimeoutSeconds int64  `json:"inactivityTimeoutSeconds,omitempty"`
}
