package contracts

// BrowserSettings is administrator-owned ConfigMap content. It contains no
// provider credentials and cannot be supplied by a session/login request.
type BrowserSettings struct {
	SchemaVersion      string `json:"schemaVersion"`
	Revision           int64  `json:"revision"`
	RootID             string `json:"rootID"`
	SessionEpoch       string `json:"sessionEpoch"`
	Issuer             string `json:"issuer"`
	ClientID           string `json:"clientID"`
	Origin             string `json:"origin"`
	Suspended          bool   `json:"suspended"`
	MaxLifetimeSeconds int    `json:"maxLifetimeSeconds"`
	MaxLogins          int    `json:"maxLogins"`
	MaxSessions        int    `json:"maxSessions"`
	MaxLogoutEvents    int    `json:"maxLogoutEvents"`
}
