package contracts

// SeaweedPrincipalKey is private provider configuration, never Helm input or a
// public identity. ScopeID is the backend for admin, the installation for hub roles and the exact
// regional cluster for regional roles. It never identifies a human.
type SeaweedPrincipalKey struct {
	Purpose string `json:"purpose"`
	ScopeID string `json:"scopeID"`
}

// SeaweedCredential is generated once and retained by the common private state
// producer BEFORE provider effects. Only its selected ordinary credential is
// projected to a runtime. The administrator remains provider/setup-only.
type SeaweedCredential struct {
	Principal       SeaweedPrincipalKey `json:"principal"`
	AccessKeyID     string              `json:"accessKeyID"`
	SecretAccessKey string              `json:"secretAccessKey"`
}

type SeaweedGrant struct {
	Credential     SeaweedCredential `json:"credential"`
	Bucket         string            `json:"bucket"`
	InstallationID string            `json:"installationID"`
	ClusterID      string            `json:"clusterID,omitempty"`
	RootID         string            `json:"rootID,omitempty"`
	// Prefixes are the selected existing provider recipe's audit prefixes.
	// The compiler independently permits only this purpose's exact families.
	Prefixes []string `json:"prefixes,omitempty"`
}

// SeaweedBucketInitialization names one bucket of one installation. Its
// ownership tags derive from these two values only.
type SeaweedBucketInitialization struct {
	InstallationID string `json:"installationID"`
	Bucket         string `json:"bucket"`
}
