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
	SourceUID      string            `json:"sourceUID,omitempty"`
	// Prefixes are the selected existing provider recipe's audit prefixes.
	// The compiler independently permits only this purpose's exact families.
	Prefixes []string `json:"prefixes,omitempty"`
}

// SeaweedProviderTarget names already-created objects. Initialization belongs
// to the common create-once producer; this target authorizes no adoption.
type SeaweedProviderTarget struct {
	InstallationID string                `json:"installationID"`
	Namespace      string                `json:"namespace"`
	StatefulSet    WorkerObjectReference `json:"statefulSet"`
	Pod            WorkerObjectReference `json:"pod"`
	Config         WorkerObjectReference `json:"config"`
	Image          string                `json:"image"`
	ExpectedArgs   []string              `json:"expectedArgs"`
}

// SeaweedBucketInitialization is supplied ONLY from the common retained private
// backend seed. Pending is valid solely before any runtime writers/activation.
// It is not a public claim, external-bucket adoption switch or minted authority.
type SeaweedBucketInitialization struct {
	BackendID        string `json:"backendID"`
	InstallationID   string `json:"installationID"`
	InitializationID string `json:"initializationID"`
	StateSecretUID   string `json:"stateSecretUID"`
	PVCUID           string `json:"pvcUID"`
	Endpoint         string `json:"endpoint"`
	Image            string `json:"image"`
	Bucket           string `json:"bucket"`
	Pending          bool   `json:"pending"`
}
