package contracts

// Optional only in a fresh installed layout selected before original claims.
// It is incompatible with native backend inputs and does not select a public
// route. The complete owner-deployment aggregate byte bound still applies.
type OwnerObservationBootstrap struct {
	Activation       *OwnerIdentityActivation `json:"activation"`
	Format           string                   `json:"format"`
	TemplateDigest   string                   `json:"templateDigest"`
	ImageDigest      string                   `json:"imageDigest"`
	ProtectionDigest string                   `json:"protectionDigest"`
	Peers            []OwnerObservationPeer   `json:"peers"`
	// LocalCapacity lets this owner serve the hub cluster's capacity
	// observation to the installed hub-worker (ADR-190 decision 7). The
	// continuation sets it after the capacity step; the projection claim pins
	// it with the rest of the input.
	LocalCapacity *OwnerLocalCapacityObservation `json:"localCapacity,omitempty"`
}

// OwnerLocalCapacityObservation is the hub cluster's selector guard, its
// dedicated probe account and the one hub-worker caller the owner admits.
type OwnerLocalCapacityObservation struct {
	Guard          OwnerDeploymentGuard  `json:"guard"`
	Keys           []string              `json:"keys"`
	ProbeNamespace WorkerObjectReference `json:"probeNamespace"`
	ProbeAccount   WorkerObjectReference `json:"probeAccount"`
	// ProbeAudience is the API audience of the probe account's minted tokens.
	ProbeAudience string                 `json:"probeAudience"`
	Caller        OwnerObservationCaller `json:"caller"`
}

// OwnerObservationCaller is the original hub-worker caller pin; the owner
// checks every current caller against it.
type OwnerObservationCaller struct {
	Account          string `json:"account"`
	AccountUID       string `json:"accountUID"`
	Deployment       string `json:"deployment"`
	DeploymentUID    string `json:"deploymentUID"`
	TemplateDigest   string `json:"templateDigest"`
	ImageDigest      string `json:"imageDigest"`
	ProtectionDigest string `json:"protectionDigest"`
}

type OwnerObservationPeer struct {
	InstallationID string   `json:"installationID"`
	ClusterID      string   `json:"clusterID"`
	IssuerEpoch    string   `json:"issuerEpoch"`
	PeerID         string   `json:"peerID"`
	Roots          [][]byte `json:"roots"`
}
