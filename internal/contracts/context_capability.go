package contracts

// ContextCapabilitySettings is an immutable, installation-owned first-profile
// qualification. No request can choose a collector, projection or source pin.
type ContextCapabilitySettings struct {
	Format               string `json:"format"`
	RootID               string `json:"rootID"`
	InstallationID       string `json:"installationID"`
	ClusterID            string `json:"clusterID"`
	IssuerEpoch          string `json:"issuerEpoch"`
	Revision             int64  `json:"revision"`
	Enabled              bool   `json:"enabled"`
	ExecutionClass       string `json:"executionClass"`
	CollectorVersion     string `json:"collectorVersion"`
	CollectorImageDigest string `json:"collectorImageDigest"`
	ProjectionDigest     string `json:"projectionDigest"`
}

const ContextCapabilityFormat = "asservat-context-capability/v1"
const ContextCapabilityMaxBytes = 4096
