package contracts

const OwnerConfigurationFormat = "asservat-hub-owner-configuration/v1"

// OwnerConfiguration is private public-trust configuration in owner-pool.json.
// Administrator subjects and private issuer credentials are separately pinned.
type OwnerConfiguration struct {
	Format               string                `json:"format"`
	InstallationID       string                `json:"installationID"`
	ClusterID            string                `json:"clusterID"`
	IssuerEpoch          string                `json:"issuerEpoch"`
	Revision             int64                 `json:"revision"`
	Suspended            bool                  `json:"suspended"`
	Namespace            WorkerObjectReference `json:"namespace"`
	Service              WorkerObjectReference `json:"service"`
	Deployment           WorkerObjectReference `json:"deployment"`
	ServiceAccount       WorkerObjectReference `json:"serviceAccount"`
	Port                 int                   `json:"port"`
	NativePort           int                   `json:"nativePort,omitzero"`
	NativeBootstrap      string                `json:"nativeBootstrap,omitempty"`
	NativeCandidateLimit int                   `json:"nativeCandidateLimit,omitzero"`
	// OperationPort is the v2 operation listener's own port (ADR-197).
	OperationPort int      `json:"operationPort,omitzero"`
	IssuerRoots   [][]byte `json:"issuerRoots"`
}
