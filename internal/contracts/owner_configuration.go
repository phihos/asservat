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

// OwnerSourceFormat is the Helm-rendered owner-pool.json of the
// `<name>-owner-source` ConfigMap.
const OwnerSourceFormat = "asservat-hub-owner-source/v1"

// OwnerSource holds only chart values: the hub-api owner Service, Deployment
// and ServiceAccount names in the release namespace, their ports, revision and
// suspension. The reader completes it into the accepted owner configuration:
// installation ID, cluster ID and issuer epoch from the generated IDs, object
// UIDs read by name, and issuer roots from the owner PKI CA. Every field is
// rendered, so the decoded value re-encodes to the same canonical bytes.
type OwnerSource struct {
	Format               string `json:"format"`
	Revision             int64  `json:"revision"`
	Suspended            bool   `json:"suspended"`
	Service              string `json:"service"`
	Deployment           string `json:"deployment"`
	ServiceAccount       string `json:"serviceAccount"`
	Port                 int    `json:"port"`
	NativePort           int    `json:"nativePort"`
	NativeBootstrap      string `json:"nativeBootstrap"`
	NativeCandidateLimit int    `json:"nativeCandidateLimit"`
	OperationPort        int    `json:"operationPort"`
}
