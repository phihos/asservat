package contracts

import "io"

// ADR-169/170 regional connector process: installation-owned public startup
// inputs at a fixed root. The process holds no hub SQL, signing or audit
// credential; its cluster credential Secret is read and CAS-updated through
// the API, never mounted.
const RegionalDeploymentFormat = "asservat-regional-deployment/v1"
const RegionalDeploymentRoot = "/run/asservat/regional"
const RegionalDeploymentMaxBytes = 256 << 10
const RegionalPodUIDEnvironment = "ASSERVAT_REGIONAL_POD_UID"

type RegionalDeployment struct {
	Format              string                    `json:"format"`
	InstallationID      string                    `json:"installationID"`
	ClusterID           string                    `json:"clusterID"`
	PermissionRootID    string                    `json:"permissionRootID"`
	IssuerEpoch         string                    `json:"issuerEpoch"`
	PeerID              string                    `json:"peerID"`
	Namespace           WorkerObjectReference     `json:"namespace"`
	Kubernetes          OwnerProviderEndpoint     `json:"kubernetes"`
	Deployment          WorkerObjectReference     `json:"deployment"`
	WorkloadGuard       OwnerDeploymentGuard      `json:"workloadGuard"`
	ConfigurationProbes []OwnerConfigurationProbe `json:"configurationProbes"`
	Source              WorkerObjectReference     `json:"source"`
	SourceGuard         OwnerDeploymentGuard      `json:"sourceGuard"`
	ClusterCredential   WorkerObjectReference     `json:"clusterCredential"`
	// ClusterCredentialAccount is the connector account whose UPDATE of that
	// Secret the workload guard admits (ADR-193).
	ClusterCredentialAccount string              `json:"clusterCredentialAccount"`
	Hub                      RegionalHubEndpoint `json:"hub"`
	// APIContext enables ADR-171 regional context start; without it the
	// process only supervises its connector credentials.
	APIContext *RegionalAPIContext `json:"apiContext,omitempty"`
	// Capacity enables the ADR-197 v2 capacity observation standby. It
	// requires APIContext, whose settings pin this Deployment's template.
	Capacity *RegionalCapacity `json:"capacity,omitempty"`
	// Collector enables the ADR-246 node work channel listener for the
	// cluster's `asservat node` DaemonSet.
	Collector *RegionalCollector `json:"collector,omitempty"`
}

// RegionalCollector names the collector namespace, DaemonSet and service
// account whose Pod-bound tokens the connector attests. The listener's
// server certificate and key are the fixed files RegionalNodeServerFile and
// RegionalNodeServerKeyFile in the deployment root; node client
// certificates come from an in-memory issuer of the connector process.
type RegionalCollector struct {
	Namespace      WorkerObjectReference `json:"namespace"`
	DaemonSet      string                `json:"daemonSet"`
	ServiceAccount string                `json:"serviceAccount"`
}

const (
	RegionalNodeListenAddress = ":8444"
	RegionalNodeServerFile    = "node-server.pem"
	RegionalNodeServerKeyFile = "node-server-key.pem"
)

// RegionalCapacity pins the region's capacity selector guard, its probe
// namespace and account (whose tokens this Pod's account mints in memory),
// and the hub owner's v2 operation address and observation pin.
type RegionalCapacity struct {
	OperationAddress string                   `json:"operationAddress"`
	Owner            RegionalOwnerObservation `json:"owner"`
	NamespaceGuard   OwnerDeploymentGuard     `json:"namespaceGuard"`
	Keys             []string                 `json:"keys"`
	ProbeNamespace   WorkerObjectReference    `json:"probeNamespace"`
	ProbeAccount     WorkerObjectReference    `json:"probeAccount"`
	ProbeAudience    string                   `json:"probeAudience"`
}

// RegionalAPIContext pins the regional context-start inputs. The capacity
// account's token is minted in memory by the Pod's own account (ADR-175);
// evidence-storage.json is the write-only evidence store credential; artifact
// keys are wrapped by the local key service per attempt (ADR-176). The
// process holds no SQL or unwrap credential.
//
// Settings names the guarded, immutable settings ConfigMap; the process
// reads the settings from it at startup. They pin every other mounted input,
// including this document's ConfigMap, so this document cannot carry them;
// the hub's pinned StartupDigest binds their UID, version and content
// (ADR-196 decision 7).
type RegionalAPIContext struct {
	Settings       string                          `json:"settings"`
	SettingsGuard  OwnerDeploymentGuard            `json:"settingsGuard"`
	Starts         OwnerDeploymentAPIContextStarts `json:"starts"`
	WorkTrust      WorkerObjectReference           `json:"workTrust"`
	WorkTrustGuard OwnerDeploymentGuard            `json:"workTrustGuard"`
	TrustSettings  APIContextWorkTrustSettings     `json:"trustSettings"`
	EvidenceStore  RegionalEvidenceStore           `json:"evidenceStore"`
	KeyService     RegionalWrapService             `json:"keyService"`
	Owners         RegionalContextOwners           `json:"owners"`
	Concurrency    int                             `json:"concurrency"`
	// Alertmanager is the cluster's in-cluster Alertmanager base URL for
	// alert policies (ADR-231): installation-owned, optional, never policy
	// input. Without it an alert policy on this cluster is refused.
	Alertmanager string `json:"alertmanager,omitempty"`
}

type RegionalEvidenceStore struct {
	Endpoint string   `json:"endpoint"`
	Roots    [][]byte `json:"roots"`
	Region   string   `json:"region"`
	Bucket   string   `json:"bucket"`
	StoreID  string   `json:"storeID"`
}

// RegionalWrapService is the hub cluster's local key service for the artifact
// purpose (ADR-176). The connector presents its own client leaf; each wrap is
// authorized for one prepared attempt.
type RegionalWrapService struct {
	Endpoint string   `json:"endpoint"`
	Roots    [][]byte `json:"roots"`
	KeyID    string   `json:"keyID"`
}

// RegionalContextOwners pins the hub's native listener address and its exact
// accepted owner configuration (pool and issuer roots), ADR-172.
type RegionalContextOwners struct {
	Address       string             `json:"address"`
	Configuration OwnerConfiguration `json:"configuration"`
}

// RegionalHubEndpoint pins the federation endpoint, the server name its
// certificate must carry and its issuer roots, independently of the address.
type RegionalHubEndpoint struct {
	Endpoint   string   `json:"endpoint"`
	ServerName string   `json:"serverName"`
	Roots      [][]byte `json:"roots"`
}

func DecodeRegionalDeployment(r io.Reader) (RegionalDeployment, error) {
	return decodeClosedRPC[RegionalDeployment](r, RegionalDeploymentMaxBytes)
}
