package contracts

import "io"

// Helm-native hub-api inputs (docs/reviews/helm-native-field-map.md). The
// chart renders HubAPIConfig into ConfigMap <name>-hub-api-config, key
// config.json. It carries only values Helm knows at render time; generated
// IDs come from the <name>-ids Secret, Kubernetes UIDs are read by name at
// startup and provider-produced keys and roots are read from OpenBao, the
// mounted CA files and SQL.
const (
	HubAPIConfigFormat   = "asservat-hub-api-config/v1"
	HubAPIConfigRoot     = "/run/asservat/hub-api"
	HubAPIConfigFile     = "config.json"
	HubAPIConfigMaxBytes = 128 << 10
)

// Fixed CA files in OwnerDeploymentRoot. Bundled providers mount their
// generated CA; external providers mount the operator's bundle.
const (
	HubAPIKubernetesCAFile = "kube-ca.crt"
	HubAPIPostgresCAFile   = "postgres-ca.crt"
	HubAPIAuditStoreCAFile = "audit-store-ca.crt"
	HubAPIKeyServiceCAFile = "key-service-ca.crt"
	HubAPIIdentityCAFile   = "identity-ca.crt"
	// HubAPIKubernetesTokenFile is the hub-api's own API token (default
	// audience) for the plain reads it performs.
	HubAPIKubernetesTokenFile = "kube-observer.token"
)

// HubAPIKubernetesEndpoint is the in-cluster API server name; its
// certificate always carries this SAN.
const HubAPIKubernetesEndpoint = "https://kubernetes.default.svc"

type HubAPIConfig struct {
	Format string `json:"format"`
	// Namespace is the release namespace; Deployment and ServiceAccount
	// name this hub-api workload, OwnerConfiguration the owner pool
	// ConfigMap the hub-worker accepts.
	Namespace          string `json:"namespace"`
	Deployment         string `json:"deployment"`
	ServiceAccount     string `json:"serviceAccount"`
	OwnerConfiguration string `json:"ownerConfiguration"`
	// AuditCredentials names the Secret mounted as provider-audit-storage.json.
	AuditCredentials  string            `json:"auditCredentials"`
	ProviderAuthMount string            `json:"providerAuthMount"`
	Postgres          HubAPIPostgres    `json:"postgres"`
	AuditStore        HubAPIAuditStore  `json:"auditStore"`
	KeyService        HubAPIKeyService  `json:"keyService"`
	Connections       int               `json:"connections"`
	Concurrency       int               `json:"concurrency"`
	APIContextStarts  *HubAPIStarts     `json:"apiContextStarts,omitempty"`
	Observation       HubAPIObservation `json:"observation"`
	Native            HubAPINative      `json:"native"`
	Public            *HubAPIPublic     `json:"public,omitempty"`
}

type HubAPIPostgres struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Database       string `json:"database"`
	MaxConnections int32  `json:"maxConnections"`
}
type HubAPIAuditStore struct {
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
}
type HubAPIKeyService struct {
	Endpoint   string `json:"endpoint"`
	AuditMount string `json:"auditMount"`
	AuditKey   string `json:"auditKey"`
	PKIMount   string `json:"pkiMount"`
	ServerRole string `json:"serverRole"`
	ClientRole string `json:"clientRole"`
}

// HubAPIStarts names the context-start accounts the hub-api admits.
type HubAPIStarts struct {
	CapacityAccount  string `json:"capacityAccount"`
	ExecutionAccount string `json:"executionAccount"`
	CapacityAudience string `json:"capacityAudience,omitempty"`
}

// HubAPIObservation: Peers are remote regions' connector peers; in
// combined mode the local connector peer is derived from the IDs Secret.
// LocalCapacity serves the hub cluster's capacity observation to the
// hub-worker, which is admitted by its ServiceAccount (TokenReview).
type HubAPIObservation struct {
	Peers         []HubAPIPeer         `json:"peers,omitempty"`
	LocalCapacity *HubAPILocalCapacity `json:"localCapacity,omitempty"`
}
type HubAPIPeer struct {
	ClusterID string `json:"clusterID"`
	PeerID    string `json:"peerID"`
	// RootsPEM is the remote connector issuer's CA bundle.
	RootsPEM string `json:"rootsPEM"`
}
type HubAPILocalCapacity struct {
	Keys           []string `json:"keys"`
	LabelKeys      []string `json:"labelKeys,omitempty"`
	AnnotationKeys []string `json:"annotationKeys,omitempty"`
	// CallerAccount and CallerDeployment name the hub-worker.
	CallerAccount    string `json:"callerAccount"`
	CallerDeployment string `json:"callerDeployment"`
}

type HubAPINative struct {
	// ConnectorPKIMount is the OpenBao PKI mount whose CA issues connector
	// certificates.
	ConnectorPKIMount   string            `json:"connectorPKIMount"`
	WorkerAPIs          []HubAPIWorkerAPI `json:"workerAPIs"`
	RetentionTopologies []HubAPITopology  `json:"retentionTopologies"`
	Connections         int               `json:"connections"`
	Concurrency         int               `json:"concurrency"`
}

// HubAPIWorkerAPI is a download-worker namespace in the hub cluster.
type HubAPIWorkerAPI struct {
	Namespace string `json:"namespace"`
}
type HubAPITopology struct {
	TargetClusterID string `json:"targetClusterID"`
	Name            string `json:"name"`
}

// HubAPIPublic enables the browser/MCP/download layer. Source fields name
// ConfigMaps in the release namespace.
type HubAPIPublic struct {
	Origin              string             `json:"origin"`
	BrowserAudience     string             `json:"browserAudience"`
	BrowserSettings     string             `json:"browserSettings"`
	IdentitySettings    string             `json:"identitySettings"`
	SessionTransit      OwnerPublicTransit `json:"sessionTransit"`
	ClusterCatalog      string             `json:"clusterCatalog"`
	WorkSigning         HubAPISigning      `json:"workSigning"`
	WorkerConfiguration string             `json:"workerConfiguration"`
	WorkerPKI           HubAPIWorkerPKI    `json:"workerPKI"`
	DownloadEnvironment string             `json:"downloadEnvironment"`
	// Processing names the capacity processing source, when configured.
	Processing           string                  `json:"processing,omitempty"`
	ArtifactKeyID        string                  `json:"artifactKeyID"`
	CaptureHistory       *CaptureHistoryLimits   `json:"captureHistory,omitempty"`
	Standby              int                     `json:"standby"`
	Captures             int                     `json:"captures"`
	PreviewSeconds       int                     `json:"previewSeconds"`
	DownloadPlan         OwnerPublicDownloadPlan `json:"downloadPlan"`
	ProxyTLS             bool                    `json:"proxyTLS,omitempty"`
	Port                 int                     `json:"port"`
	Version              string                  `json:"version"`
	OperationConcurrency int                     `json:"operationConcurrency"`
	MCPPerIdentity       int                     `json:"mcpPerIdentity"`
	DownloadConcurrency  int                     `json:"downloadConcurrency"`
	DownloadsPerIdentity int                     `json:"downloadsPerIdentity"`
	DownloadMaxSeconds   int                     `json:"downloadMaxSeconds"`
	// OperationAudit.RetentionSeconds is ignored: the current capacity
	// qualification supplies it.
	OperationAudit        OwnerPublicOperationAudit `json:"operationAudit"`
	Fleet                 *HubAPIFleet              `json:"fleet,omitempty"`
	PermissionDelegations []PermissionDelegation    `json:"permissionDelegations,omitempty"`
}
type HubAPISigning struct {
	Mount string `json:"mount"`
	Name  string `json:"name"`
}
type HubAPIWorkerPKI struct {
	Mount string `json:"mount"`
	Role  string `json:"role"`
}
type HubAPIFleet struct {
	Settings        string `json:"settings"`
	ChannelMount    string `json:"channelMount"`
	DeliveryProfile string `json:"deliveryProfile"`
}

func DecodeHubAPIConfig(r io.Reader) (HubAPIConfig, error) {
	return decodeClosedRPC[HubAPIConfig](r, HubAPIConfigMaxBytes)
}
