package contracts

import (
	"io"

	"github.com/google/uuid"
)

// Helm-native hub-api inputs (docs/reviews/helm-native-field-map.md). The
// chart renders HubAPIConfig into ConfigMap <name>-hub-api-config, key
// config.json. It carries only values Helm knows at render time. Object
// names derive from Name (HubAPIName), OpenBao mounts are the chart
// constants (SmallOpenBao*Mount) and key and PKI role names derive from the
// installation ID; generated IDs come from the <name>-ids Secret, Kubernetes
// UIDs are read by name at startup and provider-produced keys and roots are
// read from OpenBao, the mounted CA files and SQL.
const (
	HubAPIConfigFormat   = "asservat-hub-api-config/v1"
	HubAPIConfigRoot     = "/run/asservat/hub-api"
	HubAPIConfigFile     = "config.json"
	HubAPIConfigMaxBytes = 128 << 10
	// HubAPIWorkerControlsFile is the hub-api config ConfigMap's second key,
	// mounted into OwnerObservationProjectionRoot: the download-worker control
	// catalog (OwnerWorkerTrust), empty in a Helm-rendered install.
	HubAPIWorkerControlsFile = "worker-controls.json"
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

// HubAPIPostgresConnections is the owner pool's per-purpose connection count.
const HubAPIPostgresConnections = 1

type HubAPIConfig struct {
	Format string `json:"format"`
	// Name is installation.name; Namespace the release namespace.
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Postgres    HubAPIPostgres    `json:"postgres"`
	ObjectStore HubAPIObjectStore `json:"objectStore"`
	OpenBao     HubAPIOpenBao     `json:"openBao"`
	Connections int               `json:"connections"`
	Concurrency int               `json:"concurrency"`
	Observation HubAPIObservation `json:"observation"`
	// ConnectorTokens verifies the connectors' context-start tokens.
	ConnectorTokens ConnectorTokens `json:"connectorTokens"`
	Native          HubAPINative    `json:"native"`
	Public          *HubAPIPublic   `json:"public,omitempty"`
	// Clusters are the remote workload clusters joined with mode=cluster.
	Clusters []RemoteCluster `json:"clusters,omitempty"`
}

// RemoteCluster is one workload cluster an operator registered in the hub's
// values (clusters[]): its DNS-label name, its release namespace and its
// context-start reservations. Its cluster ID derives from the name
// (RemoteClusterID, ADR-335 D4) and its connector peer from the cluster ID
// (RemotePeerID). The release name (installation.name) is the hub's.
type RemoteCluster struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Standby   int    `json:"standby"`
	Captures  int    `json:"captures"`
}

// RemoteClusterID is a registered workload cluster's ID: a name-based UUID
// of the installation and the cluster name (ADR-335 D4), so every hub
// component derives it without shared state. Empty for an invalid
// installation ID.
func RemoteClusterID(installationID, name string) string {
	ns, err := uuid.Parse(installationID)
	if err != nil {
		return ""
	}
	return uuid.NewSHA1(ns, []byte("asservat-cluster/v1\x00"+name)).String()
}

// RemotePeerID is a remote cluster's connector peer: a name-based UUID of
// the installation and cluster IDs, so every hub component derives it
// without shared state.
func RemotePeerID(installationID, clusterID string) (string, bool) {
	ns, err := uuid.Parse(installationID)
	if err != nil {
		return "", false
	}
	return uuid.NewSHA1(ns, []byte("asservat-remote-connector-peer/v1\x00"+clusterID)).String(), true
}

type HubAPIPostgres struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
}

// HubAPIObjectStore is the chart's selected object store; the hub-api writes
// its audit records to AuditBucket.
type HubAPIObjectStore struct {
	Endpoint       string `json:"endpoint"`
	Region         string `json:"region"`
	AuditBucket    string `json:"auditBucket"`
	EvidenceBucket string `json:"evidenceBucket"`
}
type HubAPIOpenBao struct {
	Endpoint string `json:"endpoint"`
}

// HubAPIObservation: Peers are remote regions' connector peers; in
// combined mode the local connector peer is derived from the IDs Secret.
// LocalCapacity serves the hub cluster's capacity observation to the
// hub-worker (`<name>-hub-worker`), admitted by its ServiceAccount.
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
}

// HubAPINative: WorkerNamespaces are download-worker namespaces in the hub
// cluster.
type HubAPINative struct {
	WorkerNamespaces []string `json:"workerNamespaces"`
}

// HubAPIPublic enables the browser/MCP/download layer. Its sources are the
// Helm-rendered ConfigMaps named by HubAPIName in the release namespace.
type HubAPIPublic struct {
	Origin          string `json:"origin"`
	BrowserAudience string `json:"browserAudience"`
	// Processing reads the capacity processing source <name>-processing-source.
	Processing     bool                  `json:"processing,omitempty"`
	CaptureHistory *CaptureHistoryLimits `json:"captureHistory,omitempty"`
	Standby        int                   `json:"standby"`
	Captures       int                   `json:"captures"`
	// WorkloadRate is capacity.workload.dump: each workload's token bucket.
	WorkloadRate         *CapacityDumpValues     `json:"workloadRate,omitempty"`
	PreviewSeconds       int                     `json:"previewSeconds"`
	DownloadPlan         OwnerPublicDownloadPlan `json:"downloadPlan"`
	ProxyTLS             bool                    `json:"proxyTLS,omitempty"`
	Version              string                  `json:"version"`
	OperationConcurrency int                     `json:"operationConcurrency"`
	MCPPerIdentity       int                     `json:"mcpPerIdentity"`
	DownloadConcurrency  int                     `json:"downloadConcurrency"`
	// OperationAudit.RetentionSeconds is ignored: the current capacity
	// qualification supplies it.
	OperationAudit OwnerPublicOperationAudit `json:"operationAudit"`
	// RegionalOffer publishes ConfigMap <name>-regional-offer for the
	// combined-mode connector (mode=combined).
	RegionalOffer *HubAPIRegionalOffer `json:"regionalOffer,omitempty"`
}

// HubAPIRegionalOffer holds the offer's Helm-known values: the image.
type HubAPIRegionalOffer struct {
	Image string `json:"image"`
	// HubOnly is mode=hub: no local connector and no hub-cluster catalog
	// entry; the offer serves registered workload clusters only.
	HubOnly bool `json:"hubOnly,omitempty"`
}

// HubAPIName is "<name>-<suffix>": the chart's object name scheme.
func HubAPIName(name, suffix string) string { return name + "-" + suffix }

func DecodeHubAPIConfig(r io.Reader) (HubAPIConfig, error) {
	return decodeServiceConfig[HubAPIConfig](r)
}
