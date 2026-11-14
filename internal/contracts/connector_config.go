package contracts

import (
	"bytes"
	"encoding/json"
	"io"
)

// Regional connector process (ADR-168/169/170). Helm renders its
// configuration into the ConfigMap `<name>-connector-config` (key
// config.json), projected with the connector's tokens and credential files at
// ConnectorConfigRoot. The process holds no hub SQL, signing or audit
// credential; its cluster credential Secret is read and CAS-updated through
// the API, never mounted.
const ConnectorConfigFormat = "asservat-connector-config/v1"
const ConnectorConfigRoot = "/run/asservat/connector"
const ConnectorConfigFile = "config.json"
const ConnectorConfigMaxBytes = 256 << 10
const RegionalPodUIDEnvironment = "ASSERVAT_REGIONAL_POD_UID"

// Fixed files next to config.json: the Pod-bound tokens (enrollment audience
// and Kubernetes API), the API roots, the optional bootstrap record and the
// executor's object-store capabilities.
const (
	ConnectorPodTokenFile         = "connector-pod.token"
	ConnectorKubeTokenFile        = "kube.token"
	ConnectorKubeRootsFile        = "kube-ca.crt"
	ConnectorBootstrapFile        = "bootstrap.json"
	ConnectorEvidenceFile         = "evidence-storage.json"
	ConnectorModeCluster          = "cluster"
	ConnectorModeCombined         = "combined"
	RegionalHistoryCredentialFile = "history-storage.json"
	// Cluster mode: the hub-issued join Secret (RemoteJoinSecretName) also
	// supplies the cluster and peer IDs and the regional offer, as files
	// next to config.json.
	ConnectorJoinClusterFile = "clusterID"
	ConnectorJoinPeerFile    = "peerID"
)

// RemoteJoinSecretName is the hub-api's join Secret for one remote workload
// cluster (values clusters[].name), in the hub's release namespace. The
// operator copies it unchanged to the cluster's release namespace.
func RemoteJoinSecretName(release, cluster string) string { return release + "-join-" + cluster }

// ConnectorConfig holds only Helm values and chart constants (field map
// class H). In cluster mode the connector reads the hub's regional offer and
// its cluster and peer IDs from the copied join Secret's files; in combined
// mode it reads the hub's offer ConfigMap OfferConfigMap in its own (the
// release) namespace, dials the in-cluster Service addresses in Hub and reads
// the generated clusterID and peerID from the IDs Secret
// (InstallationIDsRoot). ClusterID and PeerID are never values: the startup
// fills them. The bootstrap record itself is a Secret file, never a value.
type ConnectorConfig struct {
	Format            string                   `json:"format"`
	Mode              string                   `json:"mode"`
	ClusterID         string                   `json:"clusterID,omitempty"`
	PeerID            string                   `json:"peerID,omitempty"`
	Namespace         string                   `json:"namespace"`
	Deployment        string                   `json:"deployment"`
	ServiceAccount    string                   `json:"serviceAccount"`
	ClusterCredential string                   `json:"clusterCredential"`
	ImageDigest       string                   `json:"imageDigest"`
	OfferConfigMap    string                   `json:"offerConfigMap,omitempty"`
	Hub               *ConnectorHubAddresses   `json:"hub,omitempty"`
	Executor          *ConnectorExecutorConfig `json:"executor,omitempty"`
	Collector         *RegionalCollector       `json:"collector,omitempty"`
}

// ConnectorHubAddresses override the offer's externally exposed addresses
// with in-cluster Service addresses (combined mode). Server names and roots
// still come from the offer: TLS verification never depends on the address.
type ConnectorHubAddresses struct {
	Federation string `json:"federation"`
	Owners     string `json:"owners"`
	KeyService string `json:"keyService"`
}

// ConnectorExecutorConfig enables ADR-171 regional context start when the
// offer names the regional executor. CapacityAccount is the separate
// account whose Pod-bound token the connector mints for CapacityReservation
// starts (ADR-175).
type ConnectorExecutorConfig struct {
	CapacityAccount      string                    `json:"capacityAccount"`
	CapacityAudience     string                    `json:"capacityAudience"`
	Concurrency          int                       `json:"concurrency"`
	Alertmanager         string                    `json:"alertmanager,omitempty"`
	IdentityMappings     []RegionalIdentityMapping `json:"identityMappings,omitempty"`
	ProfileEndpoints     []RegionalProfileEndpoint `json:"profileEndpoints,omitempty"`
	ProfileAuthorization bool                      `json:"profileAuthorization,omitempty"`
}

// DecodeConnectorConfig strictly decodes Helm-rendered JSON: unknown fields
// and trailing data are refused; key order and spacing are Helm's.
func DecodeConnectorConfig(r io.Reader) (ConnectorConfig, error) {
	var out ConnectorConfig
	if r == nil {
		return out, ErrKeyRPC
	}
	b, err := io.ReadAll(io.LimitReader(r, ConnectorConfigMaxBytes+1))
	if err != nil || len(b) == 0 || len(b) > ConnectorConfigMaxBytes {
		return out, ErrKeyRPC
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return ConnectorConfig{}, ErrKeyRPC
	}
	return out, nil
}

// RegionalCollector names the collector namespace, DaemonSet and service
// account whose Pod-bound tokens the connector attests, and the node
// listener's Helm-rendered objects: the Secret (connector namespace) holding
// the listener pair the connector generates once, the ConfigMap (collector
// namespace) where it publishes the issuing root, and the certificate's
// server name (the listener Service's DNS name). Node client certificates
// come from an in-memory issuer of the connector process.
type RegionalCollector struct {
	Namespace      string `json:"namespace"`
	DaemonSet      string `json:"daemonSet"`
	ServiceAccount string `json:"serviceAccount"`
	ListenerSecret string `json:"listenerSecret"`
	RootConfigMap  string `json:"rootConfigMap"`
	ServerName     string `json:"serverName"`
}

const (
	RegionalNodeListenAddress = ":8444"
	RegionalNodeServerFile    = "node-server.pem"
	RegionalNodeServerKeyFile = "node-server-key.pem"
)

// RegionalProfileEndpoint is one administrator profile endpoint entry. A
// template (kind template) names permitted address modes and a port range
// that maintainers bind to a declared Pod port; a profile (kind profile) fixes
// one address mode and port. Neither has a URL, path or header value:
// the path policy is the fixed go-pprof/v1 allowlist. Optional TLS carries only
// explicit public certificate roots and a fixed verification name (ADR-299).
// Optional Credential carries public audiences only (ADR-302).
type RegionalProfileEndpoint struct {
	Name           string                             `json:"name"`
	Kind           string                             `json:"kind"`
	Namespaces     []string                           `json:"namespaces,omitempty"`
	AddressModes   []string                           `json:"addressModes,omitempty"`
	MinPort        uint16                             `json:"minPort,omitempty"`
	MaxPort        uint16                             `json:"maxPort,omitempty"`
	AddressMode    string                             `json:"addressMode,omitempty"`
	Port           uint16                             `json:"port,omitempty"`
	LoopbackFamily string                             `json:"loopbackFamily,omitempty"`
	Host           string                             `json:"host,omitempty"`
	TLS            *RegionalProfileEndpointTLS        `json:"tls,omitempty"`
	Credential     *RegionalProfileEndpointCredential `json:"credential,omitempty"`
}

// RegionalProfileEndpointTLS contains public trust material, never credentials.
type RegionalProfileEndpointTLS struct {
	ServerName string `json:"serverName"`
	RootsPEM   string `json:"rootsPEM"`
}

// RegionalIdentityMapping maps one issuer's principals to this cluster's
// Kubernetes authentication: user = UsernamePrefix + the stable subject (the
// OIDC "sub" claim), groups = GroupsPrefix + each current stable group ID
// (only when GroupsPrefix is set), uid = the subject when UID is set. Display
// names and e-mail are never used. A cluster whose authenticator maps other
// claims or extra attributes needs no mapping: its sources stay unsupported.
type RegionalIdentityMapping struct {
	Name           string  `json:"name"`
	Issuer         string  `json:"issuer"`
	UsernamePrefix string  `json:"usernamePrefix"`
	GroupsPrefix   *string `json:"groupsPrefix,omitempty"`
	UID            bool    `json:"uid,omitempty"`
}

type RegionalEvidenceStore struct {
	Endpoint string `json:"endpoint"`
	// ServerName, when set, is the name the endpoint's certificate carries
	// (the in-cluster Service name behind a TCP passthrough address).
	ServerName string   `json:"serverName,omitempty"`
	Roots      [][]byte `json:"roots"`
	Region     string   `json:"region"`
	Bucket     string   `json:"bucket"`
	StoreID    string   `json:"storeID"`
}

// RegionalWrapService is the hub cluster's local key service for the artifact
// purpose (ADR-176). The connector presents its own client leaf; each wrap is
// authorized for one prepared attempt.
type RegionalWrapService struct {
	Endpoint string `json:"endpoint"`
	// ServerName as RegionalEvidenceStore.ServerName.
	ServerName string   `json:"serverName,omitempty"`
	Roots      [][]byte `json:"roots"`
	KeyID      string   `json:"keyID"`
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

// RegionalProfileEndpointCredential is public policy, never header material.
// Its implicit policy name is the containing endpoint name.
type RegionalProfileEndpointCredential struct {
	Audiences []RegionalProfileEndpointAudience `json:"audiences"`
}
type RegionalProfileEndpointAudience struct {
	ClusterID    string `json:"clusterID"`
	NamespaceUID string `json:"namespaceUID"`
	WorkloadKind string `json:"workloadKind"`
	WorkloadUID  string `json:"workloadUID"`
}
