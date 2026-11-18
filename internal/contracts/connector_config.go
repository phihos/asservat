package contracts

import (
	"bytes"
	"encoding/json"
	"io"
)

// Regional connector process (ADR-168/169/170). Helm renders its
// configuration into the ConfigMap `<name>-connector-config` (key
// config.json), projected with the connector's tokens at ConnectorConfigRoot.
// The process holds no hub SQL, signing or audit credential.
const ConnectorConfigFormat = "asservat-connector-config/v1"
const ConnectorConfigRoot = "/run/asservat/connector"
const ConnectorConfigFile = "config.json"
const ConnectorConfigMaxBytes = 256 << 10
const RegionalPodUIDEnvironment = "ASSERVAT_REGIONAL_POD_UID"

// Fixed files next to config.json: the Pod-bound tokens (hub audience and
// Kubernetes API), the API roots and the optional hub CA bundle.
const (
	ConnectorKubeTokenFile = "kube.token"
	// ConnectorHubTokenFile is the projected ServiceAccount token with the
	// hub URL as audience that authenticates the connector (ADR-334).
	ConnectorHubTokenFile  = "hub.token"
	ConnectorKubeRootsFile = "kube-ca.crt"
	// ConnectorHubRootsFile is values hub.caBundle (mode=combined: the
	// federation's CA); without it the system roots verify the hub.
	ConnectorHubRootsFile = "hub-ca.crt"

	ConnectorModeCluster  = "cluster"
	ConnectorModeCombined = "combined"
)

// ConnectorConfig holds only Helm values and chart constants. Hub is the hub
// URL the connector dials (values hub.url; mode=combined: the in-cluster
// federation). Its cluster and peer IDs, the hub's offer and its
// object-store capabilities arrive from the hub on connect.
type ConnectorConfig struct {
	Format         string                   `json:"format"`
	Mode           string                   `json:"mode"`
	Hub            string                   `json:"hub"`
	Namespace      string                   `json:"namespace"`
	Deployment     string                   `json:"deployment"`
	ServiceAccount string                   `json:"serviceAccount"`
	ImageDigest    string                   `json:"imageDigest"`
	Executor       *ConnectorExecutorConfig `json:"executor,omitempty"`
	Collector      *RegionalCollector       `json:"collector,omitempty"`
}

// ConnectorExecutorConfig enables ADR-171 regional context start.
// ProfileAuthorization mounts profile-authorization.json from the named
// Secret (ADR-302).
type ConnectorExecutorConfig struct {
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

// RegionalCollector names the collector namespace and service account whose
// projected tokens the connector reviews, and the node listener's
// Helm-rendered objects: the Secret (connector namespace) holding the
// listener pair the connector generates once, the ConfigMap (collector
// namespace) where it publishes the issuing root, and the certificate's
// server name (the listener Service's DNS name).
type RegionalCollector struct {
	Namespace      string `json:"namespace"`
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
	Endpoint string   `json:"endpoint"`
	Roots    [][]byte `json:"roots"`
	Region   string   `json:"region"`
	Bucket   string   `json:"bucket"`
	StoreID  string   `json:"storeID"`
}

// RegionalWrapService is the hub cluster's local key service for the artifact
// purpose (ADR-176). The connector presents its ServiceAccount token; each
// wrap is authorized for one prepared attempt.
type RegionalWrapService struct {
	Endpoint string   `json:"endpoint"`
	Roots    [][]byte `json:"roots"`
	KeyID    string   `json:"keyID"`
}

// RegionalContextOwners pins the accepted owner pool and issuer roots.
type RegionalContextOwners struct {
	Configuration OwnerConfiguration `json:"configuration"`
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
