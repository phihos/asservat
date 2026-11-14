package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// HubWorkerConfigFormat is the Helm-rendered hub-worker configuration
// (Helm-native installation, docs/reviews/helm-native-field-map.md). It holds
// only H values: names, endpoints and limits that Helm knows at render time.
// Generated IDs come from the `<name>-ids` Secret (InstallationIDs), the
// namespace and source ConfigMap UIDs are read by name at startup, and SQL,
// object-store and provider credentials are mounted files.
const HubWorkerConfigFormat = "asservat-hub-worker-config/v1"

// HubWorkerConfigFile is the ConfigMap key and file name under
// HubWorkerDeploymentRoot.
const HubWorkerConfigFile = "config.json"
const HubWorkerConfigMaxBytes = 256 << 10

// Fixed files under HubWorkerDeploymentRoot, projected by the chart.
const (
	// HubWorkerKubernetesTokenFile is the worker's projected service account
	// token for the Kubernetes API (default audience).
	HubWorkerKubernetesTokenFile = "kube.token"
	// HubWorkerKubernetesRootsFile is the kube-root-ca.crt ConfigMap's ca.crt.
	HubWorkerKubernetesRootsFile = "kube-ca.crt"
	// HubWorkerProviderTokenFile is the projected token, with
	// HubWorkerProvider.Audience, for the OpenBao Kubernetes auth login.
	HubWorkerProviderTokenFile = "provider.token"
	// HubWorkerAuditStorageFile is the configuration/authority audit
	// object-store principal (`<name>-s3-configuration-audit`,
	// credentials.json).
	HubWorkerAuditStorageFile = "audit-storage.json"
	// Trust roots (PEM) of the selected PostgreSQL, object store (audit and
	// evidence buckets) and OpenBao (chart helper asservat.providerRoots).
	HubWorkerPostgresRootsFile   = "roots/postgres.crt"
	HubWorkerAuditStoreRootsFile = "roots/audit-store.crt"
	HubWorkerKeyServiceRootsFile = "roots/key-service.crt"
)

type HubWorkerConfig struct {
	Format string `json:"format"`
	// Namespace is the release namespace; its UID is read by name.
	Namespace string `json:"namespace"`
	// ServiceAccount is the worker's own account name (OpenBao login
	// metadata).
	ServiceAccount string `json:"serviceAccount"`
	// FleetSource and OwnerSource name the fleet and owner configuration
	// ConfigMaps in Namespace; their UIDs are read by name.
	FleetSource string `json:"fleetSource"`
	OwnerSource string `json:"ownerSource"`
	// LeaderLease names the scheduling Lease; leader election creates it.
	LeaderLease string               `json:"leaderLease"`
	Postgres    HubWorkerPostgres    `json:"postgres"`
	AuditStore  HubWorkerObjectStore `json:"auditStore"`
	KeyService  HubWorkerKeyService  `json:"keyService"`
	Provider    HubWorkerProvider    `json:"provider"`
	Capacity    *HubWorkerCapacity   `json:"capacity,omitempty"`
	Cleanup     *HubWorkerCleanup    `json:"cleanup,omitempty"`
	Permission  *HubWorkerPermission `json:"permission,omitempty"`
}

type HubWorkerPostgres struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
}

type HubWorkerObjectStore struct {
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
}

// HubWorkerKeyService is the OpenBao endpoint. The audit mount and key are
// not rendered: the loader sets them from the fixed names.
type HubWorkerKeyService struct {
	Endpoint   string `json:"endpoint"`
	AuditMount string `json:"-"`
	AuditKey   string `json:"-"`
}

// HubWorkerProvider is the OpenBao Kubernetes auth configuration that
// `setup` applies: one auth role (and its policy of the same name,
// `<name>-hub-worker-<purpose>`) per purpose. The auth mount, token audience
// and transit key names are fixed or derive from the installation ID; they
// are not rendered; the loader sets them (providerconfig.OpenBaoNamesFor).
type HubWorkerProvider struct {
	AuthMount string                 `json:"-"`
	Audience  string                 `json:"-"`
	Roles     HubWorkerProviderRoles `json:"roles"`
	// WorkerConfigurationAudit is the worker configuration audit Transit key
	// (ADR-204); zero without the permission workerConfiguration section.
	WorkerConfigurationAudit OwnerPublicTransit `json:"-"`
	// ContextDeletionSigning is the context deletion signing key (ADR-205),
	// on the audit mount; zero without cleanup or context deletion.
	ContextDeletionSigning OwnerPublicTransit `json:"-"`
}

// HubWorkerProviderRoles names the auth roles. The cleanup roles are empty
// without the cleanup section.
type HubWorkerProviderRoles struct {
	AuditWrap     string `json:"auditWrap"`
	AuditUnwrap   string `json:"auditUnwrap"`
	CleanupWrap   string `json:"cleanupWrap,omitempty"`
	CleanupOpen   string `json:"cleanupOpen,omitempty"`
	CleanupVerify string `json:"cleanupVerify,omitempty"`
	CleanupSign   string `json:"cleanupSign,omitempty"`
}

var ErrHubWorkerConfig = errors.New("invalid hub-worker configuration")

// DecodeHubWorkerConfig decodes one bounded JSON object with no unknown
// fields. Helm renders it with toJson, so key order and omitted zero fields
// are not significant.
func DecodeHubWorkerConfig(r io.Reader) (HubWorkerConfig, error) {
	var out HubWorkerConfig
	if r == nil {
		return out, ErrHubWorkerConfig
	}
	b, err := io.ReadAll(io.LimitReader(r, HubWorkerConfigMaxBytes+1))
	if err != nil || len(b) == 0 || len(b) > HubWorkerConfigMaxBytes {
		return out, ErrHubWorkerConfig
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Format != HubWorkerConfigFormat {
		return HubWorkerConfig{}, ErrHubWorkerConfig
	}
	return out, nil
}
