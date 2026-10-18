package contracts

import (
	"io"
	"strings"
)

// ADR-176 local key service: installation-owned startup inputs at a fixed
// root. Credentials are fixed projected files (sql-key-configuration.json,
// sql-key-wrap.json, sql-key-verify.json, kube-observer.token, tls.crt,
// tls.key; with a Downloads section also sql-key-acquisition.json and
// kube-probe.token); root keys are read only through the protected local key
// source, never from this document.
const KeyServiceDeploymentFormat = "asservat-key-service-deployment/v1"
const KeyServiceDeploymentRoot = "/run/asservat/key-service"
const KeyServiceDeploymentMaxBytes = 1 << 20

// KeyServicePort is the installed key service's TLS port (ADR-198).
const KeyServicePort = 9447

type KeyServiceDeployment struct {
	Format           string                `json:"format"`
	InstallationID   string                `json:"installationID"`
	ClusterID        string                `json:"clusterID"`
	PermissionRootID string                `json:"permissionRootID"`
	Port             int                   `json:"port"`
	Namespace        WorkerObjectReference `json:"namespace"`
	Kubernetes       OwnerProviderEndpoint `json:"kubernetes"`
	// KeySource is the protected local key configuration ConfigMap (ADR-067)
	// and KeyID its artifact key; RecoveryEpoch is that configuration's epoch.
	KeySource     WorkerObjectReference `json:"keySource"`
	KeyID         string                `json:"keyID"`
	RecoveryEpoch string                `json:"recoveryEpoch"`
	Postgres      OwnerPostgresEndpoint `json:"postgres"`
	// KeyClientRoots verify key-client leaves; ConnectorClientRoots verify
	// connector client chains, whose peers resolve from their staged SQL
	// profiles (ADR-198).
	KeyClientRoots       [][]byte `json:"keyClientRoots"`
	ConnectorClientRoots [][]byte `json:"connectorClientRoots"`
	Concurrency          int      `json:"concurrency"`
	// Downloads enables acquisition unwraps (ADR-204 decision 8). Without it
	// the service authorizes wraps and verifier unwraps only.
	Downloads *KeyServiceDownloads `json:"downloads,omitempty"`
}

// KeyServiceDownloads pins what the native download key authority needs.
// WorkerProfile is the exact worker-profile.json document of the guarded
// worker source WorkerSource; it selects the profile only. Every acquisition
// unwrap still requires SQL's current audited revision to equal it (ADR-070),
// so a stale or wrong pin denies and never authorizes. RetentionTopologies are
// fixed pins (possibly none), united with each joined slot's pin from the
// guarded cluster catalog, read with the probe account like the hub-api.
type KeyServiceDownloads struct {
	WorkerSource        WorkerObjectReference    `json:"workerSource"`
	WorkerProfile       WorkerConfiguration      `json:"workerProfile"`
	ClusterCatalog      OwnerPublicGuardedSource `json:"clusterCatalog"`
	RetentionTopologies []OwnerNativeTopology    `json:"retentionTopologies"`
}

func DecodeKeyServiceDeployment(r io.Reader) (KeyServiceDeployment, error) {
	return decodeClosedRPC[KeyServiceDeployment](r, KeyServiceDeploymentMaxBytes)
}

// PublicRuntimeKeyServicePurposes are the key service's logins (ADR-198),
// projected only into its own Secret. ADR-204 adds the acquisition unwrap
// login, which spends download key slots and opens only with Downloads.
func PublicRuntimeKeyServicePurposes() []string {
	return []string{"key-configuration", "key-wrap", "key-verify", "key-acquisition"}
}

// One Recreate replica; a failed process may still close its pools.
const PublicRuntimeRetainedKeyServiceProcesses = 2
const PublicRuntimeKeyServiceRoleConnections = PublicRuntimeRetainedKeyServiceProcesses + 1

func keyServiceName(installationID, suffix string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-key-service" + suffix
}

// KeyServiceName is the key service's Deployment, Service, account and
// inputs prefix; the other names hold its key material and credentials.
func KeyServiceName(installationID string) string { return keyServiceName(installationID, "") }
func KeyServiceServingSecretName(installationID string) string {
	return keyServiceName(installationID, "-tls")
}
func KeyServiceRuntimeProjectionName(installationID string) string {
	return keyServiceName(installationID, "-sql")
}
func LocalArtifactKeySecretName(installationID string) string {
	return keyServiceName(installationID, "-root-v1")
}
func LocalArtifactKeyConfigurationName(installationID string) string {
	return keyServiceName(installationID, "-configuration")
}
