package contracts

import (
	"encoding/json"
	"io"
)

const OwnerDeploymentFormat = "asservat-owner-deployment/v1"
const OwnerDeploymentRoot = "/run/asservat/hub"
const OwnerDeploymentMaxBytes = 256 << 10
const OwnerPodUIDEnvironment = "ASSERVAT_HUB_POD_UID"
const OwnerWorkerTrustFormat = "asservat-owner-worker-trust/v1"

type OwnerWorkerTrust struct {
	Format   string   `json:"format"`
	Controls [][]byte `json:"controls"`
}

func DecodeOwnerWorkerTrust(r io.Reader) (OwnerWorkerTrust, error) {
	return decodeClosedRPC[OwnerWorkerTrust](r, 16<<20)
}

// Installation-owned public startup inputs. Credentials have fixed, separate
// projected filenames and cannot be embedded or redirected through this DTO.
type OwnerDeployment struct {
	Format                 string                           `json:"format"`
	InstallationID         string                           `json:"installationID"`
	ClusterID              string                           `json:"clusterID"`
	PermissionRootID       string                           `json:"permissionRootID"`
	Namespace              WorkerObjectReference            `json:"namespace"`
	ConfigurationUID       string                           `json:"configurationUID"`
	Kubernetes             OwnerProviderEndpoint            `json:"kubernetes"`
	WorkloadGuard          OwnerDeploymentGuard             `json:"workloadGuard"`
	ConfigurationProbes    []OwnerConfigurationProbe        `json:"configurationProbes"`
	SchedulingLeases       []OwnerSchedulingLease           `json:"schedulingLeases"`
	APIContextStarts       *OwnerDeploymentAPIContextStarts `json:"apiContextStarts,omitempty"`
	CapacityProbe          *OwnerDeploymentCapacityProbe    `json:"capacityProbe,omitempty"`
	InitialHistoryProbe    *OwnerInitialHistoryProbe        `json:"initialHistoryProbe,omitempty"`
	Postgres               OwnerPostgresEndpoint            `json:"postgres"`
	AuditStore             OwnerAuditStore                  `json:"auditStore"`
	KeyService             OwnerKeyService                  `json:"keyService"`
	Connections            int                              `json:"connections"`
	Concurrency            int                              `json:"concurrency"`
	Native                 *OwnerNativeDeployment           `json:"native,omitzero"`
	Public                 *OwnerPublicDeployment           `json:"public,omitempty"`
	ProviderAuthentication *OwnerProviderAuthentication     `json:"providerAuthentication,omitempty"`
	Observation            *OwnerObservationBootstrap       `json:"observation,omitempty"`
}

// Only the acknowledged original bootstrap account may observe the retained
// initial guard through this purpose-fixed exception. It permits no writes.
type OwnerInitialHistoryProbe struct {
	Namespace      WorkerObjectReference `json:"namespace"`
	ServiceAccount WorkerObjectReference `json:"serviceAccount"`
	Configuration  string                `json:"configuration"`
}

// OwnerPublicDeployment enables hub-api's browser/MCP/download layer
// (ADR-180). It requires Native. Credentials and keys are fixed projected
// files, never fields; no request can select an origin or endpoint.
type OwnerPublicDeployment struct {
	Format string `json:"format"`
	Origin string `json:"origin"`
	// Identity (ADR-180 decision 3): the pinned browser settings supply the
	// issuer, client and session epoch; the Keycloak profile derives the
	// provider endpoints from that issuer. BrowserAudience is the one access
	// audience of browser login; MCP and download audiences derive from Origin.
	BrowserRootID    string                `json:"browserRootID"`
	BrowserSettings  WorkerObjectReference `json:"browserSettings"`
	IdentitySettings WorkerObjectReference `json:"identitySettings"`
	BrowserAudience  string                `json:"browserAudience"`
	ProviderRoots    [][]byte              `json:"providerRoots"`
	// SessionTransit is the OpenBao Transit key on KeyService for browser
	// session ciphertext; its encrypt and decrypt tokens are separate files.
	SessionTransit OwnerPublicTransit `json:"sessionTransit"`
	// ProviderRecipeSHA256 pins the public provider recipe (ADR-182) in the
	// installed layout: the four public purposes log in with the owner's
	// Pod token instead of reading token files. Empty in the legacy layout.
	ProviderRecipeSHA256 string `json:"providerRecipeSHA256,omitempty"`
	// Investigation and regional start (ADR-180 decision 4). Each workload
	// cluster has its connector source and executor pin, router limits and
	// hub-held guarded capability and work trust (ADR-179). ADR-185: they are
	// entries of the guarded cluster catalog, read at process start, because
	// regional clusters enroll after the owner's one launch.
	ClusterCatalog OwnerPublicGuardedSource `json:"clusterCatalog"`
	WorkSigning    OwnerPublicSigning       `json:"workSigning"`
	Standby        int                      `json:"standby"`
	Captures       int                      `json:"captures"`
	// PreviewSeconds is the reviewed preview lifetime.
	PreviewSeconds int `json:"previewSeconds"`
	// Audit (decision 5): installer-provisioned lifecycle policies of the
	// capture lane and both operation lanes, as their SQL backings record them.
	CaptureAuditPolicy json.RawMessage `json:"captureAuditPolicy"`
	// ADR-190: the normal and resolution profiles are renewed by the
	// hub-worker, so the hub-api reads them at runtime under this pinned
	// capacity qualification instead of from this input.
	Capacity OwnerPublicCapacity `json:"capacity"`
	// Downloads (ADR-180 P4). Download, window and stop audits use the owner
	// audit store, identified by AuditStoreID. ArtifactKeyID is the local key
	// service artifact key bound to download workers. The worker configuration
	// and the download environment are guarded ConfigMaps in the hub's control
	// namespace; the worker namespace is one of Native.WorkerAPIs. ADR-194 D1:
	// an unconfigured worker source leaves this process without downloads.
	AuditStoreID        string                   `json:"auditStoreID"`
	ArtifactKeyID       string                   `json:"artifactKeyID"`
	WorkerConfiguration OwnerPublicGuardedSource `json:"workerConfiguration"`
	WorkerPKI           OwnerPublicWorkerPKI     `json:"workerPKI"`
	DownloadEnvironment OwnerPublicEnvironment   `json:"downloadEnvironment"`
	DownloadPlan        OwnerPublicDownloadPlan  `json:"downloadPlan"`
	// HTTPS (ADR-180 P5). hub-api terminates TLS itself with the fixed files
	// OwnerPublicTLSCertificate/OwnerPublicTLSKey; forwarded headers confer no
	// transport trust. The console package is image-owned.
	Port                 int                       `json:"port"`
	Version              string                    `json:"version"`
	OperationConcurrency int                       `json:"operationConcurrency"`
	MCPPerIdentity       int                       `json:"mcpPerIdentity"`
	DownloadConcurrency  int                       `json:"downloadConcurrency"`
	DownloadsPerIdentity int                       `json:"downloadsPerIdentity"`
	DownloadMaxSeconds   int                       `json:"downloadMaxSeconds"`
	OperationAudit       OwnerPublicOperationAudit `json:"operationAudit"`
	// Fleet enables the ADR-193 fleet-operator bootstrap issuance route.
	Fleet *OwnerFleetIssuance `json:"fleet,omitempty"`
	// RuntimeProjection names the immutable public runtime projection Secret
	// (ADR-184 decision 6, ADR-194). The provider-installed layout requires it;
	// the owner compares it with the mounted public root at startup.
	RuntimeProjection WorkerObjectReference `json:"runtimeProjection,omitzero"`
}

// OwnerFleetIssuance is the installed issuance input (ADR-193 step 4).
// Settings is the protected fleet.json ConfigMap and its guard; ChannelMount
// is the operator's KV-v2 mount and DeliveryProfile the one profile name
// fleet.json lists for it. ProviderRecipeSHA256 pins the bootstrap-channel
// provider role. No request selects any of these.
type OwnerFleetIssuance struct {
	Settings             WorkerObjectReference `json:"settings"`
	SettingsGuard        OwnerDeploymentGuard  `json:"settingsGuard"`
	ChannelMount         string                `json:"channelMount"`
	DeliveryProfile      string                `json:"deliveryProfile"`
	ProviderRecipeSHA256 string                `json:"providerRecipeSHA256"`
}

// OwnerFleetChannelPrefix is the fixed KV path prefix of bootstrap secrets.
const OwnerFleetChannelPrefix = "connector"

type OwnerPublicOperationAudit struct {
	RetentionSeconds        int `json:"retentionSeconds"`
	NormalConcurrency       int `json:"normalConcurrency"`
	ResolutionConcurrency   int `json:"resolutionConcurrency"`
	PerPrincipalConcurrency int `json:"perPrincipalConcurrency"`
	NormalPerSecond         int `json:"normalPerSecond"`
	ResolutionPerSecond     int `json:"resolutionPerSecond"`
}

// OwnerPublicWorkerPKI is the OpenBao PKI role that signs download worker
// leaves; its token is the fixed file OwnerPublicWorkerIssueToken.
type OwnerPublicWorkerPKI struct {
	Mount       string   `json:"mount"`
	Role        string   `json:"role"`
	IssuerEpoch string   `json:"issuerEpoch"`
	Roots       [][]byte `json:"roots"`
}
type OwnerPublicEnvironment struct {
	Source WorkerObjectReference     `json:"source"`
	Guard  OwnerDeploymentGuard      `json:"guard"`
	Paths  []DownloadEnvironmentPath `json:"paths"`
}
type OwnerPublicDownloadPlan struct {
	OutputLimit     int64 `json:"outputLimit"`
	ReadLimit       int64 `json:"readLimit"`
	RequestLimit    int   `json:"requestLimit"`
	DurationSeconds int   `json:"durationSeconds"`
}
type OwnerPublicCluster struct {
	ClusterID  string                      `json:"clusterID"`
	Connector  FederationPeer              `json:"connector"`
	Executor   OwnerPublicExecutor         `json:"executor"`
	Standby    int                         `json:"standby"`
	Captures   int                         `json:"captures"`
	Capability OwnerPublicGuardedSource    `json:"capability"`
	WorkTrust  OwnerPublicGuardedSource    `json:"workTrust"`
	Settings   ContextCapabilitySettings   `json:"capabilitySettings"`
	Trust      APIContextWorkTrustSettings `json:"trustSettings"`
	// Topology pins the slot's immutable retention topology (ADR-196
	// decision 7); the hub-api unions it with its input's pins at start.
	Topology OwnerNativeTopology `json:"topology"`
	// Capacity selects ADR-197 v2 capacity observation for this cluster:
	// the connector Deployment's template and workload guard digests, and the
	// region's selector guard digest and keys, which the hub-api records as
	// the cluster's write-once SQL qualification.
	Capacity *OwnerPublicClusterCapacity `json:"capacity,omitempty"`
}
type OwnerPublicClusterCapacity struct {
	TemplateDigest       string   `json:"templateDigest"`
	ProtectionDigest     string   `json:"protectionDigest"`
	NamespaceGuardDigest string   `json:"namespaceGuardDigest"`
	Keys                 []string `json:"keys"`
}
type OwnerPublicExecutor struct {
	NamespaceUID  string `json:"namespaceUID"`
	AccountUID    string `json:"accountUID"`
	StartupDigest string `json:"startupDigest"`
	ImageDigest   string `json:"imageDigest"`
}
type OwnerPublicGuardedSource struct {
	Source WorkerObjectReference `json:"source"`
	Guard  OwnerDeploymentGuard  `json:"guard"`
}

// OwnerPublicSigning is the hub's OpenBao Ed25519 work-signing key; its token
// is the fixed file OwnerPublicWorkSignToken.
type OwnerPublicSigning struct {
	Mount     string `json:"mount"`
	Name      string `json:"name"`
	Version   int    `json:"version"`
	KeyID     string `json:"keyID"`
	PublicKey []byte `json:"publicKey"`
}
type OwnerPublicTransit struct {
	Mount string `json:"mount"`
	Key   string `json:"key"`
}

const OwnerPublicDeploymentFormat = "asservat-owner-public/v1"

// Fixed projected filenames of the public layer's secrets.
const (
	OwnerPublicClientSecretFile = "oidc-client-secret"
	OwnerPublicSessionSealToken = "browser-seal.token"
	OwnerPublicSessionOpenToken = "browser-open.token"
	OwnerPublicWorkSignToken    = "work-sign.token"
	OwnerPublicWorkerIssueToken = "worker-issue.token"
	OwnerPublicTLSCertificate   = "public-tls.crt"
	OwnerPublicTLSKey           = "public-tls.key"
	OwnerPublicConsoleRoot      = "/usr/share/asservat/console"
)

// Optional protected native listener dependencies. The accepted owner pool
// independently supplies NativePort; these inputs cannot select a route/owner.
type OwnerNativeDeployment struct {
	ConnectorRoots      [][]byte               `json:"connectorRoots"`
	WorkerAPIs          []OwnerNativeWorkerAPI `json:"workerAPIs"`
	RetentionTopologies []OwnerNativeTopology  `json:"retentionTopologies"`
	Connections         int                    `json:"connections"`
	Concurrency         int                    `json:"concurrency"`
}
type OwnerNativeWorkerAPI struct {
	ClusterID  string                `json:"clusterID"`
	Namespace  WorkerObjectReference `json:"namespace"`
	Kubernetes OwnerProviderEndpoint `json:"kubernetes"`
}
type OwnerNativeTopology struct {
	TargetClusterID string `json:"targetClusterID"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	SHA256          string `json:"sha256"`
}

// OwnerGuardInputs are the owner pool's exact source pins and installed
// workload guard plan. The federation's owner reads (ADR-172) receive exactly
// the hub-api values, so both prove the same protection digest.
type OwnerGuardInputs struct {
	Namespace           WorkerObjectReference            `json:"namespace"`
	ConfigurationUID    string                           `json:"configurationUID"`
	Kubernetes          OwnerProviderEndpoint            `json:"kubernetes"`
	WorkloadGuard       OwnerDeploymentGuard             `json:"workloadGuard"`
	ConfigurationProbes []OwnerConfigurationProbe        `json:"configurationProbes"`
	SchedulingLeases    []OwnerSchedulingLease           `json:"schedulingLeases"`
	APIContextStarts    *OwnerDeploymentAPIContextStarts `json:"apiContextStarts,omitempty"`
	CapacityProbe       *OwnerDeploymentCapacityProbe    `json:"capacityProbe,omitempty"`
	InitialHistoryProbe *OwnerInitialHistoryProbe        `json:"initialHistoryProbe,omitempty"`
}

func (c OwnerDeployment) Guard() OwnerGuardInputs {
	return OwnerGuardInputs{c.Namespace, c.ConfigurationUID, c.Kubernetes, c.WorkloadGuard, c.ConfigurationProbes, c.SchedulingLeases, c.APIContextStarts, c.CapacityProbe, c.InitialHistoryProbe}
}

type OwnerConfigurationProbe struct {
	ConfigMap      string `json:"configMap"`
	ServiceAccount string `json:"serviceAccount"`
}
type OwnerSchedulingLease struct {
	Lease          string `json:"lease"`
	ServiceAccount string `json:"serviceAccount"`
}
type OwnerProviderEndpoint struct {
	Endpoint string   `json:"endpoint"`
	Roots    [][]byte `json:"roots"`
}
type OwnerDeploymentGuard struct {
	Name                   string                 `json:"name"`
	PolicyUID              string                 `json:"policyUID"`
	PolicyGeneration       int64                  `json:"policyGeneration"`
	BindingUID             string                 `json:"bindingUID"`
	BindingResourceVersion string                 `json:"bindingResourceVersion"`
	Administrators         []OwnerDeploymentActor `json:"administrators"`
}
type OwnerDeploymentActor struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}
type OwnerPostgresEndpoint struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Database       string   `json:"database"`
	Roots          [][]byte `json:"roots"`
	MaxConnections int32    `json:"maxConnections"`
}
type OwnerAuditStore struct {
	Endpoint string   `json:"endpoint"`
	Roots    [][]byte `json:"roots"`
	Region   string   `json:"region"`
	Bucket   string   `json:"bucket"`
}
type OwnerKeyService struct {
	Endpoint   string   `json:"endpoint"`
	Roots      [][]byte `json:"roots"`
	AuditMount string   `json:"auditMount"`
	AuditKey   string   `json:"auditKey"`
	PKIMount   string   `json:"pkiMount"`
	ServerRole string   `json:"serverRole"`
	ClientRole string   `json:"clientRole"`
}
type OwnerSQLCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type OwnerStorageCredential struct {
	AccessKeyID     string `json:"accessKeyID"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
}

func DecodeOwnerDeployment(r io.Reader) (OwnerDeployment, error) {
	return decodeClosedRPC[OwnerDeployment](r, OwnerDeploymentMaxBytes)
}
func DecodeOwnerSQLCredential(r io.Reader) (OwnerSQLCredential, error) {
	return decodeClosedRPC[OwnerSQLCredential](r, 16<<10)
}
func DecodeOwnerStorageCredential(r io.Reader) (OwnerStorageCredential, error) {
	return decodeClosedRPC[OwnerStorageCredential](r, 32<<10)
}

// Explicit original guard scope only. It neither grants RBAC nor replaces the
// independent start admission and original installation journal acceptance.
type OwnerDeploymentAPIContextStarts struct {
	CapacityAccount  WorkerObjectReference `json:"capacityAccount"`
	ExecutionAccount WorkerObjectReference `json:"executionAccount"`
	// CapacityAudience enables the ADR-175 capacity TokenRequest.
	CapacityAudience string `json:"capacityAudience,omitempty"`
}

// OwnerPublicCapacity pins the capacity qualification whose accepted audit
// profiles the hub-api reads (ADR-190). It is not itself a policy.
type OwnerPublicCapacity struct {
	QualificationID     string `json:"qualificationID"`
	QualificationDigest string `json:"qualificationDigest"`
	AccountVersion      string `json:"accountVersion"`
}
