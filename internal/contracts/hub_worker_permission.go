package contracts

// HubWorkerPermission is the hub-worker's permission section of
// HubWorkerConfig (Helm-native installation). Its child starts when the
// section is present. It holds only Helm values: the stream root is
// InstallationIDs.PermissionRootID, the control namespace is the release
// namespace, and the source UIDs are read by name.
type HubWorkerPermission struct {
	// StatusUsers may write PermissionSource/AccessBinding status (the
	// reconciler's own account, system:serviceaccount:<ns>:<account>).
	StatusUsers []string `json:"statusUsers"`
	// Delegations are product permission configuration: writers who may
	// author bindings inside one scope for the listed roles and issuers.
	Delegations []PermissionDelegation `json:"delegations"`
	// Review names the administrator-created initial review ConfigMap,
	// needed only when bindings exist at the first acceptance.
	Review string `json:"review,omitempty"`
	// Retention runs the hub retention source (ADR-195).
	Retention bool `json:"retention,omitempty"`
	// WorkerConfiguration is the download worker configuration acceptance
	// (ADR-204 decision 7). Its audit Transit key is
	// HubWorkerProvider.WorkerConfigurationAudit.
	WorkerConfiguration *HubWorkerWorkerConfiguration `json:"workerConfiguration,omitempty"`
	// ContextDeletion deletes expired context evidence (ADR-205). Its signing
	// key is HubWorkerProvider.ContextDeletionSigning.
	ContextDeletion *HubWorkerContextDeletion `json:"contextDeletion,omitempty"`
	// Browser projects the browser settings ConfigMap into SQL (ADR-210);
	// its session root is InstallationIDs.BrowserRootID.
	Browser *HubWorkerBrowserSettings `json:"browser,omitempty"`
	// Identity names the identity settings ConfigMap and its issuer: the
	// configured group directory of groupID PermissionSources (ADR-247) and
	// the policy grant settings projection.
	Identity *HubWorkerIdentitySettings `json:"identity,omitempty"`
}

// HubWorkerWorkerConfiguration names the worker namespace and the worker
// profile ConfigMap in it.
type HubWorkerWorkerConfiguration struct {
	Namespace string `json:"namespace"`
	Source    string `json:"source"`
}

// HubWorkerContextDeletion is the evidence store the deletion child purges.
// It is the selected object store's evidence bucket: its trust roots are
// HubWorkerAuditStoreRootsFile and its list-and-delete
// credential HubWorkerEvidenceDeleteStorageFile.
type HubWorkerContextDeletion struct {
	EvidenceStore HubWorkerObjectStore `json:"evidenceStore"`
}

type HubWorkerBrowserSettings struct {
	Settings string `json:"settings"`
}

type HubWorkerIdentitySettings struct {
	Settings string `json:"settings"`
	Issuer   string `json:"issuer"`
}

// Fixed files under HubWorkerDeploymentRoot for the context deletion child.
const (
	// HubWorkerEvidenceDeleteStorageFile is the evidence list-and-delete
	// principal (`<name>-s3-evidence-delete`, credentials.json).
	HubWorkerEvidenceDeleteStorageFile = "evidence-delete-storage.json"
)

// RetentionSourceResource names the hub retention source in its digest.
const RetentionSourceResource = "evidenceretentionpolicies"

// RetentionSourceDigest is the deterministic protection digest of the hub
// retention source, the EvidenceRetentionPolicies of one cluster's control
// namespace (retention_source.protection_digest and a retention topology's
// hub protectionSHA256).
func RetentionSourceDigest(clusterID, namespace string) [32]byte {
	return ConfigMapSourceDigest(clusterID, namespace, RetentionSourceResource)
}
