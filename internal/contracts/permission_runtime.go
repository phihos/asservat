package contracts

import (
	"strings"
	"time"
)

const PermissionDeploymentFormat = "asservat-permission-deployment/v1"
const PermissionDeploymentFile = "permission-deployment.json"
const PermissionWorkerProjectionDirectory = "permission"
const PermissionCredentialManifestFile = "permission-roles.json"

// PermissionRuntimeProjectionName is derived only from a separately validated
// installation UUID; callers still verify the original journal receipt.
func PermissionRuntimeProjectionName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-permission"
}

// PermissionGuardName is the installer-applied permission admission policy
// and binding (ADR-189).
func PermissionGuardName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-permission-guard"
}

// PermissionDeployment is the hub-worker's private permission stream input
// (ADR-189). RootID is the owner selection's PermissionRootID; the guard is
// the installer-applied policy and its pin. It grants nothing by itself: the
// reconciler proves the guard and the SQL stream on every acceptance.
type PermissionDeployment struct {
	Format         string                      `json:"format"`
	InstallationID string                      `json:"installationID"`
	RootID         string                      `json:"rootID"`
	RoleRootUID    string                      `json:"roleRootUID"`
	RoleSetupID    string                      `json:"roleSetupID"`
	Postgres       OwnerPostgresEndpoint       `json:"postgres"`
	Control        PermissionControlDeployment `json:"control"`
	// Review is the administrator-created initial review ConfigMap, needed
	// only when bindings exist at the first acceptance.
	Review *WorkerObjectReference `json:"review,omitempty"`
	// Retention is the hub retention source (ADR-195). It rides in this
	// projection: the same root, process and mount as the permission stream.
	Retention *RetentionDeployment `json:"retention,omitempty"`
	// WorkerConfiguration is the download worker configuration acceptance
	// (ADR-204 decision 7). Like retention, it rides in this projection; its
	// two logins follow the retention logins. Without it no worker
	// configuration child runs.
	WorkerConfiguration *WorkerConfigurationDeployment `json:"workerConfiguration,omitempty"`
	// ContextDeletion adds the positive deletion logins (ADR-205) after the
	// worker configuration logins. The store and signing pins they need are
	// known only later and ride in the capacity projection; without both no
	// deletion child runs.
	ContextDeletion bool `json:"contextDeletion,omitempty"`
	// Browser projects the protected browser settings into SQL (ADR-061,
	// ADR-210): the hub-worker's browser-settings login follows the deletion
	// logins. Without it no installed console login can begin.
	Browser *PermissionBrowserSettings `json:"browser,omitempty"`
	// Identity is the installed identity settings ConfigMap and its issuer:
	// its eligibleGroups are the configured group directory that groupID
	// PermissionSources validate against (ADR-247). Without it such sources
	// grant nothing.
	Identity *PermissionIdentitySettings `json:"identity,omitempty"`
}

// PermissionIdentitySettings pins the identity settings by name and UID.
type PermissionIdentitySettings struct {
	Settings WorkerObjectReference `json:"settings"`
	Issuer   string                `json:"issuer"`
}

// PermissionBrowserSettings is the installed browser settings ConfigMap,
// pinned by name and UID, and its session root.
type PermissionBrowserSettings struct {
	RootID   string                `json:"rootID"`
	Settings WorkerObjectReference `json:"settings"`
}

// ContextDeletionDeployment names the evidence store the deletion child
// purges (the endpoint, roots, region and bucket, in the audit store's
// shape) and the pinned deletion signing key from the provider setup
// readback. It rides in the capacity projection, whose qualification names
// the evidence store ID the attempts carry. The store credential is the fixed
// file EvidenceDeleteCredentialFile of the Secret
// EvidenceDeleteCredentialName; no input names a file.
type ContextDeletionDeployment struct {
	EvidenceStore OwnerAuditStore        `json:"evidenceStore"`
	Signing       ContextDeletionSigning `json:"signing"`
}

// ContextDeletionSigning is the Ed25519 Transit key that signs deletion
// records, the version it signs with, that version's key ID and every
// version's public key from the provider setup readback.
type ContextDeletionSigning struct {
	Mount      string            `json:"mount"`
	Key        string            `json:"key"`
	Version    int               `json:"version"`
	KeyID      string            `json:"keyID"`
	PublicKeys map[string][]byte `json:"publicKeys"`
}

// EvidenceDeleteDirectory is where the hub-worker Pod projects the Secret
// EvidenceDeleteCredentialName (ADR-205 decision 4).
const EvidenceDeleteDirectory = "evidence-delete"

// WorkerConfigurationDeployment pins the guarded worker profile source
// (ADR-070) in the hub cluster's worker namespace: the source ConfigMap, its
// administrator admission guard and the dedicated Transit key of the
// encrypted acceptance audit, written under
// download-worker-configuration/v1/<installation>/ by the hub-worker's audit
// principal. The SQL logins are the fixed files of
// PublicRuntimeWorkerConfigurationPurposes; no input names a file.
type WorkerConfigurationDeployment struct {
	Namespace    WorkerObjectReference `json:"namespace"`
	Source       WorkerObjectReference `json:"source"`
	Guard        OwnerDeploymentGuard  `json:"guard"`
	AuditTransit OwnerPublicTransit    `json:"auditTransit"`
}

// RetentionDeployment pins the installer-applied retention guard. Its plan
// is derived: the permission guard's administrators, the one reserved status
// user and no delegations.
type RetentionDeployment struct {
	Guard OwnerDeploymentGuard `json:"guard"`
}

// RetentionGuardName is the installer-applied retention admission policy and
// binding (ADR-195).
func RetentionGuardName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-retention-guard"
}

type PermissionControlDeployment struct {
	ClusterID    string                `json:"clusterID"`
	Namespace    WorkerObjectReference `json:"namespace"`
	Kubernetes   OwnerProviderEndpoint `json:"kubernetes"`
	Guard        OwnerDeploymentGuard  `json:"guard"`
	StatusUsers  []string              `json:"statusUsers"`
	ProbeAccount WorkerObjectReference `json:"probeAccount"`
}

// PermissionRuntimeProjectionClaim belongs to the original resource journal,
// like the capacity claim. PublicDigest covers public configuration only.
type PermissionRuntimeProjectionClaim struct {
	OperationID string `json:"operationID"`
	// RootID must equal the owner selection's PermissionRootID.
	RootID       string                              `json:"rootID"`
	PublicDigest string                              `json:"publicDigest"`
	ClaimedAt    time.Time                           `json:"claimedAt"`
	Until        time.Time                           `json:"until"`
	Receipt      *PermissionRuntimeProjectionReceipt `json:"receipt,omitempty"`
}

type PermissionRuntimeProjectionReceipt struct {
	Secret          WorkerObjectReference `json:"secret"`
	ResourceVersion string                `json:"resourceVersion"`
	ObservedAt      time.Time             `json:"observedAt"`
}
