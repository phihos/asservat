package contracts

import (
	"io"
	"strings"
	"time"
)

const PermissionDeploymentFormat = "asservat-permission-deployment/v1"
const PermissionDeploymentFile = "permission-deployment.json"
const PermissionWorkerProjectionDirectory = "permission"
const PermissionDeploymentMaxBytes = 64 << 10
const PermissionCredentialManifestFormat = "asservat-permission-credentials/v1"
const PermissionCredentialManifestFile = "permission-roles.json"
const PermissionCredentialManifestMaxBytes = 16 << 10

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
}

// RetentionDeployment pins the installer-applied retention guard. Its plan
// is derived: the permission guard's administrators, the one reserved status
// user and no delegations.
type RetentionDeployment struct {
	Guard OwnerDeploymentGuard `json:"guard"`
}

// RetentionStatusUser is the retention guard's only status user (ADR-195 D1).
// No built-in Kubernetes authenticator issues it; the hub-worker's probe
// account must not be a status user, so it cannot be the hub-worker.
const RetentionStatusUser = "system:asservat:retention-status-unused"

// RetentionGuardName is the installer-applied retention admission policy and
// binding (ADR-195).
func RetentionGuardName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-retention-guard"
}

type PermissionControlDeployment struct {
	ClusterID    string                 `json:"clusterID"`
	Namespace    WorkerObjectReference  `json:"namespace"`
	Kubernetes   OwnerProviderEndpoint  `json:"kubernetes"`
	Guard        OwnerDeploymentGuard   `json:"guard"`
	StatusUsers  []string               `json:"statusUsers"`
	Delegations  []PermissionDelegation `json:"delegations"`
	ProbeAccount WorkerObjectReference  `json:"probeAccount"`
}

// PermissionDelegation is trusted installation configuration: writers who
// may author bindings inside one scope, for the listed roles and issuers.
type PermissionDelegation struct {
	Writers   []OwnerDeploymentActor `json:"writers"`
	ClusterID string                 `json:"clusterID"`
	Namespace WorkerObjectReference  `json:"namespace"`
	Workloads []PermissionWorkload   `json:"workloads"`
	Roles     []string               `json:"roles"`
	Issuers   []string               `json:"issuers"`
}

type PermissionWorkload struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// Only the two permission logins are projected (ADR-189).
type PermissionCredentialManifest struct {
	Format  string                         `json:"format"`
	Input   PublicRuntimeRoles             `json:"input"`
	RootUID string                         `json:"rootUID"`
	SetupID string                         `json:"setupID"`
	Roles   []PublicRuntimeCredentialProof `json:"roles"`
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

func DecodePermissionDeployment(r io.Reader) (PermissionDeployment, error) {
	return decodeClosedRPC[PermissionDeployment](r, PermissionDeploymentMaxBytes)
}
func DecodePermissionCredentialManifest(r io.Reader) (PermissionCredentialManifest, error) {
	return decodeClosedRPC[PermissionCredentialManifest](r, PermissionCredentialManifestMaxBytes)
}
