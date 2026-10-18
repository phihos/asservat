package contracts

import (
	"encoding/json"
	"io"
)

const CapacityDeploymentFormat = "asservat-capacity-deployment/v1"
const CapacityDeploymentFile = "capacity-deployment.json"
const CapacityDeploymentRoot = "/run/asservat/capacity"
const CapacityWorkerProjectionDirectory = "capacity"
const CapacityDeploymentMaxBytes = 256 << 10
const CapacityCredentialManifestFormat = "asservat-capacity-credentials/v1"
const CapacityCredentialManifestFile = "capacity-roles.json"
const CapacityCredentialManifestMaxBytes = 16 << 10

// Installation-owned inputs for the existing A-HWORK process. Endpoint and
// whole-object/probe grants come from the protected producer, never a capture
// request. SQL/account credentials have fixed separate filenames.
type CapacityDeployment struct {
	LocalOwner       *CapacityLocalOwner          `json:"localOwner,omitempty"`
	Format           string                       `json:"format"`
	InstallationID   string                       `json:"installationID"`
	PermissionRootID string                       `json:"permissionRootID"`
	RoleRootUID      string                       `json:"roleRootUID"`
	RoleSetupID      string                       `json:"roleSetupID"`
	AccountVersion   string                       `json:"accountVersion"`
	Postgres         OwnerPostgresEndpoint        `json:"postgres"`
	Control          CapacityControlDeployment    `json:"control"`
	Clusters         []CapacityClusterDeployment  `json:"clusters"`
	Processing       CapacityProcessingDeployment `json:"processing"`
	Qualification    json.RawMessage              `json:"qualification"`
	// ContextDeletion pins the evidence store and deletion signing key of
	// the hub-worker's context deletion child (ADR-205), whose logins ride in
	// the permission projection. Absent without deletion.
	ContextDeletion *ContextDeletionDeployment `json:"contextDeletion,omitempty"`
}

type CapacityControlDeployment struct {
	ClusterID    string                `json:"clusterID"`
	Namespace    WorkerObjectReference `json:"namespace"`
	Kubernetes   OwnerProviderEndpoint `json:"kubernetes"`
	Guard        OwnerDeploymentGuard  `json:"guard"`
	StatusUsers  []string              `json:"statusUsers"`
	ProbeAccount WorkerObjectReference `json:"probeAccount"`
}

type CapacityClusterDeployment struct {
	ClusterID      string                `json:"clusterID"`
	ProbeNamespace WorkerObjectReference `json:"probeNamespace"`
	ProbeAccount   WorkerObjectReference `json:"probeAccount"`
	Kubernetes     OwnerProviderEndpoint `json:"kubernetes"`
	Guard          OwnerDeploymentGuard  `json:"guard"`
	Keys           []string              `json:"keys"`
}

// Reuses the independently protected ProcessingConfiguration and accepted
// installed paths. Capacity cannot initialize or alter its privacy decisions.
type CapacityProcessingDeployment struct {
	Source WorkerObjectReference     `json:"source"`
	Guard  OwnerDeploymentGuard      `json:"guard"`
	Paths  []DownloadEnvironmentPath `json:"paths"`
	// PathTemplate, when set, adds one derived path per joined regional
	// cluster, the same paths as the hub-api's (ADR-204 decision 4).
	PathTemplate *DownloadEnvironmentPathTemplate `json:"pathTemplate,omitempty"`
}

// Only these two original credentials are projected. In particular this is
// not a shortened public hub manifest or a caller-selected purpose list.
type CapacityCredentialManifest struct {
	Format   string                         `json:"format"`
	Input    PublicRuntimeRoles             `json:"input"`
	RootUID  string                         `json:"rootUID"`
	SetupID  string                         `json:"setupID"`
	Roles    []PublicRuntimeCredentialProof `json:"roles"`
	Capacity CapacityRootSetupReceipt       `json:"capacity"`
}

func CapacityRuntimePurposes() []string {
	return []string{"capacity", "capacity-capture"}
}

func DecodeCapacityDeployment(r io.Reader) (CapacityDeployment, error) {
	return decodeClosedRPC[CapacityDeployment](r, CapacityDeploymentMaxBytes)
}
func DecodeCapacityCredentialManifest(r io.Reader) (CapacityCredentialManifest, error) {
	return decodeClosedRPC[CapacityCredentialManifest](r, CapacityCredentialManifestMaxBytes)
}
