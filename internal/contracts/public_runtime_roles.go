package contracts

import (
	"errors"
	"io"
	"time"
)

const PublicRuntimeRolesFormat = "asservat-public-runtime-roles/v1"
const PublicRuntimeRoleStateFormat = "asservat-public-runtime-role-state/v1"
const PublicRuntimeRoleMaxBytes = 48 << 10
const PublicRuntimeCredentialManifestFormat = "asservat-public-runtime-credentials/v1"
const PublicRuntimeCredentialManifestFile = "public-roles.json"
const PublicRuntimeCredentialManifestMaxBytes = 32 << 10

// ErrPublicRuntimeLayout refuses unsupported retained development state without
// adopting, rewriting or removing it.
var ErrPublicRuntimeLayout = errors.New("unsupported development SQL credential layout; preserve retained state; recreate only a disposable development installation")

// The role ceiling is installation-wide. Most credentials have one connection
// per process; the ordinary hub credential has twenty aggregate connections.
// One extra slot verifies installation.
const PublicRuntimeHubOrdinaryConnections = 18
const PublicRuntimeHubResolutionConnections = 2
const PublicRuntimeHubConnections = PublicRuntimeHubOrdinaryConnections + PublicRuntimeHubResolutionConnections
const PublicRuntimeRetainedHubProcesses = 4
const PublicRuntimeRoleConnections = PublicRuntimeRetainedHubProcesses + 1

// Fixed product purposes; returned copies cannot mutate the installed inventory.
// The source-stage inventory currently covers identity and retained reads; no installed path
// can be enabled until the entire public graph and role layout are qualified.
func PublicRuntimeRolePurposes() []string {
	out := append(PublicRuntimeHubRolePurposes(), "browser-settings")
	out = append(out, PublicRuntimeCaptureCleanupPurposes()...)
	out = append(out, PublicRuntimeFederationPurposes()...)
	out = append(out, PublicRuntimePublisherPurposes()...)
	out = append(out, PublicRuntimeConnectorMaintenancePurposes()...)
	out = append(out, "capacity", "capacity-capture")
	out = append(out, PublicRuntimePermissionPurposes()...)
	out = append(out, PublicRuntimeRetentionPurposes()...)
	out = append(out, PublicRuntimeWorkerConfigurationPurposes()...)
	out = append(out, PublicRuntimeContextDeletionPurposes()...)
	return append(out, PublicRuntimeKeyServicePurposes()...)
}

// PermissionProjectionPurposes are the logins of the permission projection,
// in order: the permission stream's, then, with a retention section
// (ADR-195), the retention source's, then, with a worker configuration
// section (ADR-204), the worker configuration acceptance logins, then, with a
// context deletion section (ADR-205), the deletion logins, then, with a
// browser section (ADR-210), the browser settings login.
func PermissionProjectionPurposes(retention, workerConfiguration, contextDeletion, browser bool) []string {
	out := PublicRuntimePermissionPurposes()
	if retention {
		out = append(out, PublicRuntimeRetentionPurposes()...)
	}
	if workerConfiguration {
		out = append(out, PublicRuntimeWorkerConfigurationPurposes()...)
	}
	if contextDeletion {
		out = append(out, PublicRuntimeContextDeletionPurposes()...)
	}
	if browser {
		out = append(out, "browser-settings")
	}
	return out
}

// PublicRuntimeWorkerConfigurationPurposes are the hub-worker's download
// worker configuration logins (ADR-204 decision 7, ADR-070): the observer,
// which stages accepted revisions, and the separate audit acknowledgement.
// Like the permission logins, they never enter the hub projection.
func PublicRuntimeWorkerConfigurationPurposes() []string {
	return []string{"worker-config-observe", "worker-config-audit"}
}

// PublicRuntimeContextDeletionPurposes are the hub-worker's positive context
// deletion logins (ADR-205 decision 2, ADR-111), in order: the cleaner, which
// claims and records the purge, the separate audit acknowledgement and the
// finalizer, which releases the storage charge. Like the permission logins,
// they never enter the hub projection.
func PublicRuntimeContextDeletionPurposes() []string {
	return []string{"context-cleanup", "context-cleanup-audit", "context-cleanup-finalize"}
}

// PublicRuntimeRetentionPurposes are the hub-worker's retention source logins
// (ADR-195): the reconciler, checkpoint audit acknowledgement, catch-up and
// lifecycle decision audit. Like the permission logins, they never enter the
// hub projection.
func PublicRuntimeRetentionPurposes() []string {
	return []string{"retention-source", "retention-source-audit", "retention-catchup", "retention-lifecycle-audit"}
}

// PublicRuntimePermissionPurposes are the hub-worker's permission stream
// logins (ADR-189): acceptance and authority audit acknowledgement. Like
// capacity, they never enter the hub projection.
func PublicRuntimePermissionPurposes() []string {
	return []string{"permission-accept", "permission-audit"}
}

// This projection list is deliberately independent of the installer inventory.
// Reconciler credentials must never enter the hub merely because the installer
// learns how to create another fixed purpose.
func PublicRuntimeHubRolePurposes() []string {
	return []string{"hub-runtime", "capture-intent-read", "worker-config-read", "capacity-profile-read", "capture-admit", "capture-journal", "capture-ack"}
}

// PublicRuntimeHubSharedDuties are typed adapter duties sharing one credential,
// not additional role identities, projection files or pools (ADR-222).
func PublicRuntimeHubSharedDuties() []string {
	return []string{"identity-read", "browser-session", "hub-metadata-read", "download-source", "download-plan", "audit-normal-journal", "audit-normal-ack", "audit-resolution-journal", "audit-resolution-ack", "capture-preview", "capture-resolution", "api-execution", "download-session", "download-audit", "download-worker", "download-worker-audit", "download-worker-identity", "worker-enrollment", "worker-enrollment-audit", "worker-enrollment-activate", "native-owner", "download-key-bind", "native-key-bind", "download-stop", "download-stop-writer", "download-stop-ack", "fleet-bootstrap-reserve", "fleet-bootstrap-record", "fleet-bootstrap-audit", "fleet-bootstrap-activate", "regional-capacity", "processing-decision", "policy-automation"}
}

// Permanent role identities are not positions in a configurable or growing
// slice. Reserved reconciler slots 70/71 are unavailable until their exact
// product grants and separate projection have been implemented and qualified.
func PublicRuntimeRoleOrdinal(purpose string) (int, bool) {
	switch purpose {
	case "browser-settings":
		return 1, true
	case "capture-intent-read":
		return 16, true
	case "worker-config-read":
		return 20, true
	case "capacity-profile-read":
		return 34, true
	case "capture-admit":
		return 40, true
	case "capture-journal":
		return 41, true
	case "capture-ack":
		return 42, true
	case "capture-cleanup":
		return 43, true
	case "capture-verifier":
		return 44, true
	case "capture-finalizer":
		return 45, true
	case "connector-source":
		return 48, true
	case "connector-journal":
		return 49, true
	case "connector-ack":
		return 50, true
	case "connector-read":
		return 51, true
	case "cluster-credential":
		return 52, true
	case "connector-cleanup":
		return 53, true
	case "connector-verifier":
		return 54, true
	case "connector-finalizer":
		return 55, true
	case "connector-owner-read":
		return 56, true
	case "publication-gate":
		return 24, true
	case "context-verify":
		return 25, true
	case "context-verification-audit":
		return 26, true
	case "context-publish":
		return 27, true
	case "publisher-identity-read":
		return 65, true
	case "publisher-retention-read":
		return 66, true
	case "capacity":
		return 70, true
	case "capacity-capture":
		return 71, true
	case "permission-accept":
		return 72, true
	case "permission-audit":
		return 73, true
	case "retention-source":
		return 78, true
	case "retention-source-audit":
		return 79, true
	case "retention-catchup":
		return 80, true
	case "retention-lifecycle-audit":
		return 81, true
	// ADR-198: the installed key service's logins.
	case "key-configuration":
		return 82, true
	case "key-wrap":
		return 83, true
	case "key-verify":
		return 84, true
	// ADR-204: the hub-worker's worker configuration acceptance and the key
	// service's acquisition unwraps.
	case "worker-config-observe":
		return 86, true
	case "worker-config-audit":
		return 87, true
	case "key-acquisition":
		return 88, true
	// ADR-205: the hub-worker's positive context deletion.
	case "context-cleanup":
		return 89, true
	case "context-cleanup-audit":
		return 90, true
	case "context-cleanup-finalize":
		return 91, true
	// ADR-210: the hub-api's privacy-operator processing decisions.
	// Former metadata-reader ordinals 10-15 and 18 are not reused.
	// Former execution-facet ordinals 21-23 are not reused.
	case "hub-runtime":
		return 95, true
	default:
		return 0, false
	}
}

// Original non-secret SQL role-comment shape. Keep its established field names
// and encoding: exposing the typed provenance does not rewrite any old role.
// Current verification still requires the original protected manifest and the
// actual authenticated login, OID, exact ACL and immutable comment.
type PublicRuntimeRoleProvenance struct {
	Format, InstallationID, InitialClaimID, OwnerConfigurationUID, RootUID, SetupID, Purpose, LayoutDigest, OperationID string
	DatabaseOID                                                                                                         uint32
	PostmasterAt, ClaimedAt, Until                                                                                      time.Time
}

// Generated private installation input. Runtime receives only the resulting
// per-purpose credentials, never this document or the SQL administrator login.
// InitialClaimID identifies the original positively audited SQL activation.
type PublicRuntimeRoles struct {
	Format                string                     `json:"format"`
	InstallationID        string                     `json:"installationID"`
	InitialClaimID        string                     `json:"initialClaimID"`
	ClusterID             string                     `json:"clusterID"`
	OwnerConfigurationUID string                     `json:"ownerConfigurationUID"`
	Namespace             WorkerObjectReference      `json:"namespace"`
	LayoutDigest          string                     `json:"layoutDigest"`
	Worker                PublicRuntimeWorkerBinding `json:"worker,omitzero"`
}

type PublicRuntimeRoleState struct {
	Format      string                        `json:"format"`
	Input       PublicRuntimeRoles            `json:"input"`
	OperationID string                        `json:"operationID"`
	CreatedAt   time.Time                     `json:"createdAt"`
	Until       time.Time                     `json:"until"`
	MAC         PublicAuditKeyMaterial        `json:"mac"`
	Roles       []PublicRuntimeRoleMaterial   `json:"roles"`
	Projection  *PublicRuntimeProjectionClaim `json:"projection,omitempty"`
	// ADR-193: the federation's immutable SQL and audit-key projection.
	FederationProjection *PublicRuntimeProjectionClaim `json:"federationProjection,omitempty"`
	// ADR-198: the key service's immutable SQL projection.
	KeyServiceProjection *PublicRuntimeProjectionClaim `json:"keyServiceProjection,omitempty"`
	// ADR-203: the publisher's immutable SQL projection.
	PublisherProjection *PublicRuntimeProjectionClaim `json:"publisherProjection,omitempty"`
	CapacitySetup       *CapacityRootSetupClaim       `json:"capacitySetup,omitempty"`
}

// One original create claim for the separate immutable runtime projection.
// SecretUID is recorded only after exact independent readback. A missing Secret
// after a spent claim never permits a second CREATE or a replacement password.
type PublicRuntimeProjectionClaim struct {
	OperationID string    `json:"operationID"`
	ClaimedAt   time.Time `json:"claimedAt"`
	Until       time.Time `json:"until"`
	SecretUID   string    `json:"secretUID,omitempty"`
}

type PublicRuntimeRoleMaterial struct {
	Purpose  string                    `json:"purpose"`
	Password string                    `json:"password"`
	Claim    *PublicRuntimeRoleClaim   `json:"claim,omitempty"`
	Receipt  *PublicRuntimeRoleReceipt `json:"receipt,omitempty"`
}

type PublicRuntimeRoleClaim struct {
	OperationID  string    `json:"operationID"`
	ClaimedAt    time.Time `json:"claimedAt"`
	Until        time.Time `json:"until"`
	DatabaseOID  uint32    `json:"databaseOID"`
	PostmasterAt time.Time `json:"postmasterAt"`
}

type PublicRuntimeRoleReceipt struct {
	RoleName     string `json:"roleName"`
	RoleOID      uint32 `json:"roleOID"`
	LayoutDigest string `json:"layoutDigest"`
}

// UID and ResourceVersion are the actual protected Secret metadata. They are
// never invented before CREATE or an independently checked readback.
type PublicRuntimeRoleSnapshot struct {
	State                  PublicRuntimeRoleState
	UID, ResourceVersion   string
	ObservedAt, ValidUntil time.Time
}

// Immutable non-secret provenance accompanies the credentials in the same
// protected projection. It grants no operation/recovery authority. Startup
// compares actual SQL identities and ACLs to these retained original claims.
type PublicRuntimeCredentialManifest struct {
	Format  string                         `json:"format"`
	Input   PublicRuntimeRoles             `json:"input"`
	RootUID string                         `json:"rootUID"`
	SetupID string                         `json:"setupID"`
	Roles   []PublicRuntimeCredentialProof `json:"roles"`
}
type PublicRuntimeCredentialProof struct {
	Purpose string                   `json:"purpose"`
	Claim   PublicRuntimeRoleClaim   `json:"claim"`
	Receipt PublicRuntimeRoleReceipt `json:"receipt"`
}

func DecodePublicRuntimeCredentialManifest(r io.Reader) (PublicRuntimeCredentialManifest, error) {
	return decodeClosedRPC[PublicRuntimeCredentialManifest](r, PublicRuntimeCredentialManifestMaxBytes)
}

func DecodePublicRuntimeRoles(r io.Reader) (PublicRuntimeRoles, error) {
	return decodeClosedRPC[PublicRuntimeRoles](r, 8192)
}
func DecodePublicRuntimeRoleState(r io.Reader) (PublicRuntimeRoleState, error) {
	return decodeClosedRPC[PublicRuntimeRoleState](r, PublicRuntimeRoleMaxBytes)
}
func (PublicRuntimeRoleState) String() string      { return "protected public runtime role state" }
func (PublicRuntimeRoleState) GoString() string    { return "protected public runtime role state" }
func (PublicRuntimeRoleMaterial) String() string   { return "protected public runtime role material" }
func (PublicRuntimeRoleMaterial) GoString() string { return "protected public runtime role material" }
func (PublicRuntimeRoleSnapshot) String() string   { return "protected public runtime role snapshot" }
func (PublicRuntimeRoleSnapshot) GoString() string { return "protected public runtime role snapshot" }
