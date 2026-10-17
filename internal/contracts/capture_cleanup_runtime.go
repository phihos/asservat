package contracts

import (
	"io"
	"time"
)

const CaptureCleanupDeploymentFormat = "asservat-capture-cleanup-deployment/v1"
const CaptureCleanupManifestFormat = "asservat-capture-cleanup-credentials/v1"
const CaptureCleanupDeploymentMaxBytes = 64 << 10

// Generated public scope for the fixed A-HWORK cleanup compartment. It carries
// no current policy or replacement lifetime: each selected row retains its own
// original independently acknowledged lifecycle and current recovery checks.
type CaptureCleanupDeployment struct {
	Format         string                  `json:"format"`
	InstallationID string                  `json:"installationID"`
	RootID         string                  `json:"rootID"`
	StoreID        string                  `json:"storeID"`
	RoleRootUID    string                  `json:"roleRootUID"`
	RoleSetupID    string                  `json:"roleSetupID"`
	Postgres       OwnerPostgresEndpoint   `json:"postgres"`
	AuditStore     OwnerAuditStore         `json:"auditStore"`
	KeyService     ConfigurationKeyService `json:"keyService"`
	Signing        CaptureCleanupSigning   `json:"signing"`
}

// Dedicated provider key/version and independently protected public keys. Old
// verification keys remain available for their original retained certificates;
// no key discovery, startup generation or automatic identity rotation occurs.
type CaptureCleanupSigning struct {
	Mount      string            `json:"mount"`
	Name       string            `json:"name"`
	Version    int               `json:"version"`
	KeyID      string            `json:"keyID"`
	PublicKeys map[string][]byte `json:"publicKeys"`
}

type CaptureCleanupCredentialManifest struct {
	Format       string                         `json:"format"`
	Input        PublicRuntimeRoles             `json:"input"`
	RootUID      string                         `json:"rootUID"`
	SetupID      string                         `json:"setupID"`
	Roles        []PublicRuntimeCredentialProof `json:"roles"`
	CaptureSetup CapacityRootSetupReceipt       `json:"captureSetup"`
}

// This distinct fixed claim belongs to the original public resource journal.
// PublicDigest covers only public configuration and original role provenance,
// never a password/token/private payload or its hash. Neither a claim nor its
// positive Secret receipt substitutes for current guard/setup/recovery checks.
type CaptureCleanupProjectionClaim struct {
	OperationID  string                           `json:"operationID"`
	PublicDigest string                           `json:"publicDigest"`
	Setup        CapacityRootSetupReceipt         `json:"setup"`
	ClaimedAt    time.Time                        `json:"claimedAt"`
	Until        time.Time                        `json:"until"`
	Receipt      *CaptureCleanupProjectionReceipt `json:"receipt,omitempty"`
}

type CaptureCleanupProjectionReceipt struct {
	Secret          WorkerObjectReference `json:"secret"`
	ResourceVersion string                `json:"resourceVersion"`
	ObservedAt      time.Time             `json:"observedAt"`
}

func DecodeCaptureCleanupDeployment(r io.Reader) (CaptureCleanupDeployment, error) {
	return decodeClosedRPC[CaptureCleanupDeployment](r, CaptureCleanupDeploymentMaxBytes)
}
func DecodeCaptureCleanupCredentialManifest(r io.Reader) (CaptureCleanupCredentialManifest, error) {
	return decodeClosedRPC[CaptureCleanupCredentialManifest](r, PublicRuntimeCredentialManifestMaxBytes)
}
