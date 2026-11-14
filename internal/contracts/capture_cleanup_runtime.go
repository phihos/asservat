package contracts

import (
	"time"
)

const CaptureCleanupDeploymentFormat = "asservat-capture-cleanup-deployment/v2"
const CaptureCleanupDeploymentMaxBytes = 64 << 10

// Generated public scope for the fixed capture/normal/resolution A-HWORK
// cleanup compartment. Its single provider scope is independently pinned; an
// unmatched historical store or key cannot select another provider. It carries
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

// Selected nonexportable provider key/version and independently protected public keys. Old
// verification keys remain available for their original retained certificates;
// no key discovery, startup generation or automatic identity rotation occurs.
type CaptureCleanupSigning struct {
	Mount      string            `json:"mount"`
	Name       string            `json:"name"`
	Version    int               `json:"version"`
	KeyID      string            `json:"keyID"`
	PublicKeys map[string][]byte `json:"publicKeys"`
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
