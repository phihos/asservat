package contracts

import (
	"encoding/json"
	"io"
	"time"
)

const CapacityRootSetupFormat = "asservat-capacity-root-setup/v1"
const CapacityRootSetupFile = "capacity-root-setup.json"
const CapacityRootSetupMaxBytes = 144 << 10

// This list is a required subset of original, completed role receipts. It
// neither adds purposes to the creatable inventory nor chooses SQL privileges.
func CapacitySetupRolePurposes() []string {
	return []string{"capacity", "capacity-capture", "capacity-profile-read", "capture-admit", "capture-journal", "capture-ack", "capture-cleanup", "capture-verifier", "capture-finalizer", "capture-intent-read"}
}

// Generated, protected administrator input. Qualification is the closed C-07
// backend/history measurement accepted by the installer, never a CRD status
// flag. Its complete bytes are bound before claiming the fixed SQL effect.
// This file and the administrator credential never enter a runtime projection.
type CapacityRootSetup struct {
	Format              string          `json:"format"`
	InstallationID      string          `json:"installationID"`
	InitialClaimID      string          `json:"initialClaimID"`
	PermissionRootID    string          `json:"permissionRootID"`
	RoleRootUID         string          `json:"roleRootUID"`
	RoleSetupID         string          `json:"roleSetupID"`
	ControlClusterID    string          `json:"controlClusterID"`
	ControlNamespaceUID string          `json:"controlNamespaceUID"`
	SourceGuardDigest   string          `json:"sourceGuardDigest"`
	AccountVersion      string          `json:"accountVersion"`
	Qualification       json.RawMessage `json:"qualification"`
}

// One fixed claim, retained on the original role Secret. Only a positively
// acknowledged first CAS may enter SQL creation. Receipt is set only after
// independent exact readback of the paired transaction under current proof.
type CapacityRootSetupClaim struct {
	OperationID      string                    `json:"operationID"`
	PermissionRootID string                    `json:"permissionRootID"`
	InputDigest      string                    `json:"inputDigest"`
	DatabaseOID      uint32                    `json:"databaseOID"`
	PostmasterAt     time.Time                 `json:"postmasterAt"`
	ClaimedAt        time.Time                 `json:"claimedAt"`
	Until            time.Time                 `json:"until"`
	Receipt          *CapacityRootSetupReceipt `json:"receipt,omitempty"`
}

// Public SQL provenance only. This is not accepted capacity, an allocation,
// recovery authority, or proof that any operational source is current.
type CapacityRootSetupReceipt struct {
	Format           string    `json:"format"`
	OperationID      string    `json:"operationID"`
	InstallationID   string    `json:"installationID"`
	InitialClaimID   string    `json:"initialClaimID"`
	PermissionRootID string    `json:"permissionRootID"`
	RoleRootUID      string    `json:"roleRootUID"`
	RoleSetupID      string    `json:"roleSetupID"`
	InputDigest      string    `json:"inputDigest"`
	DatabaseOID      uint32    `json:"databaseOID"`
	PostmasterAt     time.Time `json:"postmasterAt"`
	ClaimedAt        time.Time `json:"claimedAt"`
	Until            time.Time `json:"until"`
}

func DecodeCapacityRootSetup(r io.Reader) (CapacityRootSetup, error) {
	return decodeClosedRPC[CapacityRootSetup](r, CapacityRootSetupMaxBytes)
}
