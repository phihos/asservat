package contracts

import (
	"strings"
	"time"
)

// CapacityRuntimeProjectionName is derived only from a separately validated
// original installation UUID. It does not validate or confer installation
// authority; callers still verify the original journal and setup receipts.
func CapacityRuntimeProjectionName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-capacity"
}

// This optional claim belongs to the original runtime-resource journal, whose
// immutable thirty-minute interval also bounds the claim. It is not stored in
// the later role root and cannot replace that root's exact setup provenance.
// PublicDigest covers generated public configuration/provenance only, never
// passwords, tokens, seed bytes or a private-payload digest.
type CapacityRuntimeProjectionClaim struct {
	OperationID  string                            `json:"operationID"`
	PublicDigest string                            `json:"publicDigest"`
	Setup        CapacityRootSetupReceipt          `json:"setup"`
	ClaimedAt    time.Time                         `json:"claimedAt"`
	Until        time.Time                         `json:"until"`
	Receipt      *CapacityRuntimeProjectionReceipt `json:"receipt,omitempty"`
}

// Receipt is the positively verified original immutable Secret identity. A
// Secret created before receipt persistence remains pending. Neither this
// receipt nor the Secret grants source/recovery/capacity readiness by itself.
type CapacityRuntimeProjectionReceipt struct {
	Secret          WorkerObjectReference `json:"secret"`
	ResourceVersion string                `json:"resourceVersion"`
	ObservedAt      time.Time             `json:"observedAt"`
}
