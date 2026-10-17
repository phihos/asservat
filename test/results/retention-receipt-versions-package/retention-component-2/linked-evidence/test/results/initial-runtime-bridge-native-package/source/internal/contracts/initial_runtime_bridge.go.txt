package contracts

import (
	"io"
	"time"
)

const InitialRuntimeBridgeStateFormat = "asservat-initial-runtime-bridge/v1"
const InitialRuntimeBridgeMaxBytes = 16 << 10

// This private installation journal contains only original public identities,
// two fixed native policy operations and their observed receipts. It cannot
// confer activation, recovery, source acceptance or runtime readiness.
type InitialRuntimeBridgeState struct {
	Format        string                          `json:"format"`
	BindingDigest string                          `json:"bindingDigest"`
	SetupID       string                          `json:"setupID"`
	CreatedAt     time.Time                       `json:"createdAt"`
	Until         time.Time                       `json:"until"`
	Probe         *InitialRuntimeBridgeTransition `json:"probe,omitempty"`
	Retained      *InitialRuntimeBridgeTransition `json:"retained,omitempty"`
}
type InitialRuntimeBridgeTransition struct {
	OperationID         string                       `json:"operationID"`
	FromResourceVersion string                       `json:"fromResourceVersion"`
	FromGeneration      int64                        `json:"fromGeneration"`
	ClaimedAt           time.Time                    `json:"claimedAt"`
	Until               time.Time                    `json:"until"`
	Receipt             *InitialRuntimeBridgeReceipt `json:"receipt,omitempty"`
}
type InitialRuntimeBridgeReceipt struct {
	PolicyUID       string `json:"policyUID"`
	ResourceVersion string `json:"resourceVersion"`
	Generation      int64  `json:"generation"`
	SpecDigest      string `json:"specDigest"`
}
type InitialRuntimeBridgeSnapshot struct {
	State                InitialRuntimeBridgeState
	UID, ResourceVersion string
	ValidUntil           time.Time
}

func DecodeInitialRuntimeBridgeState(r io.Reader) (InitialRuntimeBridgeState, error) {
	return decodeClosedRPC[InitialRuntimeBridgeState](r, InitialRuntimeBridgeMaxBytes)
}
