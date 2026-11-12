package contracts

import (
	"io"
	"time"
)

// InitialBootstrapProviderInput is the operator's private source fragment,
// before selected builtin providers fill their own fields. It uses the existing
// material format and field names; it cannot supply installer setup identities,
// pending setup tokens or registry credentials. Retained Material is stricter.
type InitialBootstrapProviderInput struct {
	Format          string                  `json:"format"`
	IssuerToken     string                  `json:"issuerToken,omitempty"`
	Storage         *OwnerStorageCredential `json:"storage,omitempty"`
	StorageUseUntil time.Time               `json:"storageUseUntil,omitzero"`
}

func DecodeInitialBootstrapProviderInput(r io.Reader) (InitialBootstrapProviderInput, error) {
	return decodeClosedRPC[InitialBootstrapProviderInput](r, InitialProviderMaterialMaxBytes)
}
func (InitialBootstrapProviderInput) String() string   { return "protected bootstrap provider input" }
func (InitialBootstrapProviderInput) GoString() string { return "protected bootstrap provider input" }
