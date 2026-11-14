package kubernetes

import (
	"context"

	"asservat.local/asservat/internal/contracts"
)

// Implemented by the fixed administrator SQL producer. It performs current
// recovery/role verification only, never creation or provider effects.
type OwnerIdentityRoleVerification interface {
	VerifyOwnerIdentityRoles(context.Context) (contracts.OwnerIdentityRoleSnapshot, error)
}

// These are independently provisioned credentials for the fixed owner-audit
// and purpose-separated PKI recipes. Projection does not issue provider tokens
// or validate their capabilities by interpreting token contents.
type OwnerIdentityProviderMaterial struct {
	Audit                                          contracts.OwnerStorageCredential
	WrapToken, OpenToken, ServerToken, ClientToken string
}
