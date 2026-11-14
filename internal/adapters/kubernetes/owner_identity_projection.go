package kubernetes

import (
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// Each call advances at most one fixed child attempt. No arbitrary object,
// callback, path or replay policy enters this administrator-only producer.
type OwnerIdentityProjection struct {
	root                                                                           *OwnerIdentityRoleRoot
	verification                                                                   OwnerIdentityRoleVerification
	input                                                                          contracts.OwnerDeployment
	provider                                                                       OwnerIdentityProviderMaterial
	setup                                                                          *providerconfig.SetupReader
	attemptedParent, attemptedCredentials, attemptedConfiguration, attemptedLaunch bool // root operation serialized
}
