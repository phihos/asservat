package kms

import (
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// Compatibility names retain the qualified public recipe and exact bytes. The
// pure implementation is shared with protected installation validation; it has
// no HTTP client, token, provider mutation or accepted-authority side effect.
type OwnerProviderRoleRecipe = providerconfig.OwnerProviderRoleRecipe
type OwnerProviderRecipe = providerconfig.OwnerProviderRecipe
type ownerKubernetesAuthRole = providerconfig.OwnerKubernetesAuthRole

func OwnerProviderRecipeFor(in contracts.OwnerDeployment, mount, accessor string, account, auditCredentials contracts.WorkerObjectReference, now time.Time) (OwnerProviderRecipe, error) {
	recipe, err := providerconfig.OwnerProviderRecipeFor(in, mount, accessor, account, auditCredentials, now)
	if err != nil {
		return OwnerProviderRecipe{}, ErrKeyService
	}
	return recipe, nil
}
func ValidateOwnerProviderAuthentication(in contracts.OwnerDeployment, p contracts.OwnerProviderAuthentication, now time.Time) error {
	if providerconfig.ValidateOwnerProviderAuthentication(in, p, now) != nil {
		return ErrKeyService
	}
	return nil
}
