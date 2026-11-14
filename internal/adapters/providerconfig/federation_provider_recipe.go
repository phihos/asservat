package providerconfig

import (
	"asservat.local/asservat/internal/contracts"
)

// FederationProviderPurposes are the federation's four fixed provider roles
// (ADR-193): audit wrap and unwrap on its audit transit key, and connector
// client and server leaf signing on the connector PKI mount.
var FederationProviderPurposes = [4]string{"audit-wrap", "audit-unwrap", "client-sign", "server-sign"}

type FederationProviderRecipe struct {
	Profile contracts.FederationProviderAuthentication
	Roles   [4]OwnerProviderRoleRecipe
}
