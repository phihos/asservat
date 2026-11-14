package providerconfig

import (
	"encoding/json"
)

// FederationProviderSetup is the federation's part of the phase-3 provider
// artifact (ADR-193): its four authentication roles and policies, the two
// installation-wide connector PKI roles and its create-only audit transit
// key. The operator applies it with the owner's roles in one step.
type FederationProviderSetup struct {
	Authentication FederationProviderRecipe `json:"authentication"`
	PKIRoles       [2]OwnerPKIRoleRecipe    `json:"pkiRoles"`
	TransitKey     json.RawMessage          `json:"transitKey"`
}
