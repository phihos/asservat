package providerconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// OwnerFleetProviderPurpose is the hub-api's bootstrap credential channel
// (ADR-193 step 4): KV-v2 create and read on the installation's prefix only.
const OwnerFleetProviderPurpose = "bootstrap-channel"

// OwnerFleetProviderRecipeFor derives the one fleet provider role from the
// installed owner input and its accepted identity profile. It is pure; the
// phase-3 artifact installs it and Fleet.ProviderRecipeSHA256 pins its digest.
func OwnerFleetProviderRecipeFor(in contracts.OwnerDeployment, profile contracts.OwnerProviderAuthentication, now time.Time) (OwnerProviderRoleRecipe, string, error) {
	var role OwnerProviderRoleRecipe
	if in.Public == nil || in.Public.Fleet == nil || !providerName.MatchString(in.Public.Fleet.ChannelMount) {
		return role, "", cfg.ErrInvalid
	}
	identity, err := OwnerProviderRecipeFor(in, profile.AuthMount, profile.AuthMountAccessor, profile.ServiceAccount, profile.AuditCredentials, now)
	if err != nil || identity.Profile.RecipeSHA256 != profile.RecipeSHA256 {
		return role, "", cfg.ErrInvalid
	}
	scope, err := ownerProviderCanonical(struct {
		Format         string                          `json:"format"`
		InstallationID string                          `json:"installationID"`
		ClusterID      string                          `json:"clusterID"`
		Namespace      contracts.WorkerObjectReference `json:"namespace"`
		ServiceAccount contracts.WorkerObjectReference `json:"serviceAccount"`
	}{"asservat-owner-fleet-provider-name/v1", in.InstallationID, in.ClusterID, in.Namespace, profile.ServiceAccount})
	if err != nil {
		return role, "", err
	}
	nameDigest := sha256.Sum256(scope)
	name := "asservat-owner-fleet-" + hex.EncodeToString(nameDigest[:8]) + "-" + OwnerFleetProviderPurpose
	auth := OwnerKubernetesAuthRole{Accounts: []string{profile.ServiceAccount.Name}, Namespaces: []string{in.Namespace.Name}, Audience: contracts.OwnerProviderAudience(in.InstallationID, in.ClusterID), AliasSource: "serviceaccount_uid", TTL: contracts.OwnerProviderTokenTTLSeconds, MaxTTL: contracts.OwnerProviderTokenMaxTTLSeconds, ExplicitMaxTTL: contracts.OwnerProviderTokenMaxTTLSeconds, Policies: []string{name}, NoDefault: true, Type: "service", BoundCIDRs: []string{}}
	acl := ownerProviderACL{Path: map[string]ownerProviderACLRule{
		"auth/token/lookup-self": {Capabilities: []string{"read"}},
		"auth/token/renew-self":  {Capabilities: []string{"update"}},
		"auth/token/revoke-self": {Capabilities: []string{"update"}},
		// Create-only records under this installation; no update, list,
		// metadata, delete or destroy (the bootstrap-channel contract).
		in.Public.Fleet.ChannelMount + "/data/" + contracts.OwnerFleetChannelPrefix + "/" + in.InstallationID + "/*": {Capabilities: []string{"create", "read"}},
	}}
	if role.Role, err = ownerProviderCanonical(auth); err != nil {
		return role, "", err
	}
	if role.Policy, err = ownerProviderCanonical(acl); err != nil {
		return role, "", err
	}
	role.Purpose, role.Name = OwnerFleetProviderPurpose, name
	raw, err := ownerProviderCanonical(struct {
		Format     string                    `json:"format"`
		Identity   string                    `json:"identityRecipeSHA256"`
		KeyService contracts.OwnerKeyService `json:"keyService"`
		Mount      string                    `json:"channelMount"`
		Profile    string                    `json:"deliveryProfile"`
		Role       OwnerProviderRoleRecipe   `json:"role"`
	}{"asservat-owner-fleet-provider-recipe/v1", profile.RecipeSHA256, in.KeyService, in.Public.Fleet.ChannelMount, in.Public.Fleet.DeliveryProfile, role})
	if err != nil {
		return role, "", err
	}
	d := sha256.Sum256(raw)
	return role, hex.EncodeToString(d[:]), nil
}

// ValidateOwnerFleetProviderRecipe recomputes the fleet recipe; binding
// validation only, not proof that a provider installed it.
func ValidateOwnerFleetProviderRecipe(in contracts.OwnerDeployment, profile contracts.OwnerProviderAuthentication, now time.Time) error {
	if in.Public == nil || in.Public.Fleet == nil || len(in.Public.Fleet.ProviderRecipeSHA256) != 64 {
		return cfg.ErrInvalid
	}
	_, digest, err := OwnerFleetProviderRecipeFor(in, profile, now)
	if err != nil || digest != in.Public.Fleet.ProviderRecipeSHA256 {
		return cfg.ErrInvalid
	}
	return nil
}
