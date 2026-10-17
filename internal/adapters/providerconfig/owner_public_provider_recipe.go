package providerconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// OwnerPublicProviderPurposes are the public layer's provider-authenticated
// purposes (ADR-182), separate from the four identity purposes.
var OwnerPublicProviderPurposes = [4]string{"browser-seal", "browser-open", "work-sign", "worker-issue"}

// OwnerPublicProviderRecipeFor derives the four public provider roles from the
// installed owner input and its accepted identity profile. Like the identity
// recipe it is pure; separate setup installs it and the owner's Public section
// pins its digest. The identity recipe digest is unchanged.
func OwnerPublicProviderRecipeFor(in contracts.OwnerDeployment, profile contracts.OwnerProviderAuthentication, now time.Time) ([4]OwnerProviderRoleRecipe, string, error) {
	var roles [4]OwnerProviderRoleRecipe
	p := in.Public
	if p == nil || !providerName.MatchString(p.SessionTransit.Mount) || !providerName.MatchString(p.SessionTransit.Key) || !providerName.MatchString(p.WorkSigning.Mount) || !providerName.MatchString(p.WorkSigning.Name) || !providerName.MatchString(p.WorkerPKI.Mount) || !providerName.MatchString(p.WorkerPKI.Role) {
		return roles, "", cfg.ErrInvalid
	}
	identity, err := OwnerProviderRecipeFor(in, profile.AuthMount, profile.AuthMountAccessor, profile.ServiceAccount, profile.AuditCredentials, now)
	if err != nil || identity.Profile.RecipeSHA256 != profile.RecipeSHA256 {
		return roles, "", cfg.ErrInvalid
	}
	scope, err := ownerProviderCanonical(struct {
		Format         string                          `json:"format"`
		InstallationID string                          `json:"installationID"`
		ClusterID      string                          `json:"clusterID"`
		Namespace      contracts.WorkerObjectReference `json:"namespace"`
		ServiceAccount contracts.WorkerObjectReference `json:"serviceAccount"`
	}{"asservat-owner-public-provider-name/v1", in.InstallationID, in.ClusterID, in.Namespace, profile.ServiceAccount})
	if err != nil {
		return roles, "", err
	}
	nameDigest := sha256.Sum256(scope)
	prefix := "asservat-owner-public-" + hex.EncodeToString(nameDigest[:8]) + "-"
	audience := contracts.OwnerProviderAudience(in.InstallationID, in.ClusterID)
	paths := [4]string{p.SessionTransit.Mount + "/encrypt/" + p.SessionTransit.Key, p.SessionTransit.Mount + "/decrypt/" + p.SessionTransit.Key, p.WorkSigning.Mount + "/sign/" + p.WorkSigning.Name, p.WorkerPKI.Mount + "/sign/" + p.WorkerPKI.Role}
	for i, purpose := range OwnerPublicProviderPurposes {
		name := prefix + purpose
		role := OwnerKubernetesAuthRole{Accounts: []string{profile.ServiceAccount.Name}, Namespaces: []string{in.Namespace.Name}, Audience: audience, AliasSource: "serviceaccount_uid", TTL: contracts.OwnerProviderTokenTTLSeconds, MaxTTL: contracts.OwnerProviderTokenMaxTTLSeconds, ExplicitMaxTTL: contracts.OwnerProviderTokenMaxTTLSeconds, Policies: []string{name}, NoDefault: true, Type: "service", BoundCIDRs: []string{}}
		acl := ownerProviderACL{Path: map[string]ownerProviderACLRule{
			"auth/token/lookup-self": {Capabilities: []string{"read"}},
			"auth/token/renew-self":  {Capabilities: []string{"update"}},
			"auth/token/revoke-self": {Capabilities: []string{"update"}},
			paths[i]:                 {Capabilities: []string{"update"}},
		}}
		r, e := ownerProviderCanonical(role)
		if e != nil {
			return roles, "", e
		}
		a, e := ownerProviderCanonical(acl)
		if e != nil {
			return roles, "", e
		}
		roles[i] = OwnerProviderRoleRecipe{Purpose: purpose, Name: name, Role: r, Policy: a}
	}
	public := *p
	public.ProviderRecipeSHA256 = ""
	raw, err := ownerProviderCanonical(struct {
		Format     string                         `json:"format"`
		Identity   string                         `json:"identityRecipeSHA256"`
		KeyService contracts.OwnerKeyService      `json:"keyService"`
		Transit    contracts.OwnerPublicTransit   `json:"sessionTransit"`
		Signing    contracts.OwnerPublicSigning   `json:"workSigning"`
		PKI        contracts.OwnerPublicWorkerPKI `json:"workerPKI"`
		Roles      [4]OwnerProviderRoleRecipe     `json:"roles"`
	}{"asservat-owner-public-provider-recipe/v1", profile.RecipeSHA256, in.KeyService, public.SessionTransit, public.WorkSigning, public.WorkerPKI, roles})
	if err != nil {
		return roles, "", err
	}
	d := sha256.Sum256(raw)
	return roles, hex.EncodeToString(d[:]), nil
}

// ValidateOwnerPublicProviderRecipe recomputes the public recipe; binding
// validation only, not proof that a provider installed it.
func ValidateOwnerPublicProviderRecipe(in contracts.OwnerDeployment, profile contracts.OwnerProviderAuthentication, now time.Time) error {
	if in.Public == nil || len(in.Public.ProviderRecipeSHA256) != 64 {
		return cfg.ErrInvalid
	}
	_, digest, err := OwnerPublicProviderRecipeFor(in, profile, now)
	if err != nil || digest != in.Public.ProviderRecipeSHA256 {
		return cfg.ErrInvalid
	}
	return nil
}
