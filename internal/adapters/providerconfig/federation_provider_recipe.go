package providerconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/apimachinery/pkg/util/validation"
)

// FederationProviderPurposes are the federation's four fixed provider roles
// (ADR-193): audit wrap and unwrap on its audit transit key, and connector
// client and server leaf signing on the connector PKI mount.
var FederationProviderPurposes = [4]string{"audit-wrap", "audit-unwrap", "client-sign", "server-sign"}

type FederationProviderRecipe struct {
	Profile contracts.FederationProviderAuthentication
	Roles   [4]OwnerProviderRoleRecipe
}

// FederationProviderRecipeFor derives the exact public roles for the
// federation account in the hub namespace. Like the owner recipe it is pure:
// it configures no provider, issues no token and reads no secret.
func FederationProviderRecipeFor(in contracts.FederationDeployment, selection contracts.FederationProviderAuthentication) (FederationProviderRecipe, error) {
	var out FederationProviderRecipe
	k := in.KeyService
	if in.Format != contracts.FederationDeploymentFormat || !authorization.UUID(in.InstallationID) || !authorization.UUID(in.ClusterID) ||
		!authorization.UUID(selection.Namespace.UID) || len(validation.IsDNS1123Label(selection.Namespace.Name)) != 0 ||
		selection.ServiceAccount.Name != contracts.FederationServiceAccountName(in.InstallationID) || !authorization.UUID(selection.ServiceAccount.UID) ||
		!authorization.UUID(selection.AuditCredentials.UID) || len(validation.IsDNS1123Subdomain(selection.AuditCredentials.Name)) != 0 ||
		selection.ServiceAccount.UID == selection.AuditCredentials.UID || selection.Namespace.UID == selection.ServiceAccount.UID || selection.Namespace.UID == selection.AuditCredentials.UID ||
		!providerName.MatchString(selection.AuthMount) || selection.AuthMount == "token" || !providerName.MatchString(selection.AuthMountAccessor) ||
		!providerName.MatchString(k.AuditMount) || !providerName.MatchString(k.AuditKey) || !providerName.MatchString(k.PKIMount) ||
		!providerName.MatchString(k.ClientRole) || !providerName.MatchString(k.ServerRole) || k.ClientRole == k.ServerRole {
		return out, cfg.ErrInvalid
	}
	out.Profile = contracts.FederationProviderAuthentication{Format: contracts.FederationProviderAuthenticationFormat, AuthMount: selection.AuthMount, AuthMountAccessor: selection.AuthMountAccessor,
		Namespace: selection.Namespace, ServiceAccount: selection.ServiceAccount, AuditCredentials: selection.AuditCredentials}
	scope, err := ownerProviderCanonical(struct {
		Format         string                          `json:"format"`
		InstallationID string                          `json:"installationID"`
		ClusterID      string                          `json:"clusterID"`
		Namespace      contracts.WorkerObjectReference `json:"namespace"`
		ServiceAccount contracts.WorkerObjectReference `json:"serviceAccount"`
	}{"asservat-federation-provider-name/v1", in.InstallationID, in.ClusterID, selection.Namespace, selection.ServiceAccount})
	if err != nil {
		return FederationProviderRecipe{}, err
	}
	digest := sha256.Sum256(scope)
	prefix := "asservat-federation-" + hex.EncodeToString(digest[:]) + "-"
	paths := [4]string{k.AuditMount + "/encrypt/" + k.AuditKey, k.AuditMount + "/decrypt/" + k.AuditKey, k.PKIMount + "/sign/" + k.ClientRole, k.PKIMount + "/sign/" + k.ServerRole}
	for i, purpose := range FederationProviderPurposes {
		name := prefix + purpose
		role := OwnerKubernetesAuthRole{Accounts: []string{selection.ServiceAccount.Name}, Namespaces: []string{selection.Namespace.Name},
			Audience: contracts.FederationProviderAudience(in.InstallationID, in.ClusterID), AliasSource: "serviceaccount_uid",
			TTL: contracts.OwnerProviderTokenTTLSeconds, MaxTTL: contracts.OwnerProviderTokenMaxTTLSeconds, ExplicitMaxTTL: contracts.OwnerProviderTokenMaxTTLSeconds,
			Policies: []string{name}, NoDefault: true, Type: "service", BoundCIDRs: []string{}}
		acl := ownerProviderACL{Path: map[string]ownerProviderACLRule{
			"auth/token/lookup-self": {Capabilities: []string{"read"}},
			"auth/token/renew-self":  {Capabilities: []string{"update"}},
			"auth/token/revoke-self": {Capabilities: []string{"update"}},
			paths[i]:                 {Capabilities: []string{"update"}},
		}}
		r, e := ownerProviderCanonical(role)
		if e != nil {
			return FederationProviderRecipe{}, e
		}
		p, e := ownerProviderCanonical(acl)
		if e != nil {
			return FederationProviderRecipe{}, e
		}
		out.Roles[i] = OwnerProviderRoleRecipe{Purpose: purpose, Name: name, Role: r, Policy: p}
	}
	// The profile's digest is empty in its own preimage; the key service
	// endpoint, roots and paths are bound with the generated roles.
	raw, err := ownerProviderCanonical(struct {
		Format         string                                     `json:"format"`
		InstallationID string                                     `json:"installationID"`
		ClusterID      string                                     `json:"clusterID"`
		KeyService     contracts.FederationKeyService             `json:"keyService"`
		Profile        contracts.FederationProviderAuthentication `json:"profile"`
		Roles          [4]OwnerProviderRoleRecipe                 `json:"roles"`
	}{"asservat-federation-provider-recipe/v1", in.InstallationID, in.ClusterID, in.KeyService, out.Profile, out.Roles})
	if err != nil {
		return FederationProviderRecipe{}, err
	}
	d := sha256.Sum256(raw)
	out.Profile.RecipeSHA256 = hex.EncodeToString(d[:])
	return out, nil
}

// ValidateFederationProviderAuthentication recomputes the exact recipe; it
// is binding validation only, not proof that a provider installed it.
func ValidateFederationProviderAuthentication(in contracts.FederationDeployment, p contracts.FederationProviderAuthentication, _ time.Time) error {
	if p.Format != contracts.FederationProviderAuthenticationFormat {
		return cfg.ErrInvalid
	}
	recipe, err := FederationProviderRecipeFor(in, p)
	if err != nil || recipe.Profile != p {
		return cfg.ErrInvalid
	}
	return nil
}
