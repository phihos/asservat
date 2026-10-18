package providerconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/apimachinery/pkg/util/validation"
)

// PublisherProviderPurposes are the publisher's three fixed provider roles
// (ADR-203 decision 3): audit wrap and unwrap on its own audit Transit key
// and verifier leaf signing on the worker PKI mount.
var PublisherProviderPurposes = [3]string{"audit-wrap", "audit-unwrap", "verifier-sign"}

type PublisherProviderRecipe struct {
	Profile contracts.PublisherProviderAuthentication
	Roles   [3]OwnerProviderRoleRecipe
}

// PublisherAuditKey is the publisher's own audit Transit key name; the
// publisher is the only reader of its verification audit.
func PublisherAuditKey(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-publisher-audit"
}

// publisherProviderEndpoint is the one provider holding the auth mount, the
// audit Transit key and the verifier PKI role; their endpoints must agree.
func publisherProviderEndpoint(in contracts.PublisherDeployment) (contracts.OwnerProviderEndpoint, bool) {
	a := contracts.OwnerProviderEndpoint{Endpoint: in.AuditKeys.Endpoint, Roots: in.AuditKeys.Roots}
	return a, len(a.Roots) > 0 && sameSetupEndpoint(a, contracts.OwnerProviderEndpoint{Endpoint: in.Verifier.Endpoint, Roots: in.Verifier.Roots})
}

// PublisherProviderRecipeFor derives the exact public roles for the
// publisher account in its namespace. Like the federation recipe it is pure:
// it configures no provider, issues no token and reads no secret.
func PublisherProviderRecipeFor(in contracts.PublisherDeployment, selection contracts.PublisherProviderAuthentication) (PublisherProviderRecipe, error) {
	var out PublisherProviderRecipe
	a, v := in.AuditKeys, in.Verifier
	endpoint, same := publisherProviderEndpoint(in)
	if in.Format != contracts.PublisherDeploymentFormat || !authorization.UUID(in.InstallationID) || !authorization.UUID(in.ClusterID) || !same || !validEndpoint(endpoint.Endpoint) ||
		selection.Namespace != in.Namespace || !authorization.UUID(selection.Namespace.UID) || len(validation.IsDNS1123Label(selection.Namespace.Name)) != 0 ||
		selection.ServiceAccount.Name != contracts.PublisherName(in.InstallationID) || !authorization.UUID(selection.ServiceAccount.UID) || selection.Namespace.UID == selection.ServiceAccount.UID ||
		!providerName.MatchString(selection.AuthMount) || selection.AuthMount == "token" || !providerName.MatchString(selection.AuthMountAccessor) ||
		!providerName.MatchString(a.Mount) || a.Key != PublisherAuditKey(in.InstallationID) || !providerName.MatchString(v.PKIMount) || v.Role != contracts.PublisherVerifierRole(in.InstallationID) || a.Mount == v.PKIMount {
		return out, cfg.ErrInvalid
	}
	out.Profile = contracts.PublisherProviderAuthentication{Format: contracts.PublisherProviderAuthenticationFormat, AuthMount: selection.AuthMount, AuthMountAccessor: selection.AuthMountAccessor,
		Namespace: selection.Namespace, ServiceAccount: selection.ServiceAccount}
	scope, err := ownerProviderCanonical(struct {
		Format         string                          `json:"format"`
		InstallationID string                          `json:"installationID"`
		ClusterID      string                          `json:"clusterID"`
		Namespace      contracts.WorkerObjectReference `json:"namespace"`
		ServiceAccount contracts.WorkerObjectReference `json:"serviceAccount"`
	}{"asservat-publisher-provider-name/v1", in.InstallationID, in.ClusterID, selection.Namespace, selection.ServiceAccount})
	if err != nil {
		return PublisherProviderRecipe{}, err
	}
	digest := sha256.Sum256(scope)
	prefix := "asservat-publisher-" + hex.EncodeToString(digest[:]) + "-"
	paths := [3]string{a.Mount + "/encrypt/" + a.Key, a.Mount + "/decrypt/" + a.Key, v.PKIMount + "/sign/" + v.Role}
	for i, purpose := range PublisherProviderPurposes {
		name := prefix + purpose
		role := OwnerKubernetesAuthRole{Accounts: []string{selection.ServiceAccount.Name}, Namespaces: []string{selection.Namespace.Name},
			Audience: contracts.PublisherProviderAudience(in.InstallationID, in.ClusterID), AliasSource: "serviceaccount_uid",
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
			return PublisherProviderRecipe{}, e
		}
		p, e := ownerProviderCanonical(acl)
		if e != nil {
			return PublisherProviderRecipe{}, e
		}
		out.Roles[i] = OwnerProviderRoleRecipe{Purpose: purpose, Name: name, Role: r, Policy: p}
	}
	// The profile's digest is empty in its own preimage; the provider
	// endpoint, its roots and every path are bound with the generated roles.
	raw, err := ownerProviderCanonical(struct {
		Format         string                                    `json:"format"`
		InstallationID string                                    `json:"installationID"`
		ClusterID      string                                    `json:"clusterID"`
		Provider       contracts.OwnerProviderEndpoint           `json:"provider"`
		AuditMount     string                                    `json:"auditMount"`
		AuditKey       string                                    `json:"auditKey"`
		PKIMount       string                                    `json:"pkiMount"`
		VerifierRole   string                                    `json:"verifierRole"`
		Profile        contracts.PublisherProviderAuthentication `json:"profile"`
		Roles          [3]OwnerProviderRoleRecipe                `json:"roles"`
	}{"asservat-publisher-provider-recipe/v1", in.InstallationID, in.ClusterID, endpoint, a.Mount, a.Key, v.PKIMount, v.Role, out.Profile, out.Roles})
	if err != nil {
		return PublisherProviderRecipe{}, err
	}
	d := sha256.Sum256(raw)
	out.Profile.RecipeSHA256 = hex.EncodeToString(d[:])
	return out, nil
}

// ValidatePublisherProviderAuthentication recomputes the exact recipe; it is
// binding validation only, not proof that a provider installed it.
func ValidatePublisherProviderAuthentication(in contracts.PublisherDeployment, p contracts.PublisherProviderAuthentication, _ time.Time) error {
	if p.Format != contracts.PublisherProviderAuthenticationFormat {
		return cfg.ErrInvalid
	}
	recipe, err := PublisherProviderRecipeFor(in, p)
	if err != nil || recipe.Profile != p {
		return cfg.ErrInvalid
	}
	return nil
}
