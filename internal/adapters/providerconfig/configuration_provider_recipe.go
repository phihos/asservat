package providerconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/apimachinery/pkg/util/validation"
)

type ConfigurationProviderRoleRecipe struct {
	Purpose string          `json:"purpose"`
	Name    string          `json:"name"`
	Role    json.RawMessage `json:"role"`
	Policy  json.RawMessage `json:"policy"`
}

// Two fixed effects. This pure recipe neither applies provider configuration
// nor issues credentials; the installer verifies its actual provider readback.
type ConfigurationProviderRecipe struct {
	Profile contracts.ConfigurationProviderAuthentication
	Roles   [2]ConfigurationProviderRoleRecipe
}

// ValidateConfigurationProviderSelection checks only the original public
// pre-resource selection. It never discovers a replacement Secret by name.
func ValidateConfigurationProviderSelection(installation string, p contracts.ConfigurationProviderSelection) error {
	if !authorization.UUID(installation) || !providerName.MatchString(p.AuthMount) || p.AuthMount == "token" ||
		!providerName.MatchString(p.AuthMountAccessor) || !authorization.UUID(p.AuditCredentials.UID) ||
		p.AuditCredentials.Name != "asservat-"+strings.ReplaceAll(installation, "-", "")+"-worker-providers" {
		return cfg.ErrInvalid
	}
	if w := p.WorkerConfigurationAudit; w != (contracts.OwnerPublicTransit{}) && (!providerName.MatchString(w.Mount) || w.Mount == "sys" || w.Mount == "auth" || !providerName.MatchString(w.Key)) {
		return cfg.ErrInvalid
	}
	// ADR-205: the context deletion signing key has its fixed name; the recipe
	// separately requires the configuration audit mount.
	if d := p.ContextDeletionSigning; d != (contracts.OwnerPublicTransit{}) && (!providerName.MatchString(d.Mount) || d.Mount == "sys" || d.Mount == "auth" || d.Key != contracts.ContextDeletionSigningKeyName(installation)) {
		return cfg.ErrInvalid
	}
	return nil
}

// configurationProviderSelectionOf is the selection a profile was derived from.
func configurationProviderSelectionOf(p contracts.ConfigurationProviderAuthentication) contracts.ConfigurationProviderSelection {
	return contracts.ConfigurationProviderSelection{AuthMount: p.AuthMount, AuthMountAccessor: p.AuthMountAccessor, AuditCredentials: p.AuditCredentials, WorkerConfigurationAudit: p.WorkerConfigurationAudit, ContextDeletionSigning: p.ContextDeletionSigning}
}

func ConfigurationProviderRecipeFor(in contracts.HubWorkerDeployment, selection contracts.ConfigurationProviderSelection, account contracts.WorkerObjectReference, now time.Time) (ConfigurationProviderRecipe, error) {
	var out ConfigurationProviderRecipe
	if in.Format != contracts.HubWorkerDeploymentFormat || !authorization.UUID(in.ClusterID) ||
		!authorization.UUID(in.Namespace.UID) || len(validation.IsDNS1123Label(in.Namespace.Name)) != 0 ||
		ValidateConfigurationProviderSelection(in.InstallationID, selection) != nil ||
		Validate(in.Kubernetes, in.Postgres, in.AuditStore, in.KeyService, now) != nil ||
		account.Name != "asservat-"+strings.ReplaceAll(in.InstallationID, "-", "")+"-worker" {
		return out, cfg.ErrInvalid
	}
	seen := map[string]bool{in.Namespace.UID: true}
	for _, ref := range []contracts.WorkerObjectReference{account, selection.AuditCredentials, in.FleetSource, in.OwnerSource} {
		if !authorization.UUID(ref.UID) || seen[ref.UID] || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 {
			return ConfigurationProviderRecipe{}, cfg.ErrInvalid
		}
		seen[ref.UID] = true
	}
	// The worker configuration audit key is a key of its own (ADR-070); it is
	// never the hub-worker's configuration audit key.
	worker := selection.WorkerConfigurationAudit
	if in.FleetSource.Name == in.OwnerSource.Name || worker.Mount == in.KeyService.AuditMount && worker.Key == in.KeyService.AuditKey {
		return out, cfg.ErrInvalid
	}
	// ADR-205: the context deletion signing key lives on the configuration
	// audit mount and is neither audit key.
	signing := selection.ContextDeletionSigning
	if signing != (contracts.OwnerPublicTransit{}) && (signing.Mount != in.KeyService.AuditMount || signing.Key == in.KeyService.AuditKey || signing == worker) {
		return out, cfg.ErrInvalid
	}
	out.Profile = contracts.ConfigurationProviderAuthentication{Format: contracts.ConfigurationProviderAuthenticationFormat,
		AuthMount: selection.AuthMount, AuthMountAccessor: selection.AuthMountAccessor,
		ServiceAccount: account, AuditCredentials: selection.AuditCredentials, WorkerConfigurationAudit: worker, ContextDeletionSigning: signing}
	scope, err := ownerProviderCanonical(struct {
		Format         string                          `json:"format"`
		InstallationID string                          `json:"installationID"`
		ClusterID      string                          `json:"clusterID"`
		Namespace      contracts.WorkerObjectReference `json:"namespace"`
		ServiceAccount contracts.WorkerObjectReference `json:"serviceAccount"`
	}{"asservat-configuration-provider-name/v1", in.InstallationID, in.ClusterID, in.Namespace, account})
	if err != nil {
		return ConfigurationProviderRecipe{}, err
	}
	digest := sha256.Sum256(scope)
	prefix := "asservat-configuration-" + hex.EncodeToString(digest[:]) + "-"
	purposes := [2]string{"audit-wrap", "audit-unwrap"}
	paths := [2]string{in.KeyService.AuditMount + "/encrypt/" + in.KeyService.AuditKey, in.KeyService.AuditMount + "/decrypt/" + in.KeyService.AuditKey}
	// ADR-204: the same two purposes, on the worker configuration audit key.
	var workerPaths [2]string
	if worker != (contracts.OwnerPublicTransit{}) {
		workerPaths = [2]string{worker.Mount + "/encrypt/" + worker.Key, worker.Mount + "/decrypt/" + worker.Key}
	}
	for i, purpose := range purposes {
		name := prefix + purpose
		role := OwnerKubernetesAuthRole{Accounts: []string{account.Name}, Namespaces: []string{in.Namespace.Name},
			Audience: contracts.ConfigurationProviderAudience(in.InstallationID, in.ClusterID), AliasSource: "serviceaccount_uid",
			TTL: contracts.ConfigurationProviderTokenTTLSeconds, MaxTTL: contracts.ConfigurationProviderTokenMaxTTLSeconds,
			ExplicitMaxTTL: contracts.ConfigurationProviderTokenMaxTTLSeconds, Policies: []string{name}, NoDefault: true,
			Type: "service", BoundCIDRs: []string{}}
		acl := ownerProviderACL{Path: map[string]ownerProviderACLRule{
			"auth/token/lookup-self": {Capabilities: []string{"read"}},
			"auth/token/renew-self":  {Capabilities: []string{"update"}},
			"auth/token/revoke-self": {Capabilities: []string{"update"}},
			paths[i]:                 {Capabilities: []string{"update"}},
		}}
		if workerPaths[i] != "" {
			acl.Path[workerPaths[i]] = ownerProviderACLRule{Capabilities: []string{"update"}}
		}
		// ADR-205 decision 6: only audit-wrap signs deletion records.
		if purpose == "audit-wrap" && signing != (contracts.OwnerPublicTransit{}) {
			acl.Path[signing.Mount+"/sign/"+signing.Key] = ownerProviderACLRule{Capabilities: []string{"update"}}
		}
		r, e := ownerProviderCanonical(role)
		if e != nil {
			return ConfigurationProviderRecipe{}, e
		}
		p, e := ownerProviderCanonical(acl)
		if e != nil {
			return ConfigurationProviderRecipe{}, e
		}
		out.Roles[i] = ConfigurationProviderRoleRecipe{Purpose: purpose, Name: name, Role: r, Policy: p}
	}
	// The profile's digest is empty in its own preimage. Source identity and the
	// complete original provider scope remain bound; observation times are not.
	b, err := configurationProviderRecipeBody(in, out)
	if err != nil {
		return ConfigurationProviderRecipe{}, err
	}
	digest = sha256.Sum256(b)
	out.Profile.RecipeSHA256 = hex.EncodeToString(digest[:])
	return out, nil
}

func ValidateConfigurationProviderAuthentication(in contracts.HubWorkerDeployment, p contracts.ConfigurationProviderAuthentication, now time.Time) error {
	if p.Format != contracts.ConfigurationProviderAuthenticationFormat || len(p.RecipeSHA256) != 64 {
		return cfg.ErrInvalid
	}
	want, e := ConfigurationProviderRecipeFor(in, configurationProviderSelectionOf(p), p.ServiceAccount, now)
	if e != nil || want.Profile != p {
		return cfg.ErrInvalid
	}
	return nil
}

func configurationProviderRecipeBody(in contracts.HubWorkerDeployment, r ConfigurationProviderRecipe) ([]byte, error) {
	return ownerProviderCanonical(struct {
		Format         string                                        `json:"format"`
		InstallationID string                                        `json:"installationID"`
		ClusterID      string                                        `json:"clusterID"`
		Namespace      contracts.WorkerObjectReference               `json:"namespace"`
		FleetSource    contracts.WorkerObjectReference               `json:"fleetSource"`
		OwnerSource    contracts.WorkerObjectReference               `json:"ownerSource"`
		Kubernetes     contracts.OwnerProviderEndpoint               `json:"kubernetes"`
		KeyService     contracts.ConfigurationKeyService             `json:"keyService"`
		AuditStore     contracts.OwnerAuditStore                     `json:"auditStore"`
		Profile        contracts.ConfigurationProviderAuthentication `json:"profile"`
		Roles          [2]ConfigurationProviderRoleRecipe            `json:"roles"`
	}{"asservat-configuration-provider-recipe/v1", in.InstallationID, in.ClusterID, in.Namespace, in.FleetSource,
		in.OwnerSource, in.Kubernetes, in.KeyService, in.AuditStore, r.Profile, r.Roles})
}
