package providerconfig

import (
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
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

func FederationProviderSetupFor(in contracts.FederationDeployment) (FederationProviderSetup, error) {
	var out FederationProviderSetup
	if in.ProviderAuthentication == nil {
		return out, ErrSetupUnavailable
	}
	recipe, err := FederationProviderRecipeFor(in, *in.ProviderAuthentication)
	if err != nil || recipe.Profile != *in.ProviderAuthentication {
		return out, ErrSetupUnavailable
	}
	out.Authentication = recipe
	out.TransitKey = json.RawMessage(`{"type":"aes256-gcm96","derived":false,"exportable":false,"allow_plaintext_backup":false}`)
	// Provider globs confine leaves to this installation's connector URIs and
	// server-name domain. The product verifier still checks each leaf's exact
	// peer URI and server name against the staged profile.
	uri := "spiffe://asservat." + in.InstallationID + "/cluster/*/epoch/*/connector/*"
	domains := []string{"*." + contracts.ConnectorServerSuffix(in.InstallationID)}
	ttl := int64((value.ConnectorCertificatePeriod + value.ConnectorCertificateRenewBefore) / time.Second)
	for i, name := range []string{in.KeyService.ClientRole, in.KeyService.ServerRole} {
		server := i == 1
		allowed := []string{}
		if server {
			allowed = domains
		}
		body := map[string]any{
			"issuer_ref": "default", "require_cn": false, "use_csr_common_name": false, "use_csr_sans": false,
			"allow_any_name": false, "allow_ip_sans": false, "allow_localhost": false, "allow_subdomains": false,
			"allow_glob_domains": server, "allow_bare_domains": false, "allow_wildcard_certificates": false,
			"enforce_hostnames": true, "allowed_domains": allowed, "allowed_domains_template": false,
			"allowed_uri_sans": []string{uri}, "allowed_uri_sans_template": false, "allowed_other_sans": []string{},
			"allowed_user_ids": []string{}, "allowed_serial_numbers": []string{},
			"key_type": "ec", "key_bits": 256, "server_flag": server, "client_flag": !server,
			"code_signing_flag": false, "email_protection_flag": false, "key_usage": []string{"DigitalSignature"},
			"ext_key_usage": []string{}, "ext_key_usage_oids": []string{}, "policy_identifiers": []string{},
			"organization": []string{}, "ou": []string{}, "country": []string{}, "locality": []string{},
			"province": []string{}, "street_address": []string{}, "postal_code": []string{},
			"basic_constraints_valid_for_non_ca": true, "not_before_duration": 30, "ttl": ttl, "max_ttl": ttl,
			"generate_lease": false, "no_store": false, "not_after": "",
			"not_before": "", "not_before_bound": "forbid", "not_after_bound": "ttl-limited",
			"allow_globs_in_identity_templates": false, "allow_token_displayname": false, "allowed_ip_sans_cidr": []string{},
			"signature_bits": 0, "use_pss": false, "cn_validations": []string{"email", "hostname"},
		}
		raw, e := ownerProviderCanonical(body)
		if e != nil {
			return FederationProviderSetup{}, e
		}
		out.PKIRoles[i] = OwnerPKIRoleRecipe{Name: name, Role: raw}
	}
	return out, nil
}

// requests are the create-only writes the applier performs for the federation.
func (s FederationProviderSetup) requests(in contracts.FederationDeployment) ([]ownerProviderSetupRequest, error) {
	p := s.Authentication.Profile
	var out []ownerProviderSetupRequest
	for _, role := range s.Authentication.Roles {
		body, err := ownerProviderCanonical(struct {
			Policy string `json:"policy"`
		}{string(role.Policy)})
		if err != nil {
			return nil, err
		}
		out = append(out, ownerProviderSetupRequest{Method: "POST", Path: "sys/policies/acl/" + role.Name, Body: body},
			ownerProviderSetupRequest{Method: "POST", Path: "auth/" + p.AuthMount + "/role/" + role.Name, Body: role.Role})
	}
	for _, role := range s.PKIRoles {
		out = append(out, ownerProviderSetupRequest{Method: "POST", Path: in.KeyService.PKIMount + "/roles/" + role.Name, Body: role.Role})
	}
	return append(out, ownerProviderSetupRequest{Method: "POST", Path: in.KeyService.AuditMount + "/keys/" + in.KeyService.AuditKey, Body: s.TransitKey}), nil
}

// federationSetupPaths are the named paths the inspection token may read.
func federationSetupPaths(in contracts.FederationDeployment, s FederationProviderSetup) []string {
	p := s.Authentication.Profile
	paths := setupNamedPaths(p.AuthMount, in.KeyService.AuditMount, in.KeyService.AuditKey, s.Authentication.Roles[:])
	return append(paths, "sys/mounts/"+in.KeyService.PKIMount, in.KeyService.PKIMount+"/cert/ca", in.KeyService.PKIMount+"/roles/"+in.KeyService.ClientRole, in.KeyService.PKIMount+"/roles/"+in.KeyService.ServerRole)
}
