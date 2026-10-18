package providerconfig

import (
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
)

// PublisherProviderSetup is the publisher's part of the phase-3 provider
// artifact (ADR-203): its three authentication roles and policies, the
// verifier PKI role on the worker PKI mount and its create-only audit
// Transit key. The operator applies it with the owner's roles in one step.
type PublisherProviderSetup struct {
	Authentication PublisherProviderRecipe `json:"authentication"`
	PKIRole        OwnerPKIRoleRecipe      `json:"pkiRole"`
	TransitKey     json.RawMessage         `json:"transitKey"`
}

func PublisherProviderSetupFor(in contracts.PublisherDeployment) (PublisherProviderSetup, error) {
	var out PublisherProviderSetup
	recipe, err := PublisherProviderRecipeFor(in, in.ProviderAuthentication)
	if err != nil || recipe.Profile != in.ProviderAuthentication {
		return out, ErrSetupUnavailable
	}
	role, err := publisherVerifierPKIRole(in.InstallationID)
	if err != nil {
		return out, err
	}
	out.Authentication, out.PKIRole = recipe, OwnerPKIRoleRecipe{Name: in.Verifier.Role, Role: role}
	out.TransitKey = json.RawMessage(`{"type":"aes256-gcm96","derived":false,"exportable":false,"allow_plaintext_backup":false}`)
	return out, nil
}

// publisherVerifierPKIRole is the exact verifier PKI role (ADR-203 decision
// 4). Leaves carry only a key-client/verifier URI; the in-process credential
// still checks its own exact peer URI and the chain to the pinned issuer.
func publisherVerifierPKIRole(installation string) (json.RawMessage, error) {
	ttl := int64(mtls.VerifierCertificatePeriod / time.Second)
	return ownerProviderCanonical(map[string]any{
		"issuer_ref": "default", "require_cn": false, "use_csr_common_name": false, "use_csr_sans": false,
		"allow_any_name": false, "allow_ip_sans": false, "allow_localhost": false, "allow_subdomains": false,
		"allow_glob_domains": false, "allow_bare_domains": false, "allow_wildcard_certificates": false,
		"enforce_hostnames": true, "allowed_domains": []string{}, "allowed_domains_template": false,
		"allowed_uri_sans": []string{"spiffe://asservat." + installation + "/key-client/verifier/*"}, "allowed_uri_sans_template": false,
		"allowed_other_sans": []string{}, "allowed_user_ids": []string{}, "allowed_serial_numbers": []string{},
		"key_type": "ec", "key_bits": 256, "server_flag": false, "client_flag": true,
		"code_signing_flag": false, "email_protection_flag": false, "key_usage": []string{"DigitalSignature"},
		"ext_key_usage": []string{}, "ext_key_usage_oids": []string{}, "policy_identifiers": []string{},
		"organization": []string{}, "ou": []string{}, "country": []string{}, "locality": []string{},
		"province": []string{}, "street_address": []string{}, "postal_code": []string{},
		"basic_constraints_valid_for_non_ca": true, "not_before_duration": 30, "ttl": ttl, "max_ttl": ttl,
		"generate_lease": false, "no_store": false, "not_after": "",
		"not_before": "", "not_before_bound": "forbid", "not_after_bound": "ttl-limited",
		"allow_globs_in_identity_templates": false, "allow_token_displayname": false, "allowed_ip_sans_cidr": []string{},
		"signature_bits": 0, "use_pss": false, "cn_validations": []string{"email", "hostname"},
	})
}

// requests are the create-only writes the applier performs for the publisher.
func (s PublisherProviderSetup) requests(in contracts.PublisherDeployment) ([]ownerProviderSetupRequest, error) {
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
	out = append(out, ownerProviderSetupRequest{Method: "POST", Path: in.Verifier.PKIMount + "/roles/" + s.PKIRole.Name, Body: s.PKIRole.Role})
	return append(out, ownerProviderSetupRequest{Method: "POST", Path: in.AuditKeys.Mount + "/keys/" + in.AuditKeys.Key, Body: s.TransitKey}), nil
}

// publisherSetupPaths are the named paths the inspection token may read.
func publisherSetupPaths(in contracts.PublisherDeployment, s PublisherProviderSetup) []string {
	paths := setupNamedPaths(s.Authentication.Profile.AuthMount, in.AuditKeys.Mount, in.AuditKeys.Key, s.Authentication.Roles[:])
	return append(paths, "sys/mounts/"+in.Verifier.PKIMount, in.Verifier.PKIMount+"/cert/ca", in.Verifier.PKIMount+"/roles/"+in.Verifier.Role)
}
