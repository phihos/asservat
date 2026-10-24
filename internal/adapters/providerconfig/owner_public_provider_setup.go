package providerconfig

import (
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/authorization"
)

// ownerPublicSetup adds the promoted owner's provider objects (ADR-194 step
// 5): the four public purpose roles, the create-only session and
// work-signing Transit keys and the download-worker PKI role. in.Public
// carries the derived names; the continuation reads the signing key and the
// worker roots back through the listed inspection paths afterwards. The
// operator creates both mounts. prefixes are the audit objects the hub-api
// writes with the owner's audit principal once promoted.
func ownerPublicSetup(in contracts.OwnerDeployment, profile contracts.OwnerProviderAuthentication, now time.Time) (requests []ownerProviderSetupRequest, inspect, prefixes []string, err error) {
	p := in.Public
	roles, _, err := OwnerPublicProviderRecipeFor(in, profile, now)
	if err != nil || p.WorkSigning.Mount != p.SessionTransit.Mount || p.WorkerPKI.Mount == in.KeyService.PKIMount || p.SessionTransit.Mount == in.KeyService.AuditMount {
		return nil, nil, nil, ErrSetupUnavailable
	}
	inspect = []string{"sys/mounts/" + p.SessionTransit.Mount, "sys/mounts/" + p.WorkerPKI.Mount, p.WorkerPKI.Mount + "/cert/ca"}
	for _, role := range roles {
		body, e := ownerProviderCanonical(struct {
			Policy string `json:"policy"`
		}{string(role.Policy)})
		if e != nil {
			return nil, nil, nil, e
		}
		requests = append(requests, ownerProviderSetupRequest{Method: "POST", Path: "sys/policies/acl/" + role.Name, Body: body},
			ownerProviderSetupRequest{Method: "POST", Path: "auth/" + profile.AuthMount + "/role/" + role.Name, Body: role.Role})
		inspect = append(inspect, "sys/policies/acl/"+role.Name, "auth/"+profile.AuthMount+"/role/"+role.Name)
	}
	for _, key := range [2][2]string{{p.SessionTransit.Key, "aes256-gcm96"}, {p.WorkSigning.Name, "ed25519"}} {
		body, e := ownerProviderCanonical(map[string]any{"type": key[1], "derived": false, "exportable": false, "allow_plaintext_backup": false})
		if e != nil {
			return nil, nil, nil, e
		}
		requests = append(requests, ownerProviderSetupRequest{Method: "POST", Path: p.SessionTransit.Mount + "/keys/" + key[0], Body: body})
		inspect = append(inspect, p.SessionTransit.Mount+"/keys/"+key[0])
	}
	role, err := ownerWorkerPKIRole(in.InstallationID)
	if err != nil {
		return nil, nil, nil, err
	}
	requests = append(requests, ownerProviderSetupRequest{Method: "POST", Path: p.WorkerPKI.Mount + "/roles/" + p.WorkerPKI.Role, Body: json.RawMessage(role)})
	root, installation := in.PermissionRootID, in.InstallationID
	prefixes = []string{"operation-audit/v1/" + root + "/", "capture-intent/v1/" + root + "/", "download-audit/v1/" + root + "/", "download-worker-audit/v1/" + root + "/",
		"download-window-audit/v1/" + root + "/", "download-stop/v1/" + root + "/", "download-worker-enrollment/v1/" + installation + "/", "download-worker-certificate/v1/" + installation + "/",
		// Shared acquisition workers (native download and approved inspection).
		"acquisition-enrollment/v1/native-download/" + installation + "/", "acquisition-enrollment/v1/approved-pod-status/" + installation + "/",
		"acquisition-certificate/v1/native-download/" + installation + "/", "acquisition-certificate/v1/approved-pod-status/" + installation + "/",
		"context-query-worker/v1/" + root + "/"}
	return requests, append(inspect, p.WorkerPKI.Mount+"/roles/"+p.WorkerPKI.Role), prefixes, nil
}

// ownerWorkerPKIRole is the exact download-worker PKI role (ADR-194).
func ownerWorkerPKIRole(installation string) (json.RawMessage, error) {
	// Leaves carry only the worker's acquisition URI; the product issuer
	// still binds each leaf to its admitted enrollment and issuer epoch.
	ttl := int64((value.WorkerCertificatePeriod + value.WorkerCertificateRenewBefore) / time.Second)
	return ownerProviderCanonical(map[string]any{
		"issuer_ref": "default", "require_cn": false, "use_csr_common_name": false, "use_csr_sans": false,
		"allow_any_name": false, "allow_ip_sans": false, "allow_localhost": false, "allow_subdomains": false,
		"allow_glob_domains": false, "allow_bare_domains": false, "allow_wildcard_certificates": false,
		"enforce_hostnames": true, "allowed_domains": []string{}, "allowed_domains_template": false,
		"allowed_uri_sans": []string{"spiffe://asservat." + installation + "/key-client/acquisition/*"}, "allowed_uri_sans_template": false,
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
