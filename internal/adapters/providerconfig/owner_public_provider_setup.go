package providerconfig

import (
	"encoding/json"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
)

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

// ownerProviderSetupRequest is one provider write the runtime readback
// verifiers recompute; setup applies its own plan (setup_openbao.go).
type ownerProviderSetupRequest struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"`
}
