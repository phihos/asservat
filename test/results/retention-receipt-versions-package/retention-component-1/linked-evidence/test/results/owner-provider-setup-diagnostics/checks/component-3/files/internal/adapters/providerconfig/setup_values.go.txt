package providerconfig

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/json/jsontext"
	"encoding/pem"
	"slices"
	"strings"

	"asservat.local/asservat/internal/contracts"
)

func setupValue[T any](data map[string]json.RawMessage, key string) (T, bool) {
	var v T
	raw, ok := data[key]
	if !ok || setupNull(raw) || json.Unmarshal(raw, &v) != nil {
		return v, false
	}
	return v, true
}
func setupIs[T comparable](data map[string]json.RawMessage, key string, want T) bool {
	v, ok := setupValue[T](data, key)
	return ok && v == want
}
func setupEmpty(data map[string]json.RawMessage, key string) bool {
	raw := data[key]
	if setupNull(raw) {
		return true
	}
	var list []string
	return json.Unmarshal(raw, &list) == nil && len(list) == 0
}

func verifyAuthMount(data map[string]json.RawMessage, accessor string) error {
	config, ok := setupValue[map[string]json.RawMessage](data, "config")
	if !ok || !setupIs(data, "type", "kubernetes") || !setupIs(data, "accessor", accessor) {
		return ErrSetupUnavailable
	}
	for _, key := range []string{"default_lease_ttl", "max_lease_ttl"} {
		ttl, ok := setupValue[int64](config, key)
		if !ok || ttl < 0 {
			return ErrSetupUnavailable
		}
	}
	tokenType, ok := setupValue[string](config, "token_type")
	if !ok || tokenType != "default-service" && tokenType != "default-batch" && tokenType != "service" {
		return ErrSetupUnavailable
	}
	// The exact roles explicitly select service tokens and finite TTLs. A
	// mount-wide forced batch type overrides the role and is unsupported.
	// Global defaults otherwise remain administrator-owned and may serve
	// unrelated clients; actual returned tokens are independently bounded.
	return nil
}

func verifyKubernetesAuthConfig(data map[string]json.RawMessage, endpoint contracts.OwnerProviderEndpoint) error {
	host, ok := setupValue[string](data, "kubernetes_host")
	ca, caOK := setupValue[string](data, "kubernetes_ca_cert")
	if !ok || !caOK || host != endpoint.Endpoint || !setupIs(data, "disable_local_ca_jwt", true) || !setupIs(data, "token_reviewer_jwt_set", true) || !setupEmpty(data, "pem_keys") {
		return ErrSetupUnavailable
	}
	// The initial installed profile requires the externally managed reviewer.
	// The boolean establishes configured presence only, never possession,
	// rotation, TokenReview authorization or ongoing provider availability.
	if raw, exists := data["use_annotations_as_alias_metadata"]; exists && (!bytes.Equal(raw, []byte("false"))) {
		return ErrSetupUnavailable
	}
	got, err := setupPEMCertificates(ca)
	if err != nil || len(got) != len(endpoint.Roots) {
		return ErrSetupUnavailable
	}
	for _, want := range endpoint.Roots {
		if !slices.ContainsFunc(got, func(r []byte) bool { return bytes.Equal(r, want) }) {
			return ErrSetupUnavailable
		}
	}
	return nil
}

func setupPEMCertificates(value string) ([][]byte, error) {
	if len(value) == 0 || len(value) > 32<<10 {
		return nil, ErrSetupUnavailable
	}
	raw := []byte(value)
	var out [][]byte
	for len(bytes.TrimSpace(raw)) > 0 {
		raw = bytes.TrimSpace(raw)
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrSetupUnavailable
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(out) == 4 {
			return nil, ErrSetupUnavailable
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, ErrSetupUnavailable
		}
		if slices.ContainsFunc(out, func(r []byte) bool { return bytes.Equal(r, block.Bytes) }) {
			return nil, ErrSetupUnavailable
		}
		out = append(out, block.Bytes)
		raw = rest
	}
	return out, nil
}

func verifyTransitMount(data map[string]json.RawMessage) error {
	if !setupIs(data, "type", "transit") {
		return ErrSetupUnavailable
	}
	return nil
}

func verifyTransitKey(data map[string]json.RawMessage, name string) error {
	if !setupIs(data, "name", name) || !setupIs(data, "type", "aes256-gcm96") || !setupIs(data, "derived", false) || !setupIs(data, "exportable", false) || !setupIs(data, "allow_plaintext_backup", false) || !setupIs(data, "deletion_allowed", false) || !setupIs(data, "supports_encryption", true) || !setupIs(data, "supports_decryption", true) || !setupIs(data, "min_decryption_version", int64(1)) || !setupIs(data, "min_encryption_version", int64(0)) {
		return ErrSetupUnavailable
	}
	latest, ok := setupValue[int64](data, "latest_version")
	if !ok || latest < 1 {
		return ErrSetupUnavailable
	}
	if raw, exists := data["min_available_version"]; exists {
		var earliest int64
		if json.Unmarshal(raw, &earliest) != nil || earliest < 0 || earliest > 1 {
			return ErrSetupUnavailable
		}
	}
	return nil
}

// Compare exact supported effective role fields. Nullable empty collections
// and omitted optional zero values are the documented response normalization;
// positive identity/policy/TTL constraints cannot be omitted. New effective
// fields must be reviewed instead of silently broadening the profile.
func verifyKubernetesRole(data map[string]json.RawMessage, expectedRaw json.RawMessage) error {
	var expected map[string]json.RawMessage
	if json.Unmarshal(expectedRaw, &expected) != nil {
		return ErrSetupUnavailable
	}
	for key, want := range expected {
		got, exists := data[key]
		if bytes.Equal(want, []byte("[]")) {
			if !setupEmpty(data, key) {
				return ErrSetupUnavailable
			}
			continue
		}
		if !exists && (bytes.Equal(want, []byte("0")) || bytes.Equal(want, []byte("false")) || bytes.Equal(want, []byte(`""`))) {
			continue
		}
		if !setupJSONEqual(got, want) {
			return ErrSetupUnavailable
		}
	}
	aliases := map[string]string{"ttl": "token_ttl", "max_ttl": "token_max_ttl", "period": "token_period", "policies": "token_policies"}
	for key, got := range data {
		if _, ok := expected[key]; ok {
			continue
		}
		if target, ok := aliases[key]; ok {
			if !setupJSONEqual(got, expected[target]) {
				return ErrSetupUnavailable
			}
			continue
		}
		if key == "token_strictly_bind_ip" && bytes.Equal(got, []byte("false")) {
			continue
		}
		return ErrSetupUnavailable
	}
	return nil
}

func setupJSONEqual(a, b json.RawMessage) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	x, y := jsontext.Value(bytes.Clone(a)), jsontext.Value(bytes.Clone(b))
	if x.Canonicalize() != nil || y.Canonicalize() != nil {
		return false
	}
	return bytes.Equal(x, y)
}

func verifyACL(data map[string]json.RawMessage, name string, expected json.RawMessage) error {
	if !setupIs(data, "name", name) {
		return ErrSetupUnavailable
	}
	policy, ok := setupValue[string](data, "policy")
	if !ok || len(policy) > 32<<10 || !setupJSONEqual([]byte(policy), expected) {
		return ErrSetupUnavailable
	}
	// Generated JSON policies have one exact meaning. HCL and approximate
	// substring matches are deliberately not alternate acceptance paths.
	if raw, exists := data["rules"]; exists {
		var rules string
		if json.Unmarshal(raw, &rules) != nil || !setupJSONEqual([]byte(rules), expected) {
			return ErrSetupUnavailable
		}
	}
	return nil
}

func setupNamedPaths(authMount, auditMount, auditKey string, roles []OwnerProviderRoleRecipe) []string {
	paths := []string{"sys/mounts/auth/" + authMount, "auth/" + authMount + "/config", "sys/mounts/" + auditMount, auditMount + "/keys/" + auditKey}
	for _, role := range roles {
		paths = append(paths, "auth/"+authMount+"/role/"+role.Name, "sys/policies/acl/"+role.Name)
	}
	return paths
}

func setupInspectionPolicy(paths []string) (json.RawMessage, error) {
	acl := ownerProviderACL{Path: map[string]ownerProviderACLRule{}}
	for _, path := range paths {
		if path == "" || strings.ContainsAny(path, "*+?#%") {
			return nil, ErrSetupUnavailable
		}
		acl.Path[path] = ownerProviderACLRule{Capabilities: []string{"read"}}
	}
	return ownerProviderCanonical(acl)
}
