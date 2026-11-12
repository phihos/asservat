package kubernetes

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// BuildSmallOpenBaoMaterial is pure setup generation. The create-once owner
// must persist this map before any backend effect; this function adopts no PVC,
// regenerates no retained key and grants no installation/evidence authority.
func BuildSmallOpenBaoMaterial(p contracts.SmallOpenBaoPlan, now time.Time) (map[string][]byte, error) {
	if !p.Valid() || now.IsZero() {
		return nil, cfg.ErrInvalid
	}
	backend, err := prepUUID()
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	plan, _ := json.Marshal(p)
	data := map[string][]byte{contracts.SmallOpenBaoPlanKey: plan, contracts.SmallOpenBaoBackendKey: []byte(backend), contracts.SmallOpenBaoSealKey: make([]byte, 32)}
	ok := false
	defer func() {
		if !ok {
			clearSmallOpenBaoMaterial(data)
		}
	}()
	if _, err = rand.Read(data[contracts.SmallOpenBaoSealKey]); err != nil {
		return nil, cfg.ErrUnavailable
	}
	if err = buildSmallOpenBaoTLS(p, data, now); err != nil {
		return nil, err
	}
	data[contracts.SmallOpenBaoConfigKey], err = SmallOpenBaoConfiguration(p, backend)
	if err != nil || ValidateSmallOpenBaoMaterial(p, data, now) != nil {
		return nil, cfg.ErrUnavailable
	}
	ok = true
	return data, nil
}

func clearSmallOpenBaoMaterial(data map[string][]byte) {
	for _, raw := range data {
		clear(raw)
	}
}

func buildSmallOpenBaoTLS(p contracts.SmallOpenBaoPlan, data map[string][]byte, now time.Time) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return cfg.ErrUnavailable
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return cfg.ErrUnavailable
	}
	serial := func() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
	caSerial, err := serial()
	if err != nil {
		return cfg.ErrUnavailable
	}
	leafSerial, err := serial()
	if err != nil {
		return cfg.ErrUnavailable
	}
	ca := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: p.ServiceName() + " CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return cfg.ErrUnavailable
	}
	// CreateCertificate generates the CA SubjectKeyId in DER without changing
	// its input template. Use the parsed issuer so the leaf receives the AKI
	// required by current strict OpenSSL/Python certificate verification.
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		return cfg.ErrUnavailable
	}
	leaf := &x509.Certificate{SerialNumber: leafSerial, Subject: pkix.Name{CommonName: p.Host()}, DNSNames: []string{p.ServiceName(), p.ServiceName() + "." + p.Namespace, p.Host(), p.Host() + ".cluster.local"}, NotBefore: ca.NotBefore, NotAfter: now.AddDate(1, 0, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return cfg.ErrUnavailable
	}
	data["ca.crt"], data["tls.crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	for name, key := range map[string]*ecdsa.PrivateKey{"ca.key": caKey, "tls.key": leafKey} {
		raw, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return cfg.ErrUnavailable
		}
		data[name] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
		clear(raw)
	}
	return nil
}

// SmallOpenBaoConfiguration is public config: the static seal and serving
// private key are file references. The only API bootstrap privilege is a
// finite setup login for the original runner. No root token is retained.
func SmallOpenBaoConfiguration(p contracts.SmallOpenBaoPlan, backend string) ([]byte, error) {
	if !p.Valid() || !authorization.UUID(backend) {
		return nil, cfg.ErrInvalid
	}
	var ca bytes.Buffer
	for _, der := range p.Kubernetes.Roots {
		_ = pem.Encode(&ca, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	request := func(name, path string, data any) map[string]any {
		return map[string]any{name: map[string]any{"operation": "update", "path": path, "data": data}}
	}
	policy := smallOpenBaoSetupPolicy()
	marker, err := SmallOpenBaoBackendPolicy(backend)
	if err != nil {
		return nil, err
	}
	init := []any{
		request("setup-auth", "sys/auth/"+contracts.SmallOpenBaoSetupMount, map[string]any{"type": "kubernetes"}),
		request("setup-api", "auth/"+contracts.SmallOpenBaoSetupMount+"/config", map[string]any{"kubernetes_host": p.Kubernetes.Endpoint, "kubernetes_ca_cert": ca.String(), "disable_local_ca_jwt": false, "disable_iss_validation": true}),
		request("setup-policy", "sys/policies/acl/"+contracts.SmallOpenBaoSetupPolicy, map[string]any{"policy": policy}),
		request("setup-role", "auth/"+contracts.SmallOpenBaoSetupMount+"/role/"+contracts.SmallOpenBaoSetupRole, map[string]any{"bound_service_account_names": []string{p.SetupAccount}, "bound_service_account_namespaces": []string{p.Namespace}, "alias_name_source": "serviceaccount_uid", "audience": p.SetupAudience(), "token_policies": []string{contracts.SmallOpenBaoSetupPolicy}, "token_no_default_policy": true, "token_ttl": 300, "token_max_ttl": 900, "token_explicit_max_ttl": 900, "token_num_uses": 0, "token_period": 0, "token_type": "service"}),
		request("inspection-role", "auth/token/roles/"+providerconfig.BundledSetupInspectionRole, map[string]any{"allowed_policies_glob": []string{"asservat-*-inspection"}, "disallowed_policies": []string{"root", "default"}, "orphan": false, "renewable": false, "token_no_default_policy": true, "token_type": "service", "token_explicit_max_ttl": 600, "token_num_uses": 0, "token_period": 0}),
	}
	// These are installation infrastructure prerequisites, not runtime grants.
	// Persist them under native first-initialization semantics before the final
	// marker; a partial failure cannot become a replacement-key retry.
	for _, mount := range []string{contracts.SmallOpenBaoConfigurationAuthMount, contracts.SmallOpenBaoOwnerAuthMount} {
		init = append(init, request(mount+"-mount", "sys/auth/"+mount, map[string]any{"type": "kubernetes"}),
			request(mount+"-api", "auth/"+mount+"/config", map[string]any{"kubernetes_host": p.Kubernetes.Endpoint, "kubernetes_ca_cert": ca.String(), "disable_local_ca_jwt": false, "disable_iss_validation": true}))
	}
	for _, mount := range []string{contracts.SmallOpenBaoAuditMount, contracts.SmallOpenBaoTransitMount} {
		init = append(init, request(mount+"-mount", "sys/mounts/"+mount, map[string]any{"type": "transit"}))
	}
	init = append(init, request("initial-audit-key", contracts.SmallOpenBaoAuditMount+"/keys/audit", map[string]any{"type": "aes256-gcm96", "exportable": false, "allow_plaintext_backup": false}))
	names := contracts.SmallOpenBaoInitialProviders()
	policies, err := providerconfig.InitialProviderPolicyBodies(names.IssuerPolicy, names.WrapRole, names.WrapPolicy, names.UnwrapRole, names.UnwrapPolicy, contracts.SmallOpenBaoAuditMount, "audit")
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	for _, name := range []string{names.IssuerPolicy, names.WrapPolicy, names.UnwrapPolicy} {
		init = append(init, request(name+"-policy", "sys/policies/acl/"+name, map[string]any{"policy": policies[name]}))
	}
	for _, role := range []struct{ name, policy string }{{names.WrapRole, names.WrapPolicy}, {names.UnwrapRole, names.UnwrapPolicy}, {contracts.SmallOpenBaoInitialIssuerRole, names.IssuerPolicy}} {
		init = append(init, request(role.name+"-role", "auth/token/roles/"+role.name, map[string]any{"allowed_policies": []string{role.policy}, "orphan": false, "renewable": false, "token_no_default_policy": true, "token_type": "service", "token_explicit_max_ttl": 900, "token_num_uses": 0, "token_period": 0}))
	}
	for _, mount := range []string{contracts.SmallOpenBaoOwnerPKIMount, contracts.SmallOpenBaoConnectorPKIMount, contracts.SmallOpenBaoWorkerPKIMount} {
		init = append(init, request(mount+"-mount", "sys/mounts/"+mount, map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "87600h"}}),
			request(mount+"-root", mount+"/root/generate/internal", map[string]any{"common_name": p.ServiceName() + " " + mount, "ttl": "87600h", "key_type": "ec", "key_bits": 256}))
	}
	init = append(init, request("bootstrap-mount", "sys/mounts/"+contracts.SmallOpenBaoBootstrapMount, map[string]any{"type": "kv", "options": map[string]any{"version": "2"}}),
		request("backend-identity", contracts.SmallOpenBaoBackendPolicyPath, map[string]any{"policy": marker}))
	// The pinned 2.7.2 parser does not accept the documentation's labeled
	// self-init JSON example. Native HCL is validated against that binary.
	var config bytes.Buffer
	config.WriteString("ui = false\nlog_level = \"warn\"\n")
	fmt.Fprintf(&config, "api_addr = %s\ncluster_addr = \"https://127.0.0.1:8201\"\n", smallOpenBaoHCLValue(p.Endpoint()))
	fmt.Fprintf(&config, "storage \"raft\" {\n path = %s\n node_id = %s\n}\n", smallOpenBaoHCLValue(contracts.SmallOpenBaoData), smallOpenBaoHCLValue(p.ServiceName()+"-0"))
	fmt.Fprintf(&config, "seal \"static\" {\n current_key_id = %s\n current_key = %s\n}\n", smallOpenBaoHCLValue(backend), smallOpenBaoHCLValue("file://"+contracts.SmallOpenBaoRoot+"/"+contracts.SmallOpenBaoSealKey))
	fmt.Fprintf(&config, "listener \"tcp\" {\n address = \"0.0.0.0:8200\"\n cluster_address = \"127.0.0.1:8201\"\n tls_cert_file = %s\n tls_key_file = %s\n tls_min_version = \"tls13\"\n tls_disable = false\n}\n", smallOpenBaoHCLValue(contracts.SmallOpenBaoRoot+"/tls.crt"), smallOpenBaoHCLValue(contracts.SmallOpenBaoRoot+"/tls.key"))
	config.WriteString("initialize \"asservat\" {\n")
	for _, item := range init {
		for name, raw := range item.(map[string]any) {
			fields := raw.(map[string]any)
			fmt.Fprintf(&config, " request %s {\n  operation = %s\n  path = %s\n  data = %s\n }\n", smallOpenBaoHCLValue(name), smallOpenBaoHCLValue(fields["operation"]), smallOpenBaoHCLValue(fields["path"]), smallOpenBaoHCLValue(fields["data"]))
		}
	}
	config.WriteString("}\n")
	return config.Bytes(), nil
}

// Only formats the fixed generated HCL attribute values above. Input strings
// remain quoted; this is not an operator-supplied template/profile language.
func smallOpenBaoHCLValue(value any) string {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		var out bytes.Buffer
		out.WriteString("{ ")
		for _, key := range keys {
			fmt.Fprintf(&out, "%s = %s\n", smallOpenBaoHCLValue(key), smallOpenBaoHCLValue(v[key]))
		}
		out.WriteString("}")
		return out.String()
	case map[string]string:
		fields := make(map[string]any, len(v))
		for k, x := range v {
			fields[k] = x
		}
		return smallOpenBaoHCLValue(fields)
	default:
		raw, _ := json.Marshal(value)
		return string(raw)
	}
}

func smallOpenBaoSetupPolicy() string {
	// Dedicated provider management, never an ordinary runtime capability.
	// No global root, raw storage, audit-device or seal administration rights.
	// Only two exact root-protected auth mounts receive API-scoped sudo;
	// wildcard/tune/delete administration is deliberately absent.
	paths := map[string]any{}
	for _, path := range []string{"auth/+/config", "auth/+/role/+", "sys/policies/acl/asservat-*", "auth/token/roles/asservat-*"} {
		paths[path] = map[string]any{"capabilities": []string{"create", "read", "update"}}
	}
	for _, mount := range []string{contracts.SmallOpenBaoAuditMount, contracts.SmallOpenBaoTransitMount} {
		paths[mount+"/keys/*"] = map[string]any{"capabilities": []string{"create", "read", "update"}}
	}
	for _, mount := range []string{contracts.SmallOpenBaoConfigurationAuthMount, contracts.SmallOpenBaoOwnerAuthMount} {
		paths["sys/auth/"+mount] = map[string]any{"capabilities": []string{"create", "read", "update", "sudo"}}
	}
	for _, mount := range []string{contracts.SmallOpenBaoAuditMount, contracts.SmallOpenBaoTransitMount, contracts.SmallOpenBaoOwnerPKIMount, contracts.SmallOpenBaoConnectorPKIMount, contracts.SmallOpenBaoWorkerPKIMount, contracts.SmallOpenBaoBootstrapMount} {
		paths["sys/mounts/"+mount] = map[string]any{"capabilities": []string{"create", "read", "update"}}
	}
	for _, mount := range []string{contracts.SmallOpenBaoOwnerPKIMount, contracts.SmallOpenBaoConnectorPKIMount, contracts.SmallOpenBaoWorkerPKIMount} {
		for _, path := range []string{"root/generate/internal", "roles/*", "config/*", "issuers/*"} {
			paths[mount+"/"+path] = map[string]any{"capabilities": []string{"create", "read", "update"}}
		}
		paths[mount+"/cert/ca"] = map[string]any{"capabilities": []string{"read"}}
	}
	for _, path := range []string{"auth/token/create/asservat-*", "auth/token/lookup-accessor", "auth/token/revoke-accessor", "auth/token/revoke-self"} {
		paths[path] = map[string]any{"capabilities": []string{"update"}}
	}
	for _, path := range []string{"auth/token/lookup-self", "sys/mounts/auth/asservat-*", contracts.SmallOpenBaoBackendPolicyPath} {
		paths[path] = map[string]any{"capabilities": []string{"read"}}
	}
	raw, _ := json.Marshal(map[string]any{"path": paths})
	return string(raw)
}

// SmallOpenBaoBackendPolicy is the final native initialization marker. It is
// not attached to any token and grants no capability. The bootstrap consumer
// must read this exact fixed policy and compare its original backend UUID;
// generic server health never establishes complete initialization.
func SmallOpenBaoBackendPolicy(backend string) (string, error) {
	if !authorization.UUID(backend) {
		return "", cfg.ErrInvalid
	}
	raw, err := json.Marshal(map[string]any{"path": map[string]any{"asservat-backend/" + backend: map[string]any{"capabilities": []string{"deny"}}}})
	if err != nil {
		return "", cfg.ErrInvalid
	}
	return string(raw), nil
}

func ValidateSmallOpenBaoMaterial(p contracts.SmallOpenBaoPlan, data map[string][]byte, now time.Time) error {
	if !p.Valid() || now.IsZero() || len(data) != 8 {
		return cfg.ErrInvalid
	}
	total := 0
	for key, raw := range data {
		if !slices.Contains([]string{contracts.SmallOpenBaoPlanKey, contracts.SmallOpenBaoBackendKey, contracts.SmallOpenBaoSealKey, contracts.SmallOpenBaoConfigKey, "ca.crt", "ca.key", "tls.crt", "tls.key"}, key) || len(raw) == 0 || len(raw) > contracts.SmallOpenBaoPlanLimit {
			return cfg.ErrInvalid
		}
		total += len(raw)
	}
	if total > contracts.SmallOpenBaoStateLimit || len(data[contracts.SmallOpenBaoSealKey]) != 32 || bytes.Equal(data[contracts.SmallOpenBaoSealKey], make([]byte, 32)) {
		return cfg.ErrInvalid
	}
	plan, err := contracts.DecodeSmallOpenBaoPlan(bytes.NewReader(data[contracts.SmallOpenBaoPlanKey]))
	expected, _ := json.Marshal(p)
	actual, _ := json.Marshal(plan)
	if err != nil || !bytes.Equal(expected, actual) {
		return cfg.ErrInvalid
	}
	config, err := SmallOpenBaoConfiguration(p, string(data[contracts.SmallOpenBaoBackendKey]))
	if err != nil || !bytes.Equal(config, data[contracts.SmallOpenBaoConfigKey]) {
		return cfg.ErrInvalid
	}
	for _, name := range []string{"ca.crt", "ca.key", "tls.crt", "tls.key"} {
		block, rest := pem.Decode(data[name])
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			return cfg.ErrInvalid
		}
	}
	caPair, err := tls.X509KeyPair(data["ca.crt"], data["ca.key"])
	if err != nil || len(caPair.Certificate) != 1 {
		return cfg.ErrInvalid
	}
	ca, err := x509.ParseCertificate(caPair.Certificate[0])
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.CheckSignatureFrom(ca) != nil || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return cfg.ErrInvalid
	}
	leafPair, err := tls.X509KeyPair(data["tls.crt"], data["tls.key"])
	if err != nil || len(leafPair.Certificate) != 1 {
		return cfg.ErrInvalid
	}
	leaf, err := x509.ParseCertificate(leafPair.Certificate[0])
	if err != nil || leaf.IsCA || len(ca.SubjectKeyId) == 0 || !bytes.Equal(leaf.AuthorityKeyId, ca.SubjectKeyId) || !slices.Equal(leaf.DNSNames, []string{p.ServiceName(), p.ServiceName() + "." + p.Namespace, p.Host(), p.Host() + ".cluster.local"}) || len(leaf.IPAddresses)+len(leaf.URIs)+len(leaf.EmailAddresses) != 0 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return cfg.ErrInvalid
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: p.Host(), CurrentTime: now}); err != nil {
		return cfg.ErrInvalid
	}
	return nil
}
