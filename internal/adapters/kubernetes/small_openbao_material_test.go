package kubernetes

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func smallOpenBaoFixturePlan(t *testing.T, now time.Time) contracts.SmallOpenBaoPlan {
	t.Helper()
	cert, _, ca := installerServingTLSFixture(t, "api.invalid", now)
	_ = cert
	block, _ := pem.Decode(ca)
	return contracts.SmallOpenBaoPlan{Format: contracts.SmallOpenBaoFormat, Namespace: "bootstrap", Name: "trial", Image: contracts.SmallOpenBaoImage, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://api.invalid", Roots: [][]byte{block.Bytes}}, SetupAccount: "trial-setup"}
}

func cloneSmallOpenBaoMaterial(m map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range m {
		out[k] = bytes.Clone(v)
	}
	return out
}

func TestSmallOpenBaoMaterialBindsStableSealTLSAndOriginalPlan(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	p := smallOpenBaoFixturePlan(t, now)
	m, err := BuildSmallOpenBaoMaterial(p, now)
	if err != nil || ValidateSmallOpenBaoMaterial(p, m, now) != nil {
		t.Fatal("material", err)
	}
	defer clearSmallOpenBaoMaterial(m)
	caPEM, _ := pem.Decode(m["ca.crt"])
	leafPEM, _ := pem.Decode(m["tls.crt"])
	ca, _ := x509.ParseCertificate(caPEM.Bytes)
	leaf, _ := x509.ParseCertificate(leafPEM.Bytes)
	if len(ca.SubjectKeyId) == 0 || !bytes.Equal(leaf.AuthorityKeyId, ca.SubjectKeyId) {
		t.Fatal("serving certificate lacks its actual CA authority key identifier")
	}
	if bytes.Contains(m[contracts.SmallOpenBaoConfigKey], m[contracts.SmallOpenBaoSealKey]) || bytes.Contains(m[contracts.SmallOpenBaoConfigKey], m["tls.key"]) || bytes.Contains(m[contracts.SmallOpenBaoConfigKey], []byte("root_token")) {
		t.Fatal("private material in public configuration")
	}
	for name, mutate := range map[string]func(map[string][]byte){
		"zero seal":         func(m map[string][]byte) { clear(m[contracts.SmallOpenBaoSealKey]) },
		"wrong seal length": func(m map[string][]byte) { m[contracts.SmallOpenBaoSealKey] = m[contracts.SmallOpenBaoSealKey][:31] },
		"unknown key":       func(m map[string][]byte) { m["root-token"] = []byte("invalid") },
		"wrong backend": func(m map[string][]byte) {
			m[contracts.SmallOpenBaoBackendKey] = []byte("00000000-0000-4000-8000-000000000001")
		},
		"plaintext listener": func(m map[string][]byte) {
			m[contracts.SmallOpenBaoConfigKey] = bytes.Replace(m[contracts.SmallOpenBaoConfigKey], []byte(`tls_disable = false`), []byte(`tls_disable = true`), 1)
		},
		"TLS changed":  func(m map[string][]byte) { m["tls.key"] = m["ca.key"] },
		"TLS trailing": func(m map[string][]byte) { m["tls.crt"] = append(m["tls.crt"], []byte("unrecognized")...) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneSmallOpenBaoMaterial(m)
			defer clearSmallOpenBaoMaterial(changed)
			mutate(changed)
			if ValidateSmallOpenBaoMaterial(p, changed, now) == nil {
				t.Fatal("changed private material accepted")
			}
		})
	}
	changed := p
	changed.Kubernetes.Endpoint = "https://replacement.invalid"
	if ValidateSmallOpenBaoMaterial(changed, m, now) == nil || ValidateSmallOpenBaoMaterial(p, m, now.AddDate(2, 0, 0)) == nil {
		t.Fatal("replacement source or expired TLS accepted")
	}
	second, err := BuildSmallOpenBaoMaterial(p, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clearSmallOpenBaoMaterial(second)
	if bytes.Equal(m[contracts.SmallOpenBaoSealKey], second[contracts.SmallOpenBaoSealKey]) || bytes.Equal(m["ca.crt"], second["ca.crt"]) {
		t.Fatal("generation reused randomness; owner must persist the original result")
	}
}

func TestSmallOpenBaoPlanAndConfigurationAreClosed(t *testing.T) {
	p := smallOpenBaoFixturePlan(t, time.Now().UTC())
	for name, change := range map[string]func(*contracts.SmallOpenBaoPlan){
		"foreign setup": func(p *contracts.SmallOpenBaoPlan) { p.SetupAccount = "another-runner" },
		"tag image":     func(p *contracts.SmallOpenBaoPlan) { p.Image = "openbao/openbao:latest" },
		"plaintext api": func(p *contracts.SmallOpenBaoPlan) { p.Kubernetes.Endpoint = "http://api.invalid" },
		"api path":      func(p *contracts.SmallOpenBaoPlan) { p.Kubernetes.Endpoint = "https://api.invalid/path" },
		"api user":      func(p *contracts.SmallOpenBaoPlan) { p.Kubernetes.Endpoint = "https://user@api.invalid" },
		"no roots":      func(p *contracts.SmallOpenBaoPlan) { p.Kubernetes.Roots = nil },
		"duplicate roots": func(p *contracts.SmallOpenBaoPlan) {
			p.Kubernetes.Roots = append(p.Kubernetes.Roots, p.Kubernetes.Roots[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := p
			change(&copy)
			if copy.Valid() {
				t.Fatal("invalid plan accepted")
			}
		})
	}
	raw, _ := json.Marshal(p)
	if _, err := contracts.DecodeSmallOpenBaoPlan(strings.NewReader(strings.TrimSuffix(string(raw), "}") + `,"privateKey":"forbidden"}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := contracts.DecodeSmallOpenBaoPlan(strings.NewReader(string(raw) + string(raw))); err == nil {
		t.Fatal("trailing object accepted")
	}
	command := contracts.SmallOpenBaoServerCommand()
	command[0] = "wrong"
	if contracts.SmallOpenBaoServerCommand()[0] != "/usr/bin/bao" {
		t.Fatal("shared command mutated")
	}
	data, err := SmallOpenBaoConfiguration(p, "00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("ui = false")) || bytes.Contains(data, []byte("disable_mlock")) || bytes.Contains(data, []byte("token_reviewer_jwt")) || bytes.Contains(data, []byte("root_token")) || !bytes.Contains(data, []byte(`"token_explicit_max_ttl" = 900`)) || !bytes.Contains(data, []byte(`"disable_local_ca_jwt" = false`)) || !bytes.Contains(data, []byte(contracts.SmallOpenBaoSetupAudience)) {
		t.Fatal("fixed bootstrap configuration changed")
	}
	marker, err := SmallOpenBaoBackendPolicy("00000000-0000-4000-8000-000000000001")
	if err != nil || marker != `{"path":{"asservat-backend/00000000-0000-4000-8000-000000000001":{"capabilities":["deny"]}}}` || !bytes.Contains(data, []byte(contracts.SmallOpenBaoBackendPolicyPath)) || bytes.Contains(data, []byte("metadata-mount")) {
		t.Fatal("final marker must carry exactly original backend and no granted capability")
	}
	if _, err := SmallOpenBaoBackendPolicy("replacement"); err == nil {
		t.Fatal("invalid backend marker accepted")
	}
	if !bytes.Contains(data, []byte("auth/token/roles/asservat-inspection")) || !bytes.Contains(data, []byte(`"allowed_policies_glob" = ["asservat-*-inspection"]`)) || !bytes.Contains(data, []byte(`"token_explicit_max_ttl" = 600`)) || !bytes.Contains(data, []byte(`"disallowed_policies" = ["root","default"]`)) || bytes.Index(data, []byte(`request "inspection-role"`)) > bytes.Index(data, []byte(`request "backend-identity"`)) {
		t.Fatal("inspection role must be bounded and initialized before completion marker")
	}
}

// This opt-in exports the ACTUAL generator output into the owned component's
// external private directory. It grants no product activation/provider rights.
func TestSmallOpenBaoComponentMaterial(t *testing.T) {
	dir := os.Getenv("ASSERVAT_SMALL_OPENBAO_COMPONENT_MATERIAL")
	if dir == "" {
		t.Skip("owned component export only")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("external absolute private directory required")
	}
	now := time.Now().UTC().Truncate(time.Second)
	p := smallOpenBaoFixturePlan(t, now)
	m, err := BuildSmallOpenBaoMaterial(p, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clearSmallOpenBaoMaterial(m)
	for name, raw := range m {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var certs []*x509.Certificate
	for _, der := range p.Kubernetes.Roots {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, cert)
	}
	if len(certs) != 1 {
		t.Fatal("component API root missing")
	}
}
