package kms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"testing"
	"time"
)

func (f *ownerProviderNativeFixture) firstEffects(t *testing.T) {
	t.Helper()
	f.admin(http.MethodPost, "sys/mounts/"+f.input.KeyService.AuditMount, map[string]string{"type": "transit"}, 204)
	f.admin(http.MethodPost, f.input.KeyService.AuditMount+"/keys/"+f.input.KeyService.AuditKey, map[string]string{"type": "aes256-gcm96"}, 200)
	f.admin(http.MethodPost, "sys/mounts/"+f.input.KeyService.PKIMount, map[string]string{"type": "pki"}, 204)
	f.admin(http.MethodPost, f.input.KeyService.PKIMount+"/root/generate/internal", map[string]any{"common_name": "synthetic-provider-auth-root", "ttl": "1h", "key_type": "ec", "key_bits": 256}, 200)
	for _, purpose := range []string{"server", "client"} {
		role := map[string]any{"require_cn": false, "use_csr_common_name": false, "use_csr_sans": false, "allow_ip_sans": false, "allow_localhost": false, "allowed_domains": []string{"owner.provider.invalid"}, "allow_bare_domains": true, "key_type": "ec", "key_bits": 256, "server_flag": purpose == "server", "client_flag": purpose == "client", "code_signing_flag": false, "email_protection_flag": false, "key_usage": []string{"DigitalSignature"}, "ext_key_usage": []string{}, "basic_constraints_valid_for_non_ca": true, "not_before_duration": "30s", "max_ttl": "20m", "ttl": "20m"}
		f.admin(http.MethodPost, f.input.KeyService.PKIMount+"/roles/"+purpose, role, 200)
	}
	plain := []byte("synthetic owner audit key material")
	encrypted := f.effect(t, 0, f.input.KeyService.AuditMount+"/encrypt/"+f.input.KeyService.AuditKey, map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plain)}, 200)
	data, ok := encrypted["data"].(map[string]any)
	if !ok {
		t.Fatal("Transit encryption data")
	}
	ciphertext, ok := data["ciphertext"].(string)
	if !ok || ciphertext == "" {
		t.Fatal("Transit ciphertext")
	}
	opened := f.effect(t, 1, f.input.KeyService.AuditMount+"/decrypt/"+f.input.KeyService.AuditKey, map[string]string{"ciphertext": ciphertext}, 200)
	data, ok = opened["data"].(map[string]any)
	if !ok {
		t.Fatal("Transit decryption data")
	}
	encoded, ok := data["plaintext"].(string)
	if !ok {
		t.Fatal("Transit plaintext")
	}
	actual, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || !bytes.Equal(actual, plain) {
		t.Fatal("separated audit key effects failed")
	}
	clear(actual)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	sign := map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "alt_names": "owner.provider.invalid", "ttl": "20m"}
	for i, purpose := range []string{"server", "client"} {
		result := f.effect(t, i+2, f.input.KeyService.PKIMount+"/sign/"+purpose, sign, 200)
		data, ok := result["data"].(map[string]any)
		if !ok {
			t.Fatal("PKI result")
		}
		encoded, ok := data["certificate"].(string)
		if !ok {
			t.Fatal("PKI certificate")
		}
		block, _ := pem.Decode([]byte(encoded))
		if block == nil {
			t.Fatal("PKI PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		want := x509.ExtKeyUsageServerAuth
		if purpose == "client" {
			want = x509.ExtKeyUsageClientAuth
		}
		if len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != want {
			t.Fatal("provider purpose expanded certificate usage")
		}
	}
	paths := []string{f.input.KeyService.AuditMount + "/encrypt/" + f.input.KeyService.AuditKey, f.input.KeyService.AuditMount + "/decrypt/" + f.input.KeyService.AuditKey, f.input.KeyService.PKIMount + "/sign/server", f.input.KeyService.PKIMount + "/sign/client"}
	bodies := []any{map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plain)}, map[string]string{"ciphertext": ciphertext}, sign, sign}
	for i := range f.credentials {
		for j, path := range paths {
			if i != j {
				f.effect(t, i, path, bodies[j], 403)
			}
		}
		f.effect(t, i, "auth/token/create", map[string]string{}, 403)
	}
	t.Log("real generated four-purpose ACLs permit their first exact Transit/PKI effect and deny every other purpose and token creation; no installed effect authority inferred")
}

func (f *ownerProviderNativeFixture) effect(t *testing.T, purpose int, path string, body any, want int) map[string]any {
	t.Helper()
	credential := f.credentials[purpose]
	transport := &ownerProviderLeaseTransport{base: f.http.Transport, now: time.Now, source: func(context.Context) (ownerProviderLease, error) {
		return ownerProviderLease{token: bytes.Clone(credential.token), until: credential.until, release: func() {}}, nil
	}}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	call, end := context.WithTimeout(f.ctx, 5*time.Second)
	defer end()
	request, err := http.NewRequestWithContext(call, http.MethodPost, f.input.KeyService.Endpoint+"/v1/"+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal("actual finite provider effect unavailable", path, err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("purpose %d %s status %d, want %d", purpose, path, response.StatusCode, want)
	}
	if want == 403 {
		return nil
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	defer clear(encoded)
	var out map[string]any
	if err != nil || len(encoded) > 32768 || json.Unmarshal(encoded, &out) != nil {
		t.Fatal("actual provider effect reply invalid", path)
	}
	return out
}
