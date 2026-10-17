package providerconfig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func bootstrapInputCA(t *testing.T, now time.Time, n int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(n), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func bootstrapInputHint(now time.Time, aud any) []byte {
	raw, _ := json.Marshal(map[string]any{"aud": aud, "exp": now.Add(time.Hour).Unix()})
	return []byte("e30." + base64.RawURLEncoding.EncodeToString(raw) + ".not-a-signature")
}
func TestInitialBootstrapPublicCompilerNormalizesOnlyNonAuthorizingInput(t *testing.T) {
	now := time.Now().UTC()
	ca := bootstrapInputCA(t, now, 1)
	other := bootstrapInputCA(t, now, 2)
	v := contracts.InitialBootstrapInput{Format: contracts.InitialBootstrapInputFormat, Name: "install", BootstrapNamespace: "trusted-bootstrap", TargetNamespace: "asservat", RunnerAccount: "install-bootstrap-runner", Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64), Kubernetes: contracts.InitialBootstrapEndpointInput{Endpoint: "https://kubernetes.example"}, Postgres: contracts.InitialBootstrapPostgresInput{Host: "db.example", Port: 5432, Database: "asservat", MaxConnections: 2, RootsPEM: string(ca)}, AuditStore: contracts.InitialBootstrapAuditStoreInput{Endpoint: "https://storage.example", Region: "test", Bucket: "audit", RootsPEM: string(ca)}, KeyService: contracts.InitialBootstrapKeyServiceInput{Endpoint: "https://bao.example", AuditMount: "transit", AuditKey: "audit", RootsPEM: string(ca)}, Providers: contracts.InitialBootstrapProviders{IssuerPolicy: "issuer", WrapRole: "wrap", WrapPolicy: "encrypt", UnwrapRole: "unwrap", UnwrapPolicy: "decrypt"}}
	// Unsigned input is deliberately only a hint; the result contains no
	// verified actor/token, UID, SQL OID, request or recovery claim.
	d, err := CompileInitialBootstrapInput(v, ca, bootstrapInputHint(now, []string{"api-audience"}), now)
	if err != nil || d.ProbeAudience != "api-audience" || len(d.Administrators) != 1 || d.Administrators[0].Name != "system:serviceaccount:trusted-bootstrap:install-bootstrap-runner" {
		t.Fatal("static normalization failed", err)
	}
	if d.Format != contracts.InitialBootstrapVersionedAuditFormat || len(d.Kubernetes.Roots) != 1 || bytes.Contains(d.Kubernetes.Roots[0], []byte("BEGIN")) {
		t.Fatal("normalizer retained PEM or changed selected fresh profile")
	}
	for _, aud := range []any{[]string{}, []string{"a", "b"}, 123, nil} {
		if _, e := CompileInitialBootstrapInput(v, ca, bootstrapInputHint(now, aud), now); e == nil {
			t.Fatal("ambiguous audience selected automatically")
		}
	}
	v.ProbeAudience = "explicit-audience"
	if _, e := CompileInitialBootstrapInput(v, ca, nil, now); e != nil {
		t.Fatal("explicit audience improperly required claim decoding", e)
	}
	v.Kubernetes.RootsPEM = string(ca) + string(other)
	first, e := CompileInitialBootstrapInput(v, nil, nil, now)
	if e != nil {
		t.Fatal(e)
	}
	v.Kubernetes.RootsPEM = "\n" + strings.ReplaceAll(string(other), "\n", "\r\n") + "\n" + string(ca)
	second, e := CompileInitialBootstrapInput(v, nil, nil, now)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) {
		t.Fatal("equivalent PEM ordering/line endings changed original canonical desired bytes")
	}
	for _, bad := range []string{string(ca) + string(ca), "unrecognized-prefix\n" + string(ca), string(ca) + "trailing-text", strings.Replace(string(ca), "CERTIFICATE", "PRIVATE KEY", 2)} {
		v.Kubernetes.RootsPEM = bad
		if _, e := CompileInitialBootstrapInput(v, nil, nil, now); e == nil {
			t.Fatal("noncertificate, duplicate or ignored PEM text accepted")
		}
	}
}

func TestInitialBootstrapAudienceHintNeverAcceptsExpiredOrDuplicateClaims(t *testing.T) {
	now := time.Now().UTC()
	for _, payload := range []string{`{"aud":"a","aud":"b","exp":9999999999}`, `{"aud":"a","exp":1}`, `{"aud":"a","exp":9999999999,"nbf":9999999998}`, `{"aud":"a","exp":1.5}`, `{"aud":null,"exp":9999999999}`} {
		token := []byte("e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".unsigned")
		if _, e := initialBootstrapAudienceHint(token, now); e == nil {
			t.Fatal("unsupported claim became default audience hint")
		}
	}
}
