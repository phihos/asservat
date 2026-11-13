package bootstrap

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestServingTLSMaterialVerifiesForEveryName(t *testing.T) {
	names := []string{"asservat-federation", "asservat-federation.ns.svc"}
	data, err := servingTLSMaterial("asservat-federation-tls", names, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(data["tls.crt"], data["tls.key"])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data["ca.crt"]) {
		t.Fatal("ca.crt")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots}); err != nil {
			t.Fatal(name, err)
		}
	}
	if _, err := servingTLSMaterial("x", nil, time.Now()); err == nil {
		t.Fatal("no names accepted")
	}
}
