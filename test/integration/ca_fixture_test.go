package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func connectorSQLCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	n := time.Now().UTC().Truncate(time.Second)
	c := &x509.Certificate{SerialNumber: big.NewInt(n.UnixNano()), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: n.Add(-time.Minute), NotAfter: n.Add(24 * time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, c, c, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return parsed, key
}
func connectorSQLCSR(t *testing.T) []byte {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	b, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
