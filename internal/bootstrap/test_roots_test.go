package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func downloadTestRoot(t *testing.T, serial int64) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(serial), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
