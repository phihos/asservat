package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

func TestWorkerPublicKeyDigestIsOriginalAndClosesWithProcess(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	w := &WorkerCredentials{key: key, csr: csr, now: func() time.Time { return now }, target: value.WorkerCredentialTarget{RunUntil: now.Add(time.Minute)}}
	expected := artifact.Digest(sha256.Sum256(spki))
	first, err := w.PublicKeyDigest()
	if err != nil || first != expected {
		t.Fatal("public digest changed original process key", err)
	}
	first[0] ^= 255
	second, err := w.PublicKeyDigest()
	if err != nil || second != expected {
		t.Fatal("caller changed process key identity", err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				got, e := w.PublicKeyDigest()
				if e == nil && got != expected {
					t.Error("concurrent key digest changed")
				}
			}
		})
	}
	w.Close()
	wg.Wait()
	if got, e := w.PublicKeyDigest(); e == nil || got != (artifact.Digest{}) {
		t.Fatal("closed process retained public identity success")
	}
}
