package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/execution"
)

func profileRootFixture(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic profile root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestProfileRootsCanonicalExplicitBundle(t *testing.T) {
	root := profileRootFixture(t)
	input := " \n" + strings.ReplaceAll(root, "\n", "\r\n") + "\n" + root + " \t"
	canonical, digest, err := CanonicalProfileRoots(input)
	if err != nil || canonical != root+root || digest != artifact.Digest(sha256.Sum256([]byte(canonical))) {
		t.Fatal("public bundle normalization/digest", err)
	}
	material := execution.GoProfileTLSMaterial{RootsPEM: canonical, RootsDigest: digest, ServerName: "localhost"}
	if !material.Valid() {
		t.Fatal("canonical parser and pure value disagree")
	}
	again, other, err := CanonicalProfileRoots(canonical)
	if err != nil || again != canonical || other != digest {
		t.Fatal("canonical material not stable", err)
	}
}

func TestProfileRootsRejectIgnoredJunkHeadersAndOversize(t *testing.T) {
	root := profileRootFixture(t)
	malformedFirst := "-----BEGIN CERTIFICATE-----\ninvalid!\n" + root
	for name, input := range map[string]string{
		"empty": "", "whitespace": " \n", "prefix": "ignored\n" + root, "suffix": root + "ignored", "middle": root + "ignored\n" + root,
		"headers":                strings.Replace(root, "-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\nComment: ignored\n", 1),
		"other-block":            root + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("private fixture")})),
		"bad-der":                string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})),
		"malformed-before-valid": malformedFirst,
		"oversize":               strings.Repeat(" ", execution.GoProfileTLSRootsLimit) + root,
	} {
		t.Run(name, func(t *testing.T) {
			canonical, digest, err := CanonicalProfileRoots(input)
			if !errors.Is(err, ErrProfileRoots) || canonical != "" || digest != (artifact.Digest{}) {
				t.Fatal("non-certificate/junk material admitted", err)
			}
		})
	}
}
