package kubernetes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
)

func profileEndpointTLSRoots(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic endpoint trust"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestProfileEndpointTLSConfigurationBindsCanonicalPublicRoots(t *testing.T) {
	root := profileEndpointTLSRoots(t)
	cluster := "00000000-0000-4000-8000-000000000001"
	e := contracts.RegionalProfileEndpoint{Name: "go-pprof", Kind: "template", AddressModes: []string{"targetLoopback"}, LoopbackFamily: "ipv4", MinPort: 6060, MaxPort: 6060, TLS: &contracts.RegionalProfileEndpointTLS{ServerName: "localhost", RootsPEM: " \n" + strings.ReplaceAll(root, "\n", "\r\n")}}
	entries, err := ProfileEndpointEntries(cluster, []contracts.RegionalProfileEndpoint{e})
	if err != nil {
		t.Fatal(err)
	}
	got := entries[0]
	trust := got.Definition.Source
	trust.Digest = artifact.Digest(sha256.Sum256([]byte(root)))
	if got.TLSMaterial.RootsPEM != root || got.Definition.TLS == nil || got.Definition.TLS.Trust != trust || got.TLSMaterial.RootsDigest != trust.Digest || got.Definition.TLS.ServerName != "localhost" {
		t.Fatal("public trust identity/material mismatch")
	}
	b, _ := json.Marshal(got.Definition)
	if strings.Contains(string(b), "CERTIFICATE") || strings.Contains(string(b), "RootsPEM") {
		t.Fatal("PEM entered canonical definition")
	}
	e.TLS.RootsPEM = "changed caller value"
	if got.TLSMaterial.RootsPEM != root {
		t.Fatal("material aliases caller config")
	}
	for _, tls := range []contracts.RegionalProfileEndpointTLS{
		{ServerName: "localhost", RootsPEM: "junk\n" + root}, {ServerName: "localhost", RootsPEM: root + "junk"}, {ServerName: "localhost", RootsPEM: strings.Repeat(root, 20)}, {ServerName: "localhost", RootsPEM: ""}, {ServerName: "https://localhost", RootsPEM: root}, {ServerName: "", RootsPEM: root},
	} {
		e.TLS = &tls
		if ProfileEndpointsValid([]contracts.RegionalProfileEndpoint{e}) {
			t.Fatal("invalid public TLS configuration accepted")
		}
	}
}

func TestProfileEndpointHTTPLegacyConfigurationBytes(t *testing.T) {
	e := contracts.RegionalProfileEndpoint{Name: "go-pprof", Kind: "template", AddressModes: []string{"targetLoopback"}, MinPort: 6060, MaxPort: 6060, LoopbackFamily: "ipv4"}
	const want = `{"name":"go-pprof","kind":"template","addressModes":["targetLoopback"],"minPort":6060,"maxPort":6060,"loopbackFamily":"ipv4"}`
	b, err := json.Marshal(e)
	if err != nil || string(b) != want {
		t.Fatal("legacy HTTP configuration bytes changed", err)
	}
	entries, err := ProfileEndpointEntries("00000000-0000-4000-8000-000000000001", []contracts.RegionalProfileEndpoint{e})
	if err != nil || entries[0].Definition.Source.Digest != artifact.Digest(sha256.Sum256([]byte(want))) || !entries[0].TLSMaterial.IsZero() || entries[0].Definition.TLS != nil {
		t.Fatal("legacy HTTP source identity changed", err)
	}
}
