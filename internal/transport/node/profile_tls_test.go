package node

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/netip"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
)

// This is a real canonical certificate near the public-material ceiling, not
// arbitrary ASCII that would pass the pure value but fail the actual adapter.
func largestProfileTLSRoots(t *testing.T) execution.GoProfileTLSMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var largest string
	for n := 5400; n < 6100; n++ {
		cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "public fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: bytes.Repeat([]byte{1}, n)}}}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		raw := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		if len(raw) > execution.GoProfileTLSRootsLimit {
			break
		}
		largest = raw
	}
	canonical, digest, err := mtls.CanonicalProfileRoots(largest)
	if err != nil || len(canonical) < execution.GoProfileTLSRootsLimit-128 {
		t.Fatal("near-maximum canonical roots", len(canonical), err)
	}
	return execution.GoProfileTLSMaterial{RootsPEM: canonical, RootsDigest: digest, ServerName: strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 61)}
}

func maximumProfileTLSWork(t *testing.T) collector.Work {
	t.Helper()
	const id = "11111111-1111-4111-8111-111111111111"
	now := time.Date(9999, 12, 31, 23, 58, 0, 999999000, time.UTC)
	material := largestProfileTLSRoots(t)
	// Existing text boundaries permit these HTML characters, so default Go JSON
	// escaping is included. PEM contains only canonical base64/delimiters/newlines.
	p := collector.ProfileCapture{CaptureID: id, CollectorEpoch: id, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: "targetLoopback", Address: netip.MustParseAddr("::1"), Port: 65535, Host: strings.Repeat("<", 253), TLS: material, Request: execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: id, ArtifactID: id, AttemptID: id, MediaType: artifact.ProfileMediaType}, Pin: artifact.PinnedPod{Namespace: strings.Repeat("<", 63), NamespaceUID: id, Name: strings.Repeat("<", 253), UID: id, ControllerUID: id, NodeName: strings.Repeat("<", 253)}, NodeUID: id, NodeBootID: id, SourceRef: strings.Repeat("<", 63), EndpointDigest: artifact.Digest{3}, Parameters: execution.GoProfileParameters{Type: "runtimeTrace", Mode: "interval", Duration: 15 * time.Second}, NativeLimit: artifact.MaxGoTraceBytes, NotBefore: now, Deadline: now.Add(25 * time.Second)}}
	if !p.Valid() {
		t.Fatal("maximum TLS request invalid")
	}
	return collector.Work{ID: id, Sequence: ^uint64(0), Kind: collector.WorkProfileCapture, NotAfter: now.Add(time.Second), Profile: &p}
}
