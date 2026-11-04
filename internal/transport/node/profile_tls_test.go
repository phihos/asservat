package node

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/planning"
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

func TestProfileTLSMaximumClosedPollEncodingAndMixedWork(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	now := time.Date(9999, 12, 31, 23, 58, 0, 999999000, time.UTC)
	profile := maximumProfileTLSWork(t)
	p := *profile.Profile
	material := p.TLS
	packet := collector.PacketCapture{CaptureID: id, PodUID: id, Program: make([]planning.BPFInstruction, 256), ProgramDigest: [32]byte{1}, Duration: 30 * time.Second, MaxBytes: 8 << 20}
	for i := range packet.Program {
		packet.Program[i] = planning.BPFInstruction{Code: 65535, Jt: 255, Jf: 255, K: ^uint32(0)}
	}
	if !packet.Valid() {
		t.Fatal("bounded packet payload invalid")
	}
	// Packet domain validation is its existing recorder contract; this shape
	// exercises every existing numeric wire field's widest representation.
	packetWork := WireWork(collector.Work{ID: id, Sequence: ^uint64(0), Kind: collector.WorkPacketCapture, NotAfter: now.Add(time.Second), Packet: &packet})
	for _, profiles := range []int{0, 1, 8, 15, 16} {
		wire := contracts.NodePollResponse{Format: contracts.NodePollFormat, Work: make([]contracts.NodeWork, collector.MaxWorkPerPoll)}
		for i := range wire.Work {
			wire.Work[i] = packetWork
			if i < profiles {
				wire.Work[i] = WireWork(profile)
			}
		}
		raw, err := json.Marshal(wire)
		if err != nil || len(raw) > contracts.NodeMaxResponse {
			t.Fatal("fixed 16-work poll exceeds unchanged ceiling", profiles, len(raw), err)
		}
		decoded, err := contracts.DecodeNodePollResponse(bytes.NewReader(raw))
		if err != nil || !reflect.DeepEqual(decoded, wire) {
			t.Fatal("closed poll roundtrip", profiles, len(raw), err)
		}
		for i := 0; i < len(decoded.Work); i++ {
			back, ok := DomainWork(decoded.Work[i])
			if !ok || (i < profiles && (back.Profile == nil || !reflect.DeepEqual(*back.Profile, p))) || (i >= profiles && (back.Packet == nil || !back.Packet.Valid())) {
				t.Fatal("TLS scope changed at codec", i)
			}
		}
		t.Logf("profiles=%d packets=%d roots=%d encoded=%d ceiling=%d", profiles, 16-profiles, len(material.RootsPEM), len(raw), contracts.NodeMaxResponse)
	}
	legacy := p
	legacy.TLS = execution.GoProfileTLSMaterial{}
	raw, _ := json.Marshal(WireProfile(legacy))
	if bytes.Contains(raw, []byte(`"tls"`)) {
		t.Fatal("legacy HTTP wire changed")
	}
	for _, mutate := range []func(*contracts.NodeProfileTLS){func(m *contracts.NodeProfileTLS) { m.RootsDigest = "" }, func(m *contracts.NodeProfileTLS) { m.ServerName = "https://elsewhere" }, func(m *contracts.NodeProfileTLS) { m.RootsPEM += "x" }} {
		w := WireProfile(p)
		mutate(&w.TLS)
		if _, ok := DomainProfile(w); ok {
			t.Fatal("malformed TLS wire accepted")
		}
	}
}
