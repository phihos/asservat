package node

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
)

func TestProfileWirePreservesExactRequestAndRejectsMalformedRoute(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := collector.ProfileCapture{CaptureID: id, CollectorEpoch: id, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: "targetLoopback", Address: netip.MustParseAddr("::1"), Port: 6060, Host: "localhost", Request: execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: id, ArtifactID: id, AttemptID: id, MediaType: artifact.ProfileMediaType}, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: id, Name: "app-0", UID: id, NodeName: "node"}, NodeUID: id, NodeBootID: id, SourceRef: "pprof", EndpointDigest: artifact.Digest{3}, Parameters: execution.GoProfileParameters{Type: "cpu", Mode: "interval", Duration: 10 * time.Second}, NativeLimit: 16 << 20, NotBefore: now, Deadline: now.Add(15 * time.Second)}}
	w := collector.Work{ID: id, Sequence: 1, Kind: collector.WorkProfileCapture, Profile: &p, NotAfter: now.Add(time.Second)}
	restored, valid := DomainWork(WireWork(w))
	if !valid || !reflect.DeepEqual(restored, w) {
		t.Fatalf("profile roundtrip: %+v", restored)
	}
	for _, change := range []string{"mapped", "noncanonical", "header", "duration", "digest", "cap"} {
		wire := WireProfile(p)
		switch change {
		case "mapped":
			wire.Address = "::ffff:127.0.0.1"
		case "noncanonical":
			wire.Address = "0:0:0:0:0:0:0:1"
		case "header":
			wire.Host = "localhost\r\nCookie: secret"
		case "duration":
			wire.DurationMillis = 60001
		case "digest":
			wire.ExpectationDigest = "00"
		case "cap":
			wire.NativeLimit = artifact.MaxPprofBytes + 1
		}
		if _, ok := DomainProfile(wire); ok {
			t.Fatal("invalid accepted", change)
		}
	}
	r := collector.ProfileResult{WorkID: id, CaptureID: id, ExpectationDigest: p.ExpectationDigest, EndpointDigest: p.Request.EndpointDigest, Outcome: execution.GoProfileOutcome{Format: artifact.PprofFormat, StartedAt: now, CompletedAt: now, MayHaveStarted: true, ResponseComplete: true, NativeBytes: 3}}
	wire := WireProfileResult(id, r)
	out, ok := DomainProfileResult(wire)
	if !ok || !reflect.DeepEqual(out, r) {
		t.Fatal("result roundtrip", out, ok)
	}
	wire.Format = "future-profile"
	if _, ok := DomainProfileResult(wire); ok {
		t.Fatal("unversioned result")
	}
}
