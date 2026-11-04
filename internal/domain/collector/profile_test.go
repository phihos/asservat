package collector

import (
	"net/netip"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/execution"
)

func profileFixture() ProfileCapture {
	const id = "00000000-0000-4000-8000-000000000001"
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	return ProfileCapture{CaptureID: id, CollectorEpoch: id, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: "targetLoopback", Address: netip.MustParseAddr("127.0.0.1"), Port: 6060, Host: "localhost", Request: execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: id, ArtifactID: id, AttemptID: id, MediaType: artifact.ProfileMediaType}, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: id, Name: "app-0", UID: id, NodeName: "node"}, NodeUID: id, NodeBootID: id, SourceRef: "pprof", EndpointDigest: artifact.Digest{3}, Parameters: execution.GoProfileParameters{Type: "cpu", Mode: "interval", Duration: 10 * time.Second}, NativeLimit: 16 << 20, NotBefore: now, Deadline: now.Add(15 * time.Second)}}
}
func TestProfileWorkIsTypedAndBounded(t *testing.T) {
	p := profileFixture()
	w := Work{ID: p.CaptureID, Sequence: 1, Kind: WorkProfileCapture, NotAfter: p.Request.NotBefore.Add(time.Second), Profile: &p}
	if !p.Valid() || Decide(w, p.Request.NotBefore).Reason != ReasonRecorderNotImplemented {
		t.Fatal("valid profile refused")
	}
	for _, change := range []func(*ProfileCapture){func(p *ProfileCapture) { p.Address = netip.MustParseAddr("10.0.0.1") }, func(p *ProfileCapture) { p.Host = "localhost\r\nInjected: yes" }, func(p *ProfileCapture) { p.Request.Parameters.ForceGC = true }, func(p *ProfileCapture) { p.Request.NativeLimit = artifact.MaxPprofBytes + 1 }} {
		bad := p
		change(&bad)
		w.Profile = &bad
		if Decide(w, p.Request.NotBefore).Reason != ReasonWorkUnknown {
			t.Fatal("invalid profile work accepted", bad)
		}
	}
	w.Profile = &p
	w.Kind = WorkPacketCapture
	if Decide(w, p.Request.NotBefore).Reason != ReasonWorkUnknown {
		t.Fatal("profile masqueraded as packet")
	}
	w.Kind = WorkProfileCapture
	w.NotAfter = p.Request.Deadline
	if Decide(w, p.Request.NotBefore).Reason != ReasonWorkUnknown {
		t.Fatal("start margin extended")
	}
}
func TestProfileResultDistinguishesFailedUnstartedFromSuccess(t *testing.T) {
	p := profileFixture()
	r := ProfileResult{WorkID: p.CaptureID, CaptureID: p.CaptureID, ExpectationDigest: p.ExpectationDigest, EndpointDigest: p.Request.EndpointDigest, Failure: ReasonCaptureFailed, Outcome: execution.GoProfileOutcome{Format: artifact.PprofFormat, CompletedAt: p.Request.NotBefore}}
	if !r.Valid() {
		t.Fatal("unstarted failure rejected")
	}
	r.Failure = ""
	if r.Valid() {
		t.Fatal("zero-byte success accepted")
	}
	r.Outcome.StartedAt = p.Request.NotBefore
	r.Outcome.CompletedAt = p.Request.NotBefore.Add(time.Second)
	r.Outcome.MayHaveStarted = true
	r.Outcome.ResponseComplete = true
	r.Outcome.NativeBytes = 100
	if !r.Valid() {
		t.Fatal("complete result rejected")
	}
	r.Failure = ReasonCaptureFailed
	if r.Valid() {
		t.Fatal("failed complete result accepted")
	}
}

func TestProfileUnavailableReasonDoesNotAdmitPacketOrSyscallFailures(t *testing.T) {
	p := profileFixture()
	reason := Reason("ProfileUnavailable")
	r := ProfileResult{WorkID: p.CaptureID, CaptureID: p.CaptureID, ExpectationDigest: p.ExpectationDigest, EndpointDigest: p.Request.EndpointDigest, Failure: reason, Outcome: execution.GoProfileOutcome{Format: artifact.PprofFormat, CompletedAt: p.Request.NotBefore}}
	if !reason.Valid() || !r.Valid() {
		t.Fatal("profile unavailable result rejected")
	}
	packet := PacketResult{WorkID: p.CaptureID, CaptureID: p.CaptureID, StartedAt: p.Request.NotBefore, EndedAt: p.Request.NotBefore, Retained: 1, Seen: 1, CapturedBytes: 64, Snaplen: 96, Failure: ReasonCaptureFailed}
	for _, kind := range []string{"", artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact} {
		packet.NativeType = kind
		if kind == artifact.SyscallArgumentsArtifact {
			packet.Snaplen = 0
		}
		if !packet.Valid() {
			t.Fatal("invalid non-profile fixture", kind)
		}
		packet.Failure = reason
		if packet.Valid() {
			t.Fatal("profile-only reason accepted by another native kind", kind)
		}
		packet.Failure = ReasonCaptureFailed
	}
	r.Outcome.ResponseComplete = true
	if r.Valid() {
		t.Fatal("failed profile supplied a complete result")
	}
}
