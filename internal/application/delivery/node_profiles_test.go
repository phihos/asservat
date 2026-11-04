package delivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
)

type profileSink struct {
	results []collector.ProfileResult
	bytes   []byte
	err     error
	during  func()
}

func (s *profileSink) DeliverProfile(_ context.Context, _ collector.Identity, r collector.ProfileResult, body io.Reader) error {
	if s.during != nil {
		s.during()
	}
	s.results = append(s.results, r)
	s.bytes, _ = io.ReadAll(body)
	return s.err
}
func TestProfileDeliveryBindsProcessRequestAndSingleUse(t *testing.T) {
	ch, _, clock, _ := newChannel(t)
	clock.t = time.Now().UTC().Truncate(time.Microsecond)
	peer, _ := enroll(t, ch, epochA)
	const id = "00000000-0000-4000-8000-000000000001"
	// Use a real-shaped immutable UID while retaining the enrolled test process.
	entry := ch.nodes[peer.NodeUID]
	delete(ch.nodes, peer.NodeUID)
	entry.id.NodeUID = id
	ch.nodes[id] = entry
	peer.NodeUID = id
	entry.report = &collector.Report{Mechanisms: []collector.Availability{{Mechanism: collector.MechanismProfile, Prerequisites: true, Adapter: collector.AdapterAvailable}}}
	entry.reportedAt = clock.now()
	now := clock.now()
	p := collector.ProfileCapture{CaptureID: id, CollectorEpoch: epochA, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: "targetLoopback", Address: netip.MustParseAddr("127.0.0.1"), Port: 6060, Host: "localhost", Request: execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: id, ArtifactID: id, AttemptID: id, MediaType: artifact.ProfileMediaType}, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: id, Name: "app-0", UID: id, NodeName: entry.id.NodeName}, NodeUID: id, NodeBootID: boot, SourceRef: "pprof", EndpointDigest: artifact.Digest{3}, Parameters: execution.GoProfileParameters{Type: "heap", Mode: "snapshot"}, NativeLimit: 16 << 20, NotBefore: now, Deadline: now.Add(5 * time.Second)}}
	sink := &profileSink{}
	ch.SetProfileSink(sink)
	w, err := ch.EnqueueProfile(context.Background(), p, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ch.EnqueueProfile(context.Background(), p, now.Add(time.Second)); !errors.Is(err, ErrNodeConflict) {
		t.Fatal("duplicate start", err)
	}
	r := collector.ProfileResult{WorkID: w.ID, CaptureID: id, ExpectationDigest: p.ExpectationDigest, EndpointDigest: p.Request.EndpointDigest, Outcome: execution.GoProfileOutcome{Format: artifact.PprofFormat, StartedAt: now, CompletedAt: now, MayHaveStarted: true, ResponseComplete: true, NativeBytes: 3}}
	for _, change := range []string{"endpoint", "expectation", "future", "bytes", "epoch"} {
		bad := r
		remote := peer
		switch change {
		case "endpoint":
			bad.EndpointDigest[0]++
		case "expectation":
			bad.ExpectationDigest[0]++
		case "future":
			bad.Outcome.CompletedAt = now.Add(time.Second)
		case "bytes":
			bad.Outcome.NativeBytes = p.Request.NativeLimit + 1
		case "epoch":
			remote.Epoch = epochB
		}
		if err := ch.DeliverProfile(context.Background(), remote, epochA, bad, bytes.NewBufferString("abc")); err == nil {
			t.Fatal("invalid result", change)
		}
	}
	if len(sink.results) != 0 {
		t.Fatal("invalid result reached sink")
	}
	sink.during = func() {
		stop, end := context.WithDeadline(t.Context(), now.Add(time.Second))
		defer end()
		if _, err := ch.EnqueueProfileCancel(stop, id, p.CaptureID, w.ID, now.Add(time.Second)); err != nil {
			t.Error("active upload lost restrictive cancellation identity", err)
		}
		if err := ch.DeliverProfile(t.Context(), peer, epochA, r, bytes.NewBufferString("abc")); !errors.Is(err, ErrNodeConflict) {
			t.Error("active upload accepted duplicate delivery", err)
		}
	}
	sink.err = errors.New("unknown store result")
	if err := ch.DeliverProfile(context.Background(), peer, epochA, r, bytes.NewBufferString("abcdef")); !errors.Is(err, ErrNodeUnavailable) {
		t.Fatal(err)
	}
	if len(sink.results) != 1 || string(sink.bytes) != "abc" {
		t.Fatal("unbounded result", sink.results, string(sink.bytes))
	}
	if err := ch.DeliverProfile(context.Background(), peer, epochA, r, bytes.NewBufferString("abc")); !errors.Is(err, ErrNodeConflict) {
		t.Fatal("uncertain delivery replay", err)
	}
}

func TestProfileTLSQueueRequiresCurrentExplicitCapability(t *testing.T) {
	ch, _, clock, changes := newChannel(t)
	clock.t = time.Now().UTC().Truncate(time.Microsecond)
	peer, _ := enroll(t, ch, epochA)
	const id = "00000000-0000-4000-8000-000000000001"
	entry := ch.nodes[peer.NodeUID]
	delete(ch.nodes, peer.NodeUID)
	entry.id.NodeUID = id
	ch.nodes[id] = entry
	peer.NodeUID = id
	now := clock.now()
	r := report(1, now)
	r.Mechanisms = []collector.Availability{{Mechanism: collector.MechanismProfile, Prerequisites: true, Adapter: collector.AdapterAvailable}}
	if err := ch.Report(peer, epochA, r); err != nil {
		t.Fatal(err)
	}
	material := execution.GoProfileTLSMaterial{RootsPEM: "bounded public bytes", ServerName: "profile.internal"}
	material.RootsDigest = artifact.Digest(sha256.Sum256([]byte(material.RootsPEM)))
	p := collector.ProfileCapture{CaptureID: id, CollectorEpoch: epochA, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: "targetLoopback", Address: netip.MustParseAddr("127.0.0.1"), Port: 6060, Host: "localhost", TLS: material, Request: execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: id, ArtifactID: id, AttemptID: id, MediaType: artifact.ProfileMediaType}, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: id, Name: "app", UID: id, NodeName: entry.id.NodeName}, NodeUID: id, NodeBootID: boot, SourceRef: "pprof", EndpointDigest: artifact.Digest{3}, Parameters: execution.GoProfileParameters{Type: "heap", Mode: "snapshot"}, NativeLimit: 16 << 20, NotBefore: now, Deadline: now.Add(10 * time.Second)}}
	if _, err := ch.EnqueueProfile(t.Context(), p, now.Add(time.Second)); !errors.Is(err, ErrNodeUnavailable) || len(entry.work) != 0 || len(entry.captures) != 0 {
		t.Fatal("HTTP-only collector received TLS", err)
	}
	// Updating the same current process report must publish a changed assessment.
	before := len(*changes)
	clock.add(time.Second)
	r.Sequence++
	r.Mechanisms = append([]collector.Availability(nil), r.Mechanisms...)
	r.ObservedAt = clock.now()
	r.Mechanisms[0].ProfileTLS = true
	if err := ch.Report(peer, epochA, r); err != nil || len(*changes) != before+1 {
		t.Fatal("TLS implementation observation not published", err, len(*changes), before)
	}
	w, err := ch.EnqueueProfile(t.Context(), p, now.Add(2*time.Second))
	if err != nil || w.Profile.TLS != material {
		t.Fatal("current TLS collector refused", err)
	}
	p.TLS.RootsPEM = "changed caller copy"
	polled, err := ch.Poll(t.Context(), peer, epochA, 0, 0)
	if err != nil || len(polled) != 1 || polled[0].Profile.TLS != material {
		t.Fatal("caller mutation changed queued public trust", err)
	}
	clock.add(collector.StatusStaleAfter + time.Second)
	if ch.Nodes()[0].ProfileTLSAvailable() {
		t.Fatal("stale report enabled TLS")
	}
}
