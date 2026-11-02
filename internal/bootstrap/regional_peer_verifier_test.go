package bootstrap

import (
	"asservat.local/asservat/internal/application/delivery"
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/evidence"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

// peerClock is a manual clock whose after channels the test fires.
type peerClock struct {
	mu      sync.Mutex
	t       time.Time
	afters  chan chan time.Time
	pending chan time.Time
	done    chan struct{}
}

func (c *peerClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *peerClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func (c *peerClock) after(time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.afters <- ch
	return ch
}

// watch closes done when every verifier of h has ended.
func (c *peerClock) watch(h *ConnectorRecordings) {
	c.done = make(chan struct{})
	go func() { h.wg.Wait(); close(c.done) }()
}

// settle waits until the verifier waits for its next interval (true) or
// has ended (false), so each check completes before the test continues.
func (c *peerClock) settle(t *testing.T) bool {
	t.Helper()
	if c.pending != nil {
		return true
	}
	select {
	case c.pending = <-c.afters:
		return true
	case <-c.done:
		return false
	case <-time.After(5 * time.Second):
		t.Fatal("the verifier neither waits nor ended")
	}
	return false
}

// tick advances one verifier interval, wakes the verifier and waits for
// that check to complete; false once the verifier ended.
func (c *peerClock) tick(t *testing.T) bool {
	t.Helper()
	if !c.settle(t) {
		return false
	}
	c.advance(peerVerifyInterval)
	c.pending <- c.now()
	c.pending = nil
	return c.settle(t)
}

// fakePeers answers each resolution with the current scripted answer.
type fakePeers struct {
	mu      sync.Mutex
	members []targets.PeerMember
	err     error
	calls   int
}

func (f *fakePeers) set(members []targets.PeerMember, err error) {
	f.mu.Lock()
	f.members, f.err = members, err
	f.mu.Unlock()
}

func (f *fakePeers) ResolvePacketPeers(_ context.Context, r targets.PeerRequest) (targets.PeerResolution, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return targets.PeerResolution{}, f.err
	}
	return targets.PeerResolution{Request: r, Members: append([]targets.PeerMember(nil), f.members...)}, nil
}

type cancelRecordingNodes struct {
	*fakeRecordingNodes
	mu      sync.Mutex
	cancels []collector.PacketCancel
}

// EnqueuePacketCancel enforces delivery.NodeChannel's rule that the cancel's
// until is not after the call's deadline.
func (n *cancelRecordingNodes) EnqueuePacketCancel(ctx context.Context, _, captureID, workID string, until time.Time) (collector.Work, error) {
	if end, ok := ctx.Deadline(); !ok || until.After(end) {
		return collector.Work{}, delivery.ErrNodeUnavailable
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.cancels = append(n.cancels, collector.PacketCancel{CaptureID: captureID, WorkID: workID})
	return collector.Work{}, nil
}

func (n *cancelRecordingNodes) cancelled() []collector.PacketCancel {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]collector.PacketCancel(nil), n.cancels...)
}

var frozenMember = targets.PeerMember{Kind: "Pod", UID: "11111111-aaaa-4aaa-8aaa-111111111111", IP: "10.0.0.11"}

// peerExpectation is a recording whose plan froze one Pod peer.
func peerExpectation(t *testing.T, now time.Time) artifact.ContextExpectation {
	t.Helper()
	e := recordingExpectation(now)
	e.Recording.Filter = &artifact.RecordingFilter{Expression: "(net 10.0.0.11/32) and tcp", Program: []artifact.FilterInstruction{{Code: 6, K: 65535}}}
	request := targets.PeerRequest{ClusterID: "66666666-6666-4666-8666-666666666666", Namespace: cfg.NamespaceRef{Name: "app", UID: "ns-uid"}, MaxEndpoints: 4,
		Entries: []targets.PeerEntry{{Resource: &targets.PeerResourceRef{Kind: "Pod", Namespace: "app", Name: "db"}}}}
	peers, err := compiler.RecordingPeersOf(targets.PeerResolution{Request: request, Members: []targets.PeerMember{frozenMember}, ResolvedAt: now.Add(-time.Minute)}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	e.Recording.Peers = peers
	if !e.Recording.Valid() {
		t.Fatal("invalid peer recording")
	}
	return e
}

func peerHolder(now time.Time) (*ConnectorRecordings, *peerClock, *fakePeers, *cancelRecordingNodes) {
	clock := &peerClock{t: now, afters: make(chan chan time.Time)}
	nodes := &cancelRecordingNodes{fakeRecordingNodes: &fakeRecordingNodes{available: true}}
	h := NewConnectorRecordings(nodes, fakePodNodes{}, clock.now, func(string) {})
	h.after = clock.after
	resolver := &fakePeers{members: []targets.PeerMember{frozenMember}}
	h.SetPeers(resolver)
	return h, clock, resolver, nodes
}

var peerPin = artifact.PinnedPod{UID: "pod-uid", NamespaceUID: "ns-uid", Namespace: "app", Name: "web"}

// ADR-283 part 3: while the node records, the connector re-resolves the
// frozen peers once per second; a stable set keeps running, a gone or
// reassigned member stops with PeerMembershipChanged, and reads that fail
// past maxStaleness stop with PeerMembershipStale. A stop drops the keys,
// cancels the node capture and never stores a later result.
func TestPeerVerifierStopsRecordingOnMembershipChange(t *testing.T) {
	other := targets.PeerMember{Kind: "Pod", UID: "22222222-bbbb-4bbb-8bbb-222222222222", IP: "10.0.0.11"}
	for _, tc := range []struct {
		name    string
		members []targets.PeerMember
		err     error
		ticks   int
		failure string
	}{
		// Runs until the recording window (start allowance + duration) ends.
		{name: "stable", members: []targets.PeerMember{frozenMember, {Kind: "Pod", UID: "33333333-cccc-4ccc-8ccc-333333333333", IP: "10.0.0.20"}}, ticks: 11},
		{name: "uid gone", members: []targets.PeerMember{}, ticks: 1, failure: evidence.RecordingPeersChanged},
		{name: "deleted", err: targets.ErrPeerMissing, ticks: 1, failure: evidence.RecordingPeersChanged},
		{name: "ip reassigned", members: []targets.PeerMember{other, {Kind: "Pod", UID: frozenMember.UID, IP: "10.0.0.12"}}, ticks: 1, failure: evidence.RecordingPeersChanged},
		{name: "same uid new ip", members: []targets.PeerMember{{Kind: "Pod", UID: frozenMember.UID, IP: "10.0.0.12"}}, ticks: 1, failure: evidence.RecordingPeersChanged},
		{name: "stale", err: targets.ErrUnavailable, ticks: 5, failure: evidence.RecordingPeersStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Ahead of the wall clock, so a deadline taken from the wall clock
			// instead of the verifier's own instant would refuse the cancel.
			now := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
			h, clock, resolver, nodes := peerHolder(now)
			e := peerExpectation(t, now)
			queued, err := h.Prepare(&objectstore.PreparedArtifact{}, e).StartRecording(context.Background(), peerPin, now, now.Add(time.Second))
			if err != nil || !queued.Equal(now) || len(nodes.work) != 1 || resolver.calls != 1 {
				t.Fatal(queued, err, len(nodes.work), resolver.calls)
			}
			clock.watch(h)
			// One stable check, then the scripted membership.
			if !clock.tick(t) {
				t.Fatal("a stable check ended the verifier")
			}
			resolver.set(tc.members, tc.err)
			ended := false
			for range tc.ticks {
				if !clock.tick(t) {
					ended = true
					break
				}
			}
			if !ended {
				t.Fatal("the verifier still runs")
			}
			w := fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(e)}
			c, err := h.Collect(w)
			if err != nil || !c.Valid(e.Registration) {
				t.Fatal(c, err)
			}
			if h.verifiers != 0 {
				t.Fatal("verifier still counted", h.verifiers)
			}
			if tc.failure == "" {
				if c.State != evidence.RecordingPending || len(nodes.cancelled()) != 0 {
					t.Fatal("a stable membership stopped the recording", c)
				}
				return
			}
			if c.State != evidence.RecordingFailed || c.Failure != tc.failure || !c.Acquired.Equal(queued) {
				t.Fatal(c)
			}
			if got := nodes.cancelled(); len(got) != 1 || got[0].CaptureID != e.CaptureUID || got[0].WorkID != nodes.work[0].ID {
				t.Fatal("node capture not cancelled", got)
			}
			// The node's later result is discarded, never stored.
			result := collector.PacketResult{WorkID: nodes.work[0].ID, CaptureID: e.CaptureUID, StartedAt: now, EndedAt: clock.now(), CapturedBytes: 260, Snaplen: 134, Failure: collector.ReasonCaptureFailed}
			if err := h.DeliverPacket(context.Background(), collector.Identity{NodeUID: "node-1"}, result, bytes.NewReader(make([]byte, 260))); err == nil {
				t.Fatal("a stopped recording accepted a result")
			}
			if again, _ := h.Collect(w); again.Failure != tc.failure {
				t.Fatal("stop reason overwritten", again)
			}
		})
	}
}

// ADR-283 part 3: the start resolves the frozen query once more and refuses
// before queueing unless it answers exactly the reviewed members; without a
// resolver or beyond the verifier cap nothing is queued either.
func TestPeerRecordingStartChecks(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	added := targets.PeerMember{Kind: "Pod", UID: "33333333-cccc-4ccc-8ccc-333333333333", IP: "10.0.0.20"}
	for _, tc := range []struct {
		name    string
		members []targets.PeerMember
		err     error
		want    error
	}{
		{name: "member gone", members: []targets.PeerMember{}, want: targets.ErrPeersChanged},
		{name: "member added", members: []targets.PeerMember{frozenMember, added}, want: targets.ErrPeersChanged},
		{name: "peer deleted", err: targets.ErrPeerMissing, want: targets.ErrPeersChanged},
		{name: "unconfirmed", err: targets.ErrUnavailable, want: targets.ErrPeersStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, resolver, nodes := peerHolder(now)
			resolver.set(tc.members, tc.err)
			_, err := h.Prepare(&objectstore.PreparedArtifact{}, peerExpectation(t, now)).StartRecording(context.Background(), peerPin, now, now.Add(time.Second))
			if !errors.Is(err, tc.want) || len(nodes.work) != 0 || h.verifiers != 0 {
				t.Fatal(err, len(nodes.work))
			}
		})
	}
	h, _, _, nodes := peerHolder(now)
	h.verifiers = maxPeerVerifiers
	if !h.peerVerifiersFull() {
		t.Fatal("cap not reported")
	}
	if _, err := h.Prepare(&objectstore.PreparedArtifact{}, peerExpectation(t, now)).StartRecording(context.Background(), peerPin, now, now.Add(time.Second)); !errors.Is(err, targets.ErrPeerVerifierBusy) || len(nodes.work) != 0 {
		t.Fatal("started beyond the verifier cap", err)
	}
	h.verifiers = maxPeerVerifiers - 1
	if h.peerVerifiersFull() {
		t.Fatal("cap reported early")
	}
	bare := NewConnectorRecordings(&fakeRecordingNodes{available: true}, fakePodNodes{}, func() time.Time { return now }, func(string) {})
	if _, err := bare.Prepare(&objectstore.PreparedArtifact{}, peerExpectation(t, now)).StartRecording(context.Background(), peerPin, now, now.Add(time.Second)); !errors.Is(err, targets.ErrUnavailable) {
		t.Fatal("started without a peer resolver", err)
	}
}

// The node's result ends the verifier; a later change does not touch it.
func TestPeerVerifierEndsWithNodeResult(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	h, clock, resolver, nodes := peerHolder(now)
	e := peerExpectation(t, now)
	if _, err := h.Prepare(&objectstore.PreparedArtifact{}, e).StartRecording(context.Background(), peerPin, now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	clock.watch(h)
	if !clock.tick(t) {
		t.Fatal("a stable check ended the verifier")
	}
	result := collector.PacketResult{WorkID: nodes.work[0].ID, CaptureID: e.CaptureUID, StartedAt: now, EndedAt: clock.now(), CapturedBytes: 260, Snaplen: 134, Failure: collector.ReasonCaptureFailed}
	if err := h.DeliverPacket(context.Background(), collector.Identity{NodeUID: "node-1"}, result, bytes.NewReader(make([]byte, 260))); err != nil {
		t.Fatal(err)
	}
	resolver.set(nil, targets.ErrPeerMissing)
	<-clock.done
	w := fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(e)}
	if c, _ := h.Collect(w); c.Failure != "captureFailed" || len(nodes.cancelled()) != 0 {
		t.Fatal("the verifier overwrote the node's outcome", c)
	}
}
