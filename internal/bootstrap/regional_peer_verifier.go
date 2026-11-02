package bootstrap

import (
	"context"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
)

// ADR-283 part 3: the connector's Kubernetes peer membership verifier.
//
// A manual recording whose reviewed plan froze Kubernetes peers starts only
// if the region resolves the frozen query to exactly the reviewed members.
// While the node records, one verifier per recording re-resolves the query
// once per second with the same bounded reads as the preview (the target
// namespace only). It stops the recording through the node's capture cancel
// when a frozen member is gone, changed its address or its address belongs to
// another object (peerMembershipChanged), or when no resolution confirmed the
// members within the plan's maxStaleness (peerMembershipStale). A stop
// records the cause; the committed start is never refunded. Members added
// after the review are not captured (the program is fixed), so they do not
// stop a recording.
const (
	// maxPeerVerifiers bounds concurrently verified recordings per connector.
	// One verification is the preview's reads (namespace GET, then a GET and
	// a paged LIST or two per entry: about four requests for one Service or
	// Deployment entry), so eight verifiers stay within the verifier's own
	// 50 QPS client budget without starving target resolution.
	maxPeerVerifiers   = 8
	peerVerifyInterval = time.Second
)

// peerResolver is the region's bounded peer resolution (kube.PodTargets).
type peerResolver interface {
	ResolvePacketPeers(context.Context, targets.PeerRequest) (targets.PeerResolution, error)
}

// SetPeers installs the verifier's resolver. Without it a recording with
// Kubernetes peers is refused at start.
func (h *ConnectorRecordings) SetPeers(r peerResolver) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.peers = r
}

// peerVerifiersFull reports whether a new recording with Kubernetes peers
// would exceed maxPeerVerifiers; the region's peer query refuses then.
func (h *ConnectorRecordings) peerVerifiersFull() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.verifiers >= maxPeerVerifiers
}

// confirmPeersAtStart resolves the frozen query once before the node work is
// queued. It answers the instant the confirming read started.
func (h *ConnectorRecordings) confirmPeersAtStart(ctx context.Context, frozen targets.FrozenPeers) (time.Time, error) {
	h.mu.Lock()
	resolver, full := h.peers, h.verifiers >= maxPeerVerifiers
	h.mu.Unlock()
	if resolver == nil {
		return time.Time{}, targets.ErrUnavailable
	}
	if full {
		return time.Time{}, targets.ErrPeerVerifierBusy
	}
	started := h.now()
	call, cancel := context.WithTimeout(ctx, frozen.MaxStaleness)
	defer cancel()
	fresh, err := resolver.ResolvePacketPeers(call, frozen.Resolution.Request)
	switch {
	case errors.Is(err, targets.ErrPeerMissing), errors.Is(err, targets.ErrPeerLimit), errors.Is(err, targets.ErrPeerUnsupported):
		return time.Time{}, targets.ErrPeersChanged
	case err != nil:
		return time.Time{}, targets.ErrPeersStale
	case !fresh.Answers(frozen.Resolution.Request) || !slices.Equal(fresh.Members, frozen.Resolution.Members):
		return time.Time{}, targets.ErrPeersChanged
	}
	return started, nil
}

// peerVerifier re-resolves one recording's frozen peers until it ends.
type peerVerifier struct {
	resolve peerResolver
	now     func() time.Time
	after   func(time.Duration) <-chan time.Time
	frozen  targets.FrozenPeers
}

// run checks once per interval from confirmed, the start of the last
// confirming read, until ctx ends or until passes. It returns
// ErrPeersChanged or ErrPeersStale for a stop, nil at the end.
func (v peerVerifier) run(ctx context.Context, confirmed, until time.Time) error {
	// Runtime reads accept the frozen members inside a larger current set,
	// so the bound is the region's member limit, not the reviewed maxEndpoints.
	request := v.frozen.Resolution.Request
	request.MaxEndpoints = targets.MaxPeerEndpoints
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-v.after(peerVerifyInterval):
		}
		started := v.now()
		if !started.Before(until) {
			return nil
		}
		deadline := confirmed.Add(v.frozen.MaxStaleness)
		if !started.Before(deadline) {
			return targets.ErrPeersStale
		}
		call, cancel := context.WithTimeout(ctx, deadline.Sub(started))
		fresh, err := v.resolve.ResolvePacketPeers(call, request)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		switch {
		case errors.Is(err, targets.ErrPeerMissing), errors.Is(err, targets.ErrPeerUnsupported):
			return targets.ErrPeersChanged
		case err == nil && fresh.Answers(request):
			if targets.PeerMembershipChanged(v.frozen.Resolution.Members, fresh.Members) {
				return targets.ErrPeersChanged
			}
			confirmed = started
		}
		// A failed or inconsistent read keeps the last confirmation; it never
		// extends the original freshness bound.
		if !v.now().Before(confirmed.Add(v.frozen.MaxStaleness)) {
			return targets.ErrPeersStale
		}
	}
}

// verifyPeers runs the verifier of a queued recording; the caller counted it
// in h.verifiers under h.mu.
func (h *ConnectorRecordings) verifyPeers(ctx context.Context, held *heldRecording, v peerVerifier, confirmed, until time.Time) {
	defer h.wg.Done()
	err := v.run(ctx, confirmed, until)
	h.mu.Lock()
	h.verifiers--
	failure := ""
	switch {
	case errors.Is(err, targets.ErrPeersChanged):
		failure = evidence.RecordingPeersChanged
	case errors.Is(err, targets.ErrPeersStale):
		failure = evidence.RecordingPeersStale
	}
	if failure == "" || held.outcome.State != evidence.RecordingPending || held.storing {
		// Ended, or the node's result arrived first: that result was
		// captured while the last confirmation was fresh.
		h.mu.Unlock()
		return
	}
	// The stored keys are dropped, so nothing the node still sends can be
	// stored; the start stays charged.
	held.prepared = nil
	held.outcome = evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: failure}
	capture, node, work := held.expectation.CaptureUID, held.nodeUID, held.workID
	h.mu.Unlock()
	h.log("connector recording " + capture + " stopped: " + failure)
	if nodes, ok := h.nodes.(packetCanceller); ok {
		// The channel refuses an until after the call's deadline: derive the
		// deadline from the same instant.
		until := h.now().Add(5 * time.Second)
		call, cancel := context.WithDeadline(context.Background(), until)
		defer cancel()
		if _, err := nodes.EnqueuePacketCancel(call, node, capture, work, until); err != nil {
			h.log("connector recording " + capture + " node cancel not queued; its result will not be stored")
		}
	}
}

// packetCanceller queues the node's capture cancel (delivery.NodeChannel).
// A channel without it leaves the node recording until its duration ends;
// the connector still stores nothing.
type packetCanceller interface {
	EnqueuePacketCancel(ctx context.Context, nodeUID, captureID, workID string, until time.Time) (collector.Work, error)
}
