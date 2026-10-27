package contextstart

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// A work lease belongs to one frameStream and only bounds transport. It is
// never returned through an application process/permission/identity reader.
// The first complete observation retains its original start and earliest end.
// Final result validation can shorten that end, never replace the lease.
type framePeerLease struct {
	receiver fleet.APIContextReceiver
	final    bool
	regional bool
	history  bool
	phase    framePeerPhase
}

type framePeerPhase uint8

const (
	peerIdentityIdle framePeerPhase = iota
	peerIdentityReply
	peerResult
	peerReceipt
)

type framePeerBound struct {
	stop   func() bool
	cancel context.CancelFunc
	done   chan struct{}
}
type framePeerMode uint8

const (
	peerFrame framePeerMode = iota
	peerWork
	peerFinal
)

// observePeer reserves a first/final attempt before blocking. An unsuccessful
// attempt cannot fall back to an old observation or be retried in this stream.
// Streams without an admitted work keep their original fresh-check behavior.
func (s *frameStream) observePeer(ctx context.Context, mode framePeerMode) (fleet.APIContextReceiver, framePeerMode, error) {
	var zero fleet.APIContextReceiver
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || ctx.Err() != nil {
		s.mu.Unlock()
		return zero, peerFrame, fleet.ErrUnavailable
	}
	if mode == peerWork {
		if s.leaseStarted {
			s.mu.Unlock()
			return zero, peerFrame, fleet.ErrDenied
		}
		s.leaseStarted = true
		s.mu.Unlock()
		observed, e := s.check(ctx)
		return observed, peerWork, e
	}
	if !s.leaseStarted {
		s.mu.Unlock()
		observed, e := s.check(ctx)
		return observed, peerFrame, e
	}
	if s.lease == nil || !s.lease.receiver.Valid(time.Now()) || s.lease.receiver.Channel != s.channel {
		s.mu.Unlock()
		return zero, peerFrame, fleet.ErrUnavailable
	}
	old := s.lease.receiver
	if mode != peerFinal {
		if s.lease.final && len(s.leaseBounds) != 2 {
			s.mu.Unlock()
			return zero, peerFrame, fleet.ErrUnavailable
		}
		s.mu.Unlock()
		return old, peerFrame, nil
	}
	if s.lease.final {
		s.mu.Unlock()
		return zero, peerFrame, fleet.ErrDenied
	}
	s.lease.final = true
	s.mu.Unlock()
	call, cancel := context.WithDeadline(ctx, old.ValidUntil)
	defer cancel()
	observed, e := s.check(call)
	if e != nil {
		return zero, peerFinal, e
	}
	if call.Err() != nil {
		return zero, peerFinal, fleet.ErrUnavailable
	}
	return observed, peerFinal, nil
}

// acceptPeer is called only after the ordinary exact-channel/current-result
// checks. All callbacks are retained before publishing the lease; Close joins
// them after in-flight frame operations. There are at most two per stream.
func (s *frameStream) acceptPeer(ctx context.Context, observed fleet.APIContextReceiver, mode framePeerMode) (fleet.APIContextReceiver, error) {
	if mode == peerFrame {
		return observed, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil || ctx.Err() != nil || !observed.Valid(time.Now()) || observed.Channel != s.channel || !s.leaseStarted {
		return fleet.APIContextReceiver{}, fleet.ErrUnavailable
	}
	switch mode {
	case peerWork:
		if s.lease != nil || len(s.leaseBounds) != 0 {
			return fleet.APIContextReceiver{}, fleet.ErrUnavailable
		}
		if d, ok := ctx.Deadline(); ok {
			observed.ValidUntil = identity.Earlier(observed.ValidUntil, d)
		}
		if !observed.Valid(time.Now()) {
			return fleet.APIContextReceiver{}, fleet.ErrUnavailable
		}
		s.lease = &framePeerLease{receiver: observed, regional: s.awaited, history: s.historyWork}
	case peerFinal:
		if s.lease == nil || !s.lease.final || len(s.leaseBounds) != 1 || !s.lease.receiver.Valid(time.Now()) {
			return fleet.APIContextReceiver{}, fleet.ErrUnavailable
		}
		currentUntil := observed.ValidUntil
		observed = s.lease.receiver
		observed.ValidUntil = identity.Earlier(observed.ValidUntil, currentUntil)
		if d, ok := ctx.Deadline(); ok {
			observed.ValidUntil = identity.Earlier(observed.ValidUntil, d)
		}
		if !observed.Valid(time.Now()) {
			return fleet.APIContextReceiver{}, fleet.ErrUnavailable
		}
		s.lease.receiver = observed
	default:
		return fleet.APIContextReceiver{}, fleet.ErrUnavailable
	}
	// Expiry cancels even when the caller is between frames or blocked inside
	// the application. It never waits for another Send/Receive to notice it.
	bound, cancel := context.WithDeadline(s.ctx, observed.ValidUntil)
	done := make(chan struct{})
	stop := context.AfterFunc(bound, func() { s.interruptAt(streamWorkPeerLease, streamErrorReason(bound.Err())); close(done) })
	s.leaseBounds = append(s.leaseBounds, framePeerBound{stop: stop, cancel: cancel, done: done})
	return observed, nil
}

// A result is checked again after bounded decoding but before its disposition
// reaches the conversation. A later observation can only shorten the work lease.
func (s *frameStream) confirmResultPeer(ctx context.Context) error {
	s.mu.Lock()
	leased := s.leaseStarted
	s.mu.Unlock()
	if !leased {
		return nil
	}
	observed, mode, e := s.observePeer(ctx, peerFinal)
	reason := streamNoReason
	if e != nil {
		reason = streamErrorReason(e)
	} else if !observed.Valid(time.Now()) {
		reason = streamPeerInvalid
	} else if observed.Channel != s.channel {
		reason = streamPeerChanged
	} else if err := ctx.Err(); err != nil {
		reason = streamErrorReason(err)
	}
	if reason == streamNoReason {
		if _, e = s.acceptPeer(ctx, observed, mode); e != nil {
			reason = streamErrorReason(e)
		}
	}
	if reason != streamNoReason {
		s.interruptAt(streamReceivePeer, reason)
		return fleet.ErrUnavailable
	}
	return nil
}

// Only identity question/answer pairs reuse the initial work proof. A final
// result has its own full current check, then exactly one terminal receipt.
// Frame kind/order is checked before a payload reaches its semantic consumer.
func (s *frameStream) admitLeaseFrame(kind contracts.APIContextFrameKind, receive bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.leaseStarted {
		return nil
	}
	if s.closed || s.ctx.Err() != nil || s.lease == nil {
		return fleet.ErrUnavailable
	}
	l := s.lease
	historyKind := kind == contracts.HistoryRequestFrame || kind == contracts.HistoryResponseFrame || kind == contracts.HistoryReceiptFrame
	if l.history != historyKind {
		return contracts.ErrAPIContextProtocol
	}
	switch {
	// One separately signed history effect, then a current-peer final reply.
	case !l.regional && !receive && kind == contracts.HistoryRequestFrame && l.phase == peerIdentityIdle:
		l.phase = peerIdentityReply
	case l.regional && receive && kind == contracts.HistoryRequestFrame && l.phase == peerIdentityIdle:
		l.phase = peerIdentityReply
	case l.regional && !receive && kind == contracts.HistoryResponseFrame && l.phase == peerIdentityReply:
		l.phase = peerResult
	case !l.regional && receive && kind == contracts.HistoryResponseFrame && l.phase == peerIdentityReply:
		l.phase = peerResult
	case l.regional && receive && kind == contracts.HistoryReceiptFrame && l.phase == peerResult && l.final && len(s.leaseBounds) == 2:
		l.phase = peerReceipt
	case !l.regional && !receive && kind == contracts.HistoryReceiptFrame && l.phase == peerResult && l.final && len(s.leaseBounds) == 2:
		l.phase = peerReceipt
	// ADR-171: one hub operation request, then exactly one regional reply.
	case !l.regional && !receive && kind == contracts.APIContextOperationRequestFrame && l.phase == peerIdentityIdle:
		l.phase = peerIdentityReply
	case !l.regional && receive && kind == contracts.APIContextOperationResponseFrame && l.phase == peerIdentityReply:
		l.phase = peerIdentityIdle
	case l.regional && receive && kind == contracts.APIContextOperationRequestFrame && l.phase == peerIdentityIdle:
		l.phase = peerIdentityReply
	case l.regional && !receive && kind == contracts.APIContextOperationResponseFrame && l.phase == peerIdentityReply:
		l.phase = peerIdentityIdle
	case l.regional && !receive && kind == contracts.APIContextResultFrame && l.phase == peerIdentityIdle:
		l.phase = peerResult
	case !l.regional && receive && kind == contracts.APIContextResultFrame && l.phase == peerIdentityIdle:
		l.phase = peerResult
	case l.regional && receive && kind == contracts.APIContextReceiptFrame && l.phase == peerResult && l.final && len(s.leaseBounds) == 2:
		l.phase = peerReceipt
	case !l.regional && !receive && kind == contracts.APIContextReceiptFrame && l.phase == peerResult && l.final && len(s.leaseBounds) == 2:
		l.phase = peerReceipt
	default:
		return contracts.ErrAPIContextProtocol
	}
	return nil
}
