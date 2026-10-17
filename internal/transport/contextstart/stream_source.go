package contextstart

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-178 source frames travel outside the work lease's operation phases.
// The hub pulls a fresh regional source before its attach and work checks;
// the region answers while it still waits for work and pushes one more
// source immediately before its result. Sequences are strictly increasing.

// writeSourceFrame writes one source frame under the single-writer slot and
// the caller's original deadline (at most five seconds).
func (s *frameStream) writeSourceFrame(ctx context.Context, f contracts.APIContextFrame) error {
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || ctx.Err() != nil || s.writes != 0 {
		s.mu.Unlock()
		return fleet.ErrUnavailable
	}
	s.writes++
	s.work.Add(1)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.writes--
		s.mu.Unlock()
		s.work.Done()
	}()
	until := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	if !s.count(len(f.Payload) + 5) {
		s.interruptAt(streamSendAdmission, streamBudget)
		return contracts.ErrAPIContextProtocol
	}
	if e := s.writeDeadline(until); e != nil {
		s.interruptAt(streamSendDeadline, streamErrorReason(e))
		return fleet.ErrUnavailable
	}
	writer := &streamWriteDiagnostic{writer: s.write}
	e := contracts.WriteAPIContextFrame(writer, f)
	if e == nil {
		e = s.flush()
	}
	if e != nil {
		s.interruptAt(streamWrite, streamErrorReason(e))
		return fleet.ErrUnavailable
	}
	if !time.Now().Before(until) {
		s.interruptAt(streamSendResult, streamExpired)
		return fleet.ErrUnavailable
	}
	return nil
}

// nextSequence reserves the next source sequence before any I/O.
func (s *frameStream) nextSequence() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.sourceSeq + 1
	if s.closed || next >= contracts.APIContextMaximumSourceFrames {
		return 0, contracts.ErrAPIContextProtocol
	}
	s.sourceSeq = next
	return next, nil
}

// pullSource is the hub's request for a fresh regional source. Streams without
// a feed (no ADR-178 ingress) never pull.
func (s *frameStream) pullSource(ctx context.Context) error {
	if s == nil || s.sources == nil {
		return nil
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	seq, e := s.nextSequence()
	if e != nil {
		s.interruptAt(streamSendAdmission, streamProtocol)
		return e
	}
	payload, e := contracts.EncodeAPIContextSourceRequest(contracts.APIContextSourceRequest{Format: contracts.APIContextExchangeFormat, ExchangeID: s.channel.ExchangeID, Sequence: seq})
	if e != nil {
		return e
	}
	if e = s.writeSourceFrame(call, contracts.APIContextFrame{Kind: contracts.APIContextSourceRequestFrame, Payload: payload}); e != nil {
		return e
	}
	incoming, e := s.startReader()
	if e != nil {
		return e
	}
	select {
	case f, ok := <-incoming:
		defer clear(f.Payload)
		if !ok || f.Kind != contracts.APIContextSourceFrame {
			s.interruptAt(streamReceiveResult, streamProtocol)
			return fleet.ErrUnavailable
		}
		if e = s.sources.accept(f.Payload, seq); e != nil {
			s.interruptAt(streamReceiveResult, streamErrorReason(e))
			return fleet.ErrUnavailable
		}
		return nil
	case <-call.Done():
		s.interruptAt(streamReceiveCall, streamErrorReason(call.Err()))
		return fleet.ErrUnavailable
	case <-s.ctx.Done():
		return fleet.ErrUnavailable
	}
}

// absorbSource accepts the region's pushed pre-result source on the hub.
func (s *frameStream) absorbSource(f contracts.APIContextFrame) error {
	if s.sources == nil {
		return contracts.ErrAPIContextProtocol
	}
	seq, e := s.nextSequence()
	if e != nil {
		return e
	}
	return s.sources.accept(f.Payload, seq)
}

// answerSource is the region's reply to one hub request while awaiting work.
func (s *frameStream) answerSource(ctx context.Context, f contracts.APIContextFrame) error {
	if s.local == nil {
		return contracts.ErrAPIContextProtocol
	}
	request, e := contracts.DecodeAPIContextSourceRequest(f.Payload)
	if e != nil || request.ExchangeID != s.channel.ExchangeID {
		return contracts.ErrAPIContextProtocol
	}
	seq, e := s.nextSequence()
	if e != nil || seq != request.Sequence {
		return contracts.ErrAPIContextProtocol
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, e := SourceFrame(call, s.local, s.channel.ExchangeID, seq)
	if e != nil {
		return e
	}
	defer clear(out.Payload)
	return s.writeSourceFrame(call, out)
}

// pushSource is the region's fresh source immediately before its result.
func (s *frameStream) pushSource(ctx context.Context) error {
	if s == nil || s.local == nil {
		return nil
	}
	seq, e := s.nextSequence()
	if e != nil {
		return e
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, e := SourceFrame(call, s.local, s.channel.ExchangeID, seq)
	if e != nil {
		return e
	}
	defer clear(out.Payload)
	return s.writeSourceFrame(call, out)
}
