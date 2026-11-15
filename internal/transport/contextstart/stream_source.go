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
func (s *frameStream) writeIdleFrame(ctx context.Context, f contracts.APIContextFrame) error {
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
