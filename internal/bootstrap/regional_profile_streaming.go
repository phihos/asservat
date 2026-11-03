package bootstrap

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/execution"
)

// profileStreamingJournal is private to one prepared, admitted profile attempt
// in its bound connector process. SQL already reserves both final and temporary
// worst-case bytes and binds that process once. This state never reconstructs a
// writer after restart and cannot release those durable charges (ADR-290).
// Generic resumable writers continue to use their durable SQL journal.
type profileStreamingJournal struct {
	mu    sync.Mutex
	plan  artifact.StreamingPlan
	state artifact.StreamingState
	now   func() time.Time
}

func newProfileStreamingJournal(e artifact.ContextExpectation, epoch string, now func() time.Time) (*profileStreamingJournal, error) {
	plan := artifact.StreamingPlan{Registration: e.Registration, WriterEpoch: epoch}
	if e.Profile == nil || now == nil || plan.Validate() != nil {
		return nil, artifact.ErrInvalid
	}
	return &profileStreamingJournal{plan: plan, now: now}, nil
}
func (j *profileStreamingJournal) AdvanceStreaming(ctx context.Context, plan artifact.StreamingPlan, step artifact.StreamingStep) (artifact.StreamingState, bool, error) {
	if ctx == nil {
		return artifact.StreamingState{}, false, execution.ErrInvalid
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if ctx.Err() != nil || !j.now().Before(j.plan.Registration.WriteUntil) {
		return artifact.StreamingState{}, false, execution.ErrExpired
	}
	if !j.plan.Equal(plan) || step.Kind == artifact.StreamRelease {
		return artifact.StreamingState{}, false, execution.ErrDenied
	}
	next, fresh, err := j.state.Advance(j.plan, step)
	if err != nil {
		return artifact.StreamingState{}, false, err
	}
	j.state = next
	// Returned observations cannot edit this writer's spent state.
	next.Parts = append([]artifact.StreamingPart(nil), next.Parts...)
	if next.Receipt != nil {
		receipt := *next.Receipt
		next.Receipt = &receipt
	}
	return next, fresh, nil
}
