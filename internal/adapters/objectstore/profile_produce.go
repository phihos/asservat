package objectstore

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/application/evidence"
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
	if e.Profile == nil && e.Logs == nil || now == nil || plan.Validate() != nil {
		return nil, artifact.ErrInvalid
	}
	return &profileStreamingJournal{plan: plan, now: now}, nil
}

// PrepareOneShotLogsArtifact uses the same process-owned no-release writer
// journal for one exact admitted logs attempt. Durable charges remain in SQL.
func PrepareOneShotLogsArtifact(ctx context.Context, store *CustodyStore, keys evidence.KeySealer, e artifact.ContextExpectation, writerEpoch string, now func() time.Time) (*PreparedArtifact, error) {
	if e.NativeType != artifact.LogsArtifact || e.Logs == nil || e.Validate() != nil {
		return nil, artifact.ErrInvalid
	}
	journal, err := newProfileStreamingJournal(e, writerEpoch, now)
	if err != nil {
		return nil, err
	}
	producer, err := NewArtifactProducer(store, keys, journal, now)
	if err != nil {
		return nil, err
	}
	prepared, err := producer.Prepare(ctx, e, writerEpoch)
	if err != nil {
		return nil, err
	}
	prepared.storedOnly = true
	return prepared, nil
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

// PrepareOneShotProfileArtifact is the protected connector's large-profile
// composition. The caller supplies the already accepted expectation and bound
// connector epoch; this factory grants no authority. It creates one private
// no-release journal and one-use writer, never exposes a producer or an option
// to bypass verification on another artifact. All charges remain until cleanup.
func PrepareOneShotProfileArtifact(ctx context.Context, store *CustodyStore, keys evidence.KeySealer, e artifact.ContextExpectation, writerEpoch string, now func() time.Time) (*PreparedArtifact, error) {
	if e.Profile == nil || e.Validate() != nil {
		return nil, artifact.ErrInvalid
	}
	journal, err := newProfileStreamingJournal(e, writerEpoch, now)
	if err != nil {
		return nil, err
	}
	producer, err := NewArtifactProducer(store, keys, journal, now)
	if err != nil {
		return nil, err
	}
	prepared, err := producer.Prepare(ctx, e, writerEpoch)
	if err != nil {
		return nil, err
	}
	prepared.storedOnly = true
	return prepared, nil
}
