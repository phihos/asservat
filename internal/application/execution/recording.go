package execution

import (
	"context"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
)

// RecordingExecutions is the hub's SQL facet for collecting started manual
// recordings (ADR-248). It reads without a human identity: the recording was
// authorized when it started; collecting only records its stored completion
// (or failure) with a current connector process observation.
type RecordingExecutions interface {
	StartedRecordings(ctx context.Context, startedBefore time.Time, limit int) ([]string, error)
	ReadRecordingWork(ctx context.Context, captureID string, recovery artifact.RecoveryProof) (APIContextWork, value.APIExecution, error)
}

// CollectRecording records the outcome of one started recording from one
// collect exchange. A recording still in progress stays started ("Recording").
// A stored completion is recorded like the ADR-171 stored path; a failed
// recording records captureFailed or storeUnconfirmed.
func (s APIContextRunner) CollectRecording(ctx context.Context, w APIContextWork, r value.APIExecution, collector evidence.RecordingCollector) (ContextResult, error) {
	e := w.Accepted.Expectation
	if ctx == nil || collector == nil || s.Process == nil || s.Record == nil || s.Recovery == nil || s.Now == nil || (e.Recording == nil && e.Snapshot == nil && e.Profile == nil && e.Logs == nil) || r.Phase != "started" || r.ExpectationDigest != evidence.ContextExpectationDigest(e) {
		return ContextResult{}, executeStep{"collect", value.ErrInvalid}
	}
	completionRecorder, ok := s.Record.(APIStoredCompletionRecorder)
	if !ok && e.Snapshot == nil {
		return ContextResult{}, executeStep{"collect", value.ErrUnavailable}
	}
	c, err := collector.CollectRecording(ctx)
	if err != nil {
		return ContextResult{State: "Recording"}, executeStep{"CollectRecording", err}
	}
	if !c.Valid(e.Registration) {
		return ContextResult{State: "Indeterminate"}, executeStep{"CollectRecording", value.ErrInvalid}
	}
	if c.State == evidence.RecordingPending {
		return ContextResult{State: "Recording"}, nil
	}
	process, err := s.Process.ReadAPIProcess(ctx)
	if err != nil {
		return ContextResult{State: "Indeterminate"}, executeStep{"ReadAPIProcess", err}
	}
	result := r
	if c.State == evidence.RecordingCancelled && e.Logs != nil {
		joined := c.LogsCancellation
		if joined == nil || joined.CaptureID != e.CaptureUID || joined.AttemptID != e.Registration.Location.AttemptID || joined.ExpectationDigest != r.ExpectationDigest || joined.WriterPodUID != r.Process.PodUID || joined.WriterEpoch != r.Process.ProcessEpoch || joined.JoinedAt.Before(r.StartedAt) || joined.JoinedAt.After(s.Now()) {
			return ContextResult{State: "Indeterminate"}, executeStep{"LogsCancellation", value.ErrInvalid}
		}
		recorder, ok := s.Record.(APILogsCancellationRecorder)
		if !ok {
			return ContextResult{State: "Indeterminate"}, value.ErrUnavailable
		}
		recovery, err := s.Recovery.RecoveryState(ctx)
		if err != nil {
			return ContextResult{State: "Indeterminate"}, err
		}
		result.Phase, result.CompletedAt = "cancelled", joined.JoinedAt.UTC()
		result.AcquiredAt, result.Copies = time.Time{}, artifact.Copies{}
		if _, err = recorder.RecordAPILogsCancellation(ctx, result, *joined, process, recovery); err != nil {
			return ContextResult{State: "Indeterminate"}, err
		}
		return ContextResult{State: "Cancelled"}, nil
	}
	if c.State == evidence.RecordingCancelled && e.Profile != nil {
		joined := c.ProfileCancellation
		if joined == nil || joined.CaptureID != e.CaptureUID || joined.AttemptID != e.Registration.Location.AttemptID || joined.ExpectationDigest != r.ExpectationDigest || joined.WriterPodUID != r.Process.PodUID || joined.WriterEpoch != r.Process.ProcessEpoch || joined.JoinedAt.Before(r.StartedAt) || joined.JoinedAt.After(s.Now()) {
			return ContextResult{State: "Indeterminate"}, executeStep{"ProfileCancellation", value.ErrInvalid}
		}
		recorder, ok := s.Record.(APIProfileCancellationRecorder)
		if !ok {
			return ContextResult{State: "Indeterminate"}, value.ErrUnavailable
		}
		recovery, err := s.Recovery.RecoveryState(ctx)
		if err != nil {
			return ContextResult{State: "Indeterminate"}, err
		}
		result.Phase, result.CompletedAt = "cancelled", joined.JoinedAt.UTC()
		result.AcquiredAt, result.Copies = time.Time{}, artifact.Copies{}
		if _, err = recorder.RecordAPIProfileCancellation(ctx, result, *joined, process, recovery); err != nil {
			return ContextResult{State: "Indeterminate"}, err
		}
		return ContextResult{State: "Cancelled"}, nil
	}
	if c.State == evidence.RecordingCancelled && e.Recording != nil {
		joined := c.RecordingCancellation
		if e.NativeType != artifact.SyscallArgumentsArtifact || e.DataClass != "raw" || e.Recording.Kind != "syscallTrace" || e.Recording.Profile != "arguments" || e.Recording.Arguments == nil || e.Snapshot != nil || joined == nil || joined.CaptureID != e.CaptureUID || joined.AttemptID != e.Registration.Location.AttemptID || joined.ExpectationDigest != r.ExpectationDigest || joined.WriterPodUID != r.Process.PodUID || joined.WriterEpoch != r.Process.ProcessEpoch || joined.JoinedAt.Before(r.StartedAt) || joined.JoinedAt.After(s.Now()) {
			return ContextResult{State: "Indeterminate"}, executeStep{"RecordingCancellation", value.ErrInvalid}
		}
		recorder, ok := s.Record.(APIRecordingCancellationRecorder)
		if !ok {
			return ContextResult{State: "Indeterminate"}, executeStep{"RecordAPIRecordingCancellation", value.ErrUnavailable}
		}
		recovery, err := s.Recovery.RecoveryState(ctx)
		if err != nil {
			return ContextResult{State: "Indeterminate"}, executeStep{"RecoveryState", err}
		}
		result.Phase, result.CompletedAt = "cancelled", joined.JoinedAt.UTC()
		result.AcquiredAt, result.Copies = time.Time{}, artifact.Copies{}
		if _, err = recorder.RecordAPIRecordingCancellation(ctx, result, *joined, process, recovery); err != nil {
			return ContextResult{State: "Indeterminate"}, executeStep{"RecordAPIRecordingCancellation", err}
		}
		return ContextResult{State: "Cancelled"}, nil
	}
	if c.State == evidence.RecordingCancelled {
		joined := c.SnapshotCancellation
		if e.Snapshot == nil || joined == nil || joined.CaptureID != e.CaptureUID || joined.AttemptID != e.Registration.Location.AttemptID || !joined.Request.Equal(*e.Snapshot) || joined.AcceptedExpectationDigest != evidence.ContextExpectationDigest(e) || joined.JoinedAt.Before(r.StartedAt) || joined.JoinedAt.After(s.Now()) {
			return ContextResult{State: "Indeterminate"}, executeStep{"SnapshotCancellation", value.ErrInvalid}
		}
		recorder, ok := s.Record.(APISnapshotCancellationRecorder)
		if !ok {
			return ContextResult{State: "Indeterminate"}, executeStep{"RecordAPISnapshotCancellation", value.ErrUnavailable}
		}
		recovery, err := s.Recovery.RecoveryState(ctx)
		if err != nil {
			return ContextResult{State: "Indeterminate"}, executeStep{"RecoveryState", err}
		}
		result.Phase, result.CompletedAt = "cancelled", joined.JoinedAt.UTC()
		result.AcquiredAt, result.Copies = time.Time{}, artifact.Copies{}
		if _, err = recorder.RecordAPISnapshotCancellation(ctx, result, *joined, process, recovery); err != nil {
			return ContextResult{State: "Indeterminate"}, executeStep{"RecordAPISnapshotCancellation", err}
		}
		return ContextResult{State: "Cancelled"}, nil
	}
	if c.State == evidence.RecordingStored {
		result.AcquiredAt, result.Copies, result.CompletedAt, result.Phase = c.Acquired.UTC(), c.Completion.Copies, c.Completion.StoredAt, "stored"
		recovery, err := s.Recovery.RecoveryState(ctx)
		if err != nil {
			return ContextResult{State: "Indeterminate"}, executeStep{"RecoveryState", err}
		}
		if e.Snapshot != nil {
			recorder, ok := s.Record.(APIStoredSnapshotCompletionRecorder)
			if !ok || c.SnapshotCoverage == nil {
				return ContextResult{State: "Indeterminate"}, executeStep{"RecordAPIStoredSnapshotCompletion", value.ErrUnavailable}
			}
			projected, projectionErr := artifact.ProjectSourceSnapshotCoverage(e, evidence.ContextExpectationDigest(e), *c.SnapshotCoverage)
			if projectionErr != nil || c.Completion.ExpectationDigest != evidence.ContextExpectationDigest(projected) {
				return ContextResult{State: "Indeterminate"}, executeStep{"SnapshotCoverage", value.ErrInvalid}
			}
			if _, err = recorder.RecordAPIStoredSnapshotCompletion(ctx, result, c.Completion, *c.SnapshotCoverage, process, recovery); err != nil {
				return ContextResult{State: "Indeterminate"}, executeStep{"RecordAPIStoredSnapshotCompletion", err}
			}
			return ContextResult{State: "StoredPendingVerification", Copies: result.Copies}, nil
		}
		if c.SnapshotCoverage != nil {
			return ContextResult{State: "Indeterminate"}, executeStep{"SnapshotCoverage", value.ErrInvalid}
		}
		if _, err = completionRecorder.RecordAPIStoredCompletion(ctx, result, c.Completion, process, recovery); err != nil {
			return ContextResult{State: "Indeterminate"}, executeStep{"RecordAPIStoredCompletion", err}
		}
		return ContextResult{State: "StoredPendingVerification", Copies: result.Copies}, nil
	}
	result.Phase, result.CompletedAt = c.Failure, s.Now().UTC().Truncate(time.Microsecond)
	if c.Failure == "storeUnconfirmed" {
		result.AcquiredAt = c.Acquired.UTC()
	}
	if _, err = s.Record.RecordAPIOutcome(ctx, result, process); err != nil {
		return ContextResult{State: "Indeterminate"}, executeStep{"RecordAPIOutcome", err}
	}
	return ContextResult{State: "Failed"}, nil
}

type APIProfileCancellationRecorder interface {
	RecordAPIProfileCancellation(context.Context, value.APIExecution, artifact.ProfileCancellation, value.APIProcessObservation, artifact.RecoveryProof) (value.APIExecution, error)
}

type APILogsCancellationRecorder interface {
	RecordAPILogsCancellation(context.Context, value.APIExecution, artifact.LogCancellation, value.APIProcessObservation, artifact.RecoveryProof) (value.APIExecution, error)
}

// APIRecordingCancellationRecorder persists one original writer's joined Stop.
// The durable request alone never supplies this proof.
type APIRecordingCancellationRecorder interface {
	RecordAPIRecordingCancellation(context.Context, value.APIExecution, artifact.RecordingCancellation, value.APIProcessObservation, artifact.RecoveryProof) (value.APIExecution, error)
}
