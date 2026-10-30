package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
)

type snapshotCancellationRecorder struct {
	*snapshotCompletionFixture
	cancellations, genericOutcomes int
	execution                      value.APIExecution
	proof                          artifact.SourceSnapshotCancellation
	process                        value.APIProcessObservation
	recovery                       artifact.RecoveryProof
}

func (r *snapshotCancellationRecorder) RecordAPISnapshotCancellation(_ context.Context, e value.APIExecution, p artifact.SourceSnapshotCancellation, process value.APIProcessObservation, recovery artifact.RecoveryProof) (value.APIExecution, error) {
	r.cancellations++
	r.execution, r.proof, r.process, r.recovery = e, p, process, recovery
	return e, nil
}
func (r *snapshotCancellationRecorder) RecordAPIOutcome(_ context.Context, e value.APIExecution, _ value.APIProcessObservation) (value.APIExecution, error) {
	r.genericOutcomes++
	return e, nil
}
func cancellationCollection(f *apiRunnerFixture) evidence.RecordingCollection {
	e := f.work.Accepted.Expectation
	return evidence.RecordingCollection{State: evidence.RecordingCancelled, SnapshotCancellation: &artifact.SourceSnapshotCancellation{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, Request: *e.Snapshot, AcceptedExpectationDigest: evidence.ContextExpectationDigest(e), JoinedAt: f.now}}
}
func cancellationRecord(f *apiRunnerFixture) *snapshotCancellationRecorder {
	return &snapshotCancellationRecorder{snapshotCompletionFixture: &snapshotCompletionFixture{apiRunnerFixture: f}}
}
func cancellationExecution(f *apiRunnerFixture) value.APIExecution {
	return value.APIExecution{Phase: "started", ExpectationDigest: evidence.ContextExpectationDigest(f.work.Accepted.Expectation), StartedAt: f.now}
}

func TestAPIContextSnapshotCancellationRequiresDedicatedJoinedCompletion(t *testing.T) {
	f, runner, _ := snapshotExecutionFixture(t)
	recorder := cancellationRecord(f)
	runner.Record = recorder
	c := cancellationCollection(f)
	execution := cancellationExecution(f)
	out, err := runner.CollectRecording(t.Context(), f.work, execution, snapshotCollectionFixture{c})
	if err != nil || out.State != "Cancelled" || recorder.cancellations != 1 || recorder.genericOutcomes != 0 || recorder.snapshotCompletions != 0 {
		t.Fatal("joined cancellation bypassed dedicated persistence", out, err, recorder)
	}
	if recorder.execution.Phase != "cancelled" || !recorder.execution.CompletedAt.Equal(c.SnapshotCancellation.JoinedAt) || !recorder.execution.AcquiredAt.IsZero() || recorder.execution.Copies != (artifact.Copies{}) || recorder.execution.ExpectationDigest != execution.ExpectationDigest || recorder.process.Binding != f.process || recorder.recovery != f.recovery {
		t.Fatal("cancellation changed admission or invented artifact/acquisition", recorder)
	}
	if !recorder.proof.Request.Equal(*f.work.Accepted.Expectation.Snapshot) || execution.Phase != "started" {
		t.Fatal("lost original request or mutated caller record")
	}
}
func TestAPIContextSnapshotCancellationRefusesUnboundOrMixedProof(t *testing.T) {
	for name, change := range map[string]func(*evidence.RecordingCollection, *apiRunnerFixture){
		"capture": func(c *evidence.RecordingCollection, _ *apiRunnerFixture) {
			c.SnapshotCancellation.CaptureID = contextID(91)
		},
		"attempt": func(c *evidence.RecordingCollection, _ *apiRunnerFixture) {
			c.SnapshotCancellation.AttemptID = contextID(92)
		},
		"sourceFence": func(c *evidence.RecordingCollection, _ *apiRunnerFixture) {
			c.SnapshotCancellation.Request.Fence = contextID(93)
		},
		"window": func(c *evidence.RecordingCollection, _ *apiRunnerFixture) {
			c.SnapshotCancellation.Request.Before += time.Millisecond
		},
		"acceptedDigest": func(c *evidence.RecordingCollection, _ *apiRunnerFixture) {
			c.SnapshotCancellation.AcceptedExpectationDigest[0] ^= 1
		},
		"beforeStart": func(c *evidence.RecordingCollection, f *apiRunnerFixture) {
			c.SnapshotCancellation.JoinedAt = f.now.Add(-time.Microsecond)
		},
		"futureJoin": func(c *evidence.RecordingCollection, f *apiRunnerFixture) {
			c.SnapshotCancellation.JoinedAt = f.now.Add(time.Microsecond)
		},
		"storedReceipt": func(c *evidence.RecordingCollection, _ *apiRunnerFixture) {
			c.Completion.ExpectationDigest = artifact.Digest{1}
		},
		"coverage": func(c *evidence.RecordingCollection, _ *apiRunnerFixture) {
			c.SnapshotCoverage = &artifact.SourceSnapshotCoverage{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, runner, _ := snapshotExecutionFixture(t)
			recorder := cancellationRecord(f)
			runner.Record = recorder
			c := cancellationCollection(f)
			change(&c, f)
			out, err := runner.CollectRecording(t.Context(), f.work, cancellationExecution(f), snapshotCollectionFixture{c})
			if err == nil || out.State != "Indeterminate" || recorder.cancellations != 0 || recorder.genericOutcomes != 0 || recorder.snapshotCompletions != 0 {
				t.Fatal("unbound join reached a terminal writer", out, err, recorder)
			}
		})
	}
}
func TestAPIContextSnapshotCancellationPendingAndMissingRecorderStayNonterminal(t *testing.T) {
	f, runner, _ := snapshotExecutionFixture(t)
	recorder := cancellationRecord(f)
	runner.Record = recorder
	out, err := runner.CollectRecording(t.Context(), f.work, cancellationExecution(f), snapshotCollectionFixture{evidence.RecordingCollection{State: evidence.RecordingPending}})
	if err != nil || out.State != "Recording" || recorder.cancellations != 0 || recorder.genericOutcomes != 0 {
		t.Fatal("pending/enqueue became terminal", out, err)
	}
	runner.Record = f
	out, err = runner.CollectRecording(t.Context(), f.work, cancellationExecution(f), snapshotCollectionFixture{cancellationCollection(f)})
	if !errors.Is(err, value.ErrUnavailable) || out.State != "Indeterminate" || f.record.Phase != "" {
		t.Fatal("missing cancellation facet fell back to generic outcome", out, err)
	}
}
func TestAPIContextSnapshotCancellationMatchesOriginalClockInstants(t *testing.T) {
	f, runner, _ := snapshotExecutionFixture(t)
	recorder := cancellationRecord(f)
	runner.Record = recorder
	c := cancellationCollection(f)
	q := &c.SnapshotCancellation.Request
	zone := time.FixedZone("SQL event receiver", 7200)
	q.SourceStartedAt, q.SourceHardUntil, q.T0, q.IssuedAt, q.StartBy, q.ProcessingUntil = q.SourceStartedAt.In(zone), q.SourceHardUntil.In(zone), q.T0.In(zone), q.IssuedAt.In(zone), q.StartBy.In(zone), q.ProcessingUntil.In(zone)
	if out, err := runner.CollectRecording(t.Context(), f.work, cancellationExecution(f), snapshotCollectionFixture{c}); err != nil || out.State != "Cancelled" || recorder.cancellations != 1 {
		t.Fatal("same immutable instants refused after SQL/wire roundtrip", out, err)
	}
}
