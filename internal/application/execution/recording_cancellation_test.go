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

type argumentCancellationRecorder struct {
	*apiRunnerFixture
	cancellations int
	proof         artifact.RecordingCancellation
	result        value.APIExecution
	err           error
}

func (r *argumentCancellationRecorder) RecordAPIRecordingCancellation(_ context.Context, result value.APIExecution, proof artifact.RecordingCancellation, process value.APIProcessObservation, recovery artifact.RecoveryProof) (value.APIExecution, error) {
	if process.Binding != r.process || recovery != r.recovery {
		panic("changed original process or recovery")
	}
	r.cancellations++
	r.result, r.proof = result, proof
	return result, r.err
}

func argumentCancellationCollection(f *argumentRunnerFixture) (value.APIExecution, evidence.RecordingCollection) {
	e := f.work.Accepted.Expectation
	r := value.APIExecution{Phase: "started", Process: f.process, ExpectationDigest: evidence.ContextExpectationDigest(e), StartedAt: f.now}
	p := &artifact.RecordingCancellation{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, WriterPodUID: r.Process.PodUID, WriterEpoch: r.Process.ProcessEpoch, ExpectationDigest: r.ExpectationDigest, JoinedAt: f.now}
	return r, evidence.RecordingCollection{State: evidence.RecordingCancelled, RecordingCancellation: p}
}

func TestArgumentCancellationRequiresJoinedOriginalWriter(t *testing.T) {
	f, runner, _ := argumentExecutionFixture(t)
	recorder := &argumentCancellationRecorder{apiRunnerFixture: f.apiRunnerFixture}
	runner.Record = recorder
	r, c := argumentCancellationCollection(f)
	out, err := runner.CollectRecording(t.Context(), f.work, r, snapshotCollectionFixture{c})
	if err != nil || out.State != "Cancelled" || recorder.cancellations != 1 || recorder.result.Phase != "cancelled" || !recorder.result.CompletedAt.Equal(c.RecordingCancellation.JoinedAt) || !recorder.result.AcquiredAt.IsZero() || recorder.result.Copies != (artifact.Copies{}) || f.record.Phase != "" {
		t.Fatal(out, err, recorder)
	}
}

func TestArgumentCancellationRejectsSubstitutionAndMixedOutcomes(t *testing.T) {
	for name, edit := range map[string]func(*argumentRunnerFixture, *evidence.RecordingCollection){
		"capture": func(_ *argumentRunnerFixture, c *evidence.RecordingCollection) {
			c.RecordingCancellation.CaptureID = contextID(91)
		},
		"attempt": func(_ *argumentRunnerFixture, c *evidence.RecordingCollection) {
			c.RecordingCancellation.AttemptID = contextID(92)
		},
		"writer": func(_ *argumentRunnerFixture, c *evidence.RecordingCollection) {
			c.RecordingCancellation.WriterPodUID = contextID(93)
		},
		"epoch": func(_ *argumentRunnerFixture, c *evidence.RecordingCollection) {
			c.RecordingCancellation.WriterEpoch = contextID(94)
		},
		"digest": func(_ *argumentRunnerFixture, c *evidence.RecordingCollection) {
			c.RecordingCancellation.ExpectationDigest[0] ^= 1
		},
		"before-start": func(f *argumentRunnerFixture, c *evidence.RecordingCollection) {
			c.RecordingCancellation.JoinedAt = f.now.Add(-time.Microsecond)
		},
		"future": func(f *argumentRunnerFixture, c *evidence.RecordingCollection) {
			c.RecordingCancellation.JoinedAt = f.now.Add(time.Microsecond)
		},
		"native-type": func(f *argumentRunnerFixture, _ *evidence.RecordingCollection) {
			f.work.Accepted.Expectation.NativeType = artifact.SyscallRecordsArtifact
		},
		"metadata": func(f *argumentRunnerFixture, _ *evidence.RecordingCollection) {
			f.work.Accepted.Expectation.DataClass = "metadata"
		},
		"ordinary-recording": func(f *argumentRunnerFixture, _ *evidence.RecordingCollection) {
			f.work.Accepted.Expectation.Recording.Arguments = nil
		},
		"profile-proof": func(_ *argumentRunnerFixture, c *evidence.RecordingCollection) {
			p := c.RecordingCancellation
			c.ProfileCancellation = &artifact.ProfileCancellation{CaptureID: p.CaptureID, AttemptID: p.AttemptID, WriterPodUID: p.WriterPodUID, WriterEpoch: p.WriterEpoch, ExpectationDigest: p.ExpectationDigest, JoinedAt: p.JoinedAt}
		},
		"stored-receipt": func(_ *argumentRunnerFixture, c *evidence.RecordingCollection) {
			c.Completion.ExpectationDigest = artifact.Digest{1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, runner, _ := argumentExecutionFixture(t)
			recorder := &argumentCancellationRecorder{apiRunnerFixture: f.apiRunnerFixture}
			runner.Record = recorder
			r, c := argumentCancellationCollection(f)
			edit(f, &c)
			// Keep the original execution associated with the independently supplied
			// expectation so native/class mismatches exercise the typed Stop branch.
			r.ExpectationDigest = evidence.ContextExpectationDigest(f.work.Accepted.Expectation)
			if name == "native-type" || name == "metadata" || name == "ordinary-recording" {
				c.RecordingCancellation.ExpectationDigest = r.ExpectationDigest
			}
			out, err := runner.CollectRecording(t.Context(), f.work, r, snapshotCollectionFixture{c})
			if err == nil || out.State == "Cancelled" || recorder.cancellations != 0 || f.record.Phase != "" {
				t.Fatal(out, err, recorder.cancellations)
			}
		})
	}
}

func TestArgumentCancellationPendingAndPersistenceConflictStayNonterminal(t *testing.T) {
	f, runner, _ := argumentExecutionFixture(t)
	recorder := &argumentCancellationRecorder{apiRunnerFixture: f.apiRunnerFixture, err: value.ErrConflict}
	runner.Record = recorder
	r, c := argumentCancellationCollection(f)
	f.work.CancellationRequested = true
	out, err := runner.CollectRecording(t.Context(), f.work, r, snapshotCollectionFixture{evidence.RecordingCollection{State: evidence.RecordingPending}})
	if err != nil || out.State != "Recording" || recorder.cancellations != 0 {
		t.Fatal("request alone became terminal", out, err)
	}
	out, err = runner.CollectRecording(t.Context(), f.work, r, snapshotCollectionFixture{c})
	if !errors.Is(err, value.ErrConflict) || out.State != "Indeterminate" || recorder.cancellations != 1 {
		t.Fatal("stored/conflicting SQL result was overwritten", out, err)
	}
	runner.Record = f.apiRunnerFixture
	out, err = runner.CollectRecording(t.Context(), f.work, r, snapshotCollectionFixture{c})
	if !errors.Is(err, value.ErrUnavailable) || out.State == "Cancelled" {
		t.Fatal("missing dedicated persistence fell back to generic outcome", out, err)
	}
}
