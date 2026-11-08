package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	execution "asservat.local/asservat/internal/domain/execution"
)

var _ executionapp.APIRecordingCancellationRecorder = (*APIContextExecutions)(nil)

func (s *APIContextExecutions) RecordAPIRecordingCancellation(ctx context.Context, r execution.APIExecution, proof artifact.RecordingCancellation, process execution.APIProcessObservation, recovery artifact.RecoveryProof) (execution.APIExecution, error) {
	var out execution.APIExecution
	if s == nil || !r.Valid() || r.RootID != s.root || r.Phase != "cancelled" || !proof.Valid() || !r.CompletedAt.Equal(proof.JoinedAt) || process.Binding != r.Process {
		return out, execution.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, err := s.guards.Recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return err
		}
		if _, err = q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		capture, err := q.LockContextCapture(ctx, custodydb.LockContextCaptureParams{RootID: id(s.root), ID: id(r.Binding.CaptureID)})
		if err != nil {
			return err
		}
		accepted, err := admittedRecord(capture)
		if err != nil {
			return err
		}
		e := accepted.Expectation
		if !capture.SnapshotCancelRequestedAt.Valid || !recordingCancellationMatches(e, r, proof) {
			return execution.ErrDenied
		}
		row, err := q.LockAPIExecution(ctx, custodydb.LockAPIExecutionParams{RootID: id(s.root), CaptureID: capture.ID})
		if err != nil {
			return err
		}
		old, err := apiExecution(row)
		if err != nil {
			return err
		}
		if old.Binding != r.Binding || old.Process != r.Process || old.ExpectationDigest != r.ExpectationDigest || old.ObjectUID != r.ObjectUID || !old.StartedAt.Equal(r.StartedAt) {
			return execution.ErrConflict
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !process.Valid(now.Time) || proof.JoinedAt.Before(old.StartedAt) || proof.JoinedAt.After(now.Time) {
			return execution.ErrDenied
		}
		raw, err := json.Marshal(proof)
		if err != nil || len(raw) > 8192 {
			return execution.ErrInvalid
		}
		if old.Phase == "cancelled" {
			if !reflect.DeepEqual(old, r) || !bytes.Equal(capture.SnapshotCancelProofDigest, digest(proof)) {
				return execution.ErrConflict
			}
			out = old
			return ctx.Err()
		}
		// A positively stored completion wins; nil must never mean Cancelled.
		if old.Phase != "started" {
			return execution.ErrConflict
		}
		row, err = q.RecordAPIOutcome(ctx, custodydb.RecordAPIOutcomeParams{RootID: id(s.root), CaptureID: capture.ID, Phase: "cancelled", CompletedAt: ts(proof.JoinedAt)})
		if err != nil {
			return err
		}
		if _, err = q.RecordSnapshotCancellation(ctx, custodydb.RecordSnapshotCancellationParams{RootID: id(s.root), ID: capture.ID, SnapshotCancelJoinedAt: ts(proof.JoinedAt), SnapshotCancelProof: raw, SnapshotCancelProofDigest: digest(proof)}); err != nil {
			return err
		}
		out, err = apiExecution(row)
		if err != nil {
			return err
		}
		return s.guards.Recovery.check(ctx, q, trust, s.root, recovery)
	})
	return out, captureError(err)
}

// recordingCancellationExpected reports a finite manual recording (packet
// metadata, raw packets, HTTP headers, syscall metadata or arguments) whose
// Stop joins through the original writer's RecordingCancellation. Existing
// source snapshots, profiles and logs keep their own proofs.
func recordingCancellationExpected(e artifact.ContextExpectation) bool {
	return e.Recording != nil && e.Snapshot == nil && e.Profile == nil && e.Logs == nil
}

func recordingCancellationMatches(e artifact.ContextExpectation, r execution.APIExecution, proof artifact.RecordingCancellation) bool {
	return recordingCancellationExpected(e) && proof.Valid() && proof.CaptureID == e.CaptureUID && proof.AttemptID == e.Registration.Location.AttemptID && proof.WriterPodUID == r.Process.PodUID && proof.WriterEpoch == r.Process.ProcessEpoch && proof.ExpectationDigest == r.ExpectationDigest && proof.ExpectationDigest == evidence.ContextExpectationDigest(e)
}
