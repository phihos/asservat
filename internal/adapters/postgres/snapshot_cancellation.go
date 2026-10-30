package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	execution "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

var _ app.CaptureCancellationLedger = (*APIContextExecutions)(nil)
var _ executionapp.APISnapshotCancellationRecorder = (*APIContextExecutions)(nil)

func (s *APIContextExecutions) RequestCaptureCancellation(ctx context.Context, in value.CancellationCheck) (app.SnapshotCancellationWork, error) {
	var out app.SnapshotCancellationWork
	if s == nil || s.ledger == nil || in.RootID != s.root || !in.Valid(in.CheckedAt) {
		return out, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, err := s.guards.Recovery.lock(ctx, q, s.root, in.Recovery)
		if err != nil {
			return err
		}
		stream, err := q.LockPermissionStream(ctx, id(s.root))
		if err != nil {
			return err
		}
		group, groupErr := q.LockRecordingSaveGroup(ctx, custodydb.LockRecordingSaveGroupParams{RootID: id(s.root), ID: id(in.Request.CaptureID)})
		if groupErr == nil {
			out, err = s.requestGroupCancellation(ctx, q, trust, stream, group, in)
			return err
		}
		if !errors.Is(groupErr, pgx.ErrNoRows) {
			return groupErr
		}
		out, err = s.requestSnapshotCancellationInTransaction(ctx, q, trust, stream, in)
		return err
	})
	return out, captureError(err)
}

func (s *APIContextExecutions) RecordAPISnapshotCancellation(ctx context.Context, r execution.APIExecution, proof artifact.SourceSnapshotCancellation, process execution.APIProcessObservation, recovery artifact.RecoveryProof) (execution.APIExecution, error) {
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
		if e.Snapshot == nil || !capture.SnapshotCancelRequestedAt.Valid || proof.CaptureID != accepted.CaptureID || proof.AttemptID != e.Registration.Location.AttemptID || !proof.Request.Equal(*e.Snapshot) || proof.AcceptedExpectationDigest != evidence.ContextExpectationDigest(e) {
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

func (s *APIContextExecutions) requestSnapshotCancellationInTransaction(ctx context.Context, q *custodydb.Queries, trust custodydb.FleetCurrentTrust, stream custodydb.PermissionStream, in value.CancellationCheck) (app.SnapshotCancellationWork, error) {
	var out app.SnapshotCancellationWork
	err := func() error {
		row, err := q.LockContextCapture(ctx, custodydb.LockContextCaptureParams{RootID: id(s.root), ID: id(in.Request.CaptureID)})
		if err != nil {
			return value.ErrDenied
		}
		accepted, err := admittedRecord(row)
		if err != nil {
			return err
		}
		if accepted.Expectation.Snapshot == nil {
			return value.ErrUnavailable
		}
		intent, err := captureIntent(row)
		if err != nil {
			return err
		}
		projection, err := permissionProjection(ctx, q, stream, intent.Target)
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		rights := authorization.CaptureProgressEligibility(in.Identity, projection, intent.Target, intent.Requester(), now.Time)
		if !rights.Eligible || !in.Valid(now.Time) {
			return value.ErrDenied
		}
		var old execution.APIExecution
		execRow, err := q.ReadAPIExecution(ctx, custodydb.ReadAPIExecutionParams{RootID: id(s.root), CaptureID: row.ID})
		if err == nil {
			old, err = apiExecution(execRow)
			if err != nil {
				return err
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		phase := "Pending"
		switch old.Phase {
		case "started":
			phase = "Running"
		case "stored":
			phase = "Finalizing"
		case "captureFailed", "targetGone", "denied":
			phase = "Failed"
		case "storeUnconfirmed":
			phase = "Indeterminate"
		case "cancelled":
			phase = "Cancelled"
		}
		terminal := phase == "Finalizing" || phase == "Failed" || phase == "Indeterminate" || phase == "Cancelled"
		key := contextRequestKey(in.Identity.Principal, in.Request.IdempotencyKey)
		if !terminal && !row.SnapshotCancelRequestedAt.Valid {
			if row.ProgressRevision != in.Request.ExpectedRevision {
				return value.ErrConflict
			}
			actor, err := json.Marshal(in.Identity.Principal)
			if err != nil {
				return value.ErrInvalid
			}
			if _, err = q.RequestSnapshotCancellation(ctx, custodydb.RequestSnapshotCancellationParams{RootID: id(s.root), ID: row.ID, SnapshotCancelKey: key, SnapshotCancelActor: actor, ProgressRevision: in.Request.ExpectedRevision}); err != nil {
				return err
			}
			if old.StartedAt.IsZero() {
				if _, err = q.RecordUnstartedSnapshotCancellation(ctx, custodydb.RecordUnstartedSnapshotCancellationParams{RootID: id(s.root), ID: row.ID}); err != nil {
					return err
				}
				phase = "Cancelled"
			}
		} else if row.SnapshotCancelRequestedAt.Valid && !bytes.Equal(row.SnapshotCancelKey, key) && row.ProgressRevision != in.Request.ExpectedRevision {
			return value.ErrConflict
		}
		row, err = q.LockContextCapture(ctx, custodydb.LockContextCaptureParams{RootID: id(s.root), ID: row.ID})
		if err != nil {
			return err
		}
		if row.SnapshotCancelJoinedAt.Valid {
			phase = "Cancelled"
		}
		if row.SnapshotCancelRequestedAt.Valid && !row.SnapshotCancelJoinedAt.Valid && old.Phase == "started" {
			w := executionapp.APIContextWork{Accepted: accepted, Actor: intent.Actor, Initiator: intent.Initiator}
			if err = sourceSnapshotWork(ctx, q, s.root, &w); err != nil {
				return err
			}
			if w.SourceBinding == nil {
				return value.ErrUnavailable
			}
			out.ClusterID = accepted.Expectation.Registration.Location.ClusterID
			out.Snapshot = &collector.SourceSnapshot{Binding: *w.SourceBinding, CaptureID: accepted.CaptureID, AttemptID: accepted.Expectation.Registration.Location.AttemptID, WriterPodUID: old.Process.PodUID, WriterEpoch: old.Process.ProcessEpoch, ExpectationDigest: [32]byte(evidence.ContextExpectationDigest(accepted.Expectation)), Request: *accepted.Expectation.Snapshot}
		}
		if err = s.guards.Recovery.check(ctx, q, trust, s.root, in.Recovery); err != nil {
			return err
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !in.Valid(now.Time) || !now.Time.Before(rights.ValidUntil) {
			return value.ErrDenied
		}
		out.Decision = value.Cancellation{CaptureID: accepted.CaptureID, Phase: phase, Revision: row.ProgressRevision, Requested: row.SnapshotCancelRequestedAt.Valid, ObservedAt: now.Time.UTC(), ValidUntil: identity.Earlier(in.ValidUntil, identity.Earlier(rights.ValidUntil, now.Time.Add(5*time.Second)))}
		return ctx.Err()
	}()
	return out, err
}
