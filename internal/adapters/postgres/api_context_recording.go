package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/execution"
)

// ADR-248: the hub collects a started manual recording without a human
// request. These reads expose only the accepted work and its started
// execution; they authorize no acquisition, disclosure or new spend. The
// stored completion is still recorded through RecordAPIStoredCompletion with a
// current connector process observation and recovery proof.

var _ app.RecordingExecutions = (*APIContextExecutions)(nil)

// StartedRecordings lists started recordings whose execution started at or
// before the instant, oldest first.
func (s *APIContextExecutions) StartedRecordings(ctx context.Context, startedBefore time.Time, limit int) ([]string, error) {
	if limit < 1 || limit > 64 || startedBefore.IsZero() {
		return nil, value.ErrInvalid
	}
	var out []string
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.ListStartedRecordings(ctx, custodydb.ListStartedRecordingsParams{RootID: id(s.root), StartedAt: ts(startedBefore), Limit: int32(limit)})
		if err != nil {
			return err
		}
		out = out[:0]
		for _, r := range rows {
			out = append(out, uid(r))
		}
		return nil
	})
	return out, err
}

// ReadRecordingWork reads a started recording's accepted work and execution
// under the current recovery fence.
func (s *APIContextExecutions) ReadRecordingWork(ctx context.Context, captureID string, recovery artifact.RecoveryProof) (app.APIContextWork, value.APIExecution, error) {
	var w app.APIContextWork
	var r value.APIExecution
	if !authorization.UUID(captureID) || !recovery.Valid(recovery.ObservedAt) {
		return w, r, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, err := s.guards.Recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return err
		}
		row, err := q.ReadPublicationCapture(ctx, custodydb.ReadPublicationCaptureParams{ID: id(captureID), RootID: id(s.root)})
		if err != nil {
			return value.ErrDenied
		}
		if w, err = apiWork(row); err != nil {
			return err
		}
		if w.Accepted.Expectation.Recording == nil && w.Accepted.Expectation.Snapshot == nil {
			return value.ErrDenied
		}
		if err = sourceSnapshotWork(ctx, q, s.root, &w); err != nil {
			return err
		}
		exec, err := q.ReadAPIExecution(ctx, custodydb.ReadAPIExecutionParams{RootID: id(s.root), CaptureID: row.ID})
		if err != nil {
			return value.ErrDenied
		}
		if r, err = apiExecution(exec); err != nil {
			return err
		}
		if r.Phase != "started" {
			return value.ErrConflict
		}
		return s.guards.Recovery.check(ctx, q, trust, s.root, recovery)
	})
	if err != nil {
		return app.APIContextWork{}, value.APIExecution{}, err
	}
	return w, r, nil
}
