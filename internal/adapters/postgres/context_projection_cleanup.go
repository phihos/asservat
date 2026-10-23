package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
)

// Historical cleanup is intentionally independent of ReadApproved, current
// processing settings and the old human request. It releases no evidence/history
// allocation. Only the physical worker slot can close under these exact proofs.
func (s *ProjectionWorkers) cleanupState(row custodydb.DownloadWorker) (evidence.ProjectionWorkerState, error) {
	var i query.ContextProjectionWorkerIntent
	if s == nil || queryDecode(row.IntentJson, 65536, &i) != nil || !i.Valid() || i.Query.Scope.RootID != s.queries.root || i.Worker.Profile != s.profile {
		return evidence.ProjectionWorkerState{}, query.ErrUnavailable
	}
	return projectionWorkerState(row, i.Query)
}

func (s *ProjectionWorkers) ExpiredProjectionWorkers(ctx context.Context) ([]evidence.ProjectionCleanupCandidate, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, query.ErrUnavailable
	}
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	rows, err := custodydb.New(s.queries.ledger.pool).ExpiredQueryAcquisitionWorkers(call, custodydb.ExpiredQueryAcquisitionWorkersParams{RootID: id(s.queries.root), InstallationID: id(s.profile.InstallationID)})
	if err != nil || len(rows) > 16 {
		return nil, query.ErrUnavailable
	}
	out := make([]evidence.ProjectionCleanupCandidate, 0, len(rows))
	for _, row := range rows {
		state, err := s.cleanupState(row)
		if err != nil {
			continue
		} // Foreign/unknown old profiles stay charged.
		c := evidence.ProjectionCleanupCandidate{State: state}
		if row.TerminationJson != nil {
			if queryDecode(row.TerminationJson, 32768, &c.Termination) != nil || !c.Termination.Valid(c.Termination.ObservedAt) || c.Termination.Worker != state.Worker {
				return nil, query.ErrUnavailable
			}
		}
		out = append(out, c)
	}
	if call.Err() != nil {
		return nil, query.ErrUnavailable
	}
	return out, nil
}

func (s *ProjectionWorkers) AbandonUnclaimedProjectionWorker(ctx context.Context, i query.ContextProjectionWorkerIntent) error {
	if s == nil || ctx == nil || !i.Valid() {
		return query.ErrUnavailable
	}
	return s.queries.ledger.transaction(ctx, func(tx *custodydb.Queries) error {
		row, err := tx.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(i.Worker.ID), RootID: id(s.queries.root)})
		if err != nil {
			return err
		}
		state, err := s.cleanupState(row)
		if err != nil || !sameAuditJSON(state.Intent, i) || state.Claimed || row.JobJson != nil || row.BindingJson != nil || row.TerminationJson != nil || row.RetiredProofJson != nil {
			return query.ErrUnavailable
		}
		if row.AbandonedAt.Valid {
			return nil
		}
		now, err := tx.CurrentTime(ctx)
		if err != nil || now.Time.Before(i.Worker.RunUntil) || ctx.Err() != nil {
			return query.ErrUnavailable
		}
		n, err := tx.AbandonUnclaimedQueryWorker(ctx, custodydb.AbandonUnclaimedQueryWorkerParams{ID: row.ID, RootID: row.RootID})
		if err != nil || n != 1 {
			return query.ErrUnavailable
		}
		return nil
	})
}

func (s *ProjectionWorkers) ConfirmProjectionTermination(ctx context.Context, p value.AcquisitionWorkerTermination) (value.AcquisitionWorkerTermination, error) {
	var out value.AcquisitionWorkerTermination
	if s == nil || ctx == nil || !p.Valid(p.ObservedAt) || p.Worker.Intent.Profile != s.profile || p.Worker.Intent.Parent.Purpose != value.AcquisitionProjection {
		return out, query.ErrUnavailable
	}
	err := s.queries.ledger.transaction(ctx, func(tx *custodydb.Queries) error {
		row, err := tx.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(p.Worker.Intent.ID), RootID: id(s.queries.root)})
		if err != nil {
			return err
		}
		state, err := s.cleanupState(row)
		if err != nil || !state.Claimed || state.Intent.Worker != p.Worker.Intent || row.AbandonedAt.Valid {
			return query.ErrUnavailable
		}
		if row.TerminationJson != nil {
			if queryDecode(row.TerminationJson, 32768, &out) != nil || !out.Valid(out.ObservedAt) || out.Worker != p.Worker {
				return query.ErrUnavailable
			}
			return nil
		}
		now, err := tx.CurrentTime(ctx)
		if err != nil || now.Time.Before(p.Worker.Intent.RunUntil) || !p.Valid(now.Time) || ctx.Err() != nil {
			return query.ErrUnavailable
		}
		// An abandoned startup may never have published its Job/Pod binding.
		// Persist only the now-terminated exact identity, never a live replacement.
		if row.JobJson == nil {
			raw, _ := json.Marshal(p.Worker.Job)
			n, err := tx.RecordDownloadWorkerJob(ctx, custodydb.RecordDownloadWorkerJobParams{ID: row.ID, RootID: row.RootID, JobJson: raw})
			if err != nil || n != 1 {
				return query.ErrUnavailable
			}
		} else if state.Job != p.Worker.Job {
			return query.ErrUnavailable
		}
		if row.BindingJson == nil {
			raw, _ := json.Marshal(p.Worker.Binding)
			n, err := tx.BindDownloadWorker(ctx, custodydb.BindDownloadWorkerParams{ID: row.ID, RootID: row.RootID, BindingJson: raw})
			if err != nil || n != 1 {
				return query.ErrUnavailable
			}
		} else if state.Worker != p.Worker {
			return query.ErrUnavailable
		}
		raw, _ := json.Marshal(p)
		n, err := tx.ConfirmDownloadWorkerTermination(ctx, custodydb.ConfirmDownloadWorkerTerminationParams{ID: row.ID, RootID: row.RootID, TerminationJson: raw})
		if err != nil || n != 1 {
			return query.ErrUnavailable
		}
		now, err = tx.CurrentTime(ctx)
		if err != nil || !p.Valid(now.Time) || ctx.Err() != nil {
			return query.ErrUnavailable
		}
		out = p
		return nil
	})
	if err != nil {
		return value.AcquisitionWorkerTermination{}, err
	}
	return out, nil
}

func (s *ProjectionWorkers) RetireProjectionWorker(ctx context.Context, p value.AcquisitionWorkerRetirement) error {
	if s == nil || ctx == nil || !p.Valid(p.ObservedAt) || p.Termination.Worker.Intent.Profile != s.profile {
		return query.ErrUnavailable
	}
	return s.queries.ledger.transaction(ctx, func(tx *custodydb.Queries) error {
		if _, err := tx.LockPermissionStream(ctx, id(s.queries.root)); err != nil {
			return err
		}
		row, err := tx.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(p.Termination.Worker.Intent.ID), RootID: id(s.queries.root)})
		if err != nil {
			return err
		}
		state, err := s.cleanupState(row)
		term, _ := json.Marshal(p.Termination)
		if err != nil || state.Worker != p.Termination.Worker || !bytes.Equal(row.TerminationJson, term) || row.AbandonedAt.Valid {
			return query.ErrUnavailable
		}
		if row.RetiredProofJson != nil {
			return nil
		}
		now, err := tx.CurrentTime(ctx)
		if err != nil || !p.Valid(now.Time) || ctx.Err() != nil {
			return query.ErrUnavailable
		}
		raw, _ := json.Marshal(p)
		n, err := tx.RetireDownloadWorker(ctx, custodydb.RetireDownloadWorkerParams{ID: row.ID, RootID: row.RootID, RetiredProofJson: raw})
		if err != nil || n != 1 {
			return query.ErrUnavailable
		}
		now, err = tx.CurrentTime(ctx)
		if err != nil || !p.Valid(now.Time) || ctx.Err() != nil {
			return query.ErrUnavailable
		}
		return nil
	})
}
