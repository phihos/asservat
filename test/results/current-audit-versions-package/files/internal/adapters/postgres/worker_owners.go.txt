package postgres

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type WorkerOwners struct{ workers *DownloadWorkers }

var _ evidence.WorkerOwnerStore = (*WorkerOwners)(nil)

func NewWorkerOwners(ctx context.Context, pool *pgxpool.Pool, root string, profile value.DownloadWorkerProfile, guards DownloadTransactionGuards) (*WorkerOwners, error) {
	w, err := NewDownloadWorkers(ctx, pool, root, profile, guards)
	if err != nil {
		return nil, err
	}
	return &WorkerOwners{w}, nil
}

func workerOwnerLease(r custodydb.DownloadWorkerOwner, installation, session string) value.WorkerOwnerLease {
	return value.WorkerOwnerLease{Request: value.WorkerOwnerRequest{ID: uid(r.RequestID), InstallationID: installation, SessionID: session, WorkerID: uid(r.WorkerID), PodUID: uid(r.PodUid), ProcessEpoch: uid(r.ProcessEpoch), Until: r.ExpiresAt.Time.UTC()}, Fence: r.Fence, Started: r.StartedAt.Time.UTC()}
}

func (s *WorkerOwners) ClaimWorkerOwner(ctx context.Context, w value.DownloadWorker, a artifact.DownloadAuthority, request value.WorkerOwnerRequest) (value.WorkerOwnerLease, error) {
	var out value.WorkerOwnerLease
	request.Until = request.Until.UTC().Truncate(time.Microsecond)
	if s == nil || s.workers == nil || ctx == nil || !w.Valid() || w.Intent.Profile != s.workers.profile || a.Scope != w.Intent.Authority.Scope || !request.Valid(time.Now()) || request.InstallationID != w.Binding.InstallationID || request.SessionID != w.Intent.SessionID || request.WorkerID != w.Intent.ID {
		return out, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	err := s.workers.withSession(ctx, request.SessionID, a, func(q *custodydb.Queries, parent artifact.DownloadSession, _ time.Time) error {
		row, err := q.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(request.WorkerID), RootID: id(a.Scope.RootID)})
		if err != nil {
			return err
		}
		current, err := currentAuditedWorker(row)
		if err != nil || current != w || row.AuditReceiptJson == nil || row.TerminationJson != nil || row.RetiredProofJson != nil {
			return artifact.ErrDownloadUnavailable
		}
		old, lookup := q.LockWorkerOwner(ctx, id(request.WorkerID))
		if lookup != nil && !errors.Is(lookup, pgx.ErrNoRows) {
			return lookup
		}
		// Check after all row locks. A slow previous owner cannot extend the
		// authenticated operation, configuration or access window.
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		now := n.Time.UTC()
		if !a.Valid(now) || !request.Valid(now) || request.Until.After(parent.Deadline) || request.Until.After(w.Intent.RunUntil) || request.Until.After(a.AccessUntil) {
			return artifact.ErrDownloadExpired
		}
		out = value.WorkerOwnerLease{Request: request, Fence: 1, Started: now}
		if lookup == nil {
			previous := workerOwnerLease(old, request.InstallationID, request.SessionID)
			if previous.Request.ID == request.ID {
				if previous.Request != request || old.ReleasedAt.Valid || !previous.Valid(now) {
					return artifact.ErrDownloadConflict
				}
				out = previous
				return nil
			}
			if !old.ReleasedAt.Valid && now.Before(previous.Request.Until) {
				return artifact.ErrDownloadConflict
			}
			out.Fence = old.Fence + 1
			if !out.Valid(now) {
				return artifact.ErrDownloadCapacity
			}
			count, err := q.ReplaceWorkerOwner(ctx, custodydb.ReplaceWorkerOwnerParams{WorkerID: id(request.WorkerID), RequestID: id(request.ID), PodUid: id(request.PodUID), ProcessEpoch: id(request.ProcessEpoch), StartedAt: ts(now), ExpiresAt: ts(request.Until), Fence: old.Fence})
			if err != nil {
				return err
			}
			if count != 1 {
				return artifact.ErrDownloadConflict
			}
			return nil
		}
		return q.InsertWorkerOwner(ctx, custodydb.InsertWorkerOwnerParams{WorkerID: id(request.WorkerID), RequestID: id(request.ID), PodUid: id(request.PodUID), ProcessEpoch: id(request.ProcessEpoch), StartedAt: ts(now), ExpiresAt: ts(request.Until)})
	})
	if err != nil {
		return value.WorkerOwnerLease{}, err
	}
	if !out.Valid(time.Now()) || ctx.Err() != nil {
		return value.WorkerOwnerLease{}, artifact.ErrDownloadExpired
	}
	return out, nil
}

func (s *WorkerOwners) ReadWorkerOwner(ctx context.Context, session, worker string) (value.WorkerOwnerLease, error) {
	if s == nil || s.workers == nil {
		return value.WorkerOwnerLease{}, artifact.ErrInvalid
	}
	w := s.workers
	return readWorkerOwner(ctx, w.downloads.ledger, w.downloads.root, w.profile.InstallationID, session, worker)
}

func (s *WorkerOwners) ReleaseWorkerOwner(ctx context.Context, lease value.WorkerOwnerLease) error {
	if s == nil || s.workers == nil || ctx == nil || !lease.Valid(lease.Started) || lease.Request.InstallationID != s.workers.profile.InstallationID {
		return artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	r := lease.Request
	_, err := custodydb.New(s.workers.downloads.ledger.pool).ReleaseWorkerOwner(ctx, custodydb.ReleaseWorkerOwnerParams{RootID: id(s.workers.downloads.root), InstallationID: id(r.InstallationID), SessionID: id(r.SessionID), WorkerID: id(r.WorkerID), RequestID: id(r.ID), PodUid: id(r.PodUID), ProcessEpoch: id(r.ProcessEpoch), Fence: lease.Fence, StartedAt: ts(lease.Started), ExpiresAt: ts(r.Until)})
	return err // Already closed/replaced is an idempotent no-op, never a takeover.
}
