package postgres

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/analysis"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

func (s *ContextQueries) workerCurrent(ctx context.Context, q value.ContextQuery, r value.ContextQueryRequest, w value.ContextQueryWorker, a value.ContextProjectionAuthority, fn func(context.Context) error) error {
	if s == nil || s.workers == nil || ctx == nil || ctx.Err() != nil || !w.Matches(q) || !q.Current(a, time.Now()) || !r.Valid(time.Now()) {
		return value.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, identity.Earlier(q.Deadline, identity.Earlier(r.Call.Until, a.ValidUntil)))
	defer cancel()
	e := queryGuarded(ctx, func(bound context.Context, callback func(context.Context) error) error {
		return s.workers.WithCurrentProjectionWorker(bound, q, r, w, a, callback)
	}, fn)
	if e != nil || ctx.Err() != nil || !q.Current(a, time.Now()) || !r.Valid(time.Now()) {
		return value.ErrUnavailable
	}
	return nil
}
func queryWorker(ctx context.Context, tx *custodydb.Queries, q value.ContextQuery, w value.ContextQueryWorker) error {
	row, e := tx.ReadContextQueryWorker(ctx, id(q.ID))
	var stored value.ContextQueryWorker
	if e != nil || queryDecode(row.Binding, 16384, &stored) != nil || stored != w || !stored.Matches(q) || len(row.Proof) == 0 || uid(row.WorkerID) != q.WorkerID {
		return value.ErrUnavailable
	}
	// Proof semantics belong to the independently configured C-14 guard. There
	// is no legacy empty proof or worker insertion API in this adapter.
	return nil
}
func queryBatch(row custodydb.ContextQueryBatch, q value.ContextQuery) (value.ContextReadBatch, error) {
	var b value.ContextReadBatch
	if queryDecode(row.Batch, 16384, &b) != nil || !b.Matches(q) || b.ID != uid(row.ID) || b.QueryID != uid(row.QueryID) || b.OperationID != uid(row.OperationID) || b.Generation != int64(row.Generation) {
		return value.ContextReadBatch{}, value.ErrUnavailable
	}
	return b, nil
}
func (s *ContextQueries) BeginReadBatch(ctx context.Context, q value.ContextQuery, r value.ContextQueryRequest, w value.ContextQueryWorker, batchID string, a value.ContextProjectionAuthority) (app.ContextQueryBatchAdmission, error) {
	var out app.ContextQueryBatchAdmission
	if !authorization.UUID(batchID) {
		return out, value.ErrUnavailable
	}
	e := s.workerCurrent(ctx, q, r, w, a, func(ctx context.Context) error {
		return s.current(ctx, q, r, a, func(ctx context.Context, tx *custodydb.Queries, _ custodydb.ContextQueryBacking, _ custodydb.ContextQueryAllocation) error {
			row, e := queryExact(ctx, tx, q)
			if e != nil || row.Uncertain {
				return value.ErrUnavailable
			}
			if e = queryWorker(ctx, tx, q, w); e != nil {
				return e
			}
			old, e := tx.LockContextQueryBatch(ctx, custodydb.LockContextQueryBatchParams{ID: id(batchID), QueryID: id(q.ID)})
			if e == nil {
				b, e := queryBatch(old, q)
				if e != nil || b.Worker != w || !sameAuditJSON(b.Request, r) {
					return value.ErrUnavailable
				}
				out.Batch = b
				return nil
			}
			if !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
			if row.ActiveBatch.Valid || row.Generation >= value.ContextMaxReadBatches {
				return value.ErrUnavailable
			}
			call, e := tx.ReadContextQueryCall(ctx, custodydb.ReadContextQueryCallParams{OperationID: id(r.Call.ID), QueryID: id(q.ID)})
			var request value.ContextQueryRequest
			if e != nil || queryDecode(call.Request, 8192, &request) != nil || !sameAuditJSON(request, r) {
				return value.ErrUnavailable
			}
			now, e := tx.CurrentTime(ctx)
			if e != nil {
				return e
			}
			batch := value.ContextReadBatch{QueryID: q.ID, ID: batchID, OperationID: r.Call.ID, Generation: int64(row.Generation) + 1, Worker: w, Request: r, StartedAt: now.Time, Until: identity.Earlier(q.Deadline, identity.Earlier(r.Call.Until, a.ValidUntil)), CleanupUntil: q.CleanupUntil}
			if !batch.Current(q, a, now.Time) {
				return value.ErrUnavailable
			}
			raw, e := queryJSON(batch)
			if e != nil {
				return e
			}
			result, e := tx.InsertContextQueryBatch(ctx, custodydb.InsertContextQueryBatchParams{ID: id(batchID), QueryID: id(q.ID), OperationID: id(r.Call.ID), Generation: int16(batch.Generation), Batch: raw})
			if e != nil {
				return e
			}
			out.Batch, e = queryBatch(result, q)
			out.Fresh = e == nil
			return e
		})
	})
	if e != nil {
		return app.ContextQueryBatchAdmission{}, value.ErrUnavailable
	}
	return out, nil
}
func (s *ContextQueries) withBatch(ctx context.Context, b value.ContextReadBatch, a value.ContextProjectionAuthority, fn func(context.Context, *custodydb.Queries, value.ContextQuery, custodydb.ContextQueryBatch) error) error {
	if ctx == nil || ctx.Err() != nil {
		return value.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, identity.Earlier(b.Until, identity.Earlier(b.Request.Call.Until, a.ValidUntil)))
	defer cancel()
	q, e := s.LookupQuery(ctx, a.Scope.Principal, b.QueryID)
	if e != nil || !b.Current(q, a, time.Now()) {
		return value.ErrUnavailable
	}
	return s.workerCurrent(ctx, q, b.Request, b.Worker, a, func(ctx context.Context) error {
		return s.current(ctx, q, b.Request, a, func(ctx context.Context, tx *custodydb.Queries, _ custodydb.ContextQueryBacking, _ custodydb.ContextQueryAllocation) error {
			qr, e := queryExact(ctx, tx, q)
			if e != nil || qr.Uncertain || uid(qr.ActiveBatch) != b.ID || int64(qr.Generation) != b.Generation {
				return value.ErrUnavailable
			}
			if e = queryWorker(ctx, tx, q, b.Worker); e != nil {
				return e
			}
			row, e := tx.LockContextQueryBatch(ctx, custodydb.LockContextQueryBatchParams{ID: id(b.ID), QueryID: id(q.ID)})
			if e != nil {
				return e
			}
			stored, e := queryBatch(row, q)
			if e != nil || !stored.Equal(b) || row.Closed {
				return value.ErrUnavailable
			}
			now, e := tx.CurrentTime(ctx)
			if e != nil || !b.Current(q, a, now.Time) {
				return value.ErrUnavailable
			}
			if e = fn(ctx, tx, q, row); e != nil {
				return e
			}
			now, e = tx.CurrentTime(ctx)
			if e != nil || !b.Current(q, a, now.Time) || ctx.Err() != nil {
				return value.ErrUnavailable
			}
			return nil
		})
	})
}
func (s *ContextQueries) ClaimReadBatch(ctx context.Context, b value.ContextReadBatch, a value.ContextProjectionAuthority) (value.ContextReadStart, error) {
	var out value.ContextReadStart
	e := s.withBatch(ctx, b, a, func(ctx context.Context, tx *custodydb.Queries, _ value.ContextQuery, row custodydb.ContextQueryBatch) error {
		out = value.ContextReadStart{Batch: b, ClaimID: b.ID}
		if row.ClaimID.Valid {
			if uid(row.ClaimID) != b.ID {
				return value.ErrUnavailable
			}
			return nil
		}
		n, e := tx.ClaimContextQueryBatch(ctx, custodydb.ClaimContextQueryBatchParams{ID: id(b.ID), QueryID: id(b.QueryID), ClaimID: id(b.ID)})
		if e != nil || n != 1 {
			return value.ErrUnavailable
		}
		out.Fresh = true
		return nil
	})
	if e != nil {
		return value.ContextReadStart{}, value.ErrUnavailable
	}
	return out, nil
}
func (s *ContextQueries) PermitReadBatch(ctx context.Context, b value.ContextReadBatch, a value.ContextProjectionAuthority) error {
	return s.withBatch(ctx, b, a, func(_ context.Context, _ *custodydb.Queries, _ value.ContextQuery, row custodydb.ContextQueryBatch) error {
		if uid(row.ClaimID) != b.ID {
			return value.ErrUnavailable
		}
		return nil
	})
}

// Only the actual C-14 closure handle can enter this restrictive transition.
// The active generation remains occupied through outcome audit/final write and
// joined worker+hub cleanup. No expired lease or absence observation substitutes
// for this callback, and no key/read/audit/history charge is refunded.
func (s *ContextQueries) CompleteReadBatch(ctx context.Context, b value.ContextReadBatch, closed app.ContextProjectionClosed) error {
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || closed == nil {
		return value.ErrUnavailable
	}
	originalUntil := identity.Earlier(b.CleanupUntil, b.Request.Call.WriteUntil)
	ctx, stop := context.WithDeadline(ctx, identity.Earlier(time.Now().Add(5*time.Second), originalUntil))
	defer stop()
	q, e := s.LookupQuery(ctx, b.Request.Call.Principal, b.QueryID)
	if e != nil || !b.Matches(q) || !time.Now().Before(q.CleanupUntil) {
		return value.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, identity.Earlier(time.Now().Add(5*time.Second), q.CleanupUntil))
	defer cancel()
	e = queryGuarded(ctx, func(bound context.Context, callback func(context.Context) error) error {
		return closed.WithProjectionClosed(bound, b, callback)
	}, func(joined context.Context) error {
		return s.ledger.transaction(joined, func(tx *custodydb.Queries) error {
			// Historical closure records no new access/effect. Original incarnation
			// still binds all writes; restored state needs independent reconciliation.
			trust, e := tx.ShareFleetTrust(joined, id(q.Plan.InstallationID))
			if e != nil || trust.RecoveryBlocked || uid(trust.IssuerEpoch) != q.RecoveryIssuerEpoch {
				return value.ErrUnavailable
			}
			if _, e = tx.LockPermissionStream(joined, id(s.root)); e != nil {
				return e
			}
			if _, e = tx.LockContextQueryBacking(joined, id(s.root)); e != nil {
				return e
			}
			row, e := queryExact(joined, tx, q)
			if e != nil {
				return e
			}
			incarnation, e := tx.ReadContextDatabaseIncarnation(joined, id(q.Plan.InstallationID))
			if e != nil || !row.PostmasterAt.Time.Equal(incarnation.PostmasterAt.Time) || row.DatabaseOid != incarnation.DatabaseOid {
				return value.ErrUnavailable
			}
			br, e := tx.LockContextQueryBatch(joined, custodydb.LockContextQueryBatchParams{ID: id(b.ID), QueryID: id(q.ID)})
			if e != nil {
				return e
			}
			stored, e := queryBatch(br, q)
			if e != nil || !stored.Equal(b) || uid(br.ClaimID) != b.ID {
				return value.ErrUnavailable
			}
			if br.Closed {
				return nil
			}
			if uid(row.ActiveBatch) != b.ID || int64(row.Generation) != b.Generation {
				return value.ErrUnavailable
			}
			if e = queryOutcomeFence(joined, tx, b.Request.Call); e != nil {
				return e
			}
			now, e := tx.CurrentTime(joined)
			if e != nil || joined.Err() != nil || !now.Time.Before(q.CleanupUntil) || !now.Time.Before(originalUntil) {
				return value.ErrUnavailable
			}
			n, e := tx.CloseContextQueryBatch(joined, custodydb.CloseContextQueryBatchParams{ID: id(b.ID), QueryID: id(q.ID)})
			if e != nil || n != 1 {
				return value.ErrUnavailable
			}
			return nil
		})
	})
	if e != nil || ctx.Err() != nil || !time.Now().Before(originalUntil) {
		return value.ErrUnavailable
	}
	return nil
}
