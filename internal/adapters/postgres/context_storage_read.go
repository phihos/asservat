package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContextStorageReader reads a workload's storage binding and, with an
// account key, enrolls the workload on first use (capacity_enroll).
type ContextStorageReader struct {
	ledger       *Ledger
	root         string
	installation string
	accounts     CaptureAccountKey
}

// CaptureAccountKey derives a capture audit account digest.
type CaptureAccountKey interface {
	CaptureAccount(installation, root, allocation string) (artifact.Digest, error)
}

var _ app.ContextStorageReader = (*ContextStorageReader)(nil)

func NewContextStorageReader(ctx context.Context, pool *pgxpool.Pool, root string) (*ContextStorageReader, error) {
	if !authorization.UUID(root) {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return &ContextStorageReader{ledger: l, root: root}, nil
}

// WithEnrollment enrolls missing workloads under the installation's capture
// account key.
func (s *ContextStorageReader) WithEnrollment(installation string, accounts CaptureAccountKey) *ContextStorageReader {
	out := *s
	out.installation, out.accounts = installation, accounts
	return &out
}

func (s *ContextStorageReader) enroll(ctx context.Context, q *custodydb.Queries, target authorization.Target) error {
	if s.accounts == nil {
		return pgx.ErrNoRows
	}
	allocation, download := uuid.NewString(), uuid.NewString()
	digest, err := s.accounts.CaptureAccount(s.installation, s.root, allocation)
	if err != nil {
		return err
	}
	_, err = q.EnrollCapacity(ctx, custodydb.EnrollCapacityParams{RootID: id(s.root), ClusterID: id(target.ClusterID), NamespaceUid: target.NamespaceUID, WorkloadUid: target.WorkloadUID, AllocationID: id(allocation), DownloadAllocationID: id(download), AccountDigest: digest[:]})
	return err
}

func contextStorageObservation(row custodydb.ObserveContextStorageRow, root string, target authorization.Target, now time.Time) (app.ContextStorageObservation, error) {
	refuse := func(predicate string, cause error) (app.ContextStorageObservation, error) {
		return app.ContextStorageObservation{}, contextStorageObservationFailure{predicate: predicate, cause: cause}
	}
	if !authorization.UUID(root) || !target.Valid() || row.ServiceClass != "context" || len(row.SourceDigest) != 32 || !row.PoolValidUntil.Valid || !row.AllocationValidUntil.Valid {
		return refuse("shape", value.ErrChanged)
	}
	if row.PoolPaused || !now.Before(row.PoolValidUntil.Time) {
		return refuse("pool", value.ErrChanged)
	}
	if row.AllocationPaused || !now.Before(row.AllocationValidUntil.Time) {
		return refuse("allocation", value.ErrChanged)
	}
	var d artifact.Digest
	copy(d[:], row.SourceDigest)
	b := value.StorageBinding{RootID: uid(row.RootID), ClusterID: uid(row.ClusterID), NamespaceUID: row.NamespaceUid, WorkloadUID: row.WorkloadUid, AllocationID: uid(row.AllocationID), Revision: identity.Revision{UID: row.SourceUid, Generation: row.SourceGeneration, Digest: d}, ObservedAt: row.ObservedAt.Time, FreshUntil: row.FreshUntil.Time}
	selection := value.ContextStorageSelection{StoreID: uid(row.StoreID), AllocationID: b.AllocationID, PoolRevision: row.PoolRevision, AllocationRevision: row.AllocationRevision, BindingRevision: b.Revision}
	out := app.ContextStorageObservation{Binding: b, Selection: selection}
	if b.RootID != root || !b.Matches(target) || !out.Selection.Valid() || !out.Binding.Valid(now) {
		return refuse("selection", value.ErrChanged)
	}
	return out, nil
}

// Only the rejecting predicate survives; it carries no row values or SQL text.
// Keep the original cause so diagnostics cannot change the public refusal.
type contextStorageObservationFailure struct {
	predicate string
	cause     error
}

func (e contextStorageObservationFailure) Error() string {
	return "context storage observation unavailable"
}
func (e contextStorageObservationFailure) Unwrap() error { return e.cause }

func (s *ContextStorageReader) ContextStorage(ctx context.Context, target authorization.Target) (app.ContextStorageObservation, error) {
	var out app.ContextStorageObservation
	if s == nil || s.ledger == nil || !target.Valid() {
		return out, value.ErrInvalid
	}
	stage := "transaction"
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		stage = "transaction" // A definitely aborted transaction may retry.
		// One MVCC statement observes the binding, allocation and pool together.
		// Admission independently locks/rechecks those exact revisions later.
		params := custodydb.ObserveContextStorageParams{RootID: id(s.root), ClusterID: id(target.ClusterID), NamespaceUid: target.NamespaceUID, WorkloadUid: target.WorkloadUID}
		row, err := q.ObserveContextStorage(ctx, params)
		if errors.Is(err, pgx.ErrNoRows) {
			if err = s.enroll(ctx, q, target); err == nil {
				row, err = q.ObserveContextStorage(ctx, params)
			}
		}
		if err != nil {
			stage = "query/" + storageReadCause(err)
			return value.ErrUnavailable
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			stage = "clock/" + storageReadCause(err)
			var sql *pgconn.PgError
			if errors.As(err, &sql) && (sql.Code == "40001" || sql.Code == "40P01") {
				// A later retry may fail before the callback runs again.
				stage = "transaction"
			}
			return err
		}
		out, err = contextStorageObservation(row, s.root, target, now.Time)
		if err != nil {
			stage = "observation"
			var failure contextStorageObservationFailure
			if errors.As(err, &failure) {
				stage += "/" + failure.predicate
			}
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		var transaction ledgerCause
		if errors.As(err, &transaction) && strings.HasPrefix(transaction.cause, "begin-") {
			// A retry can fail before its callback resets the prior phase.
			stage = "transaction"
		}
		return app.ContextStorageObservation{}, &contextStorageReadFailure{stage: stage, cause: captureError(err)}
	}
	return out, nil
}

// Only a fixed private phase survives the transaction's existing error
// normalization. SQL text, identifiers and dependency error strings do not.
type contextStorageReadFailure struct {
	stage string
	cause error
}

func (e *contextStorageReadFailure) Error() string              { return "context storage unavailable" }
func (e *contextStorageReadFailure) Unwrap() error              { return e.cause }
func (e *contextStorageReadFailure) ContextStorageRead() string { return e.stage }

func storageReadCause(err error) string {
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "no-row"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "unavailable"
	}
}
