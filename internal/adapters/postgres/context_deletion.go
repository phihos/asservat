package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	execapp "asservat.local/asservat/internal/application/execution"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"reflect"
	"time"
)

// ContextDeletions is constructed separately for cleanup, audit and finalization.
// Each facet requires exact current installation recovery, never human rights.
type ContextDeletions struct {
	ledger   *Ledger
	root     string
	recovery *RecoveryTransactionGuard
}

func NewContextDeletions(ctx context.Context, pool *pgxpool.Pool, root, installation string) (*ContextDeletions, error) {
	g, err := NewRecoveryTransactionGuard(root, installation)
	if err != nil {
		return nil, err
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &ContextDeletions{l, root, g}, nil
}
func (s *ContextDeletions) transaction(ctx context.Context, p artifact.RecoveryProof, body func(*custodydb.Queries) error) error {
	return s.transactionUntil(ctx, p, time.Time{}, body)
}
func (s *ContextDeletions) transactionUntil(ctx context.Context, p artifact.RecoveryProof, originalUntil time.Time, body func(*custodydb.Queries) error) error {
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, err := s.recovery.lock(ctx, q, s.root, p)
		if err != nil {
			return err
		}
		if _, err = q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		if err = body(q); err != nil {
			return err
		}
		if err = s.recovery.check(ctx, q, trust, s.root, p); err != nil {
			return err
		}
		if !originalUntil.IsZero() {
			now, err := q.CurrentTime(ctx)
			if err != nil {
				return err
			}
			if !now.Time.Before(originalUntil) || !p.Valid(now.Time) {
				return app.ErrExpired
			}
		}
		return ctx.Err()
	})
}
func (s *ContextDeletions) writer(ctx context.Context, q *custodydb.Queries, loc artifact.Location, p artifact.RecoveryProof) (custodydb.ContextWriterCompletion, error) {
	w, err := q.ReadContextWriterCompletion(ctx, custodydb.ReadContextWriterCompletionParams{RootID: id(s.root), AttemptID: id(loc.AttemptID)})
	if err != nil {
		return w, err
	}
	e, err := q.ReadAPIExecution(ctx, custodydb.ReadAPIExecutionParams{RootID: id(s.root), CaptureID: w.CaptureID})
	if err != nil {
		return w, err
	}
	execution, err := apiExecution(e)
	if err != nil {
		return w, err
	}
	d := execapp.APIExecutionDigest(execution)
	inc, err := q.ReadContextDatabaseIncarnation(ctx, id(p.InstallationID))
	if err != nil {
		return w, err
	}
	if execution.WriterProtocol != artifact.ContextWriterProtocol || execution.Phase != "stored" || execution.Binding.AttemptID != loc.AttemptID || execution.Binding.ClusterID != loc.ClusterID || !bytes.Equal(w.ExecutionDigest, d[:]) || !bytes.Equal(w.CopiesDigest, digest(execution.Copies)) || uid(w.InstallationID) != p.InstallationID || uid(w.IssuerEpoch) != p.IssuerEpoch || !inc.PostmasterAt.Valid || !inc.DatabaseOid.Valid || !w.PostmasterAt.Time.Equal(inc.PostmasterAt.Time) || w.DatabaseOid != inc.DatabaseOid {
		return w, app.ErrFence
	}
	return w, nil
}
func deletionRecord(row custodydb.ContextDeletionCheckpoint) (value.ContextDeletionCheckpoint, error) {
	var r value.ContextDeletionCheckpoint
	if len(row.RecordJson) > 8192 || json.Unmarshal(row.RecordJson, &r) != nil || !r.Valid() {
		return r, app.ErrUnavailable
	}
	d := app.ContextDeletionDigest(r)
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(canonical, row.RecordJson) || !bytes.Equal(d[:], row.RecordDigest) || r.RootID != uid(row.RootID) || r.CaptureID != uid(row.CaptureID) || r.Location.AttemptID != uid(row.AttemptID) || r.StoreID != uid(row.StoreID) || !bytes.Equal(r.RegistrationDigest[:], row.RegistrationDigest) || !bytes.Equal(r.WriterDigest[:], row.WriterDigest) || r.InstallationID != uid(row.InstallationID) || r.IssuerEpoch != uid(row.IssuerEpoch) || !r.PostmasterAt.Equal(row.PostmasterAt.Time) || r.DatabaseOID != row.DatabaseOid.Uint32 || r.PurgeFence != row.PurgeFence || !r.PurgedAt.Equal(row.PurgedAt.Time) {
		return value.ContextDeletionCheckpoint{}, app.ErrConflict
	}
	return r, nil
}
func (s *ContextDeletions) matchRecord(ctx context.Context, q *custodydb.Queries, r value.ContextDeletionCheckpoint, p artifact.RecoveryProof) error {
	if !r.Valid() || r.RootID != s.root {
		return app.ErrConflict
	}
	w, err := s.writer(ctx, q, r.Location, p)
	if err != nil {
		return err
	}
	if r.CaptureID != uid(w.CaptureID) || !bytes.Equal(r.WriterDigest[:], w.CompletionDigest) || !bytes.Equal(r.RegistrationDigest[:], w.RegistrationDigest) || r.InstallationID != uid(w.InstallationID) || r.IssuerEpoch != uid(w.IssuerEpoch) || !r.PostmasterAt.Equal(w.PostmasterAt.Time) || r.DatabaseOID != w.DatabaseOid.Uint32 {
		return app.ErrFence
	}
	return nil
}
func (s *ContextDeletions) ReadContextDeletion(ctx context.Context, loc artifact.Location, p artifact.RecoveryProof) (value.ContextDeletionCheckpoint, bool, error) {
	var out value.ContextDeletionCheckpoint
	found := false
	if loc.Validate() != nil {
		return out, false, artifact.ErrInvalid
	}
	err := s.transaction(ctx, p, func(q *custodydb.Queries) error {
		row, err := q.ReadContextDeletion(ctx, custodydb.ReadContextDeletionParams{RootID: id(s.root), AttemptID: id(loc.AttemptID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out, err = deletionRecord(row)
		if err != nil {
			return err
		}
		if out.Location != loc {
			return app.ErrConflict
		}
		if err = s.matchRecord(ctx, q, out, p); err != nil {
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return value.ContextDeletionCheckpoint{}, false, err
	}
	return out, found, nil
}
func lockDeletionAttempt(ctx context.Context, q *custodydb.Queries, loc artifact.Location) (custodydb.CustodyAttempt, custodydb.CustodyPool, custodydb.CustodyAllocation, error) {
	hint, err := q.ReadAttempt(ctx, id(loc.AttemptID))
	if err != nil {
		return hint, custodydb.CustodyPool{}, custodydb.CustodyAllocation{}, err
	}
	pool, allocation, err := lockAllocation(ctx, q, uid(hint.AllocationID))
	if err != nil {
		return hint, pool, allocation, err
	}
	row, err := q.LockAttempt(ctx, id(loc.AttemptID))
	if err == nil && (uid(row.ClusterID) != loc.ClusterID || uid(row.ArtifactID) != loc.ArtifactID) {
		err = app.ErrConflict
	}
	return row, pool, allocation, err
}
func (s *ContextDeletions) BeginContextDeletion(ctx context.Context, loc artifact.Location, p artifact.RecoveryProof) (app.ContextDeletionWork, error) {
	var out app.ContextDeletionWork
	if loc.Validate() != nil {
		return out, artifact.ErrInvalid
	}
	err := s.transaction(ctx, p, func(q *custodydb.Queries) error {
		row, pool, _, err := lockDeletionAttempt(ctx, q, loc)
		if err != nil {
			return err
		}
		w, err := s.writer(ctx, q, loc, p)
		if err != nil {
			return err
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if row.State == artifact.Deleted || n.Time.Before(row.EffectiveExpiresAt.Time) {
			return app.ErrNotDue
		}
		if row.LeaseUntil.Valid && n.Time.Before(row.LeaseUntil.Time) {
			return app.ErrFence
		}
		if _, err = q.ReadContextDeletion(ctx, custodydb.ReadContextDeletionParams{RootID: id(s.root), AttemptID: row.ID}); !errors.Is(err, pgx.ErrNoRows) {
			if err == nil {
				return app.ErrConflict
			}
			return err
		}
		rec, err := record(ctx, q, row, uid(pool.StoreID))
		if err != nil {
			return err
		}
		if !bytes.Equal(w.RegistrationDigest, digest(normalized(rec.Registration))) {
			return app.ErrConflict
		}
		until := n.Time.Add(30 * time.Second)
		fence, err := q.ClaimDeletion(ctx, custodydb.ClaimDeletionParams{ID: row.ID, LeaseUntil: ts(until)})
		if err != nil {
			return err
		}
		r := value.ContextDeletionCheckpoint{RootID: s.root, CaptureID: uid(w.CaptureID), Location: loc, StoreID: rec.Registration.StoreID, InstallationID: p.InstallationID, IssuerEpoch: p.IssuerEpoch, PostmasterAt: w.PostmasterAt.Time.UTC(), DatabaseOID: w.DatabaseOid.Uint32, PurgeFence: fence}
		copy(r.RegistrationDigest[:], w.RegistrationDigest)
		copy(r.WriterDigest[:], w.CompletionDigest)
		out = app.ContextDeletionWork{Deletion: app.Deletion{Registration: rec.Registration, Effective: rec.Effective, Fence: fence, LeaseUntil: until}, Checkpoint: r}
		return nil
	})
	if err != nil {
		return app.ContextDeletionWork{}, err
	}
	return out, nil
}
func (s *ContextDeletions) RecordContextPurge(ctx context.Context, work app.ContextDeletionWork, done time.Time, p artifact.RecoveryProof) (value.ContextDeletionCheckpoint, error) {
	r := work.Checkpoint
	r.PurgedAt = done.UTC().Truncate(time.Microsecond)
	if !r.Valid() || work.Deletion.Registration.Validate() != nil || r.Location != work.Deletion.Registration.Location || r.StoreID != work.Deletion.Registration.StoreID || r.RegistrationDigest != app.RegistrationDigest(work.Deletion.Registration) || r.PurgeFence != work.Deletion.Fence || !done.Before(work.Deletion.LeaseUntil) {
		return value.ContextDeletionCheckpoint{}, artifact.ErrInvalid
	}
	err := s.transactionUntil(ctx, p, work.Deletion.LeaseUntil, func(q *custodydb.Queries) error {
		row, pool, _, err := lockDeletionAttempt(ctx, q, r.Location)
		if err != nil {
			return err
		}
		if err = s.matchRecord(ctx, q, r, p); err != nil {
			return err
		}
		old, err := q.ReadContextDeletion(ctx, custodydb.ReadContextDeletionParams{RootID: id(s.root), AttemptID: row.ID})
		if err == nil {
			saved, e := deletionRecord(old)
			if e != nil {
				return e
			}
			if !reflect.DeepEqual(saved, r) {
				return app.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if row.State != artifact.Deleting || row.DeletionFence != r.PurgeFence || !row.LeaseUntil.Valid || !row.LeaseUntil.Time.Equal(work.Deletion.LeaseUntil) || !n.Time.Before(row.LeaseUntil.Time) || r.PurgedAt.After(n.Time) || r.PurgedAt.Before(row.EffectiveExpiresAt.Time) || r.StoreID != uid(pool.StoreID) || !bytes.Equal(row.RequestDigest, r.RegistrationDigest[:]) {
			return app.ErrFence
		}
		b, _ := json.Marshal(r)
		d := app.ContextDeletionDigest(r)
		if err = q.InsertContextDeletion(ctx, custodydb.InsertContextDeletionParams{RootID: id(s.root), CaptureID: id(r.CaptureID), AttemptID: row.ID, StoreID: id(r.StoreID), RegistrationDigest: r.RegistrationDigest[:], WriterDigest: r.WriterDigest[:], RecordDigest: d[:], RecordJson: b, InstallationID: id(r.InstallationID), IssuerEpoch: id(r.IssuerEpoch), PostmasterAt: ts(r.PostmasterAt), DatabaseOid: pgtype.Uint32{Uint32: r.DatabaseOID, Valid: true}, PurgeFence: r.PurgeFence, PurgedAt: ts(r.PurgedAt)}); err != nil {
			return err
		}
		n, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !n.Time.Before(work.Deletion.LeaseUntil) {
			return app.ErrExpired
		}
		return nil
	})
	if err != nil {
		return value.ContextDeletionCheckpoint{}, err
	}
	return r, nil
}
func (s *ContextDeletions) AcknowledgeContextDeletion(ctx context.Context, r value.ContextDeletionCheckpoint, receipt audit.Receipt, p artifact.RecoveryProof) error {
	if !r.Valid() || !receipt.ValidContextDeletion(r.RootID, r.Location.AttemptID) {
		return artifact.ErrInvalid
	}
	return s.transaction(ctx, p, func(q *custodydb.Queries) error {
		if err := s.matchRecord(ctx, q, r, p); err != nil {
			return err
		}
		row, err := q.LockContextDeletion(ctx, custodydb.LockContextDeletionParams{RootID: id(s.root), AttemptID: id(r.Location.AttemptID)})
		if err != nil {
			return err
		}
		saved, err := deletionRecord(row)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(saved, r) {
			return app.ErrConflict
		}
		b, _ := json.Marshal(receipt)
		if row.AuditAcknowledgedAt.Valid {
			if !bytes.Equal(b, row.AuditReceiptJson) {
				return app.ErrConflict
			}
			return nil
		}
		count, err := q.AcknowledgeContextDeletion(ctx, custodydb.AcknowledgeContextDeletionParams{RootID: id(s.root), AttemptID: row.AttemptID, AuditReceiptJson: b})
		if err != nil {
			return err
		}
		if count != 1 {
			return app.ErrFence
		}
		return nil
	})
}
func (s *ContextDeletions) FinalizeContextDeletion(ctx context.Context, r value.ContextDeletionCheckpoint, p artifact.RecoveryProof) error {
	if !r.Valid() {
		return artifact.ErrInvalid
	}
	return s.transaction(ctx, p, func(q *custodydb.Queries) error {
		row, _, allocation, err := lockDeletionAttempt(ctx, q, r.Location)
		if err != nil {
			return err
		}
		if err = s.matchRecord(ctx, q, r, p); err != nil {
			return err
		}
		d, err := q.LockContextDeletion(ctx, custodydb.LockContextDeletionParams{RootID: id(s.root), AttemptID: row.ID})
		if err != nil {
			return err
		}
		saved, err := deletionRecord(d)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(saved, r) || !d.AuditAcknowledgedAt.Valid {
			return app.ErrFence
		}
		var receipt audit.Receipt
		if json.Unmarshal(d.AuditReceiptJson, &receipt) != nil || !receipt.ValidContextDeletion(s.root, r.Location.AttemptID) {
			return app.ErrUnavailable
		}
		if row.State == artifact.Deleted {
			return nil
		}
		if row.State != artifact.Deleting || row.DeletionFence < r.PurgeFence || !bytes.Equal(row.RequestDigest, r.RegistrationDigest[:]) {
			return app.ErrFence
		}
		claimed, err := q.ClaimContextFinalization(ctx, custodydb.ClaimContextFinalizationParams{RootID: id(s.root), AttemptID: row.ID})
		if err != nil {
			return err
		}
		if claimed != 1 {
			return app.ErrFence
		}
		changed, err := q.ReleaseCharge(ctx, custodydb.ReleaseChargeParams{ID: allocation.ID, ChargedBytes: row.ReservedBytes})
		if err != nil {
			return err
		}
		if changed != 1 {
			return app.ErrUnavailable
		}
		if err = q.ClearReceipts(ctx, row.ID); err != nil {
			return err
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if err = q.MarkDeleted(ctx, custodydb.MarkDeletedParams{ID: row.ID, DeletedAt: n}); err != nil {
			return err
		}
		return q.InsertEvent(ctx, custodydb.InsertEventParams{AttemptID: row.ID, Phase: "deleted"})
	})
}
