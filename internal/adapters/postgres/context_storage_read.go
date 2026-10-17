package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContextStorageReader observes existing configuration with SELECT-only
// credentials. It cannot create a binding, reserve capacity or establish the
// protected source acceptance that the binding producer still must supply.
type ContextStorageReader struct {
	ledger *Ledger
	root   string
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

func contextStorageObservation(row custodydb.ObserveContextStorageRow, root string, target authorization.Target, now time.Time) (app.ContextStorageObservation, error) {
	var out app.ContextStorageObservation
	if !authorization.UUID(root) || !target.Valid() || row.AllocationPaused || row.PoolPaused || row.ServiceClass != "context" || len(row.SourceDigest) != 32 || !row.ObservedAt.Valid || !row.FreshUntil.Valid || !row.CapacityUntil.Valid || !now.Before(row.CapacityUntil.Time) || row.CapacityUntil.Time.After(row.FreshUntil.Time) || !row.PoolValidUntil.Valid || !row.AllocationValidUntil.Valid || !now.Before(row.PoolValidUntil.Time) || !now.Before(row.AllocationValidUntil.Time) {
		return out, value.ErrChanged
	}
	var d artifact.Digest
	copy(d[:], row.SourceDigest)
	b := value.StorageBinding{RootID: uid(row.RootID), ClusterID: uid(row.ClusterID), NamespaceUID: row.NamespaceUid, WorkloadUID: row.WorkloadUid, AllocationID: uid(row.AllocationID), Revision: identity.Revision{UID: row.SourceUid, Generation: row.SourceGeneration, Digest: d}, ObservedAt: row.ObservedAt.Time, FreshUntil: row.FreshUntil.Time}
	// Validate the original observation before shortening; clamping must not
	// make a source with an invalid, overlong freshness interval acceptable.
	if b.RootID != root || !b.Matches(target) || !b.Valid(now) {
		return out, value.ErrChanged
	}
	controlPool := custodydb.ContextControlPool{RootID: row.RootID, Configured: row.ControlPoolConfigured, Paused: row.ControlPoolPaused, Revision: row.ControlPoolRevision, ValidUntil: row.ControlPoolUntil, FullLimit: row.ControlPoolFull, ReplayLimit: row.ControlPoolReplay, BackedFull: row.BackedFull, BackedReplay: row.BackedReplay}
	controlAccount := custodydb.ContextControlAccount{RootID: row.RootID, AllocationID: row.AllocationID, Configured: row.ControlAccountConfigured, Paused: row.ControlAccountPaused, Revision: row.ControlAccountRevision, ValidUntil: row.ControlAccountUntil, FullLimit: row.ControlAccountFull, ReplayLimit: row.ControlAccountReplay, ChargedFull: row.ChargedFull, ChargedReplay: row.ChargedReplay}
	controlUntil, err := controlCapacityDeadline(controlPool, controlAccount, root, b.AllocationID, now)
	if err != nil {
		return out, err
	}
	b.FreshUntil = identity.Earlier(row.CapacityUntil.Time, identity.Earlier(controlUntil, identity.Earlier(b.FreshUntil, identity.Earlier(row.PoolValidUntil.Time, row.AllocationValidUntil.Time))))
	out = app.ContextStorageObservation{Binding: b, Selection: value.ContextStorageSelection{StoreID: uid(row.StoreID), AllocationID: b.AllocationID, PoolRevision: row.PoolRevision, AllocationRevision: row.AllocationRevision, BindingRevision: b.Revision}}
	if !out.Selection.Valid() || !out.Binding.Valid(now) {
		return app.ContextStorageObservation{}, value.ErrChanged
	}
	return out, nil
}

func (s *ContextStorageReader) ContextStorage(ctx context.Context, target authorization.Target) (app.ContextStorageObservation, error) {
	var out app.ContextStorageObservation
	if s == nil || s.ledger == nil || !target.Valid() {
		return out, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		// One MVCC statement observes the binding, allocation and pool together.
		// Admission independently locks/rechecks those exact revisions later.
		row, err := q.ObserveContextStorage(ctx, custodydb.ObserveContextStorageParams{RootID: id(s.root), ClusterID: id(target.ClusterID), NamespaceUid: target.NamespaceUID, WorkloadUid: target.WorkloadUID})
		if err != nil {
			return value.ErrUnavailable
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		out, err = contextStorageObservation(row, s.root, target, now.Time)
		if err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return app.ContextStorageObservation{}, captureError(err)
	}
	return out, nil
}
